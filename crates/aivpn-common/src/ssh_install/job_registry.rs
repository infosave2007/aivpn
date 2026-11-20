//! Общая очередь событий SSH-установки для мобильных клиентов.
//!
//! Старые строки вытесняются при превышении числа событий или объема журнала.
//! Итог установки и последний ключ подключения сохраняются целиком. Размер
//! ключа ограничен размером входной строки SSH; обычные сообщения сокращаются
//! внутри JSON. Событие, для которого iOS уже запросила размер буфера, хранится
//! отдельно до повторного чтения и не вытесняется новыми строками.
//! Освобождение очереди не отменяет удаленную установку.

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Mutex;

/// Предел числа событий в журнале, включая уведомление о пропущенных строках.
pub const MAX_QUEUED_EVENTS: usize = 256;
/// Предел объема журнала; последний ключ и итог установки не обрезаются.
pub const MAX_QUEUED_BYTES: usize = 256 * 1024;
/// Максимальный размер обычного события.
pub const MAX_EVENT_BYTES: usize = 16 * 1024;

const CLIP_MARK: &str = "… [строка обрезана]";
const DROP_NOTICE_PREFIX: &str = "журнал установки сокращен: отброшено ";
const DROP_NOTICE_SUFFIX: &str = " старых строк";

#[derive(Clone, Copy)]
struct QueueLimits {
    max_events: usize,
    max_bytes: usize,
    max_event_bytes: usize,
}

impl QueueLimits {
    fn production() -> Self {
        Self {
            max_events: MAX_QUEUED_EVENTS,
            max_bytes: MAX_QUEUED_BYTES,
            max_event_bytes: MAX_EVENT_BYTES,
        }
    }
}

/// Результат чтения очереди.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PollOutcome {
    /// Событие удалено из очереди и передано вызывающему коду.
    Event(String),
    /// Очередь пуста, установка продолжается.
    Pending,
    /// Очередь пуста, установка завершилась.
    Done,
    /// Буфер мал; событие закреплено до следующей попытки чтения.
    NeedsCapacity(usize),
    /// Неизвестный или освобожденный идентификатор.
    NotFound,
}

struct QueuedEvent {
    json: String,
    finished: bool,
    has_connection_key: bool,
    notice: bool,
}

impl QueuedEvent {
    fn incoming(json: String) -> Self {
        let value = serde_json::from_str::<serde_json::Value>(&json).ok();
        Self {
            finished: is_finished(value.as_ref()),
            has_connection_key: has_connection_key(value.as_ref()),
            notice: false,
            json,
        }
    }

    fn notice(dropped: u64) -> Self {
        Self {
            json: notice_json(dropped),
            finished: false,
            has_connection_key: false,
            notice: true,
        }
    }
}

struct Job {
    events: VecDeque<QueuedEvent>,
    done: bool,
    pending: Option<QueuedEvent>,
    dropped_lines: u64,
}

/// Реестр установок. Освобождение записи не отменяет фоновую работу.
pub struct JobRegistry {
    next_handle: AtomicI64,
    jobs: Mutex<HashMap<i64, Job>>,
    limits: QueueLimits,
}

impl JobRegistry {
    pub fn new() -> Self {
        Self::with_limits(QueueLimits::production())
    }

    fn with_limits(limits: QueueLimits) -> Self {
        Self {
            next_handle: AtomicI64::new(1),
            jobs: Mutex::new(HashMap::new()),
            limits,
        }
    }

    pub fn create(&self) -> i64 {
        let handle = self.next_handle.fetch_add(1, Ordering::Relaxed);
        self.jobs().insert(
            handle,
            Job {
                events: VecDeque::new(),
                done: false,
                pending: None,
                dropped_lines: 0,
            },
        );
        handle
    }

    pub fn push(&self, handle: i64, event: String) {
        let queued = QueuedEvent::incoming(clamp_event_json(&event, self.limits.max_event_bytes));
        let mut jobs = self.jobs();
        let Some(job) = jobs.get_mut(&handle) else {
            return;
        };
        job.events.push_back(queued);
        enforce(job, self.limits);
    }

    pub fn mark_done(&self, handle: i64) {
        if let Some(job) = self.jobs().get_mut(&handle) {
            job.done = true;
        }
    }

    /// Читает событие, если оно помещается в буфер, иначе сообщает нужный размер.
    pub fn poll(&self, handle: i64, cap: usize) -> PollOutcome {
        self.poll_limited(handle, Some(cap))
    }

    /// Читает событие целиком для Android, без промежуточного буфера FFI.
    pub fn poll_next(&self, handle: i64) -> PollOutcome {
        self.poll_limited(handle, None)
    }

    pub fn free(&self, handle: i64) -> bool {
        self.jobs().remove(&handle).is_some()
    }

    fn jobs(&self) -> std::sync::MutexGuard<'_, HashMap<i64, Job>> {
        self.jobs.lock().unwrap_or_else(|err| err.into_inner())
    }

    fn poll_limited(&self, handle: i64, cap: Option<usize>) -> PollOutcome {
        let mut jobs = self.jobs();
        let Some(job) = jobs.get_mut(&handle) else {
            return PollOutcome::NotFound;
        };
        let event = job.pending.take().or_else(|| {
            let event = job.events.pop_front()?;
            if event.notice {
                job.dropped_lines = 0;
            }
            Some(event)
        });
        let Some(event) = event else {
            return if job.done {
                PollOutcome::Done
            } else {
                PollOutcome::Pending
            };
        };
        if cap.is_some_and(|limit| event.json.len() > limit) {
            let needed = event.json.len();
            job.pending = Some(event);
            return PollOutcome::NeedsCapacity(needed);
        }
        PollOutcome::Event(event.json)
    }
}

impl Default for JobRegistry {
    fn default() -> Self {
        Self::new()
    }
}

fn enforce(job: &mut Job, limits: QueueLimits) {
    job.events.retain(|event| !event.notice);
    while over_limit(job, limits) && drop_oldest(job) {}
    if job.dropped_lines == 0 {
        return;
    }
    while notice_exceeds(job, limits) && drop_oldest(job) {}
    job.events
        .push_front(QueuedEvent::notice(job.dropped_lines));
}

fn over_limit(job: &Job, limits: QueueLimits) -> bool {
    job.events.len() > limits.max_events || byte_len(job) > limits.max_bytes
}

fn notice_exceeds(job: &Job, limits: QueueLimits) -> bool {
    let notice_len = notice_json(job.dropped_lines).len();
    job.events.len() + 1 > limits.max_events
        || byte_len(job).saturating_add(notice_len) > limits.max_bytes
}

fn drop_oldest(job: &mut Job) -> bool {
    let keep_finished = job.events.iter().rposition(|event| event.finished);
    let keep_key = job
        .events
        .iter()
        .rposition(|event| event.has_connection_key);
    let keep_newest = job.events.len().checked_sub(1);
    let Some(index) = job.events.iter().enumerate().find_map(|(index, event)| {
        if event.notice
            || Some(index) == keep_finished
            || Some(index) == keep_key
            || Some(index) == keep_newest
        {
            None
        } else {
            Some(index)
        }
    }) else {
        return false;
    };
    job.events.remove(index);
    job.dropped_lines = job.dropped_lines.saturating_add(1);
    true
}

fn byte_len(job: &Job) -> usize {
    job.events.iter().map(|event| event.json.len()).sum()
}

fn is_finished(value: Option<&serde_json::Value>) -> bool {
    value
        .and_then(|item| item.get("type"))
        .and_then(serde_json::Value::as_str)
        == Some("finished")
}

fn has_connection_key(value: Option<&serde_json::Value>) -> bool {
    matches!(
        value.and_then(|item| item.get("connection_key")),
        Some(serde_json::Value::String(key)) if !key.is_empty()
    )
}

fn retains_install_result(value: &serde_json::Value) -> bool {
    is_finished(Some(value)) || has_connection_key(Some(value))
}

fn notice_json(dropped: u64) -> String {
    serde_json::json!({
        "line": format!("{DROP_NOTICE_PREFIX}{dropped}{DROP_NOTICE_SUFFIX}"),
        "type": "line"
    })
    .to_string()
}

fn fallback_line() -> String {
    serde_json::json!({
        "line": "событие журнала сокращено: исходная запись не поместилась в лимит",
        "type": "line"
    })
    .to_string()
}

fn bounded_fallback(max_bytes: usize) -> String {
    let full = fallback_line();
    if full.len() <= max_bytes {
        return full;
    }
    let short = serde_json::json!({"line": "…", "type": "line"}).to_string();
    if short.len() <= max_bytes {
        short
    } else {
        "{}".to_string()
    }
}

fn clamp_event_json(event: &str, max_bytes: usize) -> String {
    if event.len() <= max_bytes {
        return event.to_string();
    }
    let Ok(value) = serde_json::from_str::<serde_json::Value>(event) else {
        return bounded_fallback(max_bytes);
    };
    shrink_to_max(value, max_bytes).unwrap_or_else(|| event.to_string())
}

fn shrink_to_max(mut value: serde_json::Value, max_bytes: usize) -> Option<String> {
    let protected = retains_install_result(&value);
    loop {
        let json = value.to_string();
        if json.len() <= max_bytes {
            return Some(json);
        }
        if !shorten_longest_field(&mut value) {
            return if protected {
                None
            } else {
                Some(bounded_fallback(max_bytes))
            };
        }
    }
}

fn shorten_longest_field(value: &mut serde_json::Value) -> bool {
    let Some(object) = value.as_object_mut() else {
        return false;
    };
    let Some(text) = object
        .iter_mut()
        .filter(|(key, _)| key.as_str() != "type" && key.as_str() != "connection_key")
        .filter_map(|(_, value)| match value {
            serde_json::Value::String(text) if text.len() > CLIP_MARK.len() => Some(text),
            _ => None,
        })
        .max_by_key(|text| text.len())
    else {
        return false;
    };
    let mut end = (text.len() - CLIP_MARK.len()) / 2;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    text.truncate(end);
    text.push_str(CLIP_MARK);
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    fn drain(reg: &JobRegistry, handle: i64) -> Vec<String> {
        let mut events = Vec::new();
        loop {
            match reg.poll(handle, usize::MAX) {
                PollOutcome::Event(event) => events.push(event),
                PollOutcome::Pending => return events,
                other => panic!("неожиданный исход опроса: {other:?}"),
            }
        }
    }

    fn notice_count(event: &str) -> Option<u64> {
        let value: serde_json::Value = serde_json::from_str(event).ok()?;
        let line = value.get("line")?.as_str()?;
        let rest = line.strip_prefix(DROP_NOTICE_PREFIX)?;
        rest.strip_suffix(DROP_NOTICE_SUFFIX)?.parse().ok()
    }

    fn limits(max_events: usize, max_bytes: usize, max_event_bytes: usize) -> QueueLimits {
        QueueLimits {
            max_events,
            max_bytes,
            max_event_bytes,
        }
    }

    #[test]
    fn handles_start_at_one_and_unknown_commands_do_nothing() {
        let reg = JobRegistry::new();
        let first = reg.create();
        let second = reg.create();
        assert_eq!(first, 1);
        assert_eq!(second, 2);
        reg.push(999, "x".to_string());
        reg.mark_done(999);
        assert_eq!(reg.poll(999, 8), PollOutcome::NotFound);
        assert!(!reg.free(42));
    }

    #[test]
    fn fifo_then_sticky_done_and_free_discards_late_events() {
        let reg = JobRegistry::new();
        let handle = reg.create();
        reg.push(handle, "a".to_string());
        reg.push(handle, "b".to_string());
        reg.mark_done(handle);
        assert_eq!(reg.poll(handle, 1), PollOutcome::Event("a".to_string()));
        assert_eq!(reg.poll(handle, 1), PollOutcome::Event("b".to_string()));
        assert_eq!(reg.poll(handle, 1), PollOutcome::Done);
        assert_eq!(reg.poll(handle, 1), PollOutcome::Done);
        assert!(reg.free(handle));
        reg.push(handle, "late".to_string());
        reg.mark_done(handle);
        assert_eq!(reg.poll(handle, 8), PollOutcome::NotFound);
    }

    #[test]
    fn short_buffer_peeks_the_same_event() {
        let reg = JobRegistry::new();
        let handle = reg.create();
        reg.push(handle, "hello".to_string());
        assert_eq!(reg.poll(handle, 4), PollOutcome::NeedsCapacity(5));
        assert_eq!(reg.poll(handle, 4), PollOutcome::NeedsCapacity(5));
        assert_eq!(reg.poll(handle, 5), PollOutcome::Event("hello".to_string()));
        assert_eq!(reg.poll_next(handle), PollOutcome::Pending);
    }

    #[test]
    fn peeked_event_survives_overflow_until_retry() {
        let reg = JobRegistry::new();
        let handle = reg.create();
        let first = serde_json::json!({"type": "line", "line": "first event"}).to_string();
        reg.push(handle, first.clone());
        assert_eq!(reg.poll(handle, 1), PollOutcome::NeedsCapacity(first.len()));
        for index in 0..1_000 {
            reg.push(
                handle,
                serde_json::json!({"type": "line", "line": index.to_string()}).to_string(),
            );
        }
        assert_eq!(reg.poll(handle, first.len()), PollOutcome::Event(first));
    }

    #[test]
    fn consumed_drop_notice_does_not_reappear() {
        let reg = JobRegistry::with_limits(limits(3, 10_000, 1_000));
        let handle = reg.create();
        for index in 0..10 {
            reg.push(handle, index.to_string());
        }
        assert!(drain(&reg, handle)
            .iter()
            .any(|event| notice_count(event).is_some()));
        reg.push(handle, "new".to_string());
        assert_eq!(drain(&reg, handle), vec!["new".to_string()]);
    }

    #[test]
    fn exact_count_and_byte_caps_keep_events_until_the_next_one() {
        let event = "x".repeat(32);
        let reg = JobRegistry::with_limits(limits(2, event.len() * 2, 100));
        let handle = reg.create();
        reg.push(handle, event.clone());
        reg.push(handle, event.clone());
        assert_eq!(drain(&reg, handle), vec![event.clone(), event]);
    }

    #[test]
    fn count_overflow_keeps_newest_and_one_notice() {
        let reg = JobRegistry::with_limits(limits(3, 10_000, 1_000));
        let handle = reg.create();
        let mut pushed = Vec::new();
        for index in 0..6 {
            let event = format!("line-{index}");
            reg.push(handle, event.clone());
            pushed.push(event);
        }
        let events = drain(&reg, handle);
        assert!(events.len() <= 3);
        assert_eq!(
            events
                .iter()
                .filter_map(|event| notice_count(event))
                .count(),
            1
        );
        assert_eq!(events.last().map(String::as_str), Some("line-5"));
        assert_missing_matches_notice(&pushed, &events);
    }

    #[test]
    fn byte_overflow_keeps_total_within_cap() {
        let event = "y".repeat(1_000);
        let reg = JobRegistry::with_limits(limits(20, event.len() * 2, event.len()));
        let handle = reg.create();
        for _ in 0..6 {
            reg.push(handle, event.clone());
        }
        let events = drain(&reg, handle);
        let bytes: usize = events.iter().map(String::len).sum();
        assert!(bytes <= event.len() * 2, "байты очереди {bytes}");
        assert_eq!(
            events.iter().filter_map(|item| notice_count(item)).count(),
            1
        );
        assert_eq!(events.last().map(String::as_str), Some(event.as_str()));
    }

    #[test]
    fn old_finished_event_and_connection_key_survive_a_later_flood() {
        let reg = JobRegistry::with_limits(limits(3, 10_000, 1_000));
        let handle = reg.create();
        let key = "aivpn://kept";
        let finished = serde_json::json!({
            "connection_key": key,
            "exit_code": 0,
            "type": "finished"
        })
        .to_string();
        reg.push(handle, finished.clone());
        let mut pushed = vec![finished.clone()];
        for index in 0..8 {
            let line =
                serde_json::json!({"line": format!("log-{index}"), "type": "line"}).to_string();
            reg.push(handle, line.clone());
            pushed.push(line);
        }
        let events = drain(&reg, handle);
        assert!(events.len() <= 3, "событий {}", events.len());
        assert!(events.iter().any(|event| event == &finished));
        assert_eq!(
            events
                .iter()
                .filter_map(|event| notice_count(event))
                .count(),
            1
        );
        assert_missing_matches_notice(&pushed, &events);
    }

    #[test]
    fn marker_key_survives_when_finished_has_no_key() {
        let reg = JobRegistry::with_limits(limits(3, 20_000, 2_000));
        let handle = reg.create();
        let key = "aivpn://marker";
        let marker = serde_json::json!({
            "code": null,
            "connection_key": key,
            "msg": null,
            "status": "ok",
            "step": "done",
            "type": "marker"
        })
        .to_string();
        let finished = serde_json::json!({
            "connection_key": null,
            "exit_code": 7,
            "type": "finished"
        })
        .to_string();
        reg.push(handle, marker);
        for index in 0..5 {
            reg.push(
                handle,
                serde_json::json!({"line": format!("old-{index}"), "type": "line"}).to_string(),
            );
        }
        reg.push(handle, finished);
        let events = drain(&reg, handle);
        let parsed: Vec<serde_json::Value> = events
            .iter()
            .map(|event| serde_json::from_str(event).expect("json"))
            .collect();
        assert!(parsed.iter().any(|event| event["connection_key"] == key));
        assert!(parsed.iter().any(|event| {
            event["type"] == "finished"
                && event["exit_code"] == 7
                && event["connection_key"].is_null()
        }));
        assert_eq!(
            events
                .iter()
                .filter_map(|event| notice_count(event))
                .count(),
            1
        );
    }

    #[test]
    fn oversized_line_stays_json_and_keeps_a_prefix() {
        let reg = JobRegistry::new();
        let handle = reg.create();
        let original = serde_json::json!({
            "line": format!("он сказал \"{}\"", "ж".repeat(12_000)),
            "type": "line"
        })
        .to_string();
        assert!(original.len() > MAX_EVENT_BYTES);
        reg.push(handle, original);
        let events = drain(&reg, handle);
        assert_eq!(events.len(), 1);
        assert!(events[0].len() <= MAX_EVENT_BYTES);
        let parsed: serde_json::Value = serde_json::from_str(&events[0]).expect("json");
        let line = parsed["line"].as_str().expect("line");
        assert_eq!(parsed["type"], "line");
        assert!(line.contains('ж'));
        assert!(line.contains("строка обрезана"));
    }

    #[test]
    fn oversized_non_json_becomes_a_valid_journal_line() {
        let reg = JobRegistry::new();
        let handle = reg.create();
        reg.push(handle, "n".repeat(MAX_EVENT_BYTES + 1));
        let events = drain(&reg, handle);
        assert_eq!(events.len(), 1);
        assert!(events[0].len() <= MAX_EVENT_BYTES);
        let parsed: serde_json::Value = serde_json::from_str(&events[0]).expect("json");
        assert_eq!(parsed["type"], "line");
    }

    #[test]
    fn event_at_the_byte_ceiling_is_not_rewritten() {
        let reg = JobRegistry::new();
        let handle = reg.create();
        let event = "n".repeat(MAX_EVENT_BYTES);
        reg.push(handle, event.clone());
        assert_eq!(drain(&reg, handle), vec![event]);
    }

    #[test]
    fn huge_connection_key_is_not_cut() {
        let reg = JobRegistry::new();
        let handle = reg.create();
        let key = format!("aivpn://{}", "k".repeat(MAX_EVENT_BYTES));
        let finished = serde_json::json!({
            "connection_key": &key,
            "exit_code": 0,
            "type": "finished"
        })
        .to_string();
        reg.push(handle, finished);
        let events = drain(&reg, handle);
        let parsed: serde_json::Value = serde_json::from_str(&events[0]).expect("json");
        assert_eq!(parsed["type"], "finished");
        assert_eq!(parsed["connection_key"], key);
        assert!(events[0].len() > MAX_EVENT_BYTES);
    }

    #[test]
    fn long_marker_text_is_cut_without_losing_connection_key() {
        let reg = JobRegistry::new();
        let handle = reg.create();
        let key = "aivpn://marker-key";
        let original = serde_json::json!({
            "code": null,
            "connection_key": key,
            "msg": "m".repeat(40_000),
            "status": "ok",
            "step": "done",
            "type": "marker"
        })
        .to_string();
        assert!(original.len() > MAX_EVENT_BYTES);
        reg.push(handle, original);
        let events = drain(&reg, handle);
        assert!(events[0].len() <= MAX_EVENT_BYTES);
        let parsed: serde_json::Value = serde_json::from_str(&events[0]).expect("json");
        assert_eq!(parsed["type"], "marker");
        assert_eq!(parsed["connection_key"], key);
        assert!(parsed["msg"].as_str().expect("msg").len() < 40_000);
    }

    #[test]
    fn jobs_do_not_share_dropped_lines() {
        let reg = JobRegistry::with_limits(limits(1, 10_000, 1_000));
        let crowded = reg.create();
        let quiet = reg.create();
        reg.push(crowded, "one".to_string());
        reg.push(crowded, "two".to_string());
        reg.push(quiet, "solo".to_string());
        assert_eq!(drain(&reg, quiet), vec!["solo".to_string()]);
    }

    #[test]
    fn second_wave_updates_the_single_notice() {
        let reg = JobRegistry::with_limits(limits(2, 10_000, 1_000));
        let handle = reg.create();
        let mut pushed = Vec::new();
        for index in 0..4 {
            let event = format!("a-{index}");
            reg.push(handle, event.clone());
            pushed.push(event);
        }
        for index in 0..4 {
            let event = format!("b-{index}");
            reg.push(handle, event.clone());
            pushed.push(event);
        }
        let events = drain(&reg, handle);
        assert_eq!(
            events
                .iter()
                .filter_map(|event| notice_count(event))
                .count(),
            1
        );
        assert_eq!(events.last().map(String::as_str), Some("b-3"));
        assert_missing_matches_notice(&pushed, &events);
    }

    fn assert_missing_matches_notice(pushed: &[String], events: &[String]) {
        let notices: Vec<u64> = events
            .iter()
            .filter_map(|event| notice_count(event))
            .collect();
        assert_eq!(notices.len(), 1);
        let kept: Vec<&str> = events
            .iter()
            .filter(|event| notice_count(event).is_none())
            .map(String::as_str)
            .collect();
        let missing = pushed
            .iter()
            .filter(|event| !kept.contains(&event.as_str()))
            .count();
        assert_eq!(notices[0], missing as u64);
    }
}
