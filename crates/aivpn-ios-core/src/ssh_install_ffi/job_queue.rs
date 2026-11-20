//! Job registry + event queue mechanics backing `aivpn_ssh_install_start` /
//! `aivpn_ssh_install_poll` / `aivpn_ssh_install_free` (see `super`). Deliberately has no
//! SSH/async/FFI awareness — just the push / peek-pop-or-needs-capacity / done / free
//! bookkeeping — so it's cheap to unit-test without a live SSH server or raw pointers.
//!
//! Buffer contract mirrors the written-len-or-needed-len convention shared by
//! `aivpn_mgmt_request` / `aivpn_qr_png` (see `lib.rs`), with one difference: on a
//! too-small buffer the queued event is left in place (peeked, not popped) rather than
//! reformatted on the next call, so a caller that retries with a bigger buffer gets the
//! exact same event instead of racing a background thread that might enqueue something
//! ahead of it in between.

pub use aivpn_common::ssh_install::job_registry::{JobRegistry, PollOutcome};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_handle_is_not_found() {
        let reg = JobRegistry::new();
        assert_eq!(reg.poll(999, 4096), PollOutcome::NotFound);
        assert!(!reg.free(999));
    }

    #[test]
    fn create_returns_increasing_handles_starting_at_one() {
        let reg = JobRegistry::new();
        let h1 = reg.create();
        let h2 = reg.create();
        assert_eq!(h1, 1);
        assert_eq!(h2, 2);
    }

    #[test]
    fn empty_queue_not_done_is_pending() {
        let reg = JobRegistry::new();
        let h = reg.create();
        assert_eq!(reg.poll(h, 4096), PollOutcome::Pending);
    }

    #[test]
    fn push_then_poll_with_enough_capacity_pops_the_event() {
        let reg = JobRegistry::new();
        let h = reg.create();
        reg.push(h, "hello".to_string());
        assert_eq!(reg.poll(h, 5), PollOutcome::Event("hello".to_string()));
        // Popped — a second poll finds the queue empty again.
        assert_eq!(reg.poll(h, 5), PollOutcome::Pending);
    }

    #[test]
    fn poll_with_too_small_buffer_peeks_not_pops() {
        let reg = JobRegistry::new();
        let h = reg.create();
        reg.push(h, "0123456789".to_string()); // 10 bytes
        assert_eq!(reg.poll(h, 4), PollOutcome::NeedsCapacity(10));
        // Still queued — a retry with the reported capacity gets the SAME event, not a
        // reformatted/skipped one.
        assert_eq!(reg.poll(h, 4), PollOutcome::NeedsCapacity(10));
        assert_eq!(
            reg.poll(h, 10),
            PollOutcome::Event("0123456789".to_string())
        );
    }

    #[test]
    fn fifo_order_preserved_across_multiple_events() {
        let reg = JobRegistry::new();
        let h = reg.create();
        reg.push(h, "a".to_string());
        reg.push(h, "b".to_string());
        reg.push(h, "c".to_string());
        assert_eq!(reg.poll(h, 10), PollOutcome::Event("a".to_string()));
        assert_eq!(reg.poll(h, 10), PollOutcome::Event("b".to_string()));
        assert_eq!(reg.poll(h, 10), PollOutcome::Event("c".to_string()));
        assert_eq!(reg.poll(h, 10), PollOutcome::Pending);
    }

    #[test]
    fn done_with_drained_queue_reports_done() {
        let reg = JobRegistry::new();
        let h = reg.create();
        reg.push(h, "only".to_string());
        reg.mark_done(h);
        // Queued event must still be delivered before Done, even though the job already
        // finished producing it.
        assert_eq!(reg.poll(h, 10), PollOutcome::Event("only".to_string()));
        assert_eq!(reg.poll(h, 10), PollOutcome::Done);
        // Done is sticky.
        assert_eq!(reg.poll(h, 10), PollOutcome::Done);
    }

    #[test]
    fn mark_done_before_any_push_then_poll_is_done_not_pending() {
        let reg = JobRegistry::new();
        let h = reg.create();
        reg.mark_done(h);
        assert_eq!(reg.poll(h, 10), PollOutcome::Done);
    }

    #[test]
    fn free_removes_the_job_and_reports_existence() {
        let reg = JobRegistry::new();
        let h = reg.create();
        assert!(reg.free(h));
        assert_eq!(reg.poll(h, 10), PollOutcome::NotFound);
        // Freeing again reports "did not exist".
        assert!(!reg.free(h));
    }

    #[test]
    fn push_and_mark_done_after_free_are_silent_no_ops() {
        let reg = JobRegistry::new();
        let h = reg.create();
        assert!(reg.free(h));
        // Simulates a still-running worker thread that hasn't noticed the handle was
        // freed yet — must not panic or resurrect the job.
        reg.push(h, "late event".to_string());
        reg.mark_done(h);
        assert_eq!(reg.poll(h, 10), PollOutcome::NotFound);
    }

    #[test]
    fn independent_handles_do_not_interfere() {
        let reg = JobRegistry::new();
        let h1 = reg.create();
        let h2 = reg.create();
        reg.push(h1, "for-h1".to_string());
        reg.mark_done(h2);
        assert_eq!(reg.poll(h1, 10), PollOutcome::Event("for-h1".to_string()));
        assert_eq!(reg.poll(h2, 10), PollOutcome::Done);
    }

    #[test]
    fn overflow_bounds_old_lines_and_keeps_finished_connection_key() {
        let reg = JobRegistry::new();
        let handle = reg.create();
        let line = format!("{{\"line\":\"{}\",\"type\":\"line\"}}", "x".repeat(4096));
        for _ in 0..1000 {
            reg.push(handle, line.clone());
        }
        let key = format!("aivpn://{}", "k".repeat(300_000));
        let finished = serde_json::json!({
            "connection_key": &key,
            "exit_code": 0,
            "type": "finished"
        })
        .to_string();
        reg.push(handle, finished);

        let mut events = Vec::new();
        loop {
            match reg.poll(handle, usize::MAX) {
                PollOutcome::Event(event) => events.push(event),
                PollOutcome::Pending => break,
                other => panic!("неожиданный исход опроса: {other:?}"),
            }
        }

        let discarded_bytes: usize = events
            .iter()
            .filter(|event| !event.contains(&key))
            .map(String::len)
            .sum();
        assert!(
            events.len() <= 256,
            "очередь событий не ограничена по количеству: {}",
            events.len()
        );
        assert!(
            discarded_bytes <= 256 * 1024,
            "очередь событий не ограничена по байтам: {discarded_bytes}"
        );
        let kept = events.iter().any(|event| {
            serde_json::from_str::<serde_json::Value>(event)
                .ok()
                .is_some_and(|value| {
                    value.get("type").and_then(|kind| kind.as_str()) == Some("finished")
                        && value.get("connection_key").and_then(|item| item.as_str())
                            == Some(key.as_str())
                })
        });
        assert!(kept, "финальное Finished вместе с connection_key потеряно");
        let notices = events
            .iter()
            .filter(|event| event.contains("журнал установки сокращен"))
            .count();
        assert_eq!(
            notices, 1,
            "о потере старых строк должно остаться одно событие журнала, получено {notices}"
        );
        for event in &events {
            serde_json::from_str::<serde_json::Value>(event)
                .unwrap_or_else(|err| panic!("событие перестало быть JSON: {err}: {event}"));
        }
    }

    #[test]
    fn oversized_line_is_cut_without_breaking_json() {
        let reg = JobRegistry::new();
        let handle = reg.create();
        let original = serde_json::json!({
            "line": "ж".repeat(20_000),
            "type": "line"
        })
        .to_string();
        assert!(original.len() > 16 * 1024);
        reg.push(handle, original.clone());
        let PollOutcome::Event(event) = reg.poll(handle, usize::MAX) else {
            panic!("обрезанная строка не вернулась из очереди");
        };
        assert!(
            event.len() <= 16 * 1024,
            "длинная строка не обрезана: {} байт",
            event.len()
        );
        let parsed: serde_json::Value = serde_json::from_str(&event)
            .unwrap_or_else(|err| panic!("обрезание сломало JSON: {err}: {event}"));
        assert_eq!(parsed["type"], "line");
        let mut end = 16 * 1024;
        while !original.is_char_boundary(end) {
            end -= 1;
        }
        assert!(serde_json::from_str::<serde_json::Value>(&original[..end]).is_err());
    }

    #[test]
    fn oversized_event_still_peeks_until_the_buffer_fits() {
        let reg = JobRegistry::new();
        let handle = reg.create();
        let original = serde_json::json!({
            "line": "ж".repeat(20_000),
            "type": "line"
        })
        .to_string();
        reg.push(handle, original);
        match reg.poll(handle, 32) {
            PollOutcome::NeedsCapacity(needed) => {
                assert!(needed > 32);
                assert!(needed <= 16 * 1024);
            }
            other => panic!("короткий буфер должен подсмотреть событие, получено {other:?}"),
        }
        assert!(matches!(
            reg.poll(handle, 32),
            PollOutcome::NeedsCapacity(_)
        ));
    }
}
