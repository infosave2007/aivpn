//! Причины отказа управления, общие для туннеля и HTTP API.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManagementError {
    pub code: String,
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retry_after_ms: Option<u64>,
}

impl ManagementError {
    pub fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
            retry_after_ms: None,
        }
    }

    pub fn for_status(status: u16) -> Self {
        let (code, message) = match status {
            400 | 422 => ("invalid_request", "Проверьте параметры запроса."),
            401 => (
                "unauthorized",
                "Для управления нужно подключиться к серверу.",
            ),
            403 => ("forbidden", "У клиента нет прав на это действие."),
            404 => ("not_found", "Запрошенный клиент или ресурс не найден."),
            405 => ("invalid_request", "Метод запроса не поддерживается."),
            409 => (
                "conflict",
                "Изменение конфликтует с текущим состоянием сервера.",
            ),
            413 => ("invalid_request", "Запрос превышает допустимый размер."),
            415 => (
                "invalid_request",
                "Тело запроса должно быть в формате JSON.",
            ),
            429 => (
                "rate_limited",
                "Запросы идут слишком часто. Повторите немного позже.",
            ),
            503 => (
                "service_unavailable",
                "Служба управления временно недоступна.",
            ),
            400..=499 => (
                "invalid_request",
                "Сервер отклонил запрос. Проверьте его параметры.",
            ),
            _ => (
                "internal_error",
                "Внутренняя ошибка сервера. Обратитесь к администратору.",
            ),
        };
        Self::new(code, message)
    }

    pub fn rate_limited(retry_after_ms: u64) -> Self {
        Self {
            retry_after_ms: Some(retry_after_ms),
            ..Self::for_status(429)
        }
    }

    pub fn to_body(&self) -> Vec<u8> {
        // Структура содержит только строки и целое число, сериализация не падает.
        serde_json::to_vec(self).unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rate_limit_body_carries_a_machine_code_and_retry_delay() {
        let error = ManagementError::rate_limited(200);
        let decoded: ManagementError = serde_json::from_slice(&error.to_body()).unwrap();
        assert_eq!(decoded.code, "rate_limited");
        assert_eq!(decoded.retry_after_ms, Some(200));
        assert!(!decoded.message.is_empty());
        assert!(!ManagementError::for_status(500).to_body().is_empty());
    }

    #[test]
    fn invalid_http_methods_sizes_and_media_types_are_client_errors() {
        for status in [405, 413, 415, 422] {
            assert_eq!(ManagementError::for_status(status).code, "invalid_request");
        }
    }
}
