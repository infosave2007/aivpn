use crate::localization::Lang;
use serde::{Deserialize, Serialize};

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UiLayout {
    Compact,
    #[default]
    #[serde(other)]
    FluentDesktop,
}

impl UiLayout {
    pub fn label(self, lang: Lang) -> &'static str {
        match self {
            Self::FluentDesktop => "Fluent Desktop",
            Self::Compact => text(lang, "Компактный Fluent", "Compact Fluent"),
        }
    }

    pub fn initial_size(self) -> [f32; 2] {
        match self {
            Self::FluentDesktop => [960.0, 680.0],
            Self::Compact => [460.0, 640.0],
        }
    }

    pub fn min_size(self) -> [f32; 2] {
        match self {
            Self::FluentDesktop => [700.0, 520.0],
            Self::Compact => [380.0, 520.0],
        }
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ColorScheme {
    Light,
    Dark,
    #[default]
    #[serde(other)]
    System,
}

impl ColorScheme {
    pub fn label(self, lang: Lang) -> &'static str {
        match self {
            Self::System => text(lang, "Как в Windows", "Windows default"),
            Self::Light => text(lang, "Светлая", "Light"),
            Self::Dark => text(lang, "Темная", "Dark"),
        }
    }

    pub fn is_dark(self, system: Option<bool>, fallback: bool) -> bool {
        match self {
            Self::System => system.unwrap_or(fallback),
            Self::Light => false,
            Self::Dark => true,
        }
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum Page {
    #[default]
    Home,
    Profiles,
    Routes,
    Masks,
    Service,
    Settings,
}

impl Page {
    pub const ALL: [Self; 6] = [
        Self::Home,
        Self::Profiles,
        Self::Routes,
        Self::Masks,
        Self::Service,
        Self::Settings,
    ];

    pub fn label(self, lang: Lang) -> &'static str {
        match self {
            Self::Home => text(lang, "Подключение", "Connection"),
            Self::Profiles => text(lang, "Профили", "Profiles"),
            Self::Routes => text(lang, "Маршруты", "Routes"),
            Self::Masks => text(lang, "Маски", "Masks"),
            Self::Service => text(lang, "Сервис", "Service"),
            Self::Settings => text(lang, "Настройки", "Settings"),
        }
    }
}

pub fn text(lang: Lang, ru: &'static str, en: &'static str) -> &'static str {
    match lang {
        Lang::Ru => ru,
        Lang::En => en,
    }
}
