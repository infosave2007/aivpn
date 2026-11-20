// Статические системные DLL ищутся в System32 еще до входа в приложение.
#include <windows.h>
const IMAGE_LOAD_CONFIG_DIRECTORY _load_config_used = {
    .Size = sizeof(IMAGE_LOAD_CONFIG_DIRECTORY),
    .DependentLoadFlags = LOAD_LIBRARY_SEARCH_SYSTEM32,
};
