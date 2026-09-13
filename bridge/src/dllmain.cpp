#include "../include/bridge_api.hpp"

#include <windows.h>

namespace hoiv {
void runtime_set_module(HMODULE module);
void runtime_detach(bool process_exiting);
}  // namespace hoiv

BOOL APIENTRY DllMain(HINSTANCE instance, DWORD reason, LPVOID reserved) {
    switch (reason) {
        case DLL_PROCESS_ATTACH:
            DisableThreadLibraryCalls(instance);
            hoiv::runtime_set_module(instance);
            break;
        case DLL_PROCESS_DETACH:
            hoiv::runtime_detach(reserved != nullptr);
            break;
        default:
            break;
    }
    return TRUE;
}
