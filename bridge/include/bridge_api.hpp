#pragma once

#include <cstdint>

#if defined(HOIV_BRIDGE_EXPORTS)
#define HOIV_BRIDGE_API extern "C" __declspec(dllexport)
#else
#define HOIV_BRIDGE_API extern "C" __declspec(dllimport)
#endif

HOIV_BRIDGE_API uint32_t Bridge_Initialize();
HOIV_BRIDGE_API uint32_t Bridge_Disable();
HOIV_BRIDGE_API uint32_t Bridge_Shutdown();
