#pragma once

#include "../schema/schema.hpp"

#include <windows.h>

namespace hoiv {

struct IpcSession {
    HANDLE mutex = nullptr;
    HANDLE mapping = nullptr;
    HANDLE ready = nullptr;
    HANDLE disable = nullptr;
    HANDLE shutdown = nullptr;
    HANDLE disabled = nullptr;
    SharedBlock* block = nullptr;
    bool created = false;
};

bool ipc_create(IpcSession* session);
bool ipc_open(IpcSession* session);
void ipc_publish_ready(IpcSession* session);
void ipc_signal_disable(IpcSession* session);
void ipc_signal_shutdown(IpcSession* session);
void ipc_close(IpcSession* session);
void ipc_reset_status(SharedBlock* block);

}  // namespace hoiv
