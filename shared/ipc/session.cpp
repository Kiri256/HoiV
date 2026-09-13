#include "session.hpp"

#include <cstring>

namespace hoiv {
namespace {

bool create_or_open_event(const char* name, HANDLE* out, bool create) {
    if (create) {
        *out = CreateEventA(nullptr, FALSE, FALSE, name);
    } else {
        *out = OpenEventA(EVENT_MODIFY_STATE | SYNCHRONIZE, FALSE, name);
    }
    return *out != nullptr;
}

}  // namespace

void ipc_reset_status(SharedBlock* block) {
    if (block == nullptr) {
        return;
    }
    block->initialized = 0;
    block->version_ok = 0;
    block->hooks_installed = 0;
    block->hook_install_calls = 0;
    block->hook_actual_installs = 0;
    block->write_enabled = 0;
    block->disabled = 0;
    block->planner_connected = 0;
    block->error_code = static_cast<uint32_t>(ErrorCode::NotInitialized);
    block->request = static_cast<uint32_t>(Request::None);
    block->module_handle = 0;
    block->pe_timestamp = 0;
    block->product_version[0] = '\0';
    block->blackice_version[0] = '\0';
    block->sha256_hex[0] = '\0';
    block->last_error[0] = '\0';
    block->read_ok = 0;
    block->division_ok = 0;
    block->org_valid = 0;
    block->game_started = 0;
    block->player_tag = 0;
    block->country_count = 0;
    block->country_index = -1;
    block->division_id = 0;
    block->division_generation = 0;
    block->division_province = 0;
    block->division_organization = 0.0f;
    block->diag_org_current = 0;
    block->diag_org_max = 0;
    block->diag_hp_current = 0;
    block->diag_hp_max = 0;
    block->division_hp = 0.0f;
    block->snapshot_tick_ms = 0;
    block->snapshot_sequence = 0;
    block->hook_enter_count = 0;
    block->diag_vt_ok = 0;
    block->diag_tag_nz = 0;
    block->diag_vote_idx = -1;
    block->diag_vote_n = 0;
    block->diag_actor_rva = 0;
    block->diag_armies = 0;
    block->diag_units = 0;
    block->player_tag_text[0] = '\0';
    block->pending_move_province = 0;
    block->order_attempts = 0;
    block->order_accepted = 0;
    block->last_order_result = 0;
}

bool ipc_create(IpcSession* session) {
    if (session == nullptr) {
        return false;
    }
    *session = {};

    session->mutex = CreateMutexA(nullptr, FALSE, kIpcMutexName);
    if (session->mutex == nullptr) {
        return false;
    }
    const DWORD wait = WaitForSingleObject(session->mutex, 0);
    if (wait != WAIT_OBJECT_0 && wait != WAIT_ABANDONED) {
        ipc_close(session);
        return false;
    }

    session->mapping = CreateFileMappingA(
        INVALID_HANDLE_VALUE,
        nullptr,
        PAGE_READWRITE,
        0,
        kSharedBlockBytes,
        kIpcMappingName);
    if (session->mapping == nullptr) {
        ipc_close(session);
        return false;
    }

    session->block = static_cast<SharedBlock*>(MapViewOfFile(session->mapping, FILE_MAP_ALL_ACCESS, 0, 0, kSharedBlockBytes));
    if (session->block == nullptr) {
        ipc_close(session);
        return false;
    }
    std::memset(session->block, 0, sizeof(SharedBlock));
    session->block->magic = kSharedMagic;
    session->block->schema_version = kSchemaVersion;
    session->block->struct_size = static_cast<uint32_t>(sizeof(SharedBlock));
    ipc_reset_status(session->block);

    if (!create_or_open_event(kIpcReadyEventName, &session->ready, true) ||
        !create_or_open_event(kIpcDisableEventName, &session->disable, true) ||
        !create_or_open_event(kIpcShutdownEventName, &session->shutdown, true) ||
        !create_or_open_event(kIpcDisabledEventName, &session->disabled, true)) {
        ipc_close(session);
        return false;
    }

    ResetEvent(session->ready);
    ResetEvent(session->disable);
    ResetEvent(session->shutdown);
    ResetEvent(session->disabled);
    session->created = true;
    return true;
}

bool ipc_open(IpcSession* session) {
    if (session == nullptr) {
        return false;
    }
    *session = {};
    session->mapping = OpenFileMappingA(FILE_MAP_ALL_ACCESS, FALSE, kIpcMappingName);
    if (session->mapping == nullptr) {
        return false;
    }
    session->block = static_cast<SharedBlock*>(MapViewOfFile(session->mapping, FILE_MAP_ALL_ACCESS, 0, 0, kSharedBlockBytes));
    if (session->block == nullptr) {
        ipc_close(session);
        return false;
    }
    if (session->block->magic != kSharedMagic || session->block->schema_version != kSchemaVersion ||
        session->block->struct_size != sizeof(SharedBlock)) {
        ipc_close(session);
        return false;
    }
    if (!create_or_open_event(kIpcReadyEventName, &session->ready, false) ||
        !create_or_open_event(kIpcDisableEventName, &session->disable, false) ||
        !create_or_open_event(kIpcShutdownEventName, &session->shutdown, false) ||
        !create_or_open_event(kIpcDisabledEventName, &session->disabled, false)) {
        ipc_close(session);
        return false;
    }
    return true;
}

void ipc_publish_ready(IpcSession* session) {
    if (session != nullptr && session->ready != nullptr) {
        SetEvent(session->ready);
    }
}

void ipc_signal_disable(IpcSession* session) {
    if (session != nullptr && session->block != nullptr) {
        session->block->request = static_cast<uint32_t>(Request::Disable);
    }
    if (session != nullptr && session->disable != nullptr) {
        SetEvent(session->disable);
    }
}

void ipc_signal_shutdown(IpcSession* session) {
    if (session != nullptr && session->block != nullptr) {
        session->block->request = static_cast<uint32_t>(Request::Shutdown);
    }
    if (session != nullptr && session->shutdown != nullptr) {
        SetEvent(session->shutdown);
    }
}

void ipc_close(IpcSession* session) {
    if (session == nullptr) {
        return;
    }
    if (session->block != nullptr) {
        UnmapViewOfFile(session->block);
        session->block = nullptr;
    }
    const HANDLE handles[] = {
        session->ready,
        session->disable,
        session->shutdown,
        session->disabled,
        session->mapping,
        session->mutex,
    };
    for (HANDLE handle : handles) {
        if (handle != nullptr) {
            CloseHandle(handle);
        }
    }
    *session = {};
}

}  // namespace hoiv
