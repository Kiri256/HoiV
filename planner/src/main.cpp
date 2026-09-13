#include "../../shared/ipc/session.hpp"
#include "../../shared/logging/log.hpp"
#include "../../shared/process/process.hpp"

#include <windows.h>

int main() {
    hoiv::log_open(hoiv::join_path(hoiv::sibling_path(L"logs"), L"planner.log"), "planner");
    hoiv::IpcSession session {};
    if (!hoiv::ipc_open(&session) || session.block == nullptr) {
        hoiv::log_line("planner", static_cast<unsigned>(hoiv::ErrorCode::IpcFailed), "no bridge session");
        hoiv::log_close();
        return 1;
    }
    session.block->planner_connected = 1;
    hoiv::log_line("planner", 0, "planner started; P0.1 performs no planning");

    HANDLE events[] = {session.shutdown, session.disabled};
    WaitForMultipleObjects(2, events, FALSE, INFINITE);
    session.block->planner_connected = 0;
    hoiv::ipc_close(&session);
    hoiv::log_close();
    return 0;
}
