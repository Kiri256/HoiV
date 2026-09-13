#include <windows.h>

int main() {
    HANDLE shutdown = CreateEventW(nullptr, TRUE, FALSE, L"Local\\HoiV.P0Host.Shutdown");
    if (shutdown == nullptr) {
        return 1;
    }
    WaitForSingleObject(shutdown, INFINITE);
    CloseHandle(shutdown);
    return 0;
}
