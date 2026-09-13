#pragma once

#include <cstdint>
#include <string>
#include <windows.h>

namespace hoiv {

bool create_owned_process(const std::wstring& exe_path, HANDLE* process, DWORD* pid, std::string* error);
bool open_process_by_pid(DWORD pid, HANDLE* process, std::string* error);
bool find_pid_by_image(const std::string& image_lower, DWORD* pid);
std::wstring current_process_image();
std::wstring sibling_path(const std::wstring& file_name);
std::wstring join_path(const std::wstring& dir, const std::wstring& name);

}  // namespace hoiv
