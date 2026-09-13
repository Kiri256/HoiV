#pragma once

#include <string>

namespace hoiv {

void log_open(const std::wstring& path, const char* component);
void log_line(const char* component, unsigned error_code, const char* message);
void log_close();

}  // namespace hoiv
