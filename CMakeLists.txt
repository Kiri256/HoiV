cmake_minimum_required(VERSION 3.20)
project(HoiV LANGUAGES CXX RC)

if(NOT CMAKE_SIZEOF_VOID_P EQUAL 8)
    message(FATAL_ERROR "First version supports Windows x64 only")
endif()

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}")
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}")
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}")

add_compile_definitions(NOMINMAX WIN32_LEAN_AND_MEAN UNICODE _UNICODE)

set(HOIV_CORE_SOURCES
    shared/logging/log.cpp
    shared/identity/identity.cpp
    shared/config/config.cpp
    shared/ipc/session.cpp
    shared/process/process.cpp
    shared/loader/remote_load.cpp
    bridge/src/version_gate/version_gate.cpp
    bridge/src/hook_manager/hook_manager.cpp
)

add_library(hoiv_core STATIC ${HOIV_CORE_SOURCES})
target_include_directories(hoiv_core PUBLIC "${CMAKE_SOURCE_DIR}")
target_link_libraries(hoiv_core PUBLIC bcrypt version advapi32)

add_library(bridge SHARED
    bridge/src/dllmain.cpp
    bridge/src/runtime.cpp
    bridge/src/game_reader/game_reader.cpp
    bridge/bridge.def
)
target_compile_definitions(bridge PRIVATE HOIV_BRIDGE_EXPORTS)
target_link_libraries(bridge PRIVATE hoiv_core)
set_target_properties(bridge PROPERTIES PREFIX "" OUTPUT_NAME "bridge")
if(MINGW)
    target_link_options(bridge PRIVATE -static-libgcc -static-libstdc++ -static)
endif()

add_executable(launcher tools/launcher/src/main.cpp)
target_link_libraries(launcher PRIVATE hoiv_core)
if(MINGW)
    target_link_options(launcher PRIVATE -municode -static-libgcc -static-libstdc++)
endif()

add_executable(planner planner/src/main.cpp)
target_link_libraries(planner PRIVATE hoiv_core)
if(MINGW)
    target_link_options(planner PRIVATE -static-libgcc -static-libstdc++)
endif()

add_executable(p0_host
    tools/p0_host/src/main.cpp
    tools/p0_host/p0_host.rc
)
if(MINGW)
    target_link_options(p0_host PRIVATE -static-libgcc -static-libstdc++)
endif()

add_executable(p0_tests tools/test_runner/src/p0_gate_test.cpp)
target_link_libraries(p0_tests PRIVATE hoiv_core)
if(MINGW)
    target_link_options(p0_tests PRIVATE -static-libgcc -static-libstdc++)
endif()

enable_testing()
add_test(NAME p0_offline COMMAND p0_tests)
set_tests_properties(p0_offline PROPERTIES WORKING_DIRECTORY "${CMAKE_BINARY_DIR}")
