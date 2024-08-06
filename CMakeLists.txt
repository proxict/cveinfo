cmake_minimum_required(VERSION 3.28)
project(cveinfo VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -pedantic -fPIC -fvisibility=hidden")
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -Wall -Wextra -pedantic")

set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

add_subdirectory(external/spdlog)
add_subdirectory(external/cpr)
add_subdirectory(external/json)

add_executable(cveinfo
    src/main.cpp
    src/DebianSecurityTracker.cpp
    src/nist.cpp
)

target_include_directories(cveinfo
    PRIVATE include
)

target_link_libraries(cveinfo
    PRIVATE spdlog::spdlog
    PRIVATE cpr::cpr
    PRIVATE nlohmann_json::nlohmann_json
)

set_property(TARGET cveinfo PROPERTY CXX_STANDARD 20)
set_property(TARGET cveinfo PROPERTY CXX_STANDARD_REQUIRED TRUE)
set_property(TARGET cveinfo PROPERTY CXX_EXTENSIONS OFF)

target_compile_options(cveinfo PRIVATE
    -Wall
    -Wextra
    -Wpedantic
    -Wnon-virtual-dtor
    -Wold-style-cast
    -Woverloaded-virtual
    -Wnull-dereference
    -Wformat=2
    -Wsign-conversion
)

install(TARGETS cveinfo DESTINATION bin)
