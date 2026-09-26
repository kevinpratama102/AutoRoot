cmake_minimum_required(VERSION 3.22.1)
project("badbinder" C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

add_library(
        cve-2019-2215
        SHARED
        cve-2019-2215.c
)

target_compile_options(
        cve-2019-2215
        PRIVATE
        -O3
        -Wall
        -Wextra
        -pedantic
        -Wformat
        -Werror=format-security
        -std=gnu11
)

find_library(
        log-lib
        log
)

target_link_libraries(
        cve-2019-2215
        ${log-lib}
)
