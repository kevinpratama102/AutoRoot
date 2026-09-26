project("exp")
cmake_minimum_required(VERSION 3.22)

include(FetchContent)
include_directories(/usr/include/fuse)
set(CXX_STANDARD_REQUIRED 17)

FetchContent_Declare(fmt
  GIT_REPOSITORY https://github.com/fmtlib/fmt.git
  GIT_TAG master
)
FetchContent_MakeAvailable(fmt)

FetchContent_Declare(kt
  GIT_REPOSITORY https://github.com/elbiazo/kerntools.git
  GIT_TAG 12c2d03c64f2e1ec0c589501796de0356ac9254b
)
FetchContent_MakeAvailable(kt)

include_directories(${CMAKE_CURRENT_BINARY_DIR}/_deps/kt-src/libkt/include)
add_subdirectory(${CMAKE_CURRENT_BINARY_DIR}/_deps/kt-src/libkt)
set(CXX_STANDARD_REQUIRED 17)

add_executable(exp exp.cc)
target_link_libraries(exp kt fmt::fmt fuse pthread -static -Wall -Werror)
target_compile_definitions(exp PRIVATE -D_FILE_OFFSET_BITS=64)

add_executable(win win.cc)
target_link_libraries(win kt -static -Wall -Werror)
