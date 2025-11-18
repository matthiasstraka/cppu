cmake_minimum_required(VERSION 3.10)

project(cppu)

enable_testing()

add_subdirectory(lib/elf)
add_subdirectory(lib/kernel)
add_subdirectory(lib/utils)
add_subdirectory(lib/x86-64)

add_executable(${PROJECT_NAME}
  src/cppu.cpp
)

set_property(TARGET ${PROJECT_NAME} PROPERTY CXX_STANDARD 20)
add_definitions(-DTEST_FILES_PATH="${CMAKE_SOURCE_DIR}/examples/")
target_link_libraries(${PROJECT_NAME}
  elf
  kernel
  x86-64
)
