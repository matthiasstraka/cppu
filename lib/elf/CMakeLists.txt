cmake_minimum_required(VERSION 3.12)

project(elf)

add_library(${PROJECT_NAME} STATIC
  inc/elf_headers.h
  inc/elf_file.h
  src/elf_file.cpp
)

set_property(TARGET ${PROJECT_NAME} PROPERTY CXX_STANDARD 20)
target_include_directories(${PROJECT_NAME}
    PUBLIC inc/
)

# Unit tests
add_subdirectory(tests)
