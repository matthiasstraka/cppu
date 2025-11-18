cmake_minimum_required(VERSION 3.10)

project(cppu)

enable_testing()

add_subdirectory(lib/elf)
add_subdirectory(lib/kernel)
add_subdirectory(lib/utils)
add_subdirectory(lib/x86-64)
