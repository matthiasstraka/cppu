cmake_minimum_required(VERSION 3.12)

project(cpu_utils)

add_library(${PROJECT_NAME} STATIC
  inc/carry_addsub.h
  src/cpu_utils.cpp
)

set_property(TARGET ${PROJECT_NAME} PROPERTY CXX_STANDARD 20)
target_include_directories(${PROJECT_NAME}
    PUBLIC inc/
)

# Unit tests
add_subdirectory(tests)
