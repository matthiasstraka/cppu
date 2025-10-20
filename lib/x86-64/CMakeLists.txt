cmake_minimum_required(VERSION 3.12)

project(x86-64)

add_library(${PROJECT_NAME} STATIC
  inc/x86-64.h
  inc/x86-64_ops.h
  inc/x86-64_structs.h
  inc/x86-64_types.h
  inc/x86-64_utils.h
  src/x86-64.cpp
)

set_property(TARGET ${PROJECT_NAME} PROPERTY CXX_STANDARD 20)
target_include_directories(${PROJECT_NAME}
    PUBLIC inc/
)

target_link_libraries(${PROJECT_NAME}
  libkernel
)

# Unit tests
add_subdirectory(tests)
