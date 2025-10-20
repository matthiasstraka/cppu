cmake_minimum_required(VERSION 3.12)

project(libkernel)

add_library(${PROJECT_NAME} STATIC
  inc/vmemory.h
  inc/if_kernel.h
  inc/memory_adapter.h
  inc/linux64_kernel.h
  src/vmemory.cpp
  src/linux64_kernel.cpp
)

set_property(TARGET ${PROJECT_NAME} PROPERTY CXX_STANDARD 20)
target_include_directories(${PROJECT_NAME}
    PUBLIC inc/
)
