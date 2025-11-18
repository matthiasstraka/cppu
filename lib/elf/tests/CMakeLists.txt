cmake_minimum_required(VERSION 3.12)

set(PROJECT_UNIT_TESTS_NAME ${PROJECT_NAME}.test)

if (MSVC)
    set(Boost_USE_STATIC_LIBS ON)
endif()
find_package(Boost REQUIRED
    COMPONENTS unit_test_framework
)

include_directories(${Boost_INCLUDE_DIRS})
add_definitions(-DTEST_FILES_PATH="${CMAKE_SOURCE_DIR}/examples/")

add_executable(${PROJECT_UNIT_TESTS_NAME}
    elf_test.cpp
    test_main.cpp
)

set_property(TARGET ${PROJECT_UNIT_TESTS_NAME} PROPERTY CXX_STANDARD 20)
target_link_libraries(${PROJECT_UNIT_TESTS_NAME} PRIVATE
    Boost::unit_test_framework
    elf
)

add_test(NAME ${PROJECT_UNIT_TESTS_NAME} COMMAND ${PROJECT_UNIT_TESTS_NAME})
