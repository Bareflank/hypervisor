cmake_minimum_required(VERSION 3.13)
project(hypervisor CXX ASM-ATT)
include(${CMAKE_CURRENT_LIST_DIR}/cmake/init_build.cmake)

hypervisor_print_banner()

add_subdirectory(loader)
add_subdirectory(kernel)
add_subdirectory(microv)
add_subdirectory(vmmctl)
add_subdirectory(example)

export(PACKAGE hypervisor)

hypervisor_print_usage()
