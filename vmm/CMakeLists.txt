cmake_minimum_required(VERSION 3.13)
project(vmm CXX ASM)
include(${HYPERVISOR_PROJECT_DIR}/cmake/init_subproject.cmake)

add_subdirectory(src)

install(DIRECTORY include/ DESTINATION include/vmm)
