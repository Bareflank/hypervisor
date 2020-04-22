cmake_minimum_required(VERSION 3.13)
project(vmcall_vmm_example CXX)

add_executable(vmcall)

target_sources(vmcall PRIVATE
    src/vmcall.cpp
)

target_link_libraries(vmcall vmm)

set_target_properties(vmcall PROPERTIES
    SUFFIX ".vmm"
)

install(TARGETS vmcall DESTINATION bin)
