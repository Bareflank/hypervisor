cmake_minimum_required(VERSION 3.13)
project(vmcs_vmm_example CXX)

add_executable(vmcs)

target_sources(vmcs PRIVATE
    src/vmcs.cpp
)

target_link_libraries(vmcs vmm)

set_target_properties(vmcs PROPERTIES
    SUFFIX ".vmm"
)

install(TARGETS vmcs DESTINATION bin)
