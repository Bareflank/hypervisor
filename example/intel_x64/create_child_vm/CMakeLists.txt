cmake_minimum_required(VERSION 3.13)
project(create_child_vm_vmm_example CXX)

add_executable(create_child_vm)

target_sources(create_child_vm PRIVATE
    src/create_child_vm.cpp
)

target_link_libraries(create_child_vm vmm)

set_target_properties(create_child_vm PROPERTIES
    SUFFIX ".vmm"
)

install(TARGETS create_child_vm DESTINATION bin)
