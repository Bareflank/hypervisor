cmake_minimum_required(VERSION 3.13)
project(control_register_vmm_example CXX)

add_executable(control_register)

target_sources(control_register PRIVATE
    src/control_register.cpp
)

target_link_libraries(control_register vmm)

set_target_properties(control_register PROPERTIES
    SUFFIX ".vmm"
)

install(TARGETS control_register DESTINATION bin)
