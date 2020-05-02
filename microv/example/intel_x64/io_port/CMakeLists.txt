cmake_minimum_required(VERSION 3.13)
project(io_port_vmm_example CXX)

add_executable(io_port)

target_sources(io_port PRIVATE
    src/io_port.cpp
)

target_link_libraries(io_port vmm)

set_target_properties(io_port PROPERTIES
    SUFFIX ".vmm"
)

install(TARGETS io_port DESTINATION bin)
