cmake_minimum_required(VERSION 3.13)
project(hello_world_vmm_example CXX)

add_executable(intel_hello_world)

target_sources(intel_hello_world PRIVATE
    src/intel_hello_world.cpp
)

target_link_libraries(intel_hello_world vmm)

set_target_properties(intel_hello_world PROPERTIES
    SUFFIX ".vmm"
)

install(TARGETS intel_hello_world DESTINATION bin)
