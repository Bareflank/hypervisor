cmake_minimum_required(VERSION 3.13)
project(memory_vmm_example CXX)

add_executable(memory)

target_sources(memory PRIVATE
    src/memory.cpp
)

target_link_libraries(memory vmm)

set_target_properties(memory PROPERTIES
    SUFFIX ".vmm"
)

install(TARGETS memory DESTINATION bin)
