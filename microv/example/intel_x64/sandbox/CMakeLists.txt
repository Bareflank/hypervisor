cmake_minimum_required(VERSION 3.13)
project(sandbox_vmm_example CXX)

add_executable(sandbox)

target_sources(sandbox PRIVATE
    src/sandbox.cpp
)

target_link_libraries(sandbox microv)

set_target_properties(sandbox PROPERTIES
    SUFFIX ".vmm"
)

install(TARGETS sandbox DESTINATION bin)
