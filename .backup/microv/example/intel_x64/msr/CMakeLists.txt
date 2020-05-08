cmake_minimum_required(VERSION 3.13)
project(msr_vmm_example CXX)

add_executable(msr)

target_sources(msr PRIVATE
    src/msr.cpp
)

target_link_libraries(msr vmm)

set_target_properties(msr PROPERTIES
    SUFFIX ".vmm"
)

install(TARGETS msr DESTINATION bin)
