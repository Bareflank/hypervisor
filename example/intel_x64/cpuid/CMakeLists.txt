cmake_minimum_required(VERSION 3.13)
project(cpuid_vmm_example CXX)

add_executable(cpuid)

target_sources(cpuid PRIVATE
    src/cpuid.cpp
)

target_link_libraries(cpuid vmm)

set_target_properties(cpuid PROPERTIES
    SUFFIX ".vmm"
)

install(TARGETS cpuid DESTINATION bin)
