cmake_minimum_required(VERSION 3.13)
project(properties_vmm_example CXX)

add_executable(properties)

target_sources(properties PRIVATE
    src/properties.cpp
)

target_link_libraries(properties vmm)

set_target_properties(properties PROPERTIES
    SUFFIX ".vmm"
)

install(TARGETS properties DESTINATION bin)
