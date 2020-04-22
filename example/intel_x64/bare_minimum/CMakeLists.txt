cmake_minimum_required(VERSION 3.13)
project(bare_minimum_vmm_example CXX)

add_executable(bare_minimum)

target_sources(bare_minimum PRIVATE
    src/bare_minimum.cpp
)

target_link_libraries(bare_minimum vmm)

set_target_properties(bare_minimum PROPERTIES
    SUFFIX ".vmm"
)

install(TARGETS bare_minimum DESTINATION bin)
