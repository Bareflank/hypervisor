add_executable(hello_world_vmm)

target_sources(hello_world_vmm PRIVATE
    src/main.cpp
)

target_link_libraries(hello_world_vmm vmm)

install(TARGETS hello_world_vmm DESTINATION bin)
