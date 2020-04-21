add_executable(memory)

target_sources(memory PRIVATE
    src/memory.cpp
)

target_link_libraries(memory vmm)

set_target_properties(memory PROPERTIES
    SUFFIX ".vmm"
)

install(TARGETS memory DESTINATION bin)
