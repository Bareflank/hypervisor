add_executable(vmexit)

target_sources(vmexit PRIVATE
    src/vmexit.cpp
)

target_link_libraries(vmexit vmm)

set_target_properties(vmexit PROPERTIES
    SUFFIX ".vmm"
)

install(TARGETS vmexit DESTINATION bin)
