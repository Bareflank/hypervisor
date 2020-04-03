add_executable(vcpu_properties)

target_sources(vcpu_properties PRIVATE
    src/vcpu_properties.cpp
)

target_link_libraries(vcpu_properties vmm)

set_target_properties(vcpu_properties PROPERTIES
    SUFFIX ".vmm"
)

install(TARGETS vcpu_properties DESTINATION bin)
