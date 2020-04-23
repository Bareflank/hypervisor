if(HYPERVISOR_TARGET_ARCH STREQUAL "x86_64")
    # Always build a hello_world example
    add_subdirectory(intel_x64/hello_world)

    if(HYPERVISOR_BUILD_EXAMPLES)
        # TODO: Add other examples here
        add_subdirectory(intel_x64/bare_minimum)
        add_subdirectory(intel_x64/cpuid)
        add_subdirectory(intel_x64/control_register)
        add_subdirectory(intel_x64/create_child_vm)
        add_subdirectory(intel_x64/io_port)
        add_subdirectory(intel_x64/memory)
        add_subdirectory(intel_x64/msr)
        add_subdirectory(intel_x64/properties)
        add_subdirectory(intel_x64/vmcall)
        add_subdirectory(intel_x64/vmexit)

        # PAL needs a few bug fixes before this example will compile:
        # add_subdirectory(intel_x64/vmcs)
    endif()
endif()

