if(HYPERVISOR_TARGET_ARCH STREQUAL "x86_64")
    # Always build a hello_world example
    add_subdirectory(intel_x64/hello_world)

    if(HYPERVISOR_BUILD_EXAMPLES)
        # TODO: Add other examples here
    endif()
endif()

