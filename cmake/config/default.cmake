hypervisor_add_config(
    CONFIG_NAME HYPERVISOR_TARGET_ARCH
    CONFIG_TYPE STRING
    DEFAULT_VAL ${CMAKE_HOST_SYSTEM_PROCESSOR}
    DESCRIPTION "The target architecture for the build"
    OPTIONS x86_64 AMD64 armv8a
)

hypervisor_add_config(
    CONFIG_NAME HYPERVISOR_TARGET_PLATFORM
    CONFIG_TYPE STRING
    DEFAULT_VAL ${CMAKE_HOST_SYSTEM_NAME}
    DESCRIPTION "The target platform for the build"
    OPTIONS Windows Linux UEFI
)

hypervisor_add_config(
    CONFIG_NAME HYPERVISOR_BUILD_VMMCTL
    CONFIG_TYPE BOOL
    DEFAULT_VAL ON
    DESCRIPTION "Set true to build the vmmctl component"
)

hypervisor_add_config(
    CONFIG_NAME HYPERVISOR_BUILD_VMM
    CONFIG_TYPE BOOL
    DEFAULT_VAL ON
    DESCRIPTION "Set true to build the vmm component"
)

hypervisor_add_config(
    CONFIG_NAME HYPERVISOR_BUILD_EXAMPLES
    CONFIG_TYPE BOOL
    DEFAULT_VAL ON
    DESCRIPTION "Set true to build the examples"
)

hypervisor_add_config(
    CONFIG_NAME HYPERVISOR_BUILD_TESTS
    CONFIG_TYPE BOOL
    DEFAULT_VAL ON
    DESCRIPTION "Set true to build tests"
)
