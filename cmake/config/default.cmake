add_config(
    CONFIG_NAME CMAKE_BUILD_TYPE
    CONFIG_TYPE STRING
    DEFAULT_VAL Release
    DESCRIPTION "The target build type"
    OPTIONS Release Debug HelixQAC
)

add_config(
    CONFIG_NAME TARGET_ARCH
    CONFIG_TYPE STRING
    DEFAULT_VAL ${CMAKE_HOST_SYSTEM_PROCESSOR}
    DESCRIPTION "The target architecture for the build"
    OPTIONS x86_64 AMD64 armv8a
)

add_config(
    CONFIG_NAME TARGET_PLATFORM
    CONFIG_TYPE STRING
    DEFAULT_VAL ${CMAKE_HOST_SYSTEM_NAME}
    DESCRIPTION "The target platform for the build"
    OPTIONS Windows Linux UEFI
)

add_config(
    CONFIG_NAME BUILD_VMMCTL
    CONFIG_TYPE BOOL
    DEFAULT_VAL ON
    DESCRIPTION "Set true to build the vmmctl component"
)

add_config(
    CONFIG_NAME BUILD_VMM
    CONFIG_TYPE BOOL
    DEFAULT_VAL ON
    DESCRIPTION "Set true to build the vmm component"
)

add_config(
    CONFIG_NAME BUILD_EXAMPLES
    CONFIG_TYPE BOOL
    DEFAULT_VAL ON
    DESCRIPTION "Set true to build the examples"
)

add_config(
    CONFIG_NAME BUILD_TESTS
    CONFIG_TYPE BOOL
    DEFAULT_VAL ON
    DESCRIPTION "Set true to build tests"
)
