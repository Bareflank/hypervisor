add_constant(
    CONST_NAME  HYPERVISOR_PROJECT_DIR
    CONST_VALUE ${CMAKE_CURRENT_LIST_DIR}/../../
    DESCRIPTION "Top-level directory for the Bareflank hypervisor project"
)

add_config(
    CONFIG_NAME TARGET_ARCH
    CONFIG_TYPE STRING
    DEFAULT_VAL ${CMAKE_HOST_SYSTEM_PROCESSOR}
    DESCRIPTION "The target architecture for the build"
    OPTIONS x86_64 amd64 armv8-a
)

add_config(
    CONFIG_NAME TARGET_OS
    CONFIG_TYPE STRING
    DEFAULT_VAL ${CMAKE_HOST_SYSTEM_NAME}
    DESCRIPTION "The target operating system for the build"
    OPTIONS Linux Windows Darwin
)

add_constant(
    CONST_NAME  VMM_PREFIX_PATH
    CONST_VALUE ${CMAKE_CURRENT_BINARY_DIR}/install/${TARGET_ARCH}-vmm
    DESCRIPTION "Installation prefix for VMM components"
)

add_constant(
    CONST_NAME  HOST_PREFIX_PATH
    CONST_VALUE ${CMAKE_CURRENT_BINARY_DIR}/install/${TARGET_ARCH}-${TARGET_OS}
    DESCRIPTION "Installation prefix for host OS components"
)

ProcessorCount(HOST_NUMBER_CORES)
add_constant(
    CONST_NAME  HOST_NUMBER_CORES
    CONST_VALUE ${HOST_NUMBER_CORES}
    DESCRIPTION "The number of cores available on the project's build environment"
)
