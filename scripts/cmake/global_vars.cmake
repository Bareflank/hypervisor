# This file defines all variables that are shared across all sub-projects,
# but are NOT meant to be configurable. Reserve the use of the "BF_" prefix as
# a way to signify that the variable is bareflank specific and applies to all
# sub-projects and dependencies globally
#
# Do NOT assign built-in CMake variables here (vars that start with "CMAKE_")
#

# ------------------------------------------------------------------------------
# Source tree structure
# ------------------------------------------------------------------------------

set(BF_SOURCE_DIR ${CMAKE_SOURCE_DIR}
    CACHE INTERNAL
    "Top-level source directory"
)

set(BF_SCRIPTS_DIR "${BF_SOURCE_DIR}/scripts"
    CACHE INTERNAL
    "Scripts directory"
)

set(BF_CONFIG_DIR "${BF_SCRIPTS_DIR}/cmake/config"
    CACHE INTERNAL
    "Cmake build configurations directory"
)

set(BF_DEPENDS_DIR "${BF_SCRIPTS_DIR}/cmake/depends"
    CACHE INTERNAL
    "Cmake external dependencies directory"
)

set(BF_FLAGS_DIR "${BF_SCRIPTS_DIR}/cmake/flags"
    CACHE INTERNAL
    "Cmake compiler flags directory"
)

set(BF_TARGETS_DIR "${BF_SCRIPTS_DIR}/cmake/targets"
    CACHE INTERNAL
    "Cmake custom build targets directory"
)

set(BF_TOOLCHAIN_DIR "${BF_SCRIPTS_DIR}/cmake/toolchain"
    CACHE INTERNAL
    "Cmake toolchain files directory"
)

# ------------------------------------------------------------------------------
# Build tree structure
# ------------------------------------------------------------------------------

set(BF_BUILD_DIR ${CMAKE_BINARY_DIR}
    CACHE INTERNAL
    "Top-level build directory"
)

set(BF_BUILD_DEPENDS_DIR ${BF_BUILD_DIR}/depends
    CACHE INTERNAL
    "Build directory for external dependencies"
)

# TODO: The path to a directory named "bfprefix" is currently dictated
# by the env.sh script. Remove that requirement and make this path configurable
# set(BF_BUILD_INSTALL_DIR ${BF_BUILD_DIR}/install
set(BF_BUILD_INSTALL_DIR ${BF_BUILD_DIR}/bfprefix
    CACHE INTERNAL
    "Intermediate build installation directory"
)

# ------------------------------------------------------------------------------
# Default toolchains
# ------------------------------------------------------------------------------

set(BF_DEFAULT_TOOLCHAIN_FILE "${BF_TOOLCHAIN_DIR}/default.cmake"
    CACHE INTERNAL
    "Path to the default cmake toolchain file for building userspace tools"
)

set(BF_DEFAULT_KERNEL_TOOLCHAIN_FILE "${BF_TOOLCHAIN_DIR}/default_kernel.cmake"
    CACHE INTERNAL
    "Path to the default cmake toolchain file for building kernel/driver tools"
)

set(BF_DEFAULT_VMM_TOOLCHAIN_FILE "${BF_TOOLCHAIN_DIR}/default_vmm.cmake"
    CACHE INTERNAL
    "Path to the default cmake toolchain file for building vmm tools"
)

