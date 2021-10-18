#
# Copyright (C) 2020 Assured Information Security, Inc.
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

if(NOT CMAKE_PROJECT_NAME STREQUAL "hypervisor")
    if(CMAKE_PROJECT_NAME STREQUAL "hypervisor_microkernel")
        include(mk_lib.cmake)
    else()
        include(ext_lib_cpp.cmake)
    endif()
endif()

if(CMAKE_PROJECT_NAME STREQUAL "hypervisor" AND NOT EXISTS ${CMAKE_BINARY_DIR}/rust/syscall_rust_files.txt)

    # --------------------------------------------------------------------------
    # Rebuild Flag
    # --------------------------------------------------------------------------

    file(MAKE_DIRECTORY ${CMAKE_BINARY_DIR}/rust)
    set(HYPERVISOR_CONSTANTS ${CMAKE_BINARY_DIR}/rust/syscall_rust_files.txt)

    file(WRITE ${HYPERVISOR_CONSTANTS} "touched\n")

    # --------------------------------------------------------------------------
    # Cargo.toml
    # --------------------------------------------------------------------------

    set(HYPERVISOR_CARGO_TOML ${CMAKE_SOURCE_DIR}/syscall/Cargo.toml)

    file(WRITE ${HYPERVISOR_CARGO_TOML} "[package]\n")
    file(APPEND ${HYPERVISOR_CARGO_TOML} "name = \"syscall\"\n")
    file(APPEND ${HYPERVISOR_CARGO_TOML} "version = \"0.1.0\"\n")
    file(APPEND ${HYPERVISOR_CARGO_TOML} "edition = \"2018\"\n")
    file(APPEND ${HYPERVISOR_CARGO_TOML} "\n")
    file(APPEND ${HYPERVISOR_CARGO_TOML} "[lib]\n")
    file(APPEND ${HYPERVISOR_CARGO_TOML} "path = \"lib.rs\"\n")
    file(APPEND ${HYPERVISOR_CARGO_TOML} "\n")
    file(APPEND ${HYPERVISOR_CARGO_TOML} "[features]\n")

    set(SYSCALL_DEFAULT_FEATURES "[\"custom_print_thread_id\"")

    if(HYPERVISOR_TARGET_ARCH STREQUAL "AuthenticAMD")
        set(SYSCALL_DEFAULT_FEATURES "${SYSCALL_DEFAULT_FEATURES},\"AuthenticAMD\"")
    endif()

    if(HYPERVISOR_TARGET_ARCH STREQUAL "GenuineIntel")
        set(SYSCALL_DEFAULT_FEATURES "${SYSCALL_DEFAULT_FEATURES},\"GenuineIntel\"")
    endif()

    if(NOT ENABLE_COLOR)
        set(SYSCALL_DEFAULT_FEATURES "${SYSCALL_DEFAULT_FEATURES},\"disable_color\"")
    endif()

    if(BSL_DEBUG_LEVEL STREQUAL "bsl::V")
        set(SYSCALL_DEFAULT_FEATURES "${SYSCALL_DEFAULT_FEATURES},\"debug_level_v\"")
    endif()

    if(BSL_DEBUG_LEVEL STREQUAL "bsl::VV")
        set(SYSCALL_DEFAULT_FEATURES "${SYSCALL_DEFAULT_FEATURES},\"debug_level_v\",\"debug_level_vv\"")
    endif()

    if(BSL_DEBUG_LEVEL STREQUAL "bsl::VVV")
        set(SYSCALL_DEFAULT_FEATURES "${SYSCALL_DEFAULT_FEATURES},\"debug_level_v\",\"debug_level_vv\",\"debug_level_vvv\"")
    endif()

    if(CMAKE_BUILD_TYPE STREQUAL RELEASE OR CMAKE_BUILD_TYPE STREQUAL MINSIZEREL)
        set(SYSCALL_DEFAULT_FEATURES "${SYSCALL_DEFAULT_FEATURES},\"release_mode\"]")
    else()
        set(SYSCALL_DEFAULT_FEATURES "${SYSCALL_DEFAULT_FEATURES}]")
    endif()

    file(APPEND ${HYPERVISOR_CARGO_TOML} "default = ${SYSCALL_DEFAULT_FEATURES}\n")
    file(APPEND ${HYPERVISOR_CARGO_TOML} "debug_level_v = []\n")
    file(APPEND ${HYPERVISOR_CARGO_TOML} "debug_level_vv = []\n")
    file(APPEND ${HYPERVISOR_CARGO_TOML} "debug_level_vvv = []\n")
    file(APPEND ${HYPERVISOR_CARGO_TOML} "disable_color = []\n")
    file(APPEND ${HYPERVISOR_CARGO_TOML} "release_mode = []\n")
    file(APPEND ${HYPERVISOR_CARGO_TOML} "AuthenticAMD = []\n")
    file(APPEND ${HYPERVISOR_CARGO_TOML} "GenuineIntel = []\n")
    file(APPEND ${HYPERVISOR_CARGO_TOML} "custom_print_thread_id = []\n")
    file(APPEND ${HYPERVISOR_CARGO_TOML} "\n")

    file(APPEND ${HYPERVISOR_CARGO_TOML} "[dependencies]\n")
    file(APPEND ${HYPERVISOR_CARGO_TOML} "bsl = { path = \"${bsl_SOURCE_DIR}\" }\n")

    # --------------------------------------------------------------------------
    # Constants
    # --------------------------------------------------------------------------

    set(HYPERVISOR_CONSTANTS ${CMAKE_SOURCE_DIR}/syscall/constants.rs)

    file(WRITE ${HYPERVISOR_CONSTANTS} "\n")
    file(APPEND ${HYPERVISOR_CONSTANTS} "pub const HYPERVISOR_PAGE_SIZE:bsl::SafeU64 = bsl::SafeU64::new(${HYPERVISOR_PAGE_SIZE});\n")
    file(APPEND ${HYPERVISOR_CONSTANTS} "pub const HYPERVISOR_PAGE_SHIFT:bsl::SafeU64 = bsl::SafeU64::new(${HYPERVISOR_PAGE_SHIFT});\n")
    file(APPEND ${HYPERVISOR_CONSTANTS} "pub const HYPERVISOR_MAX_PPS:bsl::SafeUMx = bsl::SafeUMx::new(${HYPERVISOR_MAX_PPS});\n")
    file(APPEND ${HYPERVISOR_CONSTANTS} "pub const HYPERVISOR_MAX_VMS:bsl::SafeUMx = bsl::SafeUMx::new(${HYPERVISOR_MAX_VMS});\n")
    file(APPEND ${HYPERVISOR_CONSTANTS} "pub const HYPERVISOR_MAX_VPS:bsl::SafeUMx = bsl::SafeUMx::new(${HYPERVISOR_MAX_VPS});\n")
    file(APPEND ${HYPERVISOR_CONSTANTS} "pub const HYPERVISOR_MAX_VSS:bsl::SafeUMx = bsl::SafeUMx::new(${HYPERVISOR_MAX_VSS});\n")
    file(APPEND ${HYPERVISOR_CONSTANTS} "pub const HYPERVISOR_EXT_DIRECT_MAP_ADDR:bsl::SafeU64 = bsl::SafeU64::new(${HYPERVISOR_EXT_DIRECT_MAP_ADDR});\n")
    file(APPEND ${HYPERVISOR_CONSTANTS} "pub const HYPERVISOR_EXT_DIRECT_MAP_SIZE:bsl::SafeU64 = bsl::SafeU64::new(${HYPERVISOR_EXT_DIRECT_MAP_SIZE});\n")
    file(APPEND ${HYPERVISOR_CONSTANTS} "pub const HYPERVISOR_EXT_PAGE_POOL_ADDR:bsl::SafeU64 = bsl::SafeU64::new(${HYPERVISOR_EXT_PAGE_POOL_ADDR});\n")
    file(APPEND ${HYPERVISOR_CONSTANTS} "pub const HYPERVISOR_EXT_PAGE_POOL_SIZE:bsl::SafeU64 = bsl::SafeU64::new(${HYPERVISOR_EXT_PAGE_POOL_SIZE});\n")
    file(APPEND ${HYPERVISOR_CONSTANTS} "pub const HYPERVISOR_EXT_HUGE_POOL_ADDR:bsl::SafeU64 = bsl::SafeU64::new(${HYPERVISOR_EXT_HUGE_POOL_ADDR});\n")
    file(APPEND ${HYPERVISOR_CONSTANTS} "pub const HYPERVISOR_EXT_HUGE_POOL_SIZE:bsl::SafeU64 = bsl::SafeU64::new(${HYPERVISOR_EXT_HUGE_POOL_SIZE});\n")
endif()
