#
# Copyright (C) 2019 Assured Information Security, Inc.
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

if(NOT WIN32 AND NOT CYGWIN)
    set(SUDO sudo)
else()
    set(SUDO "")
endif()

# ------------------------------------------------------------------------------
# Target Prototypes
# ------------------------------------------------------------------------------

if(ENABLE_BUILD_TEST)
    add_custom_target(unittest)
endif()

if(ENABLE_TIDY)
    add_custom_target(tidy)
    add_custom_target(tidy-all)
    add_custom_target(tidy-upstream)
endif()

if(ENABLE_FORMAT)
    add_custom_target(format)
    add_custom_target(format-all)
    add_custom_target(format-upstream)
endif()

add_custom_target(clean-depends)
add_custom_target(clean-subprojects)

if(NOT WIN32)
    add_custom_target(info)
endif()

# ------------------------------------------------------------------------------
# Driver
# ------------------------------------------------------------------------------

if(NOT WIN32)
    add_custom_target_category("Bareflank Driver")

    add_custom_target(driver_build
        COMMAND ${SOURCE_UTIL_DIR}/driver_build.sh ${SOURCE_BFDRIVER_DIR}
        USES_TERMINAL
    )
    add_custom_target_info(
        TARGET driver_build
        COMMENT "Build the Bareflank driver"
    )

    add_custom_target(driver_clean
        COMMAND ${SOURCE_UTIL_DIR}/driver_clean.sh ${SOURCE_BFDRIVER_DIR}
        USES_TERMINAL
    )
    add_custom_target_info(
        TARGET driver_clean
        COMMENT "Clean the Bareflank driver"
    )

    add_custom_target(driver_load
        COMMAND ${SOURCE_UTIL_DIR}/driver_load.sh ${SOURCE_BFDRIVER_DIR}
        USES_TERMINAL
    )
    add_custom_target_info(
        TARGET driver_load
        COMMENT "Load the Bareflank driver"
    )

    add_custom_target(driver_unload
        COMMAND ${SOURCE_UTIL_DIR}/driver_unload.sh ${SOURCE_BFDRIVER_DIR}
        USES_TERMINAL
    )
    add_custom_target_info(
        TARGET driver_unload
        COMMENT "Unload the Bareflank driver"
    )

    add_custom_target(
        driver_quick
        COMMAND ${CMAKE_COMMAND} --build . --target driver_unload
        COMMAND ${CMAKE_COMMAND} --build . --target driver_clean
        COMMAND ${CMAKE_COMMAND} --build . --target driver_build
        COMMAND ${CMAKE_COMMAND} --build . --target driver_load
        USES_TERMINAL
    )
    add_custom_target_info(
        TARGET driver_quick
        COMMENT "Unload, clean, build, and load the Bareflank driver"
    )
endif()

# ------------------------------------------------------------------------------
# Astyle
# ------------------------------------------------------------------------------

if(NOT WIN32)
    add_custom_target_category("Query Commands")

    add_custom_target(ack
        COMMAND ${USERSPACE_PREFIX_PATH}/bin/bfack
        USES_TERMINAL
    )

    add_custom_target_info(
        TARGET ack
        COMMENT "Ack the hypervisor"
    )
endif()

# ------------------------------------------------------------------------------
# BFM
# ------------------------------------------------------------------------------

if(NOT WIN32 AND ENABLE_BUILD_VMM AND ENABLE_BUILD_USERSPACE)
    add_custom_target_category("Bareflank Manager")

    if(UNIX)
        add_custom_target(
            quick
            COMMAND ${SUDO} ${USERSPACE_PREFIX_PATH}/bin/bfm load ${BFM_VMM_BIN_PATH}/${BFM_VMM}
            COMMAND sync
            COMMAND ${SUDO} ${USERSPACE_PREFIX_PATH}/bin/bfm start
            USES_TERMINAL
        )
    else()
        add_custom_target(
            quick
            COMMAND ${SUDO} ${USERSPACE_PREFIX_PATH}/bin/bfm load ${BFM_VMM_BIN_PATH}/${BFM_VMM}
            COMMAND ${SUDO} ${USERSPACE_PREFIX_PATH}/bin/bfm start
            USES_TERMINAL
        )
    endif()

    add_custom_target_info(
        TARGET quick
        COMMENT "Load and start the VMM"
    )

    add_custom_target(
        cycle
        COMMAND ${SUDO} ${USERSPACE_PREFIX_PATH}/bin/bfm load ${BFM_VMM_BIN_PATH}/${BFM_VMM}
        COMMAND ${SUDO} ${USERSPACE_PREFIX_PATH}/bin/bfm start
        COMMAND ${SUDO} ${USERSPACE_PREFIX_PATH}/bin/bfm stop
        COMMAND ${SUDO} ${USERSPACE_PREFIX_PATH}/bin/bfm unload
        USES_TERMINAL
    )
    add_custom_target_info(
        TARGET cycle
        COMMENT "Load, start, stop, unload the VMM"
    )

    add_custom_target(
        load
        COMMAND ${SUDO} ${USERSPACE_PREFIX_PATH}/bin/bfm load ${BFM_VMM_BIN_PATH}/${BFM_VMM}
        USES_TERMINAL
    )
    add_custom_target_info(
        TARGET load
        COMMENT "Load the VMM"
    )

    if(UNIX)
        add_custom_target(
            start
            COMMAND sync
            COMMAND ${SUDO} ${USERSPACE_PREFIX_PATH}/bin/bfm start
            USES_TERMINAL
        )
    else()
        add_custom_target(
            start
            COMMAND ${SUDO} ${USERSPACE_PREFIX_PATH}/bin/bfm start
            USES_TERMINAL
        )
    endif()

    add_custom_target_info(
        TARGET start
        COMMENT "Start the VMM"
    )

    add_custom_target(
        stop
        COMMAND ${SUDO} ${USERSPACE_PREFIX_PATH}/bin/bfm stop
        USES_TERMINAL
    )
    add_custom_target_info(
        TARGET stop
        COMMENT "Stop the VMM"
    )

    add_custom_target(
        unload
        COMMAND ${SUDO} ${USERSPACE_PREFIX_PATH}/bin/bfm unload
        USES_TERMINAL
    )
    add_custom_target_info(
        TARGET unload
        COMMENT "Unload the VMM"
    )

    add_custom_target(
        dump
        COMMAND ${SUDO} ${USERSPACE_PREFIX_PATH}/bin/bfm dump
        USES_TERMINAL
    )
    add_custom_target_info(
        TARGET dump
        COMMENT "Print the contents of the VMMs debug ring"
    )

    add_custom_target(
        status
        COMMAND ${SUDO} ${USERSPACE_PREFIX_PATH}/bin/bfm status
        USES_TERMINAL
    )
    add_custom_target_info(
        TARGET status
        COMMENT "Display the status of the VMM"
    )
endif()

# ------------------------------------------------------------------------------
# Unix
# ------------------------------------------------------------------------------

if(UNIX AND ENABLE_BUILD_VMM AND ENABLE_BUILD_USERSPACE)
    add_custom_target(
        oppss
        COMMAND ${SOURCE_UTIL_DIR}/driver_load.sh ${SOURCE_BFDRIVER_DIR}
        COMMAND ${SUDO} ${USERSPACE_PREFIX_PATH}/bin/bfm load ${BFM_VMM_BIN_PATH}/${BFM_VMM}
        COMMAND sync
        COMMAND ${SUDO} ${USERSPACE_PREFIX_PATH}/bin/bfm start
        COMMAND ${SUDO} ${USERSPACE_PREFIX_PATH}/bin/bfm dump
        USES_TERMINAL
    )
    add_custom_target_info(
        TARGET oppss
        COMMENT "Sync, driver load, hypervisor load, start"
    )
endif()

# ------------------------------------------------------------------------------
# Build / Clean
# ------------------------------------------------------------------------------

add_custom_target_category("Clean / Rebuild")

add_custom_target(
    clean-prefixes
    COMMAND ${CMAKE_COMMAND} -E remove_directory ${PREFIXES_DIR}
)

add_custom_target(
    clean-all
    COMMAND ${CMAKE_COMMAND} --build . --target clean
    COMMAND ${CMAKE_COMMAND} -E remove_directory ${DEPENDS_DIR}
    COMMAND ${CMAKE_COMMAND} -E remove_directory ${PREFIXES_DIR}
    USES_TERMINAL
)
add_custom_target_info(
    TARGET clean-all
    COMMENT "Clean everything"
)

add_custom_target(
    rebuild
    COMMAND ${CMAKE_COMMAND} --build . --target clean-subprojects
    COMMAND ${CMAKE_COMMAND} --build .
    USES_TERMINAL
)
add_custom_target_info(
    TARGET rebuild
    COMMENT "Clean the subprojects and rebuild"
)

# ------------------------------------------------------------------------------
# Test
# ------------------------------------------------------------------------------

if(ENABLE_BUILD_TEST)
    add_custom_target_category("Unit Testing")

    add_custom_target_info(
        TARGET unittest
        COMMENT "Run Bareflank unit tests"
    )
endif()

# ------------------------------------------------------------------------------
# Clang Tidy
# ------------------------------------------------------------------------------

if(ENABLE_TIDY)
    add_custom_target_category("Clang Tidy Static Analysis")

    add_custom_target_info(
        TARGET tidy
        COMMENT "Statically analyze modified files"
    )

    add_custom_target_info(
        TARGET tidy-all
        COMMENT "Statically analyze all files"
    )
endif()

# ------------------------------------------------------------------------------
# Astyle
# ------------------------------------------------------------------------------

if(ENABLE_FORMAT)
    add_custom_target_category("Asyle Code Formatting")

    add_custom_target_info(
        TARGET format
        COMMENT "Format modified files"
    )

    add_custom_target_info(
        TARGET format-all
        COMMENT "Format all files"
    )
endif()
