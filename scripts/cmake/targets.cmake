#
# Bareflank Hypervisor
# Copyright (C) 2015 Assured Information Security, Inc.
#
# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 2.1 of the License, or (at your option) any later version.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this library; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA

# ------------------------------------------------------------------------------
# Info
# ------------------------------------------------------------------------------

# Use this target along with the macros below to add entries to be displayed
# when you run 'make info'
add_custom_target(info)

# Add a new category heading to be displayed in 'make info'
# @param text: The text to be displayed on a new category heading
macro(add_info_category text)
    add_custom_command(
        TARGET info
        COMMAND ${CMAKE_COMMAND} -E cmake_echo_color " "
        COMMAND ${CMAKE_COMMAND} -E cmake_echo_color --magenta --bold "${text}:"
    )
endmacro(add_info_category)

# Creates a string that can be used to right justify text.
# @param text: the text on the left
# @param width: the total number of characters allowed on the left
# @param output: the variable to store the result.
function(right_justify text width output)
    set(str "")
    string(LENGTH "${text}" text_len)
    foreach(i RANGE ${text_len} ${width})
        set(str " ${str}")
    endforeach(i)
    set(${output} ${str} PARENT_SCOPE)
endfunction(right_justify)

# Add an informational description about a custom build target to be displayed
# in 'make info'
# @param TARGET: The name of the target this info message is about
# @param NO_TARGET: Set if this message has no target (i.e. just 'make')
# @param INFO_COMMENT: The informational message to be displayed about TARGET
macro(add_custom_target_info)
    set(bools NO_TARGET)
    set(oneVal TARGET INFO_COMMENT)
    cmake_parse_arguments(_INFO "${bools}" "${oneVal}" "" ${ARGN})

    if(_INFO_NO_TARGET)
        right_justify("${BF_BUILD_COMMAND}" 20 JUSTIFY_STR)
        add_custom_command(
            TARGET info
            COMMAND ${CMAKE_COMMAND} -E cmake_echo_color --green --bold --no-newline "    ${BF_BUILD_COMMAND}"
            COMMAND ${CMAKE_COMMAND} -E cmake_echo_color --red --no-newline "${JUSTIFY_STR}- "
            COMMAND ${CMAKE_COMMAND} -E cmake_echo_color --white "${_INFO_INFO_COMMENT}"
        )
    else()
        right_justify("${BF_BUILD_COMMAND} ${_INFO_TARGET}" 20 JUSTIFY_STR)
        add_custom_command(
            TARGET info
            COMMAND ${CMAKE_COMMAND} -E cmake_echo_color --green --bold --no-newline "    ${BF_BUILD_COMMAND} ${_INFO_TARGET}"
            COMMAND ${CMAKE_COMMAND} -E cmake_echo_color --red --no-newline "${JUSTIFY_STR}- "
            COMMAND ${CMAKE_COMMAND} -E cmake_echo_color --white "${_INFO_INFO_COMMENT}"
        )
    endif()
endmacro(add_custom_target_info)

# ------------------------------------------------------------------------------
# Build/Clean
# ------------------------------------------------------------------------------

add_info_category("Build")
add_custom_target_info(
    NO_TARGET
    INFO_COMMENT "Build Bareflank"
)

if(${BF_BUILD_COMMAND} STREQUAL "make")
    add_custom_target_info(
        TARGET "-j[# of jobs]"
        INFO_COMMENT "Build Bareflank using [# of jobs] parallel jobs for faster builds"
    )
endif()

add_custom_target_info(
    TARGET clean
    INFO_COMMENT "Clean the build tree"
)

add_custom_target(
    distclean
    COMMAND ${CMAKE_COMMAND} --build . --target clean
    COMMAND ${CMAKE_COMMAND} --build ${BF_BUILD_DIR_BFDRIVER} --target clean
    COMMAND ${CMAKE_COMMAND} --build ${BF_BUILD_DIR_BFELF_LOADER} --target clean
    COMMAND ${CMAKE_COMMAND} --build ${BF_BUILD_DIR_BFM} --target clean
    COMMAND ${CMAKE_COMMAND} --build ${BF_BUILD_DIR_BFSDK} --target clean
    COMMAND ${CMAKE_COMMAND} --build ${BF_BUILD_DIR_BFSUPPORT} --target clean
    COMMAND ${CMAKE_COMMAND} --build ${BF_BUILD_DIR_BFUNWIND} --target clean
    COMMAND ${CMAKE_COMMAND} --build ${BF_BUILD_DIR_BFVMM} --target clean
    COMMAND ${CMAKE_COMMAND} -E remove_directory ${BF_BUILD_INSTALL_DIR}
    COMMAND ${CMAKE_COMMAND} -E remove_directory ${BF_BUILD_DEPENDS_DIR}
    COMMENT "Cleaning build tree, removing all dependencies, and removing all build artifacts"
)
add_custom_target_info(
    TARGET distclean
    INFO_COMMENT "Clean the build tree, remove all dependencies, and remove all build artifacts"
)

if(ENABLE_UNITTESTING)
    add_custom_command(TARGET distclean COMMAND ${CMAKE_COMMAND} --build ${BF_BUILD_DIR_BFSUPPORT_TEST} --target clean)
    add_custom_command(TARGET distclean COMMAND ${CMAKE_COMMAND} --build ${BF_BUILD_DIR_VMM_TEST} --target clean)
endif()

if(BUILD_EXTENDED_APIS)
    add_custom_command(TARGET distclean COMMAND ${CMAKE_COMMAND} --build ${BF_BUILD_DIR_EXTENDED_APIS} --target clean)
    if(ENABLE_UNITTESTING)
        add_custom_command(TARGET distclean COMMAND ${CMAKE_COMMAND} --build ${BF_BUILD_DIR_EXTENDED_APIS_TEST})
    endif()
endif()

# ------------------------------------------------------------------------------
# BFM
# ------------------------------------------------------------------------------

add_info_category("Bareflank Manager")

add_custom_target(
    quick
    COMMAND ${SUDO} ${BUILD_SYSROOT_OS}/bin/bfm quick
    COMMENT "Loading and starting the VMM: ${BFM_VMM_BIN_PATH}/${BFM_DEFAULT_VMM}"
)
add_custom_target_info(
    TARGET quick
    INFO_COMMENT "Load and start the default VMM"
)

add_custom_target(
    stop
    COMMAND ${SUDO} ${BUILD_SYSROOT_OS}/bin/bfm stop
    COMMENT "Stopping the currently loaded VMM"
)
add_custom_target_info(
    TARGET stop
    INFO_COMMENT "Stop the curently loaded VMM"
)

add_custom_target(
    unload
    COMMAND ${SUDO} ${BUILD_SYSROOT_OS}/bin/bfm unload
    COMMENT "Unloading the currently loaded VMM"
)
add_custom_target_info(
    TARGET unload
    INFO_COMMENT "Unload the curently loaded VMM"
)

add_custom_target(
    dump
    COMMAND ${SUDO} ${BUILD_SYSROOT_OS}/bin/bfm dump
    COMMENT "Dumping debug output from the VMM"
)
add_custom_target_info(
    TARGET dump
    INFO_COMMENT "Dump debug output from the VMM"
)

add_custom_target(
    status
    COMMAND ${SUDO} ${BUILD_SYSROOT_OS}/bin/bfm status
    COMMENT "Displaying status of the current VMM"
)
add_custom_target_info(
    TARGET status
    INFO_COMMENT "Display status of the current VMM"
)

# ------------------------------------------------------------------------------
# Driver
# ------------------------------------------------------------------------------

add_info_category("Bareflank Driver")

add_custom_target(
    driver_quick
    COMMAND ${SUDO} ${CMAKE_COMMAND} --build ${BF_BUILD_DIR_BFDRIVER} --target bfdriver_unload
    COMMAND ${CMAKE_COMMAND} --build ${BF_BUILD_DIR_BFDRIVER} --target bfdriver_clean
    COMMAND ${CMAKE_COMMAND} --build ${BF_BUILD_DIR_BFDRIVER} --target bfdriver_build
    COMMAND ${SUDO} ${CMAKE_COMMAND} --build ${BF_BUILD_DIR_BFDRIVER} --target bfdriver_load
    COMMENT "Unloading, cleaning, building, and reloading bfdriver"
)
add_custom_target_info(
    TARGET driver_quick
    INFO_COMMENT "Unload, clean, build, and reload the Bareflank driver"
)

add_custom_target(
    driver_load
    COMMAND ${SUDO} ${CMAKE_COMMAND} --build ${BF_BUILD_DIR_BFDRIVER} --target bfdriver_load
    COMMENT "Loading bfdriver to the local OS"
)
add_custom_target_info(
    TARGET driver_load
    INFO_COMMENT "Load and start the Bareflank driver"
)

add_custom_target(
    driver_unload
    COMMAND ${SUDO} ${CMAKE_COMMAND} --build ${BF_BUILD_DIR_BFDRIVER} --target bfdriver_unload
    COMMENT "Unloading bfdriver from the local OS"
)
add_custom_target_info(
    TARGET driver_unload
    INFO_COMMENT "Unload and stop the Bareflank driver"
)

# ------------------------------------------------------------------------------
# Test
# ------------------------------------------------------------------------------

if(ENABLE_UNITTESTING)
    add_info_category("Unit Testing")
    if(POLICY CMP0037)
        cmake_policy(SET CMP0037 OLD)
    endif()

    if(ENABLE_DEVELOPER_MODE)
        add_custom_target(test ALL COMMENT "Running unit tests")
    else()
        add_custom_target(test COMMENT "Running unit tests")
    endif()
    add_custom_target_info(
        TARGET test
        INFO_COMMENT "Run Bareflank unit tests configured for the current build"
    )

    add_custom_command(TARGET test COMMAND ${CMAKE_COMMAND} -E chdir ${BF_BUILD_DIR_BFSDK_TEST} ctest)
    if(ENABLE_DEVELOPER_MODE)
        add_dependencies(test bfsdk_test)
    endif()
    if(${UNITTEST_BFSUPPORT})
        add_custom_command(TARGET test COMMAND ${CMAKE_COMMAND} --build ${BF_BUILD_DIR_BFSUPPORT_TEST} --target test)
        if(ENABLE_DEVELOPER_MODE)
            add_dependencies(test bfsupport_test)
        endif()
    endif()
    if(${UNITTEST_BFDRIVER})
        add_custom_command(TARGET test COMMAND ${CMAKE_COMMAND} -E chdir ${BF_BUILD_DIR_BFDRIVER_TEST} ctest)
        if(ENABLE_DEVELOPER_MODE)
            add_dependencies(test bfdriver_test)
        endif()
    endif()
    if(${UNITTEST_BFELF_LOADER})
        add_custom_command(TARGET test COMMAND ${CMAKE_COMMAND} -E chdir ${BF_BUILD_DIR_BFELF_LOADER_TEST} ctest)
        if(ENABLE_DEVELOPER_MODE)
            add_dependencies(test bfelf_loader_test)
        endif()
    endif()
    if(${UNITTEST_BFM})
        add_custom_command(TARGET test COMMAND ${CMAKE_COMMAND} -E chdir ${BF_BUILD_DIR_BFM_TEST} ctest)
        if(ENABLE_DEVELOPER_MODE)
            add_dependencies(test bfm_test)
        endif()
    endif()
    if(${UNITTEST_VMM})
        add_custom_command(TARGET test COMMAND ${CMAKE_COMMAND} -E chdir ${BF_BUILD_DIR_BFVMM_TEST} ctest)
        if(ENABLE_DEVELOPER_MODE)
            add_dependencies(test bfvmm_test)
        endif()
    endif()
    if(${UNITTEST_EXTENDED_APIS})
        add_custom_command(TARGET test COMMAND ${CMAKE_COMMAND} -E chdir ${BF_BUILD_DIR_EXTENDED_APIS_TEST} ctest)
        if(ENABLE_DEVELOPER_MODE)
            add_dependencies(test extended_apis_test)
        endif()
    endif()

endif()

# ------------------------------------------------------------------------------
# Clang Tidy
# ------------------------------------------------------------------------------

if(ENABLE_TIDY)
    add_info_category("Clang Tidy Static Analysis")

    set(TIDY_SCRIPT ${BF_SCRIPTS_DIR}/util/bareflank_clang_tidy.sh CACHE INTERNAL "")
    set(TIDY_EXCLUSIONS_BFELF_LOADER ,-cppcoreguidelines-pro-type-const-cast CACHE INTERNAL "")
    set(TIDY_EXCLUSIONS_BFSUPPORT ,-cert-err34-c,-misc-misplaced-widening-cast,-cppcoreguidelines-no-malloc CACHE INTERNAL "")
    set(TIDY_EXCLUSIONS_BFUNWIND ,-cppcoreguidelines-pro* CACHE INTERNAL "")

    if(ENABLE_DEVELOPER_MODE)
        add_custom_target(tidy ALL COMMENT "Running clang-tidy static analysis checks")
    else()
        add_custom_target(tidy COMMENT "Running clang-tidy static analysis checks")
    endif()
    add_custom_target_info(
        TARGET tidy
        INFO_COMMENT "Run minimal clang-tidy static analysis checks"
    )
    add_custom_target(tidy-all COMMENT "Running all clang-tidy static analysis checks")
    add_custom_target_info(
        TARGET tidy-all
        INFO_COMMENT "Run detailed clang-tidy static analysis checks"
    )

    if(BUILD_BFM)
        add_custom_command(TARGET tidy COMMAND cd ${BF_BUILD_DIR_BFM} && ${TIDY_SCRIPT} diff ${BF_SOURCE_DIR}/bfm)
        add_custom_command(TARGET tidy-all COMMAND cd ${BF_BUILD_DIR_BFM} && ${TIDY_SCRIPT} all ${BF_SOURCE_DIR}/bfm)
        if(ENABLE_DEVELOPER_MODE)
            add_dependencies(tidy bfm)
        endif()
    endif()

    if(BUILD_VMM)
        add_custom_command(TARGET tidy COMMAND cd ${BF_BUILD_DIR_BFSUPPORT} && ${TIDY_SCRIPT} diff ${BF_SOURCE_DIR}/bfsysroot/bfsupport ${TIDY_EXCLUSIONS_BFSUPPORT})
        add_custom_command(TARGET tidy-all COMMAND cd ${BF_BUILD_DIR_BFSUPPORT} && ${TIDY_SCRIPT} all ${BF_SOURCE_DIR}/bfsysroot/bfsupport ${TIDY_EXCLUSIONS_BFSUPPORT})
        add_custom_command(TARGET tidy COMMAND cd ${BF_BUILD_DIR_BFVMM} && ${TIDY_SCRIPT} diff ${BF_SOURCE_DIR}/bfvmm)
        add_custom_command(TARGET tidy-all COMMAND cd ${BF_BUILD_DIR_BFVMM} && ${TIDY_SCRIPT} all ${BF_SOURCE_DIR}/bfvmm)
        if(ENABLE_DEVELOPER_MODE)
            add_dependencies(tidy bfvmm)
        endif()
    endif()

    if(BUILD_EXTENDED_APIS)
        add_custom_command(TARGET tidy COMMAND cd ${BF_BUILD_DIR_EXTENDED_APIS} && ${TIDY_SCRIPT} diff ${EXTENDED_APIS_PATH})
        add_custom_command(TARGET tidy-all COMMAND cd ${BF_BUILD_DIR_EXTENDED_APIS} && ${TIDY_SCRIPT} all ${EXTENDED_APIS_PATH})
        if(ENABLE_DEVELOPER_MODE)
            add_dependencies(tidy extended_apis)
        endif()
    endif()

endif()

# ------------------------------------------------------------------------------
# Astyle
# ------------------------------------------------------------------------------

if(ENABLE_ASTYLE)
    add_info_category("Asyle Code Formatting")

    set(ASTYLE_SCRIPT ${BF_SCRIPTS_DIR}/util/bareflank_astyle_format.sh CACHE INTERNAL "")

    if(ENABLE_DEVELOPER_MODE)
        add_custom_target(
            format ALL
            COMMAND ${ASTYLE_SCRIPT} diff ${BF_SOURCE_DIR}/bfdriver
            COMMAND ${ASTYLE_SCRIPT} diff ${BF_SOURCE_DIR}/bfelf_loader
            COMMAND ${ASTYLE_SCRIPT} diff ${BF_SOURCE_DIR}/bfm
            COMMAND ${ASTYLE_SCRIPT} diff ${BF_SOURCE_DIR}/bfsdk
            COMMAND ${ASTYLE_SCRIPT} diff ${BF_SOURCE_DIR}/bfsysroot
            COMMAND ${ASTYLE_SCRIPT} diff ${BF_SOURCE_DIR}/bfvmm
            COMMENT "Running astyle code format checks"
        )
    else()
        add_custom_target(
            format
            COMMAND ${ASTYLE_SCRIPT} diff ${BF_SOURCE_DIR}/bfdriver
            COMMAND ${ASTYLE_SCRIPT} diff ${BF_SOURCE_DIR}/bfelf_loader
            COMMAND ${ASTYLE_SCRIPT} diff ${BF_SOURCE_DIR}/bfm
            COMMAND ${ASTYLE_SCRIPT} diff ${BF_SOURCE_DIR}/bfsdk
            COMMAND ${ASTYLE_SCRIPT} diff ${BF_SOURCE_DIR}/bfsysroot
            COMMAND ${ASTYLE_SCRIPT} diff ${BF_SOURCE_DIR}/bfvmm
            COMMENT "Running astyle code format checks"
        )
    endif()
    add_custom_target_info(
        TARGET format
        INFO_COMMENT "Run minimal astyle code format checks"
    )

    add_custom_target(
        format-all
        COMMAND ${ASTYLE_SCRIPT} all ${BF_SOURCE_DIR}/bfdriver
        COMMAND ${ASTYLE_SCRIPT} all ${BF_SOURCE_DIR}/bfelf_loader
        COMMAND ${ASTYLE_SCRIPT} all ${BF_SOURCE_DIR}/bfm
        COMMAND ${ASTYLE_SCRIPT} all ${BF_SOURCE_DIR}/bfsdk
        COMMAND ${ASTYLE_SCRIPT} all ${BF_SOURCE_DIR}/bfsysroot
        COMMAND ${ASTYLE_SCRIPT} all ${BF_SOURCE_DIR}/bfvmm
        COMMENT "Running all astyle code format checks"
    )
    add_custom_target_info(
        TARGET format-all
        INFO_COMMENT "Run detailed astyle code format checks"
    )

    if(BUILD_EXTENDED_APIS)
        add_custom_command(TARGET format COMMAND ${ASTYLE_SCRIPT} diff ${EXTENDED_APIS_PATH})
        add_custom_command(TARGET format-all COMMAND ${ASTYLE_SCRIPT} all ${EXTENDED_APIS_PATH})
    endif()

endif()

# Add a newline after the last info message of 'make info'
add_custom_command(TARGET info COMMAND ${CMAKE_COMMAND} -E cmake_echo_color " ")
