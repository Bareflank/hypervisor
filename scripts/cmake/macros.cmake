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
# Sub-project and VMM extension management
# ------------------------------------------------------------------------------

# Generate common cmake arguements shared across all projects added to the build
# system using ExternalProject_Add()
macro(generate_external_project_args args_out)
    # Silence noisy cmake warnings
    list(APPEND ${args_out}
        -DCMAKE_TARGET_MESSAGES=OFF
        -DCMAKE_INSTALL_MESSAGE=NEVER
        --no-warn-unused-cli
    )

    # Copy all non-built-in cmake cache variables to the external project scope
    # (i.e. build configuration variables, build global variables, etc.)
    get_cmake_property(_vars CACHE_VARIABLES)
    foreach (_var ${_vars})
        STRING(REGEX MATCH "^CMAKE" is_cmake_var ${_var})
        if(NOT is_cmake_var)
            list(APPEND ${args_out} -D${_var}=${${_var}})
        endif()
    endforeach()

    # Support for clang-tidy (if enabled)
    if(ENABLE_TIDY)
        list(APPEND ${args_out} -DCMAKE_EXPORT_COMPILE_COMMANDS=ON)
    endif()

endmacro(generate_external_project_args)

# Add a sub-project directory to be built with the specified toolchain
# @arg SOURCE_DIR: Path to a source code directory to be built with cmake
# @arg TARGET: The name of the cmake target to be created for this project
# @arg TOOLCHAIN: Path to a cmake toolchain file to use for compiling "project"
# @arg DEPENDS: A list of other targets this project depends on
# @arg VERBOSE: Display debug messages
function(add_subproject)
    set(options VERBOSE)
    set(oneVal SOURCE_DIR TARGET TOOLCHAIN)
    set(multiVal DEPENDS)
    cmake_parse_arguments(ADD_SUBPROJECT "${options}" "${oneVal}" "${multiVal}" ${ARGN})

    if(NOT EXISTS ${ADD_SUBPROJECT_SOURCE_DIR})
        message(FATAL_ERROR "Unable to find project at path ${ADD_SUBPROJECT_SOURCE_DIR}")
    endif()

    if(NOT EXISTS ${ADD_SUBPROJECT_TOOLCHAIN})
        message(FATAL_ERROR "Unable to find toolchain file ${ADD_SUBPROJECT_TOOLCHAIN}")
    endif()

    if(${ADD_SUBPROJECT_VERBOSE})
        message(STATUS "Adding subproject: ${ADD_SUBPROJECT_TARGET}")
        message(STATUS "\t${ADD_SUBPROJECT_TARGET} source path: ${ADD_SUBPROJECT_SOURCE_DIR}")
        message(STATUS "\t${ADD_SUBPROJECT_TARGET} toolchain file: ${ADD_SUBPROJECT_TOOLCHAIN}")
        message(STATUS "\t${ADD_SUBPROJECT_TARGET} dependencies: ${ADD_SUBPROJECT_DEPENDS}")
    endif()

    generate_external_project_args(_PROJECT_CMAKE_ARGS)
    list(APPEND _PROJECT_CMAKE_ARGS
        -DCMAKE_TOOLCHAIN_FILE=${ADD_SUBPROJECT_TOOLCHAIN}
    )

    ExternalProject_Add(
        ${ADD_SUBPROJECT_TARGET}
        CMAKE_ARGS ${_PROJECT_CMAKE_ARGS}
        SOURCE_DIR ${ADD_SUBPROJECT_SOURCE_DIR}
        BINARY_DIR ${BF_BUILD_PROJECTS_DIR}/${ADD_SUBPROJECT_TARGET}/build
        PREFIX ${BF_BUILD_PROJECTS_DIR}/${ADD_SUBPROJECT_TARGET}
        TMP_DIR ${BF_BUILD_PROJECTS_DIR}/${ADD_SUBPROJECT_TARGET}/tmp
        STAMP_DIR ${BF_BUILD_PROJECTS_DIR}/${ADD_SUBPROJECT_TARGET}/stamp
        UPDATE_DISCONNECTED 0
        UPDATE_COMMAND ""
        DEPENDS ${ADD_SUBPROJECT_DEPENDS}
    )
endfunction(add_subproject)

# Cmake variables to orchestrate adding VMM extensions to the build system
# using vmm_extension() and add_vmm_extensions()
set(VMM_EXTENSIONS ""
    CACHE INTERNAL
    "A list of target names for VMM extensions to be built"
)
set(VMM_EXTENSION_ARGS ""
    CACHE INTERNAL
    "A list of arguments to be passed to ExternalProject_Add() for each VMM extension in VMM_EXTENSIONS"
)

# Add a VMM extension to the build system. This macro is intended to be used
# from a build configuration file, using any arguments compatible with cmake's
# built-in ExternalProject_Add() function.
#
# NOTE: Since this macro is intended to be called from a build configuration
# file, build variables and internal targets will not be defined when
# this macro is called. Therfore, DO NOT use any build variables inside this
# macro!! See add_vmm_extensions() for the "second half" of the extension
# registration process.
#
# Usage: vmm_extension(name argn ...)
#     name = a unique name for this vmm extension
#     argn = Any number of arguments compatible with ExternlProject_Add()
#
# Example: Add the Bareflank extended apis extension from GitHub
#     vmm_extension(
#         extended_apis
#         GIT_REPOSITORY https://github.com/bareflank/extended_apis.git
#         GIT_TAG dev
#     )
macro(vmm_extension)
    set(EXTENSION_ARGS ${ARGN})
    list(GET EXTENSION_ARGS 0 EXTENSION_NAME)
    list(FIND VMM_EXTENSIONS ${EXTENSION_NAME} EXTENSION_IDX)
    if(NOT ${EXTENSION_IDX} EQUAL -1)
        message(FATAL_ERROR "VMM extension already registered with name: ${EXTENSION_NAME}")
    endif()

    # Reserve the suffix "_test" for auto-generated extension unit test targets
    STRING(REGEX MATCH "_test$" has_test_keyword ${EXTENSION_NAME})
    if(has_test_keyword)
        message(
            FATAL_ERROR
            "VMM extension names may not end in \"_test\", "
            "failed to add VMM extension: ${EXTENSION_NAME}"
        )
    endif()

    # Auto-generate an extension unit test build with the reserved "_test"
    # suffix (appended to the given target name)
    set(TEST_EXTENSION_ARGS ${ARGN})
    set(TEST_EXTENSION_NAME ${EXTENSION_NAME}_test)
    list(REMOVE_AT TEST_EXTENSION_ARGS 0)
    list(INSERT TEST_EXTENSION_ARGS 0 ${TEST_EXTENSION_NAME})

    # For each extension dependency, add the generated name + "_test"
    # as an additional dependency
    cmake_parse_arguments(VMM_EX "" "" "DEPENDS" ${ARGN})
    if(VMM_EX_DEPENDS)
        list(APPEND TEST_EXTENSION_ARGS "DEPENDS")
        foreach(depend_name ${VMM_EX_DEPENDS})
            list(APPEND TEST_EXTENSION_ARGS ${depend_name}_test)
        endforeach()
    endif()

    # Add the extension and unit tests to a waiting list, to be added
    # (registered) to the build system later when add_vmm_extensions() is called
    string(REPLACE ";" " " ARG_STRING "${EXTENSION_ARGS}")
    string(REPLACE ";" " " TEST_ARG_STRING "${TEST_EXTENSION_ARGS}")
    list(APPEND VMM_EXTENSIONS ${EXTENSION_NAME})
    list(APPEND VMM_EXTENSIONS ${TEST_EXTENSION_NAME})
    list(APPEND VMM_EXTENSION_ARGS "${ARG_STRING}")
    list(APPEND VMM_EXTENSION_ARGS "${TEST_ARG_STRING}")
endmacro(vmm_extension)

# Add all components configured with vmm_extension() to the build system.
# NOTE: This macro needs to be called at the very end of
# the top-level CMakeLists.txt
macro(add_vmm_extensions)
    if(VMM_EXTENSIONS)
        generate_external_project_args(_EXTENSION_CMAKE_ARGS)

        list(LENGTH VMM_EXTENSION_ARGS count)
        math(EXPR count "${count} - 1")
        foreach(i RANGE ${count})
            list(GET VMM_EXTENSIONS ${i} EXTENSION_NAME)
            list(GET VMM_EXTENSION_ARGS ${i} EXTENSION_ARGS)
            string(REPLACE " " ";" EXTENSION_ARGS ${EXTENSION_ARGS})

            STRING(REGEX MATCH "_test$" IS_TEST_EXTENSION ${EXTENSION_NAME})
            if(IS_TEST_EXTENSION)
                # If unit testing for VMM extensions is turned off, don't add
                # the auto-generated extension test projects
                if(NOT UNITTEST_VMM_EXTENSIONS OR NOT ENABLE_UNITTESTING)
                    continue()
                endif()

                # VMM extension unit test specific cmake arguments
                list(APPEND EXTENSION_ARGS
                    DEPENDS bfvmm_test
                    CMAKE_ARGS
                        -DCMAKE_TOOLCHAIN_FILE=${TOOLCHAIN_PATH_UNITTEST}
                        -DVMM_EX_IS_UNITTEST_BUILD=ON
                )

                # Add the unit tests to the 'make test' target
                add_custom_command(
                    TARGET test
                    COMMAND ${CMAKE_COMMAND}
                        --build ${BF_BUILD_EXTENSIONS_DIR}/${EXTENSION_NAME}/build
                        --target test
                )
                if(ENABLE_DEVELOPER_MODE)
                    add_dependencies(test ${EXTENSION_NAME})
                endif()
            else()
                # VMM extension specific cmake arguments
                list(APPEND EXTENSION_ARGS
                    DEPENDS bfvmm
                    CMAKE_ARGS -DCMAKE_TOOLCHAIN_FILE=${TOOLCHAIN_PATH_VMM}
                )
            endif()

            # Add the extension to the build system
            ExternalProject_Add(
                ${EXTENSION_ARGS}
                CMAKE_ARGS ${_EXTENSION_CMAKE_ARGS}
                BINARY_DIR ${BF_BUILD_EXTENSIONS_DIR}/${EXTENSION_NAME}/build
                PREFIX ${BF_BUILD_EXTENSIONS_DIR}/${EXTENSION_NAME}
                TMP_DIR ${BF_BUILD_EXTENSIONS_DIR}/${EXTENSION_NAME}/tmp
                STAMP_DIR ${BF_BUILD_EXTENSIONS_DIR}/${EXTENSION_NAME}/stamp
                UPDATE_DISCONNECTED 0
                UPDATE_COMMAND ""
            )

            list(APPEND REGISTERED_EXTENSIONS ${EXTENSION_NAME})
        endforeach()

        string(REPLACE ";" " " REGISTERED_EXTENSIONS "${REGISTERED_EXTENSIONS}")
        message(STATUS "Registered VMM Extensions: ${REGISTERED_EXTENSIONS}")
    endif()
endmacro(add_vmm_extensions)

# ------------------------------------------------------------------------------
# Build configuration and validation
# ------------------------------------------------------------------------------

# Cmake variables to orchestrate adding build rules to the build system
# using add_build_rule() and validate_build()
set(BUILD_RULES ""
    CACHE INTERNAL
    "A list of build validation rules added with the add_build_rule() macro"
)
set(BUILD_RULE_MESSAGES ""
    CACHE INTERNAL
    "Messages to be displayed when each of the above build rules fail"
)

# Add a new rule to be validated by the build system
# @arg FAIL_ON: Any valid cmake expression to be evalued by cmake's if(). If the
#       given expression evaultes TRUE, the build will fail
# @arg FAIL_MSG: A message to be displayed by cmake if FAIL_ON evaluates TRUE
macro(add_build_rule)
    set(oneVal FAIL_MSG)
    set(multiVal FAIL_ON)
    cmake_parse_arguments(ADD_BUILD_RULE "" "${oneVal}" "${multiVal}" ${ARGN})

    string(REPLACE ";" " " ADD_BUILD_RULE_FAIL_ON "${ADD_BUILD_RULE_FAIL_ON}")
    list(APPEND BUILD_RULES "${ADD_BUILD_RULE_FAIL_ON}")
    list(APPEND BUILD_RULE_MESSAGES "${ADD_BUILD_RULE_FAIL_MSG}")
endmacro(add_build_rule)

# Validates the current build configuration against all rules configured using
# add_build_rule()
macro(validate_build)
    message(STATUS "Validating build configuration...")
    list(LENGTH BUILD_RULES count)
    math(EXPR count "${count} - 1")

    foreach(i RANGE ${count})
        list(GET BUILD_RULES ${i} e)
        list(GET BUILD_RULE_MESSAGES ${i} m)
        string(REPLACE " " ";" e "${e}")
        if(${e})
            message("ERROR - Build validation failed: ${m}")
            message(SEND_ERROR "")
            set(BUILD_VALIDATOR_ERROR ON)
        endif()
    endforeach()

    if(BUILD_VALIDATOR_ERROR)
        message(FATAL_ERROR "Build validation failed")
    endif()
endmacro(validate_build)

# Add a build configuration to the build system
# @arg CONFIG_NAME: The name of the build configuration variable
# @arg DEFAULT_VAL: The default value for the configuration, if the variable
#       'CONFIG_NAME' is not already set
# @arg CONFIG_TYPE: A cmake cache variable type, to be used by cmake-gui/ccmake
#       Accepted values: BOOL, PATH, FILE, STRING
# @arg DESCRIPTION: A description of this configuration to be displayed in
#       cmake-gui and ccmake
# @arg ADVANCED: Hide this variable by default in cmake-gui/ccmake, showing the
#       variable when the user choses to see "advanced" variables
# @arg SKIP_VALIDATION: Do not perform any validation on this build config
# @arg OPTIONS: Set which options are valid for this configuration (applies to
#       STRING type variables only)
macro(add_config)
    set(bools ADVANCED SKIP_VALIDATION)
    set(oneVal CONFIG_NAME CONFIG_TYPE DEFAULT_VAL DESCRIPTION)
    set(multiVal OPTIONS)
    cmake_parse_arguments(_AC "${bools}" "${oneVal}" "${multiVal}" ${ARGN})

    # If this configuration has already been set, don't update the value, but
    # do update the cmake CACHE type and description
    if(DEFINED ${_AC_CONFIG_NAME})
        set(${_AC_CONFIG_NAME} ${${_AC_CONFIG_NAME}} CACHE ${_AC_CONFIG_TYPE} ${_AC_DESCRIPTION})
        # Otherwise, use the specified DEFAULT value
    else()
        set(${_AC_CONFIG_NAME} ${_AC_DEFAULT_VAL} CACHE ${_AC_CONFIG_TYPE} ${_AC_DESCRIPTION})
    endif()
    set(_config_val ${${_AC_CONFIG_NAME}})

    # STRING type configs support the OPTIONS parameter
    if(_AC_OPTIONS AND ${_AC_CONFIG_TYPE} STREQUAL "STRING")
        # Set cmake-gui selectable options for STRING type configurations
        set_property(CACHE ${_AC_CONFIG_NAME} PROPERTY STRINGS ${_AC_OPTIONS})
        # Validate this configuration agaist the specified options
        if(NOT _AC_SKIP_VALIDATION)
            string(REPLACE ";" " " _options_str "${_AC_OPTIONS}")
            if(NOT ${_config_val} IN_LIST _AC_OPTIONS)
                set(_invalid_option 1)
            else()
                set(_invalid_option 0)
            endif()
            add_build_rule(
                FAIL_ON ${_invalid_option}
                FAIL_MSG "${_AC_CONFIG_NAME} invalid option \'${_config_val}\' Options: ${_options_str}"
            )
        endif()
    endif()

    # Validate that all FILE type configurations exist
    if(${_AC_CONFIG_TYPE} STREQUAL "FILE" AND NOT _AC_SKIP_VALIDATION)
        add_build_rule(
            FAIL_ON NOT EXISTS ${_config_val}
            FAIL_MSG "Configuration ${_AC_CONFIG_NAME} file not found: ${_config_val}"
        )
    endif()

    # Validate that all BOOL type configurations are set to ON or OFF
    if(${_AC_CONFIG_TYPE} STREQUAL "BOOL" AND NOT _AC_SKIP_VALIDATION)
        add_build_rule(
            FAIL_ON NOT ${_config_val} STREQUAL ON AND NOT ${_config_val} STREQUAL OFF
            FAIL_MSG "Boolean configuration ${_AC_CONFIG_NAME} must be set to ON or OFF, current value is \'${_config_val}\'"
        )
    endif()

    # Make variable "advanced" for cmake-gui/ccmake
    if(_AC_ADVANCED)
        mark_as_advanced(${_AC_CONFIG_NAME})
    endif()
endmacro(add_config)

# ------------------------------------------------------------------------------
# Miscellaneous
# ------------------------------------------------------------------------------

# Print the Bareflank ASCII-art banner
macro(print_banner)
    message(STATUS "${BoldMagenta}  ___                __ _           _   ${ColorReset}")
    message(STATUS "${BoldMagenta} | _ ) __ _ _ _ ___ / _| |__ _ _ _ | |__${ColorReset}")
    message(STATUS "${BoldMagenta} | _ \\/ _` | '_/ -_)  _| / _` | ' \\| / /${ColorReset}")
    message(STATUS "${BoldMagenta} |___/\\__,_|_| \\___|_| |_\\__,_|_||_|_\\_\\${ColorReset}")
    message(STATUS "")
    message(STATUS "${Green} Please give us a star on:${White} https://github.com/Bareflank/hypervisor${ColorReset}")
    message(STATUS "")
endmacro(print_banner)

# Print the Bareflank build system top-level usage instructions:
macro(print_usage)
    message(STATUS "${Green} Bareflank is ready to build, usage:${ColorReset}")
    message(STATUS "${Yellow}    ${BF_BUILD_COMMAND}${ColorReset}")
    message(STATUS "")
    message(STATUS "${Green} For more build options:${ColorReset}")
    message(STATUS "${Yellow}    ${BF_BUILD_COMMAND} info${ColorReset}")
    message(STATUS "")
endmacro(print_usage)

# Copies all files that match the given recursive GLOB expression (relative to
# to the given GLOB directory) only if the matched source file has changed.
# @arg GLOB_EXPR: A cmake GLOB_RECURSE expression to generate a list of files
#           to be copied
# @arg GLOB_DIR: The directory that GLOB_EXPR will be calculated relative to
# @arg INSTALL_DIR: The directory to install all files that matched GLOB_EXPR to
macro(copy_files_if_different)
    set(oneVal GLOB_DIR GLOB_EXPR INSTALL_DIR)
    cmake_parse_arguments(_EP_INSTALL "" "${oneVal}" "" ${ARGN})

    file(GLOB_RECURSE out_files RELATIVE ${_EP_INSTALL_GLOB_DIR} ${_EP_INSTALL_GLOB_DIR}/${_EP_INSTALL_GLOB_EXPR})
    foreach(file ${out_files})
        execute_process(COMMAND ${CMAKE_COMMAND} -E copy_if_different ${_EP_INSTALL_GLOB_DIR}/${file} ${_EP_INSTALL_INSTALL_DIR}/${file})
    endforeach()
endmacro(copy_files_if_different)

# Platform independent symbolic link creation
macro(install_symlink filepath sympath)
    if(WIN32)
        install(CODE "execute_process(COMMAND mklink ${sympath} ${filepath})")
        install(CODE "message(STATUS \"Created symlink: ${sympath} -> ${filepath}\")")
    else()
        install(CODE "execute_process(COMMAND ${CMAKE_COMMAND} -E create_symlink ${filepath} ${sympath})")
        install(CODE "message(STATUS \"Created symlink: ${sympath} -> ${filepath}\")")
    endif()
endmacro(install_symlink)

# Convenience wrapper around cmake's built-in find_program()
# @arg path: Will hold the path to the program given by "name" on success
# @arg name: The program to be searched for.
# If the program given by "name" is not found, cmake exits with an error
macro(check_program_installed path name)
    find_program(${path} ${name})
    if(${path} MATCHES "-NOTFOUND$")
        message(FATAL_ERROR "Unable to find ${name}, or ${name} is not installed")
    endif()
endmacro(check_program_installed)
