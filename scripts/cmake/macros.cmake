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

# Add a project directory to be built with a new toolchain
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

    list(APPEND _PROJECT_CMAKE_ARGS
        -DCMAKE_TOOLCHAIN_FILE=${ADD_SUBPROJECT_TOOLCHAIN}
        -DCMAKE_TARGET_MESSAGES=OFF
        -DCMAKE_INSTALL_MESSAGE=NEVER
        --no-warn-unused-cli
    )

    if(${ADD_SUBPROJECT_VERBOSE})
        message(STATUS "Adding subproject: ${ADD_SUBPROJECT_TARGET}")
        message(STATUS "\t${ADD_SUBPROJECT_TARGET} source path: ${ADD_SUBPROJECT_SOURCE_DIR}")
        message(STATUS "\t${ADD_SUBPROJECT_TARGET} toolchain file: ${ADD_SUBPROJECT_TOOLCHAIN}")
        message(STATUS "\t${ADD_SUBPROJECT_TARGET} dependencies: ${ADD_SUBPROJECT_DEPENDS}")
    endif()

    # Copy all non-built-in cmake cache variables to the new project scope
    get_cmake_property(_vars CACHE_VARIABLES)
    foreach (_var ${_vars})
        STRING(REGEX MATCH "^CMAKE" is_cmake_var ${_var})
        if(NOT is_cmake_var)
            list(APPEND _PROJECT_CMAKE_ARGS -D${_var}=${${_var}})
        endif()
    endforeach()

    # If clang-tidy is enabled, each project must generate compile_commands.json
    if(ENABLE_TIDY)
        list(APPEND _PROJECT_CMAKE_ARGS -DCMAKE_EXPORT_COMPILE_COMMANDS=ON)
    endif()

    ExternalProject_Add(
        ${ADD_SUBPROJECT_TARGET}
        CMAKE_ARGS ${_PROJECT_CMAKE_ARGS}
        SOURCE_DIR ${ADD_SUBPROJECT_SOURCE_DIR}
        BINARY_DIR ${BF_BUILD_DIR}/${ADD_SUBPROJECT_TARGET}/build
        PREFIX ${BF_BUILD_DIR}/${ADD_SUBPROJECT_TARGET}
        TMP_DIR ${BF_BUILD_DIR}/${ADD_SUBPROJECT_TARGET}/tmp
        STAMP_DIR ${BF_BUILD_DIR}/${ADD_SUBPROJECT_TARGET}/stamp
        UPDATE_DISCONNECTED 0
        UPDATE_COMMAND ""
        DEPENDS ${ADD_SUBPROJECT_DEPENDS}
    )
endfunction(add_subproject)


set(_validator_expressions "" CACHE INTERNAL "")
set(_validator_messages "" CACHE INTERNAL "")

# Add a new rule to be validated by the build system
# @arg FAIL_ON: Any valid cmake expression to be evalued by cmake's if(). If the
#       given expression evaultes TRUE, the build will fail
# @arg FAIL_MSG: A message to be displayed by cmake if FAIL_ON evaluates TRUE
macro(add_build_rule)
    set(oneVal FAIL_MSG)
    set(multiVal FAIL_ON)
    cmake_parse_arguments(ADD_BUILD_RULE "" "${oneVal}" "${multiVal}" ${ARGN})

    string(REPLACE ";" " " ADD_BUILD_RULE_FAIL_ON "${ADD_BUILD_RULE_FAIL_ON}")
    list(APPEND _validator_expressions "${ADD_BUILD_RULE_FAIL_ON}")
    list(APPEND _validator_messages "${ADD_BUILD_RULE_FAIL_MSG}")
endmacro(add_build_rule)

# Validates the current build configuration against all rules configured using
# add_build_rule()
macro(validate_build)
    message(STATUS "Validating build configuration...")
    list(LENGTH _validator_expressions count)
    math(EXPR count "${count} - 1")

    foreach(i RANGE ${count})
        list(GET _validator_expressions ${i} e)
        list(GET _validator_messages ${i} m)
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
