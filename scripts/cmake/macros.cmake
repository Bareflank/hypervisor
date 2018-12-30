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
# colors
# ------------------------------------------------------------------------------

if(NOT WIN32)
    string(ASCII 27 Esc)
    set(ColorReset  "${Esc}[m")
    set(ColorBold   "${Esc}[1m")
    set(Red         "${Esc}[31m")
    set(Green       "${Esc}[32m")
    set(Yellow      "${Esc}[33m")
    set(Blue        "${Esc}[34m")
    set(Magenta     "${Esc}[35m")
    set(Cyan        "${Esc}[36m")
    set(White       "${Esc}[37m")
    set(BoldRed     "${Esc}[1;31m")
    set(BoldGreen   "${Esc}[1;32m")
    set(BoldYellow  "${Esc}[1;33m")
    set(BoldBlue    "${Esc}[1;34m")
    set(BoldMagenta "${Esc}[1;35m")
    set(BoldCyan    "${Esc}[1;36m")
    set(BoldWhite   "${Esc}[1;37m")
endif()

# ------------------------------------------------------------------------------
# Macro File List
# ------------------------------------------------------------------------------

macro(add_project_include FILE)
    set(PROJECT_INCLUDE_LIST "${PROJECT_INCLUDE_LIST}|${FILE}")
endmacro(add_project_include)

# ------------------------------------------------------------------------------
# include_external_extensions
# ------------------------------------------------------------------------------

macro(include_external_extensions)
    foreach(e ${EXTENSION})
        if(NOT IS_ABSOLUTE "${e}")
            get_filename_component(e "${BUILD_ROOT_DIR}/${e}" ABSOLUTE)
        endif()
        if(EXISTS "${e}/CMakeLists.txt")
            message(STATUS "Extension: ${e}")
            include(${e}/CMakeLists.txt)
        else()
            message(FATAL_ERROR "Extension not found: ${e}")
        endif()
    endforeach(e)
endmacro(include_external_extensions)

# ------------------------------------------------------------------------------
# generate_flags
# ------------------------------------------------------------------------------

# Generate Flags
#
# Sets up CMAKE_C_FLAGS and CMAKE_CXX_FLAGS based on the provided flags and
# prefix value. Each time this is executed, CMAKE_XXX_FLAGS are overwritten
# and globally set. The add_subproject function performs this action on your
# behalf, and this function generally should not be used unless you are
# compiling a dependency, in which case, you will need to run this manually.
#
# @param PREFIX (macro arg) Defines which prefix the flags belong too. Valid
#     values are: vmm, userspace, and test
# @param C_FLAGS Additional C flags to add to CMAKE_C_FLAGS
# @param CXX_FLAGS Additional CXX flags to add to CMAKE_CXX_FLAGS
#
function(generate_flags PREFIX)
    set(options NOWARNINGS)
    set(multiVal C_FLAGS CXX_FLAGS)
    cmake_parse_arguments(ARG "${options}" "" "${multiVal}" ${ARGN})

    list(APPEND _C_FLAGS ${ARG_C_FLAGS} $ENV{C_FLAGS})
    list(APPEND _CXX_FLAGS ${ARG_CXX_FLAGS} $ENV{CXX_FLAGS})

    if(PREFIX STREQUAL "vmm")
        list(APPEND _C_FLAGS ${BFFLAGS_VMM} ${BFFLAGS_VMM_C} ${C_FLAGS_VMM})
        list(APPEND _CXX_FLAGS ${BFFLAGS_VMM} ${BFFLAGS_VMM_CXX} ${CXX_FLAGS_VMM})
        if(${BUILD_TARGET_ARCH} STREQUAL "x86_64")
            list(APPEND _C_FLAGS ${BFFLAGS_VMM_X86_64})
            list(APPEND _CXX_FLAGS ${BFFLAGS_VMM_X86_64})
        endif()
        if(${BUILD_TARGET_ARCH} STREQUAL "aarch64")
            list(APPEND _C_FLAGS ${BFFLAGS_VMM_AARCH64})
            list(APPEND _CXX_FLAGS ${BFFLAGS_VMM_AARCH64})
        endif()
    elseif(PREFIX STREQUAL "userspace")
        list(APPEND _C_FLAGS ${BFFLAGS_USERSPACE} ${BFFLAGS_USERSPACE_C} ${C_FLAGS_USERSPACE})
        list(APPEND _CXX_FLAGS ${BFFLAGS_USERSPACE} ${BFFLAGS_USERSPACE_CXX} ${CXX_FLAGS_USERSPACE})
        if(${BUILD_TARGET_ARCH} STREQUAL "x86_64")
            list(APPEND _C_FLAGS ${BFFLAGS_USERSPACE_X86_64})
            list(APPEND _CXX_FLAGS ${BFFLAGS_USERSPACE_X86_64})
        endif()
        if(${BUILD_TARGET_ARCH} STREQUAL "aarch64")
            list(APPEND _C_FLAGS ${BFFLAGS_USERSPACE_AARCH64})
            list(APPEND _CXX_FLAGS ${BFFLAGS_USERSPACE_AARCH64})
        endif()
    elseif(PREFIX STREQUAL "test")
        list(APPEND _C_FLAGS ${BFFLAGS_TEST} ${BFFLAGS_TEST_C} ${C_FLAGS_TEST})
        list(APPEND _CXX_FLAGS ${BFFLAGS_TEST} ${BFFLAGS_TEST_CXX} ${CXX_FLAGS_TEST})
        if(${BUILD_TARGET_ARCH} STREQUAL "x86_64")
            list(APPEND _C_FLAGS ${BFFLAGS_TEST_X86_64})
            list(APPEND _CXX_FLAGS ${BFFLAGS_TEST_X86_64})
        endif()
        if(${BUILD_TARGET_ARCH} STREQUAL "aarch64")
            list(APPEND _C_FLAGS ${BFFLAGS_TEST_AARCH64})
            list(APPEND _CXX_FLAGS ${BFFLAGS_TEST_AARCH64})
        endif()
        if(ENABLE_ASAN)
            list(APPEND _C_FLAGS ${BFFLAGS_ASAN})
            list(APPEND _CXX_FLAGS ${BFFLAGS_ASAN})
        endif()
        if(ENABLE_USAN)
            list(APPEND _C_FLAGS ${BFFLAGS_USAN})
            list(APPEND _CXX_FLAGS ${BFFLAGS_USAN})
        endif()
        if(ENABLE_CODECOV)
            list(APPEND _C_FLAGS ${BFFLAGS_CODECOV})
            list(APPEND _CXX_FLAGS ${BFFLAGS_CODECOV})
        endif()
    elseif(PREFIX STREQUAL "efi")
        list(APPEND _C_FLAGS ${BFFLAGS_EFI} ${BFFLAGS_EFI_C} ${C_FLAGS_EFI})
        list(APPEND _CXX_FLAGS ${BFFLAGS_EFI} ${BFFLAGS_EFI_CXX} ${CXX_FLAGS_EFI})
        if(${BUILD_TARGET_ARCH} STREQUAL "x86_64")
            list(APPEND _C_FLAGS ${BFFLAGS_EFI_X86_64})
            list(APPEND _CXX_FLAGS ${BFFLAGS_EFI_X86_64})
        endif()
        if(${BUILD_TARGET_ARCH} STREQUAL "aarch64")
            list(APPEND _C_FLAGS ${BFFLAGS_EFI_AARCH64})
            list(APPEND _CXX_FLAGS ${BFFLAGS_EFI_AARCH64})
        endif()
    else()
        message(FATAL_ERROR "Invalid prefix: ${PREFIX}")
    endif()

    if(NOT ARG_NOWARNINGS)
        if(ENABLE_COMPILER_WARNINGS)
            list(APPEND _C_FLAGS ${BFFLAGS_WARNING_C})
            list(APPEND _CXX_FLAGS ${BFFLAGS_WARNING_CXX})
        endif()

        if(CMAKE_BUILD_TYPE STREQUAL "Release")
            if(NOT WIN32)
                list(APPEND _C_FLAGS -Werror)
                list(APPEND _CXX_FLAGS -Werror)
            else()
                list(APPEND _C_FLAGS /WX)
                list(APPEND _CXX_FLAGS /WX)
            endif()
        endif()
    endif()

    string(REPLACE ";" " " _C_FLAGS "${_C_FLAGS}")
    string(REPLACE ";" " " _CXX_FLAGS "${_CXX_FLAGS}")

    set(CMAKE_C_FLAGS ${_C_FLAGS} PARENT_SCOPE)
    set(CMAKE_CXX_FLAGS ${_CXX_FLAGS} PARENT_SCOPE)
endfunction(generate_flags)

# ------------------------------------------------------------------------------
# include_dependency
# ------------------------------------------------------------------------------

# Private
#
function(include_dependency DIR NAME)
    include(${${DIR}}/${NAME}.cmake)
endfunction(include_dependency)

# ------------------------------------------------------------------------------
# download_dependency
# ------------------------------------------------------------------------------

# Download Dependency
#
# Downloads a dependency from a URL. Dependencies can either be
# a tarball or a zip file. These downloaded files are placeed in the CACHE_DIR.
# If the provided MD5 hash does not match, the cached download is redownloaded.
#
# @param NAME the name of the dependency
# @param URL The URL for the dependency
# @param URL_MD5 The MD5 of the file being downloaded
# @param PREFIX An optional prefix. This is only needed if downloading the
#     dependency is the only required step, in which case this function will
#     create the custom target for dependency tracking.
#
function(download_dependency NAME)
    set(oneVal URL URL_MD5 GIT_REPOSITORY GIT_TAG PREFIX)
    cmake_parse_arguments(ARG "" "${oneVal}" "" ${ARGN})

    set(SRC ${CACHE_DIR}/${NAME})

    if(ARG_URL)
        if(NOT ARG_URL_MD5)
            message(FATAL_ERROR "Invalid URL MD5: ${ARG_URL_MD5}")
        endif()

        string(REGEX REPLACE "\\.[^.]*$" "" FILENAME ${ARG_URL})
        string(REPLACE "${FILENAME}" "" EXT ${ARG_URL})
        get_filename_component(LONG_EXT ${ARG_URL} EXT)
        if(NOT LONG_EXT MATCHES "(\\.|=)(7z|tar\\.bz2|tar\\.gz|tar\\.xz|tbz2|tgz|txz|zip)$")
            message(FATAL_ERROR "Unsupported file format: ${ARG_URL}")
        endif()

        if(LONG_EXT MATCHES ".tar.gz$")
            set(EXT ".tar.gz")
        endif()

        if(LONG_EXT MATCHES ".tar.xz$")
            set(EXT ".tar.xz")
        endif()

        if(LONG_EXT MATCHES ".tar.bz2$")
            set(EXT ".tar.bz2")
        endif()

        set(TMP ${CACHE_DIR}/${NAME}_tmp)
        set(TAR ${CACHE_DIR}/${NAME}${EXT})

        # TODO
        #
        # If a dependency needs to be downloaded, currently, we remove the
        # source directory which forces a recompile. We need to verify that
        # when this happens, all of the targets that rely on this dependency
        # are also recompiled / relinked.
        #

        foreach(ATTEMPT RANGE 1 5 1)
            if(EXISTS "${TAR}")
                message(STATUS "    checking hash: ${ARG_URL_MD5}")
                file(MD5 ${TAR} MD5)
                if(NOT "${MD5}" STREQUAL "${ARG_URL_MD5}")
                    message(STATUS "    ${Red}md5 mismatch: expecting ${ARG_URL_MD5}, got ${MD5}${ColorReset}")
                    set_property(GLOBAL PROPERTY "FORCE_REBUILD" "ON")
                    file(REMOVE_RECURSE ${SRC})
                    file(REMOVE_RECURSE ${TMP})
                    file(REMOVE_RECURSE ${TAR})
                    message(STATUS "    checking hash: ${Yellow}complete, redownload required${ColorReset}")
                else()
                    message(STATUS "    checking hash: ${Green}complete${ColorReset}")
                    break()
                endif()
            endif()

            if(ATTEMPT GREATER 1)
                message(STATUS "    attempt: ${ATTEMPT}")
            endif()

            message(STATUS "    download file: ${ARG_URL} -> ${TAR}")
            file(DOWNLOAD ${ARG_URL} ${TAR} STATUS DOWNLOAD_STATUS)
            if(NOT DOWNLOAD_STATUS MATCHES "0;")
                message(STATUS "    ${Red}failed to download ${ARG_URL}${ColorReset}")
                file(REMOVE_RECURSE ${TAR})
                continue()
            endif()
            message(STATUS "    download file: ${Green}complete${ColorReset}")
        endforeach()

        if(EXISTS ${TAR})
            file(MD5 ${TAR} MD5)
            if(NOT "${MD5}" STREQUAL "${ARG_URL_MD5}")
                message(FATAL_ERROR "Failed to download ${ARG_URL} with md5 hash of ${ARG_URL_MD5}")
            endif()
        else()
            message(FATAL_ERROR "Failed to download ${ARG_URL} with md5 hash of ${ARG_URL_MD5}")
        endif()

        if(NOT EXISTS "${SRC}")
            file(REMOVE_RECURSE ${TMP})
            file(REMOVE_RECURSE ${SRC})
            file(MAKE_DIRECTORY ${TMP})

            execute_process(
                COMMAND ${CMAKE_COMMAND} -E tar xfz ${TAR}
                WORKING_DIRECTORY ${TMP}
            )

            file(GLOB CONTENTS "${TMP}/*")

            list(LENGTH CONTENTS LEN)
            if(NOT LEN EQUAL 1 OR NOT IS_DIRECTORY ${CONTENTS})
                message(FATAL_ERROR "Invalid tarball: ${ARG_URL}")
            endif()

            get_filename_component(CONTENTS ${CONTENTS} ABSOLUTE)
            execute_process(
                COMMAND ${CMAKE_COMMAND} -E rename ${CONTENTS} ${SRC}
            )

            file(REMOVE_RECURSE ${TMP})
        endif()
    endif()

    if(ARG_GIT_REPOSITORY)
        if(ARG_GIT_TAG)
            set(ARG_GIT_TAG -b ${ARG_GIT_TAG})
        endif()
        if(NOT EXISTS "${SRC}")
            execute_process(COMMAND git clone ${ARG_GIT_REPOSITORY} ${ARG_GIT_TAG} ${SRC})
        endif()
    endif()

    if(ARG_PREFIX)
        if(ARG_PREFIX STREQUAL "vmm")
            add_custom_target(${NAME}_${VMM_PREFIX})
        elseif(ARG_PREFIX STREQUAL "userspace")
            add_custom_target(${NAME}_${USERSPACE_PREFIX})
        elseif(ARG_PREFIX STREQUAL "test")
            add_custom_target(${NAME}_${TEST_PREFIX})
        else()
            message(FATAL_ERROR "Invalid prefix: ${PREFIX}")
        endif()
    endif()
endfunction(download_dependency)

# ------------------------------------------------------------------------------
# add_dependency
# ------------------------------------------------------------------------------

# Add Dependency
#
# Uses ExternalProject_Add to add the dependency to the build. All of the
# optional arguments are passed directly to ExternalProject_Add, so most of
# ExternalProject_Add's options are supported by this function.
#
# @param NAME the name of the dependency
# @param PREFIX the prefix this dependency belongs too. Valid values are:
#     vmm, userspace and test.
#
function(add_dependency NAME PREFIX)
    if(PREFIX STREQUAL "vmm")
        set(PREFIX ${VMM_PREFIX})
    elseif(PREFIX STREQUAL "userspace")
        set(PREFIX ${USERSPACE_PREFIX})
    elseif(PREFIX STREQUAL "test")
        set(PREFIX ${TEST_PREFIX})
    elseif(PREFIX STREQUAL "efi")
        set(PREFIX ${EFI_PREFIX})
    else()
        message(FATAL_ERROR "Invalid prefix: ${PREFIX}")
    endif()

    if(EXISTS "${CACHE_DIR}/${NAME}/CMakeLists.txt")
        list(APPEND ARGN
            CMAKE_ARGS -DCMAKE_INSTALL_PREFIX=${PREFIXES_DIR}/${PREFIX}
            CMAKE_ARGS -DCMAKE_INSTALL_MESSAGE=${CMAKE_INSTALL_MESSAGE}
            CMAKE_ARGS -DCMAKE_VERBOSE_MAKEFILE=${CMAKE_VERBOSE_MAKEFILE}
        )
        if(NOT WIN32 AND NOT CMAKE_GENERATOR STREQUAL "Ninja")
            list(APPEND ARGN
                CMAKE_ARGS -DCMAKE_TARGET_MESSAGES=${CMAKE_TARGET_MESSAGES}
            )
        endif()
        if(NOT WIN32)
            list(APPEND ARGN
                CMAKE_ARGS -DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}
            )
        endif()
    else()
        list(APPEND ARGN
            LOG_CONFIGURE 1
            LOG_BUILD 1
            LOG_INSTALL 1
        )
    endif()

    add_custom_command(
        TARGET clean-all
        COMMAND ${CMAKE_COMMAND} -E remove_directory ${DEPENDS_DIR}/${NAME}
    )

    add_custom_command(
        TARGET clean-depends
        COMMAND ${CMAKE_COMMAND} -E remove_directory ${DEPENDS_DIR}/${NAME}
    )

    # TODO
    #
    # As a post install step, we need to touch a file that states that the
    # dependency has been compiled. If this is the case, we would then only
    # run the install step, skipping the compile step. This should allow us
    # to move the depends directory outside of the build tree and safely use
    # it for future compilations.
    #

    ExternalProject_Add(
        ${NAME}_${PREFIX}
        ${ARGN}
        PREFIX              ${DEPENDS_DIR}/${NAME}/${PREFIX}
        STAMP_DIR           ${DEPENDS_DIR}/${NAME}/${PREFIX}/stamp
        TMP_DIR             ${DEPENDS_DIR}/${NAME}/${PREFIX}/tmp
        BINARY_DIR          ${DEPENDS_DIR}/${NAME}/${PREFIX}/build
        SOURCE_DIR          ${CACHE_DIR}/${NAME}
    )

    ExternalProject_Add_Step(
        ${NAME}_${PREFIX}
        ${NAME}_${PREFIX}_cleanup
        COMMAND ${CMAKE_COMMAND} -E remove_directory ${DEPENDS_DIR}/${NAME}/${PREFIX}/src
        DEPENDEES configure
    )
endfunction(add_dependency)

# Add Dependency Step
#
# Uses ExternalProject_Add_Step to add an additional step to external project
# add after "install" is executed by ExternalProject_Add. Only one additional
# step is supported. Like add_dependency, add_dependency_step passes all
# optional parameters to ExternalProject_Add_Step, so most options are
# supported.
#
# @param NAME the name of the dependency
# @param PREFIX the prefix this dependency belongs too. Valid values are:
#     vmm, userspace and test.
#
function(add_dependency_step NAME PREFIX)
    if(PREFIX STREQUAL "vmm")
        set(PREFIX ${VMM_PREFIX})
    elseif(PREFIX STREQUAL "userspace")
        set(PREFIX ${USERSPACE_PREFIX})
    elseif(PREFIX STREQUAL "test")
        set(PREFIX ${TEST_PREFIX})
    elseif(PREFIX STREQUAL "efi")
        set(PREFIX ${EFI_PREFIX})
    else()
        message(FATAL_ERROR "Invalid prefix: ${PREFIX}")
    endif()

    ExternalProject_Add_Step(
        ${NAME}_${PREFIX}
        step_${NAME}_${PREFIX}
        ${ARGN}
        DEPENDEES install
    )
endfunction(add_dependency_step)

# ------------------------------------------------------------------------------
# add_targets
# ------------------------------------------------------------------------------

# Private
#
function(add_tidy_targets NAME PREFIX SOURCE_DIR)
    if(PREFIX STREQUAL "vmm")
        set(PREFIX ${VMM_PREFIX})
    elseif(PREFIX STREQUAL "userspace")
        set(PREFIX ${USERSPACE_PREFIX})
    elseif(PREFIX STREQUAL "test")
        set(PREFIX ${TEST_PREFIX})
    endif()

    if(NOT EXISTS "${SOURCE_DIR}")
        return()
    endif()

    add_custom_command(
        TARGET tidy
        COMMAND ${CMAKE_COMMAND} -E chdir ${CMAKE_BINARY_DIR}/${NAME}/${PREFIX}/build
            ${TIDY_SCRIPT} diff ${SOURCE_DIR}
    )

    add_custom_command(
        TARGET tidy-all
        COMMAND ${CMAKE_COMMAND} -E chdir ${CMAKE_BINARY_DIR}/${NAME}/${PREFIX}/build
            ${TIDY_SCRIPT} all ${SOURCE_DIR}
    )

    add_custom_command(
        TARGET tidy-upstream
        COMMAND ${CMAKE_COMMAND} -E chdir ${CMAKE_BINARY_DIR}/${NAME}/${PREFIX}/build
            ${TIDY_SCRIPT} upstream ${SOURCE_DIR}
    )

    add_custom_command(
        TARGET tidy-${NAME}_${PREFIX}
        COMMAND ${CMAKE_COMMAND} -E chdir ${CMAKE_BINARY_DIR}/${NAME}/${PREFIX}/build
            ${TIDY_SCRIPT} diff ${SOURCE_DIR}
    )

    add_custom_command(
        TARGET tidy-${NAME}_${PREFIX}-all
        COMMAND ${CMAKE_COMMAND} -E chdir ${CMAKE_BINARY_DIR}/${NAME}/${PREFIX}/build
            ${TIDY_SCRIPT} all ${SOURCE_DIR}
    )

    add_custom_command(
        TARGET tidy-${NAME}_${PREFIX}-upstream
        COMMAND ${CMAKE_COMMAND} -E chdir ${CMAKE_BINARY_DIR}/${NAME}/${PREFIX}/build
            ${TIDY_SCRIPT} upstream ${SOURCE_DIR}
    )
endfunction(add_tidy_targets)

# Private
#
function(add_format_targets NAME PREFIX SOURCE_DIR)
    if(PREFIX STREQUAL "vmm")
        set(PREFIX ${VMM_PREFIX})
    elseif(PREFIX STREQUAL "userspace")
        set(PREFIX ${USERSPACE_PREFIX})
    elseif(PREFIX STREQUAL "test")
        set(PREFIX ${TEST_PREFIX})
    endif()

    if(NOT EXISTS "${SOURCE_DIR}")
        return()
    endif()

    add_custom_command(
        TARGET format
        COMMAND ${ASTYLE_SCRIPT} ${USERSPACE_PREFIX_PATH}/bin/astyle diff ${SOURCE_DIR}
    )

    add_custom_command(
        TARGET format-all
        COMMAND ${ASTYLE_SCRIPT} ${USERSPACE_PREFIX_PATH}/bin/astyle all ${SOURCE_DIR}
    )

    add_custom_command(
        TARGET format-upstream
        COMMAND ${ASTYLE_SCRIPT} ${USERSPACE_PREFIX_PATH}/bin/astyle upstream ${SOURCE_DIR}
    )

    add_custom_command(
        TARGET format-${NAME}_${PREFIX}
        COMMAND ${ASTYLE_SCRIPT} ${USERSPACE_PREFIX_PATH}/bin/astyle diff ${SOURCE_DIR}
    )

    add_custom_command(
        TARGET format-${NAME}_${PREFIX}-all
        COMMAND ${ASTYLE_SCRIPT} ${USERSPACE_PREFIX_PATH}/bin/astyle all ${SOURCE_DIR}
    )

    add_custom_command(
        TARGET format-${NAME}_${PREFIX}-upstream
        COMMAND ${ASTYLE_SCRIPT} ${USERSPACE_PREFIX_PATH}/bin/astyle upstream ${SOURCE_DIR}
    )
endfunction(add_format_targets)

# Private
#
function(add_targets NAME PREFIX SOURCE_DIR)
    if(PREFIX STREQUAL "vmm")
        set(FULLPREFIX ${VMM_PREFIX})
    elseif(PREFIX STREQUAL "userspace")
        set(FULLPREFIX ${USERSPACE_PREFIX})
    elseif(PREFIX STREQUAL "test")
        set(FULLPREFIX ${TEST_PREFIX})
    elseif(PREFIX STREQUAL "none")
        set(FULLPREFIX ${PREFIX})
    endif()

    if(NOT PREFIX STREQUAL "none")
        add_custom_target(
            clean-${NAME}_${FULLPREFIX}
            COMMAND ${CMAKE_COMMAND} -E remove_directory ${CMAKE_BINARY_DIR}/${NAME}/${FULLPREFIX}
        )

        add_custom_command(
            TARGET clean-all
            COMMAND ${CMAKE_COMMAND} -E remove_directory ${CMAKE_BINARY_DIR}/${NAME}/${FULLPREFIX}
        )

        add_custom_command(
            TARGET clean-subprojects
            COMMAND ${CMAKE_COMMAND} -E remove_directory ${CMAKE_BINARY_DIR}/${NAME}/${FULLPREFIX}
        )

        add_custom_target(
            rebuild-${NAME}_${FULLPREFIX}
            COMMAND ${CMAKE_COMMAND} -E remove_directory ${CMAKE_BINARY_DIR}/${NAME}/${FULLPREFIX}
            COMMAND ${CMAKE_COMMAND} --build . --target ${NAME}_${FULLPREFIX}
        )

        if(ENABLE_TIDY)
            add_custom_target(tidy-${NAME}_${FULLPREFIX})
            add_custom_target(tidy-${NAME}_${FULLPREFIX}-all)
            add_custom_target(tidy-${NAME}_${FULLPREFIX}-upstream)
            add_tidy_targets(${NAME} ${PREFIX} ${SOURCE_DIR})
        endif()

        if(ENABLE_FORMAT)
            add_custom_target(format-${NAME}_${FULLPREFIX})
            add_custom_target(format-${NAME}_${FULLPREFIX}-all)
            add_custom_target(format-${NAME}_${FULLPREFIX}-upstream)
            add_format_targets(${NAME} ${PREFIX} ${SOURCE_DIR})
            add_format_targets(${NAME} ${PREFIX} ${SOURCE_DIR}/../include)
        endif()
    endif()

    if(PREFIX STREQUAL "test")
        add_custom_command(
            TARGET unittest
            COMMAND ${CMAKE_COMMAND} -E chdir ${CMAKE_BINARY_DIR}/${NAME}/${FULLPREFIX}/build
                ctest --output-on-failure
        )

        add_custom_target(
            unittest-${NAME}_${FULLPREFIX}
            COMMAND ${CMAKE_COMMAND} -E chdir ${CMAKE_BINARY_DIR}/${NAME}/${FULLPREFIX}/build
                ctest --output-on-failure
        )
    endif()
endfunction(add_targets)

# ------------------------------------------------------------------------------
# right_justify
# ------------------------------------------------------------------------------

# Private
#
function(right_justify text width output)
    set(str "")
    string(LENGTH "${text}" text_len)
    foreach(i RANGE ${text_len} ${width})
        set(str " ${str}")
    endforeach(i)
    set(${output} ${str} PARENT_SCOPE)
endfunction(right_justify)

# ------------------------------------------------------------------------------
# add_custom_target_category
# ------------------------------------------------------------------------------

# Private
#
function(add_custom_target_category TEXT)
    if(NOT WIN32)
        add_custom_command(
            TARGET info
            COMMAND ${CMAKE_COMMAND} -E cmake_echo_color " "
            COMMAND ${CMAKE_COMMAND} -E cmake_echo_color --green "${TEXT}:"
        )
    endif()
endfunction(add_custom_target_category)

# ------------------------------------------------------------------------------
# add_custom_target_info
# ------------------------------------------------------------------------------

# Private
#
function(add_custom_target_info)
    if(NOT WIN32)
        set(oneVal TARGET COMMENT)
        cmake_parse_arguments(ARG "" "${oneVal}" "" ${ARGN})

        if(NOT_ARG_TARGET)
            right_justify("${BUILD_COMMAND}" 20 JUSTIFY_STR)
            add_custom_command(
                TARGET info
                COMMAND ${CMAKE_COMMAND} -E cmake_echo_color --yellow --no-newline "    ${BUILD_COMMAND}"
                COMMAND ${CMAKE_COMMAND} -E cmake_echo_color --red --no-newline "${JUSTIFY_STR}- "
                COMMAND ${CMAKE_COMMAND} -E cmake_echo_color --white "${ARG_COMMENT}"
            )
        else()
            right_justify("${BUILD_COMMAND} ${ARG_TARGET}" 20 JUSTIFY_STR)
            add_custom_command(
                TARGET info
                COMMAND ${CMAKE_COMMAND} -E cmake_echo_color --yellow --no-newline "    ${BUILD_COMMAND} ${ARG_TARGET}"
                COMMAND ${CMAKE_COMMAND} -E cmake_echo_color --red --no-newline "${JUSTIFY_STR}- "
                COMMAND ${CMAKE_COMMAND} -E cmake_echo_color --white "${ARG_COMMENT}"
            )
        endif()
    endif()
endfunction(add_custom_target_info)

# ------------------------------------------------------------------------------
# add_subproject
# ------------------------------------------------------------------------------

# Add Sub Project
#
# Adds a Bareflank specific project to the build. Unlike dependencies,
# sub projects are checked for changes. This function is not only used
# internally by the main build system, but can also be used by extensions
# for adding additional logic to the hypervisor.
#
# @param NOBUILD Include the sub project, but don't build the code. This is
#     mainly used to register targets for a given sub project, and the prefix
#     is usually "none".
# @param NOINSTALL Skip the install step for the sub project
# @param
#
#
function(add_subproject NAME PREFIX)
    set(options NOBUILD NOINSTALL)
    set(oneVal SOURCE_DIR TOOLCHAIN)
    set(multiVal C_FLAGS CXX_FLAGS DEPENDS)
    cmake_parse_arguments(ARG "${options}" "${oneVal}" "${multiVal}" ${ARGN})

    if(PREFIX STREQUAL "vmm" AND NOT BUILD_VMM AND NOT BUILD_TEST)
        return()
    endif()

    if(PREFIX STREQUAL "userspace" AND NOT BUILD_USERSPACE)
        return()
    endif()

    if(PREFIX STREQUAL "test" AND NOT BUILD_TEST)
        return()
    endif()

    if(PREFIX STREQUAL "efi" AND NOT BUILD_EFI)
        return()
    endif()

    if(ARG_SOURCE_DIR)
        set(SOURCE_DIR ${ARG_SOURCE_DIR})
    else()
        if(PREFIX STREQUAL "test")
            set(SOURCE_DIR ${CMAKE_CURRENT_LIST_DIR}/${NAME}/tests)
        else()
            set(SOURCE_DIR ${CMAKE_CURRENT_LIST_DIR}/${NAME}/src)
        endif()
    endif()

    if(NOT PREFIX STREQUAL "efi")
        add_targets(${NAME} ${PREFIX} ${SOURCE_DIR})
    endif()

    if(ARG_NOBUILD)
        return()
    endif()

    if(NOT ARG_TOOLCHAIN)
        if(PREFIX STREQUAL "vmm")
            set(TOOLCHAIN ${VMM_TOOLCHAIN_PATH})
        elseif(PREFIX STREQUAL "userspace")
            set(TOOLCHAIN ${USERSPACE_TOOLCHAIN_PATH})
        elseif(PREFIX STREQUAL "test")
            set(TOOLCHAIN ${TEST_TOOLCHAIN_PATH})
        elseif(PREFIX STREQUAL "efi")
            set(TOOLCHAIN ${EFI_TOOLCHAIN_PATH})
        else()
            message(FATAL_ERROR "Invalid prefix: ${PREFIX}")
        endif()
    else()
        set(TOOLCHAIN ${ARG_TOOLCHAIN})
    endif()

    if(PREFIX STREQUAL "vmm")
        set(PREFIX ${VMM_PREFIX})
    elseif(PREFIX STREQUAL "userspace")
        set(PREFIX ${USERSPACE_PREFIX})
    elseif(PREFIX STREQUAL "test")
        set(PREFIX ${TEST_PREFIX})
    elseif(PREFIX STREQUAL "efi")
        set(PREFIX ${EFI_PREFIX})
    else()
        message(FATAL_ERROR "Invalid prefix: ${PREFIX}")
    endif()

    foreach(d ${ARG_DEPENDS})
        if(d MATCHES ${VMM_PREFIX})
            list(APPEND DEPENDS "${d}")
        elseif(d MATCHES ${USERSPACE_PREFIX})
            list(APPEND DEPENDS "${d}")
        elseif(d MATCHES ${TEST_PREFIX})
            list(APPEND DEPENDS "${d}")
        elseif(d MATCHES ${EFI_PREFIX})
            list(APPEND DEPENDS "${d}")
        else()
            list(APPEND DEPENDS "${d}_${PREFIX}")
        endif()
    endforeach(d)

    get_cmake_property(_vars CACHE_VARIABLES)
    foreach (_var ${_vars})
        STRING(REGEX MATCH "^CMAKE" is_cmake_var ${_var})
        if(NOT is_cmake_var)
            list(APPEND CMAKE_ARGS -D${_var}=${${_var}})
        endif()
    endforeach()

    if(BUILD_TEST)
        list(APPEND CMAKE_ARGS -DCMAKE_EXPORT_COMPILE_COMMANDS=ON)
    endif()

    list(APPEND CMAKE_ARGS
        -DCMAKE_INSTALL_PREFIX=${PREFIXES_DIR}/${PREFIX}
        -DCMAKE_INSTALL_MESSAGE=${CMAKE_INSTALL_MESSAGE}
        -DCMAKE_VERBOSE_MAKEFILE=${CMAKE_VERBOSE_MAKEFILE}
        -DCMAKE_TOOLCHAIN_FILE=${TOOLCHAIN}
        -DPROJECT_INCLUDE_LIST=${PROJECT_INCLUDE_LIST}
        -DPACKAGE_LIST=${PACKAGE_LIST}
        -DBFM_VMM=${BFM_VMM}
        -DEFI_EXTENSION_SOURCES=${EFI_EXTENSION_SOURCES}
        -DCMAKE_PROJECT_${NAME}_INCLUDE=${SOURCE_CMAKE_DIR}/project.cmake
        -DCMAKE_PREFIX_PATH=${EXPORT_DIR}
    )

    if(NOT WIN32 AND NOT CMAKE_GENERATOR STREQUAL "Ninja")
        list(APPEND CMAKE_ARGS
            -DCMAKE_TARGET_MESSAGES=${CMAKE_TARGET_MESSAGES}
        )
    endif()
    if(NOT WIN32)
        list(APPEND CMAKE_ARGS
            -DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}
        )
    endif()

    if(ARG_NOINSTALL)
        list(APPEND EPA_ARGS
            INSTALL_COMMAND ${CMAKE_COMMAND} -E echo "-- Install step ignored"
        )
    endif()

    ExternalProject_Add(
        ${NAME}_${PREFIX}
        ${EPA_ARGS}
        PREFIX          ${CMAKE_BINARY_DIR}/${NAME}/${PREFIX}
        STAMP_DIR       ${CMAKE_BINARY_DIR}/${NAME}/${PREFIX}/stamp
        TMP_DIR         ${CMAKE_BINARY_DIR}/${NAME}/${PREFIX}/tmp
        BINARY_DIR      ${CMAKE_BINARY_DIR}/${NAME}/${PREFIX}/build
        SOURCE_DIR      ${SOURCE_DIR}
        CMAKE_ARGS      ${CMAKE_ARGS}
        DEPENDS         ${DEPENDS}
        UPDATE_COMMAND  ${CMAKE_COMMAND} -E echo "-- checking for updates"
    )

    ExternalProject_Add_Step(
        ${NAME}_${PREFIX}
        ${NAME}_${PREFIX}_cleanup
        COMMAND ${CMAKE_COMMAND} -E remove_directory ${CMAKE_BINARY_DIR}/${NAME}/${PREFIX}/src
        DEPENDEES configure
    )

    # This must come *after* ExternalProject_Add, otherwise find_package
    # will fail since it hasn't been installed yet
    #
    set(PACKAGE_LIST "${PACKAGE_LIST}|${NAME}" PARENT_SCOPE)

endfunction(add_subproject)

# ------------------------------------------------------------------------------
# EFI Build
# ------------------------------------------------------------------------------

macro(add_efi_source)
    list(APPEND EFI_EXTENSION_SOURCES
        ${ARGN}
    )
endmacro(add_efi_source)

# ------------------------------------------------------------------------------
# Extensions
# ------------------------------------------------------------------------------

function(vmm_extension NAME)
    list(APPEND ARGN
        DEPENDS bfvmm
        DEPENDS bfintrinsics
    )

    add_subproject(
        ${NAME} vmm
        ${ARGN}
    )
endfunction(vmm_extension)

function(userspace_extension NAME)
    add_subproject(
        ${NAME} userspace
        ${ARGN}
    )
endfunction(userspace_extension)

function(test_extension NAME)
    add_subproject(
        ${NAME} test
        ${ARGN}
    )
endfunction(test_extension)

# ------------------------------------------------------------------------------
# init_project
# ------------------------------------------------------------------------------

# Private
#
macro(enable_asm PREFIX)
    if(${BUILD_TARGET_ARCH} STREQUAL "x86_64")
        find_program(NASM_BIN nasm)

        if(NOT NASM_BIN)
            set(NASM_BIN "c:\\Program Files\\NASM\\nasm.exe")
            if(NOT EXISTS ${NASM_BIN})
                message(FATAL_ERROR "Unable to find nasm, or nasm is not installed")
            endif()
        endif()

        execute_process(COMMAND ${NASM_BIN} -v OUTPUT_VARIABLE NASM_ID OUTPUT_STRIP_TRAILING_WHITESPACE)
        set(CMAKE_ASM_NASM_COMPILER_ID ${NASM_ID})

        if(PREFIX STREQUAL "vmm")
            set(CMAKE_ASM_NASM_OBJECT_FORMAT "elf64")
        else()
            if(HOST_FORMAT_TYPE STREQUAL "pe")
                set(CMAKE_ASM_NASM_OBJECT_FORMAT "win64")
            endif()
            if(HOST_FORMAT_TYPE STREQUAL "elf")
                set(CMAKE_ASM_NASM_OBJECT_FORMAT "elf64")
            endif()
        endif()

        enable_language(ASM_NASM)

        if(PREFIX STREQUAL "vmm")
            set(CMAKE_ASM_NASM_FLAGS "-d ${PREFIX} -d ${OSTYPE} -d SYSV")
        else()
            set(CMAKE_ASM_NASM_FLAGS "-d ${PREFIX} -d ${OSTYPE} -d ${ABITYPE}")
        endif()

        set(CMAKE_ASM_NASM_CREATE_STATIC_LIBRARY TRUE)
    endif()
    if(${BUILD_TARGET_ARCH} STREQUAL "aarch64")
        message(WARNING "unimplemented")
    endif()
endmacro(enable_asm)

# Init Project
#
# Initializes a subproject or extension.
#
# @param TARGET the name of the project target to create
# @param INTERFACE make TARGET an interface library
#
macro(init_project TARGET)
    set(options INTERFACE)
    cmake_parse_arguments(ARG "${options}" "${oneVal}" "" ${ARGN})

    if(CMAKE_INSTALL_PREFIX STREQUAL "${VMM_PREFIX_PATH}")
        set(PREFIX "vmm")
    elseif(CMAKE_INSTALL_PREFIX STREQUAL "${USERSPACE_PREFIX_PATH}")
        set(PREFIX "userspace")
    elseif(CMAKE_INSTALL_PREFIX STREQUAL "${TEST_PREFIX_PATH}")
        set(PREFIX "test")
    elseif(CMAKE_INSTALL_PREFIX STREQUAL "${EFI_PREFIX_PATH}")
        set(PREFIX "efi")
    else()
        message(FATAL_ERROR "Invalid prefix: ${CMAKE_INSTALL_PREFIX}")
    endif()
    message(STATUS "Project: ${TARGET} @ prefix: ${CMAKE_INSTALL_PREFIX}")

    set(CMAKE_C_EXTENSIONS OFF)
    set(CMAKE_CXX_EXTENSIONS OFF)
    enable_asm(${PREFIX})

    if(${ARG_INTERFACE})
        add_library(${TARGET} INTERFACE)
    else()
        add_library(${TARGET})
        set_target_properties(${TARGET} PROPERTIES LINKER_LANGUAGE C)
    endif()

    if(PREFIX STREQUAL "vmm")
        set(CMAKE_SKIP_RPATH TRUE)
    endif()

    if(PREFIX STREQUAL "test")
        set(ENABLE_MOCKING ON)
        set(CMAKE_BUILD_TYPE "Debug")
    endif()

    get_cmake_property(_vars CACHE_VARIABLES)
    foreach (_var ${_vars})
        set(${_var} ${${_var}})
    endforeach()
endmacro(init_project)

# Fini Project
#
# @param TARGET the name of the target associated with this project
#
macro(fini_project)
    set(PROJ ${CMAKE_PROJECT_NAME})
    install(TARGETS ${PROJ} DESTINATION lib EXPORT ${PROJ}-targets)
    install(EXPORT ${PROJ}-targets DESTINATION ${EXPORT_DIR})
    configure_file(
        ${SOURCE_CMAKE_DIR}/target-config.cmake.in
        ${EXPORT_DIR}/${PROJ}-config.cmake
        @ONLY
    )
endmacro(fini_project)

# ------------------------------------------------------------------------------
# validate_build / invalid_config
# ------------------------------------------------------------------------------

# Private
#
function(validate_build)
    if(BUILD_VALIDATOR_ERROR)
        message(FATAL_ERROR "Build validation failed")
    endif()
endfunction(validate_build)

# Invalidate Config
#
# Use this function to invalidate the configuration of the build. Unlike
# message(FATAL_ERROR), this function will queue up errors, and exit when
# the build is validated ensuring all errors are reported at once.
#
# @param MSG the message to report on error
#
macro(invalid_config MSG)
    message(SEND_ERROR "${MSG}")
    set(BUILD_VALIDATOR_ERROR ON)
endmacro(invalid_config)

# Add Static Library
#
# Creates a static library, sets the appropriate defintions and dependencies
# and installs the library into the prefix
#
# @param NAME The name of the library. "_static" is added for you
# @param ALWAYS Always compile this library regardless of BUILD_STATIC_LIBS
# @param SOURCES The source files for the library
# @param DEFINES The definitions to add to the library
#
function(add_static_library NAME)
    set(options ALWAYS)
    set(multiVal SOURCES DEFINES)
    cmake_parse_arguments(ARG "${options}" "" "${multiVal}" ${ARGN})

    if(NOT ARG_SOURCES)
        return()
    endif()

    if(NOT ARG_SOURCES)
        message(FATAL_ERROR "SOURCES must be defined when creating a library")
    endif()

    add_library(${NAME} STATIC ${ARG_SOURCES})
    set_target_properties(${NAME} PROPERTIES LINKER_LANGUAGE C)
    target_compile_definitions(${NAME} PRIVATE ${ARG_DEFINES})
    install(TARGETS ${NAME} DESTINATION lib)
endfunction(add_static_library)

# ------------------------------------------------------------------------------
# target_link_xxx_libraries
# ------------------------------------------------------------------------------

# Target Link Static Libraries
#
# This function is similar to target_link_libraries, but adds _static
# to the library name before adding the library to the target
#
# @param NAME The name of the target.
#
function(target_link_static_libraries NAME)
    foreach(l ${ARGN})
        target_link_libraries(${NAME} ${l})
    endforeach(l)
endfunction(target_link_static_libraries)

# ------------------------------------------------------------------------------
# add_vmm
# ------------------------------------------------------------------------------

# Add VMM Executable
#
# Creates a VMM executable. Specifically, this takes a set of sources,
# compiles them, and then links the result to the provided libraries and
# installs the result into the VMM prefix.
#
# @param NOVMMLIBS Do not include the bfvmm libraries.
# @param LIBRARIES Additional libraries to link the new executable against.
# @param SOURCES Sources to compile for the executable. If this is left blank,
#     a null.cpp file will be compiled for you.
# @param DEFINES Additional definitions to add to the executable
#
function(add_vmm_executable NAME)
    set(options NOVMMLIBS)
    set(multiVal LIBRARIES EXT_LIBRARIES SOURCES DEFINES)
    cmake_parse_arguments(ARG "${options}" "" "${multiVal}" ${ARGN})

    if(NOT ARG_SOURCES)
        if(NOT EXISTS ${CMAKE_BINARY_DIR}/null.cpp)
            file(WRITE
                ${CMAKE_BINARY_DIR}/null.cpp ""
            )
        endif()
        set(ARG_SOURCES ${CMAKE_BINARY_DIR}/null.cpp)
    endif()

    add_executable(${NAME} ${ARG_SOURCES})
    target_compile_definitions(${NAME} PRIVATE ${ARG_DEFINES})

    set(LIBRARIES "")
    foreach(d ${ARG_LIBRARIES})
        list(APPEND LIBRARIES "${CMAKE_INSTALL_PREFIX}/lib/lib${d}.a")
    endforeach(d)

    foreach(d ${ARG_EXT_LIBRARIES})
        list(APPEND LIBRARIES "${CMAKE_INSTALL_PREFIX}/lib/lib${d}.a")
    endforeach(d)

    if(NOT ARG_NOVMMLIBS)
        list(APPEND LIBRARIES
            --whole-archive ${CMAKE_INSTALL_PREFIX}/lib/libbfvmm_entry.a --no-whole-archive
            ${CMAKE_INSTALL_PREFIX}/lib/libbfvmm_vcpu.a
            ${CMAKE_INSTALL_PREFIX}/lib/libbfvmm_hve.a
            ${CMAKE_INSTALL_PREFIX}/lib/libbfvmm_memory_manager.a
            ${CMAKE_INSTALL_PREFIX}/lib/libbfvmm_debug.a
            ${CMAKE_INSTALL_PREFIX}/lib/libbfintrinsics.a
        )
    endif()

    list(APPEND LIBRARIES
        ${CMAKE_INSTALL_PREFIX}/lib/libc++.a
        ${CMAKE_INSTALL_PREFIX}/lib/libc++abi.a
        ${CMAKE_INSTALL_PREFIX}/lib/libbfpthread.a
        ${CMAKE_INSTALL_PREFIX}/lib/libbfunwind.a
        ${CMAKE_INSTALL_PREFIX}/lib/libc.a
        ${CMAKE_INSTALL_PREFIX}/lib/libm.a
        ${CMAKE_INSTALL_PREFIX}/lib/libbfsyscall.a
        --whole-archive ${CMAKE_INSTALL_PREFIX}/lib/libbfcrt.a --no-whole-archive
    )

    target_link_libraries(${NAME} ${LIBRARIES})
    install(TARGETS ${NAME} DESTINATION bin)

endfunction(add_vmm_executable)

# ------------------------------------------------------------------------------
# do_test
# ------------------------------------------------------------------------------

# Do Test
#
# Adds a unit test.
#
# @param FILENAME the file name of the test. Must start with "test_"
# @param DEFINES Additional definitions for the test
# @param DEPENDS Additional dependencies for the test. "_static" is added
#     for you
# @param SOURCES The source files to use for the test. If this is not defined,
#     the file used is ${FILENAME}.cpp. This is only needed if the test file
#     is not in the same directory, allowing you to pass a source file with
#     a directory. Nomrally FILENAME should still match the filename being
#     used.
#
function(do_test FILENAME)
    set(multiVal DEFINES DEPENDS SOURCES CMD_LINE_ARGS)
    cmake_parse_arguments(ARG "" "" "${multiVal}" ${ARGN})

    if(NOT ARG_SOURCES)
        set(ARG_SOURCES "${FILENAME}.cpp")
    endif()

    string(REPLACE "test_" "" NAME "${FILENAME}")

    add_executable(test_${NAME} ${ARG_SOURCES})
    target_link_libraries(test_${NAME} ${ARG_DEPENDS} test_catch)
    target_compile_definitions(test_${NAME} PRIVATE ${ARG_DEFINES})
    add_test(test_${NAME} test_${NAME} ${ARG_CMD_LINE_ARGS})
    if(CYGWIN OR WIN32)
        target_link_libraries(test_${NAME} setupapi)
    endif()
endfunction(do_test)

# ------------------------------------------------------------------------------
# print_xxx
# ------------------------------------------------------------------------------

# Private
#
function(print_banner)
    message(STATUS "${BoldMagenta}  ___                __ _           _   ${ColorReset}")
    message(STATUS "${BoldMagenta} | _ ) __ _ _ _ ___ / _| |__ _ _ _ | |__${ColorReset}")
    message(STATUS "${BoldMagenta} | _ \\/ _` | '_/ -_)  _| / _` | ' \\| / /${ColorReset}")
    message(STATUS "${BoldMagenta} |___/\\__,_|_| \\___|_| |_\\__,_|_||_|_\\_\\${ColorReset}")
    message(STATUS "")
    message(STATUS "${Green} Please give us a star on: ${White}https://github.com/Bareflank/hypervisor${ColorReset}")
    message(STATUS "")
endfunction(print_banner)

# Private
#
function(print_usage)
    message(STATUS "${Green} Bareflank is ready to build, usage:${ColorReset}")
    message(STATUS "${Yellow}    ${BUILD_COMMAND}${ColorReset}")
    message(STATUS "")

    if(NOT WIN32)
        message(STATUS "${Green} For more build options:${ColorReset}")
        message(STATUS "${Yellow}    ${BUILD_COMMAND} info${ColorReset}")
        message(STATUS "")
    else()
        message(STATUS "${Green} Additional build options:${ColorReset}")
        message(STATUS "${Yellow}    cmake --build . --target unittest${ColorReset}")
        message(STATUS "${Yellow}    cmake --build . --target clean-all${ColorReset}")
        message(STATUS "")
    endif()
endfunction(print_usage)

# ------------------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------------------

function(git_dir_script)
    if(NOT UNIX)
        return()
    endif()
    if(NOT EXISTS "${BUILD_ROOT_DIR}/setup_git_dir.sh")
        file(APPEND "${BUILD_ROOT_DIR}/setup_git_dir.sh" "export GIT_WORK_TREE=${SOURCE_ROOT_DIR}\n")
        file(APPEND "${BUILD_ROOT_DIR}/setup_git_dir.sh" "export GIT_DIR=${SOURCE_ROOT_DIR}/.git\n")
        execute_process(COMMAND chmod +x ${BUILD_ROOT_DIR}/setup_git_dir.sh)
    endif()
endfunction()
