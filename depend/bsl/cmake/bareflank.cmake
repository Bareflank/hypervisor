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

# This file contains a set of macros that all Bareflank projects need to
# function "internally". These are not intended to be exposed to the user.

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# ------------------------------------------------------------------------------
# Color
# ------------------------------------------------------------------------------

string(ASCII 27 Esc)
set(BF_COLOR_RST "${Esc}[m")
set(BF_COLOR_RED "${Esc}[91m")
set(BF_COLOR_GRN "${Esc}[92m")
set(BF_COLOR_YLW "${Esc}[93m")
set(BF_COLOR_BLU "${Esc}[94m")
set(BF_COLOR_MAG "${Esc}[95m")
set(BF_COLOR_CYN "${Esc}[96m")
set(BF_COLOR_WHT "${Esc}[97m")

set(BF_ENABLED "${BF_COLOR_GRN}enabled${BF_COLOR_RST}")
set(BF_DISABLED "${BF_COLOR_YLW}disabled${BF_COLOR_RST}")

# ------------------------------------------------------------------------------
# supported generator/compiler
# ------------------------------------------------------------------------------

if(NOT CMAKE_GENERATOR MATCHES "Ninja")
    bf_configuration_error("ninja is required: cmake -G Ninja -DCMAKE_CXX_COMPILER=\"clang++\"")
endif()

if(NOT CMAKE_CXX_COMPILER MATCHES "clang")
    bf_configuration_error("clang is required: cmake -G Ninja -DCMAKE_CXX_COMPILER=\"clang++\"")
endif()

# ------------------------------------------------------------------------------
# default build type
# ------------------------------------------------------------------------------

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE DEBUG)
endif()

if(CMAKE_BUILD_TYPE STREQUAL Release)
    set(CMAKE_BUILD_TYPE RELEASE)
endif()

if(CMAKE_BUILD_TYPE STREQUAL Debug)
    set(CMAKE_BUILD_TYPE DEBUG)
endif()

# TODO
#
# Add MinRelSize which will need:
# - Add -O for size (think it is -Os)
# - Remove all debug symbols
# - Add the compiler and linker flags for -fsections on UNIX

# ------------------------------------------------------------------------------
# bf_error
# ------------------------------------------------------------------------------

# Error
#
# Prints an error message, and then errors out to stop processing.
#
# MSG: The message to show when erroring out
#
macro(bf_error MSG)
    message(FATAL_ERROR "${BF_COLOR_RED}${MSG}${BF_COLOR_RST}")
endmacro(bf_error)

# ------------------------------------------------------------------------------
# bf_configuration_error
# ------------------------------------------------------------------------------

# Configuration Error
#
# Prints an error message, shows the configuration options, and then errors
# out to stop processing.
#
# MSG: The message to show when erroring out
#
macro(bf_configuration_error MSG)
    bf_error(${MSG})
endmacro(bf_configuration_error)

# ------------------------------------------------------------------------------
# bf_find_program
# ------------------------------------------------------------------------------

# Find Program
#
# The only difference between this function and find_program() is that is
# makes sure that the program is found. If it is not, it will error out.
#
macro(bf_find_program VAR NAME URL)
    find_program(${VAR} ${NAME})
    if(NOT ${VAR})
        bf_error("Unable to locate: ${NAME} - ${URL}")
    endif()
endmacro(bf_find_program)

# ------------------------------------------------------------------------------
# Info
# ------------------------------------------------------------------------------

add_custom_target(
    info
)

add_custom_command(TARGET info
    COMMAND ${CMAKE_COMMAND} -E cmake_echo_color --magenta "  ___   _   ___ ___ ___ _      _   _  _ _  __ "
    COMMAND ${CMAKE_COMMAND} -E cmake_echo_color --magenta " | _ ) /_\\ | _ \\ __| __| |    /_\\ | \\| | |/ / "
    COMMAND ${CMAKE_COMMAND} -E cmake_echo_color --magenta " | _ \\/ _ \\|   / _|| _|| |__ / _ \\| .` | ' <  "
    COMMAND ${CMAKE_COMMAND} -E cmake_echo_color --magenta " |___/_/ \\_\\_|_\\___|_| |____/_/ \\_\\_|\\_|_|\\_\\ "
    COMMAND ${CMAKE_COMMAND} -E cmake_echo_color " "
    COMMAND ${CMAKE_COMMAND} -E cmake_echo_color --green   " Please give us a star on: ${BF_COLOR_WHT}https://github.com/Bareflank "
    COMMAND ${CMAKE_COMMAND} -E cmake_echo_color --blue    " ------------------------------------------------------ "
    COMMAND ${CMAKE_COMMAND} -E cmake_echo_color " "
    VERBATIM
)

# ------------------------------------------------------------------------------
# supported build types
# ------------------------------------------------------------------------------

if(NOT CMAKE_BUILD_TYPE STREQUAL RELEASE AND
   NOT CMAKE_BUILD_TYPE STREQUAL DEBUG AND
   NOT CMAKE_BUILD_TYPE STREQUAL CLANG_TIDY AND
   NOT CMAKE_BUILD_TYPE STREQUAL PERFORCE AND
   NOT CMAKE_BUILD_TYPE STREQUAL ASAN AND
   NOT CMAKE_BUILD_TYPE STREQUAL UBSAN AND
   NOT CMAKE_BUILD_TYPE STREQUAL COVERAGE)
    bf_error("Unknown CMAKE_BUILD_TYPE: ${CMAKE_BUILD_TYPE}")
endif()

add_custom_command(TARGET info
    COMMAND ${CMAKE_COMMAND} -E cmake_echo_color --green   " Supported CMake Build Types:"
    COMMAND ${CMAKE_COMMAND} -E cmake_echo_color --yellow  "   -DCMAKE_BUILD_TYPE=RELEASE            compile in release mode"
    COMMAND ${CMAKE_COMMAND} -E cmake_echo_color --yellow  "   -DCMAKE_BUILD_TYPE=DEBUG              compile in debug mode"
    COMMAND ${CMAKE_COMMAND} -E cmake_echo_color --yellow  "   -DCMAKE_BUILD_TYPE=CLANG_TIDY         compile with Clang Tidy checks"
    COMMAND ${CMAKE_COMMAND} -E cmake_echo_color --yellow  "   -DCMAKE_BUILD_TYPE=PERFORCE           compile with Perforce checks"
    COMMAND ${CMAKE_COMMAND} -E cmake_echo_color --yellow  "   -DCMAKE_BUILD_TYPE=ASAN               compile with Google ASAN"
    COMMAND ${CMAKE_COMMAND} -E cmake_echo_color --yellow  "   -DCMAKE_BUILD_TYPE=UBSAN              compile with Google UBSAN"
    COMMAND ${CMAKE_COMMAND} -E cmake_echo_color --yellow  "   -DCMAKE_BUILD_TYPE=COVERAGE           compile with LLVM coverage"
    COMMAND ${CMAKE_COMMAND} -E cmake_echo_color " "
    VERBATIM
)

message(STATUS "Build type: ${BF_COLOR_CYN}${CMAKE_BUILD_TYPE}${BF_COLOR_RST}")

# ------------------------------------------------------------------------------
# default build commands
# ------------------------------------------------------------------------------

add_custom_command(TARGET info
    COMMAND ${CMAKE_COMMAND} -E cmake_echo_color --green   " Basic Commands:"
    COMMAND ${CMAKE_COMMAND} -E cmake_echo_color --yellow  "   ninja info                            shows this help info"
    COMMAND ${CMAKE_COMMAND} -E cmake_echo_color --yellow  "   ninja                                 builds the project"
    COMMAND ${CMAKE_COMMAND} -E cmake_echo_color --yellow  "   ninja clean                           cleans the project"
    COMMAND ${CMAKE_COMMAND} -E cmake_echo_color --yellow  "   ninja install                         installs the project on your system"
    COMMAND ${CMAKE_COMMAND} -E cmake_echo_color " "
    COMMAND ${CMAKE_COMMAND} -E cmake_echo_color --green   " Supported Build Targets:"
    VERBATIM
)

# ------------------------------------------------------------------------------
# examples
# ------------------------------------------------------------------------------

if(CMAKE_BUILD_TYPE STREQUAL DEBUG OR
   CMAKE_BUILD_TYPE STREQUAL CLANG_TIDY OR
   CMAKE_BUILD_TYPE STREQUAL PERFORCE OR
   CMAKE_BUILD_TYPE STREQUAL ASAN OR
   CMAKE_BUILD_TYPE STREQUAL UBSAN)
    if(NOT DEFINED BUILD_EXAMPLES)
        set(BUILD_EXAMPLES ON)
    endif()
endif()

if(BUILD_EXAMPLES)
    message(STATUS "Build examples: ${BF_ENABLED}")
else()
    message(STATUS "Build examples: ${BF_DISABLED}")
endif()

# ------------------------------------------------------------------------------
# tests
# ------------------------------------------------------------------------------

if(CMAKE_BUILD_TYPE STREQUAL DEBUG OR
   CMAKE_BUILD_TYPE STREQUAL CLANG_TIDY OR
   CMAKE_BUILD_TYPE STREQUAL ASAN OR
   CMAKE_BUILD_TYPE STREQUAL UBSAN OR
   CMAKE_BUILD_TYPE STREQUAL COVERAGE)
    if(NOT DEFINED BUILD_TESTS)
        set(BUILD_TESTS ON)
    endif()
endif()

if(BUILD_TESTS)
    include(CTest)
    add_custom_target(
        unittest
        COMMAND ctest --output-on-failure
    )
    add_custom_command(TARGET info
        COMMAND ${CMAKE_COMMAND} -E cmake_echo_color --yellow  "   ninja unittest                        run the project's unit tests"
        VERBATIM
    )
    message(STATUS "Build tests: ${BF_ENABLED}")
else()
    message(STATUS "Build tests: ${BF_DISABLED}")
endif()

# ------------------------------------------------------------------------------
# clang tidy
# ------------------------------------------------------------------------------

if(CMAKE_BUILD_TYPE STREQUAL CLANG_TIDY)
    bf_find_program(CMAKE_CXX_CLANG_TIDY "clang-tidy" "https://clang.llvm.org/extra/clang-tidy/")
    message(STATUS "Tool [Clang Tidy]: ${BF_ENABLED} - ${CMAKE_CXX_CLANG_TIDY}")
endif()

# ------------------------------------------------------------------------------
# clang format
# ------------------------------------------------------------------------------

FILE(GLOB_RECURSE BF_HEADERS_EXAMPLES RELATIVE ${CMAKE_BINARY_DIR} ${CMAKE_SOURCE_DIR}/examples/*.hpp)
FILE(GLOB_RECURSE BF_SOURCES_EXAMPLES RELATIVE ${CMAKE_BINARY_DIR} ${CMAKE_SOURCE_DIR}/examples/*.cpp)
FILE(GLOB_RECURSE BF_HEADERS_INCLUDE RELATIVE ${CMAKE_BINARY_DIR} ${CMAKE_SOURCE_DIR}/include/*.hpp)
FILE(GLOB_RECURSE BF_SOURCES_INCLUDE RELATIVE ${CMAKE_BINARY_DIR} ${CMAKE_SOURCE_DIR}/include/*.cpp)
FILE(GLOB_RECURSE BF_HEADERS_TESTS RELATIVE ${CMAKE_BINARY_DIR} ${CMAKE_SOURCE_DIR}/tests/*.hpp)
FILE(GLOB_RECURSE BF_SOURCES_TESTS RELATIVE ${CMAKE_BINARY_DIR} ${CMAKE_SOURCE_DIR}/tests/*.cpp)
FILE(GLOB_RECURSE BF_HEADERS_SRC RELATIVE ${CMAKE_BINARY_DIR} ${CMAKE_SOURCE_DIR}/src/*.hpp)
FILE(GLOB_RECURSE BF_SOURCES_SRC RELATIVE ${CMAKE_BINARY_DIR} ${CMAKE_SOURCE_DIR}/src/*.cpp)

if(CMAKE_BUILD_TYPE STREQUAL DEBUG OR
   CMAKE_BUILD_TYPE STREQUAL CLANG_TIDY OR
   CMAKE_BUILD_TYPE STREQUAL ASAN OR
   CMAKE_BUILD_TYPE STREQUAL UBSAN OR
   CMAKE_BUILD_TYPE STREQUAL COVERAGE)
    if(NOT DEFINED ENABLE_CLANG_FORMAT)
        set(ENABLE_CLANG_FORMAT ON)
    endif()
endif()

if(ENABLE_CLANG_FORMAT)
    bf_find_program(BF_CLANG_FORMAT "clang-format" "https://clang.llvm.org/docs/ClangFormat.html")
    add_custom_target(
        format
        COMMAND ${BF_CLANG_FORMAT} -i
        ${BF_HEADERS_EXAMPLES} ${BF_SOURCES_EXAMPLES}
        ${BF_HEADERS_INCLUDE} ${BF_SOURCES_INCLUDE}
        ${BF_HEADERS_TESTS} ${BF_SOURCES_TESTS}
        ${BF_HEADERS_SRC} ${BF_SOURCES_SRC}
    )
    add_custom_command(TARGET info
        COMMAND ${CMAKE_COMMAND} -E cmake_echo_color --yellow  "   ninja format                          formats the source code"
        VERBATIM
    )
    message(STATUS "Tool [Clang Format]: ${BF_ENABLED} - ${BF_CLANG_FORMAT}")
else()
    message(STATUS "Tool [Clang Format]: ${BF_DISABLED}")
endif()

# ------------------------------------------------------------------------------
# llvm-cov
# ------------------------------------------------------------------------------

if(NOT DEFINED BSL_CODECOV_TOKEN)
    set(BSL_CODECOV_TOKEN "3127698f-3d70-4a23-a00f-cd7e54768434")
endif()

if(CMAKE_BUILD_TYPE STREQUAL COVERAGE)
    bf_find_program(BF_GRCOV "grcov" "https://github.com/mozilla/grcov")
    message(STATUS "Tool [grcov]: ${BF_ENABLED} - ${BF_GRCOV}")
    add_custom_target(codecov-upload
        COMMAND ctest --output-on-failure
        COMMAND grcov ${CMAKE_BINARY_DIR} -s ${CMAKE_SOURCE_DIR} -t lcov --branch -o ${CMAKE_BINARY_DIR}/coverage.info
        COMMAND curl -s https://codecov.io/bash > ${CMAKE_BINARY_DIR}/codecov.sh
        COMMAND ${CMAKE_COMMAND} -E chdir ${CMAKE_SOURCE_DIR}
        bash ${CMAKE_BINARY_DIR}/codecov.sh -t ${BSL_CODECOV_TOKEN} -f ${CMAKE_BINARY_DIR}/coverage.info
    )
    add_custom_command(TARGET info
        COMMAND ${CMAKE_COMMAND} -E cmake_echo_color --yellow  "   ninja codecov-upload                  checks source against regex rules"
        VERBATIM
    )
else()
    message(STATUS "Tool [grcov]: ${BF_DISABLED}")
endif()

# ------------------------------------------------------------------------------
# doxygen
# ------------------------------------------------------------------------------

if(CMAKE_BUILD_TYPE STREQUAL DEBUG OR
   CMAKE_BUILD_TYPE STREQUAL CLANG_TIDY OR
   CMAKE_BUILD_TYPE STREQUAL ASAN OR
   CMAKE_BUILD_TYPE STREQUAL UBSAN OR
   CMAKE_BUILD_TYPE STREQUAL COVERAGE)
    if(NOT DEFINED ENABLE_DOXYGEN)
        set(ENABLE_DOXYGEN ON)
    endif()
endif()

if(ENABLE_DOXYGEN)
    bf_find_program(BF_DOXYGEN "doxygen" "http://doxygen.nl/")
    add_custom_target(doxygen
        COMMAND ${CMAKE_COMMAND} -E chdir ${CMAKE_SOURCE_DIR} doxygen .doxygen
        VERBATIM
    )
    add_custom_command(TARGET info
        COMMAND ${CMAKE_COMMAND} -E cmake_echo_color --yellow  "   ninja doxygen                         generates documentation"
        VERBATIM
    )
    message(STATUS "Tool [Doxygen]: ${BF_ENABLED} - ${BF_DOXYGEN}")
else()
    message(STATUS "Tool [Doxygen]: ${BF_DISABLED}")
endif()

# ------------------------------------------------------------------------------
# flexlint
# ------------------------------------------------------------------------------

if(CMAKE_BUILD_TYPE STREQUAL DEBUG OR
   CMAKE_BUILD_TYPE STREQUAL CLANG_TIDY OR
   CMAKE_BUILD_TYPE STREQUAL ASAN OR
   CMAKE_BUILD_TYPE STREQUAL UBSAN OR
   CMAKE_BUILD_TYPE STREQUAL COVERAGE)
    if(NOT DEFINED ENABLE_FLEXLINT)
        set(ENABLE_FLEXLINT ON)
    endif()
endif()

if(ENABLE_FLEXLINT)
    bf_find_program(BF_FLEXLINT "flexlint" "https://github.com/dalance/flexlint")
    add_custom_target(flexlint
        COMMAND ${CMAKE_COMMAND} -E chdir ${CMAKE_SOURCE_DIR} flexlint
        VERBATIM
    )
    add_custom_command(TARGET info
        COMMAND ${CMAKE_COMMAND} -E cmake_echo_color --yellow  "   ninja flexlint                        checks source against regex rules"
        VERBATIM
    )
    message(STATUS "Tool [Flexlint]: ${BF_ENABLED} - ${BF_FLEXLINT}")
else()
    message(STATUS "Tool [Flexlint]: ${BF_DISABLED}")
endif()

# ------------------------------------------------------------------------------
# asan
# ------------------------------------------------------------------------------

if(CMAKE_BUILD_TYPE STREQUAL ASAN)
    message(STATUS "Tool [Google's ASAN]: ${BF_ENABLED}")
else()
    message(STATUS "Tool [Google's ASAN]: ${BF_DISABLED}")
endif()

# ------------------------------------------------------------------------------
# ubsan
# ------------------------------------------------------------------------------

if(CMAKE_BUILD_TYPE STREQUAL UBSAN)
    message(STATUS "Tool [Google's UBSAN]: ${BF_ENABLED}")
else()
    message(STATUS "Tool [Google's UBSAN]: ${BF_DISABLED}")
endif()

# ------------------------------------------------------------------------------
# c++ flags
# ------------------------------------------------------------------------------

string(APPEND CMAKE_CXX_FLAGS
    "${CMAKE_CXX_FLAGS} "
    "-ffreestanding "
    "-fno-exceptions "
    "-fno-rtti "
    "-fcomment-block-commands=include "
    "-fcomment-block-commands=cond "
    "-fcomment-block-commands=endcond "
    "-Weverything "
    "-Wno-c++98-compat "
    "-Wno-c++98-compat-pedantic "
    "-Wno-padded "
    "-Wno-weak-vtables "
    "-Wno-ctad-maybe-unsupported "
)

set(CMAKE_CXX_FLAGS_RELEASE "-O3 -DNDEBUG -Werror")
set(CMAKE_LINKER_FLAGS_RELEASE "-O3 -DNDEBUG -Werror")
set(CMAKE_CXX_FLAGS_DEBUG "-Og -g")
set(CMAKE_LINKER_FLAGS_DEBUG "-Og -g")
set(CMAKE_CXX_FLAGS_CLANG_TIDY "-O0 -Werror")
set(CMAKE_LINKER_FLAGS_CLANG_TIDY "-O0 -Werror")
set(CMAKE_CXX_FLAGS_PERFORCE "-O0 -Werror")
set(CMAKE_LINKER_FLAGS_PERFORCE "-O0 -Werror")
set(CMAKE_CXX_FLAGS_ASAN "-Og -g -fno-omit-frame-pointer -fsanitize=address")
set(CMAKE_LINKER_FLAGS_ASAN "-Og -g -fno-omit-frame-pointer -fsanitize=address")
set(CMAKE_CXX_FLAGS_UBSAN "-Og -g -fsanitize=undefined")
set(CMAKE_LINKER_FLAGS_UBSAN "-Og -g -fsanitize=undefined")
set(CMAKE_CXX_FLAGS_COVERAGE "-O0 -fprofile-arcs -ftest-coverage")
set(CMAKE_LINKER_FLAGS_COVERAGE "-O0 -fprofile-arcs -ftest-coverage")

message(STATUS "CXX Flags:${CMAKE_CXX_FLAGS} ${CMAKE_CXX_FLAGS_${CMAKE_BUILD_TYPE}}")

# ------------------------------------------------------------------------------
# info done
# ------------------------------------------------------------------------------

add_custom_command(TARGET info
    COMMAND ${CMAKE_COMMAND} -E cmake_echo_color " "
    VERBATIM
)

# ------------------------------------------------------------------------------
# default definitions
# ------------------------------------------------------------------------------

if(NOT DEFINED BSL_DEBUG_LEVEL)
    set(BSL_DEBUG_LEVEL "debug_level_t::verbosity_level_0")
endif()

if(NOT DEFINED BSL_PAGE_SIZE)
    set(BSL_PAGE_SIZE "0x10'00U")
endif()

if(CMAKE_BUILD_TYPE STREQUAL PERFORCE)
    set(BSL_BUILTIN_FILE "\"file\"")
    set(BSL_BUILTIN_FUNCTION "\"function\"")
    set(BSL_BUILTIN_LINE "0")
else()
    set(BSL_BUILTIN_FILE "__builtin_FILE()")
    set(BSL_BUILTIN_FUNCTION "__builtin_FUNCTION()")
    set(BSL_BUILTIN_LINE "__builtin_LINE()")
endif()

list(APPEND BSL_DEFAULT_DEFINES
    BSL_DEBUG_LEVEL=${BSL_DEBUG_LEVEL}
    BSL_PAGE_SIZE=${BSL_PAGE_SIZE}
    BSL_BUILTIN_FILE=${BSL_BUILTIN_FILE}
    BSL_BUILTIN_FUNCTION=${BSL_BUILTIN_FUNCTION}
    BSL_BUILTIN_LINE=${BSL_BUILTIN_LINE}
)

# ------------------------------------------------------------------------------
# bf_generate_defines
# ------------------------------------------------------------------------------

# Generate Defines
#
# This function takes the default defines and merges it with any defines that
# that are provided for a target. This is capable of handling defines that
# include a value or simply are defined, as well as defines that are similar
# in name. If a target provides a define that is also in the defaults list,
# the target's define wins.
#
# NAME the name of of the target to set the merged defines.
# DEFINES the defines to provide the target that either override a default
#    or provide above and beyond the defaults.
#
function(bf_generate_defines NAME)
    set(multiValueArgs DEFINES)
    cmake_parse_arguments(ARGS "" "" "${multiValueArgs}" ${ARGN})

    foreach(d ${BSL_DEFAULT_DEFINES})
        string(REPLACE "=" ";" d "${d}")
        list(GET d 0 FIELD_NAME)
        list(APPEND BSL_DEFAULT_DEFINES_FIELDS ${FIELD_NAME})
    endforeach(d)

    foreach(d ${ARGS_DEFINES})
        string(REPLACE "=" ";" d "${d}")
        list(GET d 0 FIELD_NAME)
        list(APPEND ARGS_DEFINES_FIELDS ${FIELD_NAME})
    endforeach(d)

    list(APPEND ALL_FIELDS ${ARGS_DEFINES_FIELDS} ${BSL_DEFAULT_DEFINES_FIELDS})
    list(REMOVE_DUPLICATES ALL_FIELDS)

    foreach(f ${ALL_FIELDS})
        set(FOUND 0)

        foreach(d ${ARGS_DEFINES})
            set(fd "${d}=")
            string(REPLACE "=" ";" fd "${fd}")
            list(GET fd 0 fd)
            if(f STREQUAL fd)
                list(APPEND GENERATED_DEFINED ${d})
                set(FOUND 1)
                break()
            endif()
        endforeach(d)

        if(FOUND)
            continue()
        endif()

        foreach(d ${BSL_DEFAULT_DEFINES})
            set(fd "${d}=")
            string(REPLACE "=" ";" fd "${fd}")
            list(GET fd 0 fd)
            if(f STREQUAL fd)
                list(APPEND GENERATED_DEFINED ${d})
                set(FOUND 1)
                break()
            endif()
        endforeach(d)
    endforeach(f)
    target_compile_definitions(${NAME} PRIVATE ${GENERATED_DEFINED})
endfunction(bf_generate_defines)

# ------------------------------------------------------------------------------
# bf_add_example
# ------------------------------------------------------------------------------

# Add Test
#
# Adds a test case given a name. Note that this will disable C++ access
# controls, assisting in unit testing.
#
# NAME: The name of the test case to add
#
macro(bf_add_example NAME)
    set(multiValueArgs DEFINES)
    cmake_parse_arguments(ARGS "" "" "${multiValueArgs}" ${ARGN})

    file(RELATIVE_PATH REL_NAME ${CMAKE_SOURCE_DIR} ${CMAKE_CURRENT_LIST_DIR})
    file(TO_CMAKE_PATH "${REL_NAME}" REL_NAME)
    string(REPLACE "/" "_" REL_NAME ${REL_NAME})

    add_executable(${REL_NAME}_${NAME} ${NAME}.cpp)
    target_include_directories(${REL_NAME}_${NAME} PRIVATE ${CMAKE_SOURCE_DIR}/include)
    if(WIN32)
        target_link_libraries(${REL_NAME}_${NAME} libcmt.lib)
    endif()
    bf_generate_defines(${REL_NAME}_${NAME} ${ARGN})
endmacro(bf_add_example)

# ------------------------------------------------------------------------------
# bf_add_test
# ------------------------------------------------------------------------------

# Add Test
#
# Adds a test case given a name. Note that this will disable C++ access
# controls, assisting in unit testing.
#
# NAME: The name of the test case to add
#
macro(bf_add_test NAME)
    set(multiValueArgs DEFINES)
    cmake_parse_arguments(ARGS "" "" "${multiValueArgs}" ${ARGN})

    file(RELATIVE_PATH REL_NAME ${CMAKE_SOURCE_DIR} ${CMAKE_CURRENT_LIST_DIR})
    file(TO_CMAKE_PATH "${REL_NAME}" REL_NAME)
    string(REPLACE "/" "_" REL_NAME ${REL_NAME})

    add_executable(${REL_NAME}_${NAME} ${NAME}.cpp)
    target_include_directories(${REL_NAME}_${NAME} PRIVATE ${CMAKE_SOURCE_DIR}/include)
    if(WIN32)
        target_link_libraries(${REL_NAME}_${NAME} libcmt.lib)
    endif()
    target_compile_options(${REL_NAME}_${NAME} PRIVATE -fno-access-control)
    add_test(${REL_NAME}_${NAME} ${REL_NAME}_${NAME})
    bf_generate_defines(${REL_NAME}_${NAME} ${ARGN})
endmacro(bf_add_test)
