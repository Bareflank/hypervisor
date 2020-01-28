# Add Sub Project
#
# Adds a sub-project to the build
#
# @param SOURCE_DIR path to the sub-project's top-level source directory,
#       conaining a CMakeLists.txt file
# @param BINARY_DIR path to the sub-project's top-level binary directory
# @param TOOLCHAIN path to a cmake toolchain file
# @param DEPENDS list of CMake targets this subproject depends on
#
function(add_subproject NAME)
    set(oneVal SOURCE_DIR BINARY_DIR TOOLCHAIN INSTALL_PREFIX)
    set(multiVal DEPENDS)
    cmake_parse_arguments(ARG "" "${oneVal}" "${multiVal}" ${ARGN})

    if(ARG_SOURCE_DIR)
        set(SOURCE_DIR ${ARG_SOURCE_DIR})
    else()
        message(FATAL_ERROR "add_subproject: SOURCE_DIR not provided")
    endif()

    if(ARG_BINARY_DIR)
        set(BINARY_DIR ${ARG_BINARY_DIR})
    else()
        set(BINARY_DIR ${CMAKE_BINARY_DIR})
    endif()

    if(NOT ARG_INSTALL_PREFIX)
        set(ARG_INSTALL_PREFIX ${BINARY_DIR})
    endif()

    get_cmake_property(_vars CACHE_VARIABLES)
    foreach (_var ${_vars})
        STRING(REGEX MATCH "^CMAKE" is_cmake_var ${_var})
        if(NOT is_cmake_var)
            list(APPEND CMAKE_ARGS -D${_var}=${${_var}})
        endif()
    endforeach()

    list(APPEND CMAKE_ARGS
        -DCMAKE_INSTALL_PREFIX=${ARG_INSTALL_PREFIX}
        -DCMAKE_INSTALL_MESSAGE=LAZY
        -DCMAKE_TARGET_MESSAGES=OFF
        -DCMAKE_VERBOSE_MAKEFILE=${CMAKE_VERBOSE_MAKEFILE}
        -DCMAKE_C_FLAGS=${CMAKE_C_FLAGS}
        -DCMAKE_CXX_FLAGS=${CMAKE_CXX_FLAGS}
        -DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}
    )

    if(ARG_TOOLCHAIN)
        list(APPEND CMAKE_ARGS -DCMAKE_TOOLCHAIN_FILE=${ARG_TOOLCHAIN})
    endif()

    ExternalProject_Add(
        ${NAME}
        PREFIX          ${BINARY_DIR}/${NAME}/
        STAMP_DIR       ${BINARY_DIR}/${NAME}/stamp
        TMP_DIR         ${BINARY_DIR}/${NAME}/tmp
        BINARY_DIR      ${BINARY_DIR}/${NAME}/build
        SOURCE_DIR      ${SOURCE_DIR}
        CMAKE_ARGS      ${CMAKE_ARGS}
        DEPENDS         ${ARG_DEPENDS}
        UPDATE_COMMAND  ${CMAKE_COMMAND} -E echo "-- checking for updates"
    )

endfunction(add_subproject)
