# Ninja is the hypervisor's only supported CMake generator on Windows
# Override the user's command line settings if any other generator is specified
if(${CMAKE_HOST_SYSTEM_NAME} STREQUAL Windows)
    message(STATUS "Using CMake Generator: Ninja")
    set(CMAKE_GENERATOR "Ninja" CACHE INTERNAL "")
endif()

# The following setting fixes a cmake linker quirk when building on MacOS
if(${CMAKE_HOST_SYSTEM_NAME} STREQUAL Darwin)
    set(HAVE_FLAG_SEARCH_PATHS_FIRST 0 CACHE INTERNAL "")
endif()

# Default to the project's built in clang toolchain if not specified
if(NOT CMAKE_TOOLCHAIN_FILE)

    # Default the C compiler to Clang if not specified
    if(NOT CMAKE_C_COMPILER)

        if(CMAKE_HOST_SYSTEM_NAME STREQUAL Darwin)
            set(CMAKE_C_COMPILER llvm-clang)
        else()
            set(CMAKE_C_COMPILER clang)
        endif()

    endif()

    find_program(CLANG_BIN ${CMAKE_C_COMPILER})

    if(CLANG_BIN)
        set(CMAKE_C_COMPILER ${CLANG_BIN} CACHE INTERNAL "")
        set(CMAKE_ASM-ATT_COMPILER ${CLANG_BIN} CACHE INTERNAL "")
    else()
        message(FATAL_ERROR "Unable to find C compiler: ${CMAKE_C_COMPILER}")
    endif()

    # Default the C++ compiler and linker to Clang++ if not specified
    if(NOT CMAKE_CXX_COMPILER)

        if(CMAKE_HOST_SYSTEM_NAME STREQUAL Darwin)
            set(CMAKE_CXX_COMPILER llvm-clang++)
        else()
            set(CMAKE_CXX_COMPILER clang++)
        endif()

    endif()

    find_program(CLANG++_BIN ${CMAKE_CXX_COMPILER})

    if(CLANG++_BIN)
        set(CMAKE_CXX_COMPILER ${CLANG++_BIN} CACHE INTERNAL "")
    else()
        message(FATAL_ERROR "Unable to find C++ compiler: ${CMAKE_CXX_COMPILER}")
    endif()

    set(CMAKE_TOOLCHAIN_FILE ${CMAKE_CURRENT_LIST_DIR}/cmake/toolchain/clang.cmake CACHE INTERNAL "")

endif()
