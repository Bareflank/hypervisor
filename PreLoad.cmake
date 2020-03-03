# Ninja is the only supported CMake generator on Windows
if(${CMAKE_HOST_SYSTEM_NAME} STREQUAL Windows)
    message(STATUS "Using CMake Generator: Ninja")
    set(CMAKE_GENERATOR "Ninja" CACHE INTERNAL "")
endif()

# The following setting fixes a cmake linker quirk when building on MacOS
if(${CMAKE_HOST_SYSTEM_NAME} STREQUAL Darwin)
    set(HAVE_FLAG_SEARCH_PATHS_FIRST 0 CACHE INTERNAL "")
endif()

# Default to the project's built in clang toolchain
if(NOT CMAKE_TOOLCHAIN_FILE)
    # Default the C compiler to Clang
    if(NOT CMAKE_C_COMPILER)

        if(CMAKE_HOST_SYSTEM_NAME STREQUAL Darwin)
            find_program(CLANG_BIN llvm-clang)
        else()
            find_program(CLANG_BIN clang)
        endif()

        if(CLANG_BIN)
            set(CMAKE_C_COMPILER ${CLANG_BIN} CACHE INTERNAL "")
            set(CMAKE_ASM-ATT_COMPILER ${CLANG_BIN} CACHE INTERNAL "")
        else()
            message(FATAL_ERROR "Unable to find default C compiler: clang")
        endif()

    endif()

    # Default the C++ compiler and linker to Clang++
    if(NOT CMAKE_CXX_COMPILER)

        if(CMAKE_HOST_SYSTEM_NAME STREQUAL Darwin)
            find_program(CLANG++_BIN llvm-clang++)
        else()
            find_program(CLANG++_BIN clang++)
        endif()

        if(CLANG++_BIN)
            set(CMAKE_CXX_COMPILER ${CLANG++_BIN} CACHE INTERNAL "")
        else()
            message(FATAL_ERROR "Unable to find default C++ compiler: clang++")
        endif()

    endif()

    set(CMAKE_TOOLCHAIN_FILE ${CMAKE_CURRENT_LIST_DIR}/cmake/toolchain/clang.cmake CACHE INTERNAL "")
endif()
