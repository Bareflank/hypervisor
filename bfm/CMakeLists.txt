# cmake ..

cmake_minimum_required(VERSION 3.6)
project(bfm C CXX)

if(CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT)
    if(NOT WIN32 STREQUAL "1")
        set(CMAKE_INSTALL_PREFIX $ENV{HOME}/bfprefix CACHE PATH "" FORCE)
    else()
        set(CMAKE_INSTALL_PREFIX $ENV{HOMEPATH}/bfprefix CACHE PATH "" FORCE)
    endif()
endif()

include(${CMAKE_INSTALL_PREFIX}/cmake/CMakeGlobal_Project.txt)

# ------------------------------------------------------------------------------
# Subdirectories
# ------------------------------------------------------------------------------

add_subdirectory(ioctl)
add_subdirectory(src)
add_subdirectory(main)

# if(ENABLE_UNITTESTING)
#     add_subdirectory(tests)
# endif()
