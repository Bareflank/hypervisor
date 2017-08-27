cmake_minimum_required(VERSION 3.6)
project(bfm C CXX)

include(${CMAKE_INSTALL_PREFIX}/cmake/CMakeGlobal_Project.txt)

# ------------------------------------------------------------------------------
# Subdirectories
# ------------------------------------------------------------------------------

add_subdirectory(ioctl)
add_subdirectory(src)
add_subdirectory(main)

if(ENABLE_UNITTESTING)
    add_subdirectory(tests)
endif()
