# cmake ..

cmake_minimum_required(VERSION 3.6)
project(bfdrivers C CXX)

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

# if(ENABLE_UNITTESTING)
#     add_subdirectory(tests)
# endif()

# ------------------------------------------------------------------------------
# Custom Targets
# ------------------------------------------------------------------------------

add_custom_target(driver_build COMMAND ${CMAKE_SOURCE_DIR}/scripts/driver_build.sh ${CMAKE_SOURCE_DIR} ${CMAKE_INSTALL_PREFIX})
add_custom_target(driver_clean COMMAND ${CMAKE_SOURCE_DIR}/scripts/driver_clean.sh ${CMAKE_SOURCE_DIR})
add_custom_target(driver_load COMMAND ${CMAKE_SOURCE_DIR}/scripts/driver_load.sh ${CMAKE_SOURCE_DIR})
add_custom_target(driver_unload COMMAND ${CMAKE_SOURCE_DIR}/scripts/driver_unload.sh ${CMAKE_SOURCE_DIR})
