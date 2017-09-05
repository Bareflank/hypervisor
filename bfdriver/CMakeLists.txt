cmake_minimum_required(VERSION 3.6)
project(bfdrivers C CXX)

include(${CMAKE_INSTALL_PREFIX}/cmake/CMakeGlobal_Project.txt)

# ------------------------------------------------------------------------------
# Subdirectories
# ------------------------------------------------------------------------------

if(NOT WIN32 AND ENABLE_UNITTESTING AND BUILD_SHARED_LIBS)
    add_subdirectory(src)
    add_subdirectory(tests)
endif()

# ------------------------------------------------------------------------------
# Custom Targets
# ------------------------------------------------------------------------------

add_custom_target(driver_build COMMAND ${CMAKE_SOURCE_DIR}/scripts/driver_build.sh ${CMAKE_SOURCE_DIR} ${CMAKE_INSTALL_PREFIX})
add_custom_target(driver_clean COMMAND ${CMAKE_SOURCE_DIR}/scripts/driver_clean.sh ${CMAKE_SOURCE_DIR})
add_custom_target(driver_load COMMAND ${CMAKE_SOURCE_DIR}/scripts/driver_load.sh ${CMAKE_SOURCE_DIR})
add_custom_target(driver_unload COMMAND ${CMAKE_SOURCE_DIR}/scripts/driver_unload.sh ${CMAKE_SOURCE_DIR})
