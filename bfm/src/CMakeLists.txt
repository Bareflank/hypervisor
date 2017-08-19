# ------------------------------------------------------------------------------
# CMake Includes
# ------------------------------------------------------------------------------

include(${CMAKE_INSTALL_PREFIX}/cmake/CMakeGlobal_Includes.txt)

# ------------------------------------------------------------------------------
# Targets
# ------------------------------------------------------------------------------

list(APPEND SOURCES
    command_line_parser.cpp
    ioctl_driver.cpp
    ${CMAKE_INSTALL_PREFIX}/src/bfvmcall_intel_x64.asm
)

add_library(bfm_src OBJECT ${SOURCES})
target_compile_definitions(bfm_src PUBLIC STATIC_BFM_SRC)
