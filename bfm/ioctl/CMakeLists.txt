# ------------------------------------------------------------------------------
# CMake Includes
# ------------------------------------------------------------------------------

include(${CMAKE_INSTALL_PREFIX}/cmake/CMakeGlobal_Includes.txt)

# ------------------------------------------------------------------------------
# Targets
# ------------------------------------------------------------------------------

if(NOT WIN32 STREQUAL "1")
    list(APPEND SOURCES
        arch/linux/ioctl.cpp
        arch/linux/ioctl_private.cpp
    )
    include_directories(arch/linux/)
else()
    list(APPEND SOURCES
        arch/windows/ioctl.cpp
        arch/windows/ioctl_private.cpp
    )
    include_directories(arch/windows/)
endif()

add_library(bfm_ioctl STATIC ${SOURCES})
target_compile_definitions(bfm_ioctl PUBLIC STATIC_BFM_IOCTL)

# ------------------------------------------------------------------------------
# Install
# ------------------------------------------------------------------------------

install(TARGETS bfm_ioctl DESTINATION lib)
