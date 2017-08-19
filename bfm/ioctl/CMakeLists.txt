# ------------------------------------------------------------------------------
# CMake Includes
# ------------------------------------------------------------------------------

include(${CMAKE_INSTALL_PREFIX}/cmake/CMakeGlobal_Includes.txt)

# ------------------------------------------------------------------------------
# Targets
# ------------------------------------------------------------------------------

if(NOT CYGWIN STREQUAL "1")
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

add_library(bfm_ioctl OBJECT ${SOURCES})
target_compile_definitions(bfm_ioctl PUBLIC STATIC_BFM_IOCTL)

add_library(bf_ioctl SHARED ${SOURCES})
target_compile_definitions(bf_ioctl PUBLIC SHARED_BFM_IOCTL)

if(CYGWIN STREQUAL "1")
    target_link_libraries(bf_ioctl setupapi)
endif()

# ------------------------------------------------------------------------------
# Install
# ------------------------------------------------------------------------------

install(TARGETS bf_ioctl DESTINATION lib)
