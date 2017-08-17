# ------------------------------------------------------------------------------
# CMake Includes
# ------------------------------------------------------------------------------

include(${CMAKE_INSTALL_PREFIX}/cmake/CMakeGlobal_Includes.txt)

# ------------------------------------------------------------------------------
# Targets
# ------------------------------------------------------------------------------

list(APPEND SOURCES
    serial_port_intel_x64.cpp
)

if(BUILD_SHARED_LIBS)
    add_library(bfvmm_serial SHARED ${SOURCES})
    target_compile_definitions(bfvmm_serial PRIVATE SHARED_SERIAL)
    target_link_libraries(bfvmm_serial bfvmm_intrinsics)
endif()

if(BUILD_STATIC_LIBS)
    add_library(bfvmm_serial STATIC ${SOURCES})
    target_compile_definitions(bfvmm_serial PUBLIC STATIC_SERIAL)
    target_compile_definitions(bfvmm_serial PUBLIC STATIC_INTRINSICS)
endif()

install(TARGETS bfvmm_serial DESTINATION ${INSTALL_LIB_DIR})
