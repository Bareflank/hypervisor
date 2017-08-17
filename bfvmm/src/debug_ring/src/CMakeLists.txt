# ------------------------------------------------------------------------------
# CMake Includes
# ------------------------------------------------------------------------------

include(${CMAKE_INSTALL_PREFIX}/cmake/CMakeGlobal_Includes.txt)

# ------------------------------------------------------------------------------
# Targets
# ------------------------------------------------------------------------------

list(APPEND SOURCES
    debug_ring.cpp
)

if(BUILD_SHARED_LIBS)
    add_library(bfvmm_debug_ring SHARED ${SOURCES})
    target_compile_definitions(bfvmm_debug_ring PRIVATE SHARED_DEBUG_RING)
endif()

if(BUILD_STATIC_LIBS)
    add_library(bfvmm_debug_ring STATIC ${SOURCES})
    target_compile_definitions(bfvmm_debug_ring PUBLIC STATIC_DEBUG_RING)
endif()

install(TARGETS bfvmm_debug_ring DESTINATION ${INSTALL_LIB_DIR})
