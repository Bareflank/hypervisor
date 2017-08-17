# ------------------------------------------------------------------------------
# CMake Includes
# ------------------------------------------------------------------------------

include(${CMAKE_INSTALL_PREFIX}/cmake/CMakeGlobal_Includes.txt)

# ------------------------------------------------------------------------------
# Targets
# ------------------------------------------------------------------------------

list(APPEND SOURCES
    unistd.cpp
)

if(BUILD_SHARED_LIBS)
    add_library(bfvmm_support SHARED ${SOURCES})
endif()

if(BUILD_STATIC_LIBS)
    add_library(bfvmm_support STATIC ${SOURCES})
endif()

install(TARGETS bfvmm_support DESTINATION ${INSTALL_LIB_DIR})
