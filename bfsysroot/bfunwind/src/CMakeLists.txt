# ------------------------------------------------------------------------------
# CMake Includes
# ------------------------------------------------------------------------------

include(${CMAKE_INSTALL_PREFIX}/cmake/CMakeGlobal_Includes.txt)

# ------------------------------------------------------------------------------
# Targets
# ------------------------------------------------------------------------------

list(APPEND SOURCES
    dwarf4.cpp
    eh_frame.cpp
    ia64_cxx_abi.cpp
    registers_intel_x64.asm
)

if(BUILD_SHARED_LIBS)
    add_library(bfunwind SHARED ${SOURCES})
    target_compile_definitions(bfunwind PRIVATE SHARED_SYSCALL)
endif()

if(BUILD_STATIC_LIBS)
    add_library(bfunwind STATIC ${SOURCES})
    target_compile_definitions(bfunwind PUBLIC STATIC_SYSCALL)
endif()

# ------------------------------------------------------------------------------
# Install
# ------------------------------------------------------------------------------

install(TARGETS bfunwind DESTINATION ${INSTALL_LIB_DIR})
