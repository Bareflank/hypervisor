# ------------------------------------------------------------------------------
# CMake Includes
# ------------------------------------------------------------------------------

include(${CMAKE_INSTALL_PREFIX}/cmake/CMakeGlobal_Includes.txt)

# ------------------------------------------------------------------------------
# Targets
# ------------------------------------------------------------------------------

list(APPEND SOURCES
    vmxon_intel_x64.cpp
)

if(BUILD_SHARED_LIBS)
    add_library(bfvmm_vmxon SHARED ${SOURCES})
    target_compile_definitions(bfvmm_vmxon PRIVATE SHARED_VMXON)
    target_link_libraries(bfvmm_vmxon bfvmm_memory_manager)
    target_link_libraries(bfvmm_vmxon bfvmm_intrinsics)
endif()

if(BUILD_STATIC_LIBS)
    add_library(bfvmm_vmxon STATIC ${SOURCES})
    target_compile_definitions(bfvmm_vmxon PUBLIC STATIC_VMXON)
    target_compile_definitions(bfvmm_vmxon PUBLIC STATIC_MEMORY_MANAGER)
    target_compile_definitions(bfvmm_vmxon PUBLIC STATIC_INTRINSICS)
endif()

install(TARGETS bfvmm_vmxon DESTINATION ${INSTALL_LIB_DIR})
