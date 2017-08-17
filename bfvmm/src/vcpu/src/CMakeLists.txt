# ------------------------------------------------------------------------------
# CMake Includes
# ------------------------------------------------------------------------------

include(${CMAKE_INSTALL_PREFIX}/cmake/CMakeGlobal_Includes.txt)

# ------------------------------------------------------------------------------
# Targets
# ------------------------------------------------------------------------------

list(APPEND SOURCES
    vcpu.cpp
    vcpu_intel_x64.cpp
)

if(BUILD_SHARED_LIBS)
    add_library(bfvmm_vcpu SHARED ${SOURCES})
    target_compile_definitions(bfvmm_vcpu PRIVATE SHARED_VCPU)
    target_link_libraries(bfvmm_vcpu bfvmm_vmxon)
    target_link_libraries(bfvmm_vcpu bfvmm_exit_handler)
    target_link_libraries(bfvmm_vcpu bfvmm_vmcs)
    target_link_libraries(bfvmm_vcpu bfvmm_memory_manager)
    target_link_libraries(bfvmm_vcpu bfvmm_intrinsics)
endif()

if(BUILD_STATIC_LIBS)
    add_library(bfvmm_vcpu STATIC ${SOURCES})
    target_compile_definitions(bfvmm_vcpu PUBLIC STATIC_VCPU)
    target_compile_definitions(bfvmm_vcpu PUBLIC STATIC_VMXON)
    target_compile_definitions(bfvmm_vcpu PUBLIC STATIC_EXIT_HANDLER)
    target_compile_definitions(bfvmm_vcpu PUBLIC STATIC_VMCS)
    target_compile_definitions(bfvmm_vcpu PUBLIC STATIC_MEMORY_MANAGER)
    target_compile_definitions(bfvmm_vcpu PUBLIC STATIC_INTRINSICS)
endif()

install(TARGETS bfvmm_vcpu DESTINATION ${INSTALL_LIB_DIR})
