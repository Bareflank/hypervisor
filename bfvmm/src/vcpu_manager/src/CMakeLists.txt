# ------------------------------------------------------------------------------
# CMake Includes
# ------------------------------------------------------------------------------

include(${CMAKE_INSTALL_PREFIX}/cmake/CMakeGlobal_Includes.txt)

# ------------------------------------------------------------------------------
# Targets
# ------------------------------------------------------------------------------

list(APPEND SOURCES
    vcpu_manager.cpp
)

if(BUILD_SHARED_LIBS)
    add_library(bfvmm_vcpu_manager SHARED ${SOURCES})
    target_compile_definitions(bfvmm_vcpu_manager PRIVATE SHARED_VCPU)
    target_link_libraries(bfvmm_vcpu_manager bfvmm_vcpu)
    target_link_libraries(bfvmm_vcpu_manager bfvmm_vcpu_factory)
    target_link_libraries(bfvmm_vcpu_manager bfvmm_vmxon)
    target_link_libraries(bfvmm_vcpu_manager bfvmm_exit_handler)
    target_link_libraries(bfvmm_vcpu_manager bfvmm_vmcs)
    target_link_libraries(bfvmm_vcpu_manager bfvmm_memory_manager)
    target_link_libraries(bfvmm_vcpu_manager bfvmm_intrinsics)
endif()

if(BUILD_STATIC_LIBS)
    add_library(bfvmm_vcpu_manager STATIC ${SOURCES})
    target_compile_definitions(bfvmm_vcpu_manager PUBLIC STATIC_VCPU)
    target_compile_definitions(bfvmm_vcpu_manager PUBLIC STATIC_VMXON)
    target_compile_definitions(bfvmm_vcpu_manager PUBLIC STATIC_EXIT_HANDLER)
    target_compile_definitions(bfvmm_vcpu_manager PUBLIC STATIC_VMCS)
    target_compile_definitions(bfvmm_vcpu_manager PUBLIC STATIC_MEMORY_MANAGER)
    target_compile_definitions(bfvmm_vcpu_manager PUBLIC STATIC_INTRINSICS)
endif()

install(TARGETS bfvmm_vcpu_manager DESTINATION ${INSTALL_LIB_DIR})
