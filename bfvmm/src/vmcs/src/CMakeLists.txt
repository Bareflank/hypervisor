# ------------------------------------------------------------------------------
# CMake Includes
# ------------------------------------------------------------------------------

include(${CMAKE_INSTALL_PREFIX}/cmake/CMakeGlobal_Includes.txt)

# ------------------------------------------------------------------------------
# Targets
# ------------------------------------------------------------------------------

list(APPEND SOURCES
    vmcs_intel_x64.cpp
    vmcs_intel_x64_host_vm_state.cpp
    vmcs_intel_x64_vmm_state.cpp
)

if(CMAKE_TOOLCHAIN_FILE)
    list(APPEND SOURCES vmcs_intel_x64_launch.asm)
    list(APPEND SOURCES vmcs_intel_x64_promote.asm)
    list(APPEND SOURCES vmcs_intel_x64_resume.asm)
else()
    list(APPEND SOURCES vmcs_intel_x64_launch_mock.cpp)
    list(APPEND SOURCES vmcs_intel_x64_promote_mock.cpp)
    list(APPEND SOURCES vmcs_intel_x64_resume_mock.cpp)
endif()

if(BUILD_SHARED_LIBS)
    add_library(bfvmm_vmcs SHARED ${SOURCES})
    target_compile_definitions(bfvmm_vmcs PRIVATE SHARED_VMCS)
    target_link_libraries(bfvmm_vmcs bfvmm_memory_manager)
    target_link_libraries(bfvmm_vmcs bfvmm_intrinsics)
endif()

if(BUILD_STATIC_LIBS)
    add_library(bfvmm_vmcs STATIC ${SOURCES})
    target_compile_definitions(bfvmm_vmcs PUBLIC STATIC_VMCS)
    target_compile_definitions(bfvmm_vmcs PUBLIC STATIC_MEMORY_MANAGER)
    target_compile_definitions(bfvmm_vmcs PUBLIC STATIC_INTRINSICS)
endif()

install(TARGETS bfvmm_vmcs DESTINATION ${INSTALL_LIB_DIR})
