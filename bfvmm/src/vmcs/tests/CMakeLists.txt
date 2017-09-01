# ------------------------------------------------------------------------------
# CMake Includes
# ------------------------------------------------------------------------------

include(${CMAKE_INSTALL_PREFIX}/cmake/CMakeGlobal_Includes.txt)

# ------------------------------------------------------------------------------
# Targets
# ------------------------------------------------------------------------------

macro(do_test str)
    add_executable(test_${str} test_${str}.cpp)
    target_compile_definitions(test_${str} PRIVATE STATIC_VMCS)
    target_include_directories(test_${str} PRIVATE ${CMAKE_SOURCE_DIR}/test/include)
    target_link_libraries(test_${str} bfvmm_vmcs)
    target_link_libraries(test_${str} bfvmm_memory_manager)
    target_link_libraries(test_${str} bfvmm_intrinsics)
    target_link_libraries(test_${str} test_catch)
    add_test(test_${str} test_${str})
endmacro(do_test)

do_test(vmcs_intel_x64)
do_test(vmcs_intel_x64_host_vm_state)
do_test(vmcs_intel_x64_launch_mock)
do_test(vmcs_intel_x64_promote_mock)
do_test(vmcs_intel_x64_resume_mock)
do_test(vmcs_intel_x64_state)
do_test(vmcs_intel_x64_vmm_state)
