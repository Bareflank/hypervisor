# ------------------------------------------------------------------------------
# CMake Includes
# ------------------------------------------------------------------------------

include(${CMAKE_INSTALL_PREFIX}/cmake/CMakeGlobal_Includes.txt)

# ------------------------------------------------------------------------------
# Targets
# ------------------------------------------------------------------------------

macro(do_test str)
    add_executable(test_${str} test_${str}.cpp)
    target_compile_definitions(test_${str} PRIVATE STATIC_VCPU)
    target_link_libraries(test_${str} bfvmm_vcpu_factory)
    target_link_libraries(test_${str} bfvmm_vcpu)
    target_link_libraries(test_${str} bfvmm_vcpu_manager)
    target_link_libraries(test_${str} bfvmm_vmxon)
    target_link_libraries(test_${str} bfvmm_exit_handler)
    target_link_libraries(test_${str} bfvmm_vmcs)
    target_link_libraries(test_${str} bfvmm_memory_manager)
    target_link_libraries(test_${str} bfvmm_intrinsics)
    target_link_libraries(test_${str} test_catch)
    add_test(test_${str} test_${str})
endmacro(do_test)

do_test(vcpu_manager)
