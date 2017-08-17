# ------------------------------------------------------------------------------
# CMake Includes
# ------------------------------------------------------------------------------

include(${CMAKE_INSTALL_PREFIX}/cmake/CMakeGlobal_Includes.txt)

# ------------------------------------------------------------------------------
# Targets
# ------------------------------------------------------------------------------

macro(do_test str)
    add_executable(test_${str} test_${str}.cpp)
    target_compile_definitions(test_${str} PUBLIC STATIC_VMXON)
    target_compile_definitions(test_${str} PUBLIC STATIC_MEMORY_MANAGER)
    target_compile_definitions(test_${str} PUBLIC STATIC_INTRINSICS)
    target_link_libraries(test_${str} bfvmm_vmxon)
    target_link_libraries(test_${str} bfvmm_memory_manager)
    target_link_libraries(test_${str} bfvmm_intrinsics)
    target_link_libraries(test_${str} test_catch)
    add_test(test_${str} test_${str})
endmacro(do_test)

do_test(vmxon_intel_x64)
