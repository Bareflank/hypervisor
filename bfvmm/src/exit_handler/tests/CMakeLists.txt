# ------------------------------------------------------------------------------
# CMake Includes
# ------------------------------------------------------------------------------

include(${CMAKE_INSTALL_PREFIX}/cmake/CMakeGlobal_Includes.txt)

# ------------------------------------------------------------------------------
# Definitions
# ------------------------------------------------------------------------------

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DEXIT_HANDLER_TEST")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DEXIT_HANDLER_TEST")

# ------------------------------------------------------------------------------
# Targets
# ------------------------------------------------------------------------------

macro(do_test str)
    add_executable(test_${str} test_${str}.cpp)
    target_compile_definitions(test_${str} PRIVATE STATIC_EXIT_HANDLER)
    target_compile_definitions(test_${str} PRIVATE EXIT_HANDLER_TEST)
    target_link_libraries(test_${str} bfvmm_exit_handler)
    target_link_libraries(test_${str} bfvmm_vmcs)
    target_link_libraries(test_${str} bfvmm_memory_manager)
    target_link_libraries(test_${str} bfvmm_intrinsics)
    target_link_libraries(test_${str} test_catch)
    add_test(test_${str} test_${str})
endmacro(do_test)

do_test(exit_handler_intel_x64)
do_test(exit_handler_intel_x64_support_mock)
do_test(exit_handler_intel_x64_entry)
