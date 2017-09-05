# ------------------------------------------------------------------------------
# CMake Includes
# ------------------------------------------------------------------------------

include(${CMAKE_INSTALL_PREFIX}/cmake/CMakeGlobal_Includes.txt)

# ------------------------------------------------------------------------------
# Targets
# ------------------------------------------------------------------------------

add_library(test_support STATIC test_support.cpp)

macro(do_test str)
    add_executable(test_${str} test_${str}.cpp)
    target_link_libraries(test_${str} bfdriver)
    target_link_libraries(test_${str} test_support)
    target_link_libraries(test_${str} test_catch)
    add_test(bfelf_${str} test_${str})
endmacro(do_test)

do_test(common_add_module)
do_test(common_dump)
do_test(common_fini)
do_test(common_init)
do_test(common_load)
do_test(common_start)
do_test(common_stop)
do_test(common_unload)
