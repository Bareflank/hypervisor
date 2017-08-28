# ------------------------------------------------------------------------------
# CMake Includes
# ------------------------------------------------------------------------------

include("../cmake/CMakeGlobal_Includes.txt")

# ------------------------------------------------------------------------------
# Targets
# ------------------------------------------------------------------------------

add_library(test_catch STATIC test.cpp)
add_dependencies(test_catch catch)

macro(do_test str)
    add_executable(test_${str} test_${str}.cpp)
    target_link_libraries(test_${str} test_catch)
    add_dependencies(test_${str} json)
    add_dependencies(test_${str} gsl)
    add_dependencies(test_${str} catch)
    add_dependencies(test_${str} hippomocks)
    add_test(test_${str} test_${str})
endmacro(do_test)

do_test(affinity)
do_test(benchmark)
do_test(bitmanip)
do_test(buffer)
do_test(debug)
do_test(debugringinterface)
do_test(errorcodes)
do_test(exceptions)
do_test(file)
do_test(gsl)
do_test(json)
do_test(newdelete)
do_test(shuffle)
do_test(string)
do_test(types)
do_test(upperlower)
do_test(vector)

# ------------------------------------------------------------------------------
# Install
# ------------------------------------------------------------------------------

install(TARGETS test_catch DESTINATION lib)
