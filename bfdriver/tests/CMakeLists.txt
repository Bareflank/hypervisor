# ------------------------------------------------------------------------------
# CMake Includes
# ------------------------------------------------------------------------------

include(${CMAKE_INSTALL_PREFIX}/cmake/CMakeGlobal_Includes.txt)

# ------------------------------------------------------------------------------
# Targets
# ------------------------------------------------------------------------------

# add_library(test_support STATIC test_real_elf.cpp test_fake_elf.cpp)

macro(do_test str)
    add_executable(test_${str} test_${str}.cpp)
    target_link_libraries(test_${str} test_support)
    target_link_libraries(test_${str} test_catch)
    add_test(bfelf_${str} test_${str})
endmacro(do_test)
