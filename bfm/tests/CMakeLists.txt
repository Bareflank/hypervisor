# ------------------------------------------------------------------------------
# CMake Includes
# ------------------------------------------------------------------------------

include(${CMAKE_INSTALL_PREFIX}/cmake/CMakeGlobal_Includes.txt)

# ------------------------------------------------------------------------------
# Targets
# ------------------------------------------------------------------------------

add_library(test_vmcall STATIC test_vmcall.cpp)

macro(do_test str)
    add_executable(test_${str} test_${str}.cpp $<TARGET_OBJECTS:bfm_src> $<TARGET_OBJECTS:bfm_ioctl>)
    target_link_libraries(test_${str} test_catch)
    target_link_libraries(test_${str} test_vmcall)
    target_compile_definitions(test_${str} PRIVATE STATIC_BFM_SRC)
    target_compile_definitions(test_${str} PRIVATE STATIC_BFM_IOCTL)
    add_test(test_${str} test_${str})
    if(CYGWIN OR WIN32)
        target_link_libraries(test_${str} setupapi)
    endif()
endmacro(do_test)

do_test(command_line_parser)
do_test(ioctl_driver)
do_test(ioctl)

add_executable(test_main test_main.cpp)
target_link_libraries(test_main bfm_static)
target_link_libraries(test_main test_catch)
target_link_libraries(test_main test_vmcall)
target_compile_definitions(test_main PRIVATE STATIC_BFM_SRC)
target_compile_definitions(test_main PRIVATE STATIC_BFM_IOCTL)
add_test(test_main test_main)
