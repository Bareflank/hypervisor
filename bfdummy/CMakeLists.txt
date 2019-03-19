#
# Copyright (C) 2019 Assured Information Security, Inc.
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

cmake_minimum_required(VERSION 3.13)
project(bfdummy C CXX)

init_project(bfdummy INTERFACE)

target_include_directories(bfdummy INTERFACE
    $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
)

target_link_libraries(bfdummy INTERFACE
    --whole-archive -lbfcrt -lbfdso --no-whole-archive
    ${CMAKE_INSTALL_PREFIX}/lib/libc++.a
    ${CMAKE_INSTALL_PREFIX}/lib/libc++abi.a
    vmm::bfpthread
    vmm::bfunwind
    ${CMAKE_INSTALL_PREFIX}/lib/libm.a
    ${CMAKE_INSTALL_PREFIX}/lib/libc.a
    vmm::bfsyscall
)

#------------------------------------------------------------------------------
# Libraries
#------------------------------------------------------------------------------

add_library(dummy_lib1 src/libs/dummy_lib1.cpp)
add_library(dummy_lib2 src/libs/dummy_lib2.cpp)

target_link_libraries(dummy_lib1 PUBLIC bfdummy)
target_link_libraries(dummy_lib2 PUBLIC bfdummy)

set_target_properties(dummy_lib1 PROPERTIES LINKER_LANGUAGE C)
set_target_properties(dummy_lib2 PROPERTIES LINKER_LANGUAGE C)

install(TARGETS dummy_lib1 DESTINATION lib EXPORT bfdummy-vmm-targets)
install(TARGETS dummy_lib2 DESTINATION lib EXPORT bfdummy-vmm-targets)

#------------------------------------------------------------------------------
# Executables
#------------------------------------------------------------------------------

add_executable(dummy_main src/main/dummy_main.cpp)
add_executable(dummy_main_init_fails src/main/dummy_main.cpp)
add_executable(dummy_main_fini_fails src/main/dummy_main.cpp)
add_executable(dummy_main_add_mdl_fails src/main/dummy_main.cpp)
add_executable(dummy_main_get_drr_fails src/main/dummy_main.cpp)
add_executable(dummy_main_set_rsdp_fails src/main/dummy_main.cpp)
add_executable(dummy_main_vmm_init_fails src/main/dummy_main.cpp)
add_executable(dummy_main_vmm_fini_fails src/main/dummy_main.cpp)

target_link_libraries(dummy_main PRIVATE dummy_lib1 dummy_lib2)
target_link_libraries(dummy_main_init_fails PRIVATE dummy_lib1 dummy_lib2)
target_link_libraries(dummy_main_fini_fails PRIVATE dummy_lib1 dummy_lib2)
target_link_libraries(dummy_main_add_mdl_fails PRIVATE dummy_lib1 dummy_lib2)
target_link_libraries(dummy_main_get_drr_fails PRIVATE dummy_lib1 dummy_lib2)
target_link_libraries(dummy_main_set_rsdp_fails PRIVATE dummy_lib1 dummy_lib2)
target_link_libraries(dummy_main_vmm_init_fails PRIVATE dummy_lib1 dummy_lib2)
target_link_libraries(dummy_main_vmm_fini_fails PRIVATE dummy_lib1 dummy_lib2)

target_compile_definitions(dummy_main_init_fails PRIVATE REQUEST_INIT_FAILS)
target_compile_definitions(dummy_main_fini_fails PRIVATE REQUEST_FINI_FAILS)
target_compile_definitions(dummy_main_add_mdl_fails PRIVATE REQUEST_ADD_MDL_FAILS)
target_compile_definitions(dummy_main_get_drr_fails PRIVATE REQUEST_GET_DRR_FAILS)
target_compile_definitions(dummy_main_set_rsdp_fails PRIVATE REQUEST_SET_RSDP_FAILS)
target_compile_definitions(dummy_main_vmm_init_fails PRIVATE REQUEST_VMM_INIT_FAILS)
target_compile_definitions(dummy_main_vmm_fini_fails PRIVATE REQUEST_VMM_FINI_FAILS)

install(TARGETS dummy_main DESTINATION bin EXPORT bfdummy-vmm-targets)
install(TARGETS dummy_main_init_fails DESTINATION bin EXPORT bfdummy-vmm-targets)
install(TARGETS dummy_main_fini_fails DESTINATION bin EXPORT bfdummy-vmm-targets)
install(TARGETS dummy_main_add_mdl_fails DESTINATION bin EXPORT bfdummy-vmm-targets)
install(TARGETS dummy_main_get_drr_fails DESTINATION bin EXPORT bfdummy-vmm-targets)
install(TARGETS dummy_main_set_rsdp_fails DESTINATION bin EXPORT bfdummy-vmm-targets)
install(TARGETS dummy_main_vmm_init_fails DESTINATION bin EXPORT bfdummy-vmm-targets)
install(TARGETS dummy_main_vmm_fini_fails DESTINATION bin EXPORT bfdummy-vmm-targets)

fini_project()
