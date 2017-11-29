#
# Bareflank Hypervisor
# Copyright (C) 2015 Assured Information Security, Inc.
#
# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 2.1 of the License, or (at your option) any later version.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this library; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA

set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -pie")

list(APPEND LIBRARIES
    dummy_lib1
    dummy_lib2
    -Wl,--whole-archive bfcrt -Wl,--no-whole-archive
    bfsyscall_shared
    pthread_shared
    bfunwind
    c++
    c++abi
    c
)

add_executable(dummy_main dummy_main.cpp)
target_link_libraries(dummy_main ${LIBRARIES})

add_executable(dummy_main_init_fails dummy_main.cpp)
target_link_libraries(dummy_main_init_fails ${LIBRARIES})
target_compile_definitions(dummy_main_init_fails PUBLIC REQUEST_INIT_FAILS)

add_executable(dummy_main_fini_fails dummy_main.cpp)
target_link_libraries(dummy_main_fini_fails ${LIBRARIES})
target_compile_definitions(dummy_main_fini_fails PUBLIC REQUEST_FINI_FAILS)

add_executable(dummy_main_add_mdl_fails dummy_main.cpp)
target_link_libraries(dummy_main_add_mdl_fails ${LIBRARIES})
target_compile_definitions(dummy_main_add_mdl_fails PUBLIC REQUEST_ADD_MDL_FAILS)

add_executable(dummy_main_get_drr_fails dummy_main.cpp)
target_link_libraries(dummy_main_get_drr_fails ${LIBRARIES})
target_compile_definitions(dummy_main_get_drr_fails PUBLIC REQUEST_GET_DRR_FAILS)

add_executable(dummy_main_vmm_init_fails dummy_main.cpp)
target_link_libraries(dummy_main_vmm_init_fails ${LIBRARIES})
target_compile_definitions(dummy_main_vmm_init_fails PUBLIC REQUEST_VMM_INIT_FAILS)

add_executable(dummy_main_vmm_fini_fails dummy_main.cpp)
target_link_libraries(dummy_main_vmm_fini_fails ${LIBRARIES})
target_compile_definitions(dummy_main_vmm_fini_fails PUBLIC REQUEST_VMM_FINI_FAILS)

install(TARGETS dummy_main DESTINATION ${BUILD_SYSROOT_VMM}/bin)
install(TARGETS dummy_main_init_fails DESTINATION ${BUILD_SYSROOT_VMM}/bin)
install(TARGETS dummy_main_fini_fails DESTINATION ${BUILD_SYSROOT_VMM}/bin)
install(TARGETS dummy_main_add_mdl_fails DESTINATION ${BUILD_SYSROOT_VMM}/bin)
install(TARGETS dummy_main_get_drr_fails DESTINATION ${BUILD_SYSROOT_VMM}/bin)
install(TARGETS dummy_main_vmm_init_fails DESTINATION ${BUILD_SYSROOT_VMM}/bin)
install(TARGETS dummy_main_vmm_fini_fails DESTINATION ${BUILD_SYSROOT_VMM}/bin)
