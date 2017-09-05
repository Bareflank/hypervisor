# ------------------------------------------------------------------------------
# CMake Includes
# ------------------------------------------------------------------------------

include(${CMAKE_INSTALL_PREFIX}/cmake/CMakeGlobal_Includes.txt)

# ------------------------------------------------------------------------------
# Custom Flags
# ------------------------------------------------------------------------------

set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -pie")

# ------------------------------------------------------------------------------
# Targets
# ------------------------------------------------------------------------------

list(APPEND LIBRARIES
    dummy_lib1
    dummy_lib2
    -Wl,--whole-archive bfcrt -Wl,--no-whole-archive
    bfsyscall
    bfunwind
    c++
    c++abi
    c
    pthread
    bfsyscall
    bfunwind
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

# ------------------------------------------------------------------------------
# Install
# ------------------------------------------------------------------------------

install(TARGETS dummy_main DESTINATION ${BAREFLANK_SYSROOT_PATH}/bin)
install(TARGETS dummy_main_init_fails DESTINATION ${BAREFLANK_SYSROOT_PATH}/bin)
install(TARGETS dummy_main_fini_fails DESTINATION ${BAREFLANK_SYSROOT_PATH}/bin)
install(TARGETS dummy_main_add_mdl_fails DESTINATION ${BAREFLANK_SYSROOT_PATH}/bin)
install(TARGETS dummy_main_get_drr_fails DESTINATION ${BAREFLANK_SYSROOT_PATH}/bin)
install(TARGETS dummy_main_vmm_init_fails DESTINATION ${BAREFLANK_SYSROOT_PATH}/bin)
install(TARGETS dummy_main_vmm_fini_fails DESTINATION ${BAREFLANK_SYSROOT_PATH}/bin)
