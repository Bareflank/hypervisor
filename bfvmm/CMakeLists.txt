cmake_minimum_required(VERSION 3.6)
project(bfvmm C CXX)

include(${CMAKE_INSTALL_PREFIX}/cmake/CMakeGlobal_Project.txt)

# ------------------------------------------------------------------------------
# Subdirectories
# ------------------------------------------------------------------------------

if(CMAKE_TOOLCHAIN_FILE)
    set(INSTALL_LIB_DIR ${BAREFLANK_SYSROOT_PATH}/lib)
    set(INSTALL_BIN_DIR ${BAREFLANK_SYSROOT_PATH}/bin)
else()
    set(INSTALL_LIB_DIR ${CMAKE_INSTALL_PREFIX}/lib)
    set(INSTALL_BIN_DIR ${CMAKE_INSTALL_PREFIX}/bin)
endif()

add_subdirectory(src)

# ------------------------------------------------------------------------------
# Install
# ------------------------------------------------------------------------------

install(DIRECTORY include/debug_ring DESTINATION include)
install(DIRECTORY include/exit_handler DESTINATION include)
install(DIRECTORY include/intrinsics DESTINATION include)
install(DIRECTORY include/memory_manager DESTINATION include)
install(DIRECTORY include/serial DESTINATION include)
install(DIRECTORY include/vcpu DESTINATION include)
install(DIRECTORY include/vmcs DESTINATION include)
install(DIRECTORY include/vmxon DESTINATION include)
install(FILES include/user_data.h DESTINATION include)
