cmake_minimum_required(VERSION 3.6)
project(bfunwind C CXX)

include(${CMAKE_INSTALL_PREFIX}/cmake/CMakeGlobal_Project.txt)

# ------------------------------------------------------------------------------
# Flags
# ------------------------------------------------------------------------------

if(CMAKE_TOOLCHAIN_FILE)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -nostdlib-c")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -nostdlib-c -nostdinc-c++")
endif()

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

install(FILES include/ia64_cxx_abi.h DESTINATION ${BAREFLANK_SYSROOT_PATH}/include RENAME unwind.h)
