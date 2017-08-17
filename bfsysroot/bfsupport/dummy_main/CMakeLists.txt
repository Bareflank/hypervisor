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

add_executable(dummy_main dummy_main.cpp)

target_link_libraries(dummy_main dummy_lib1)
target_link_libraries(dummy_main dummy_lib2)
target_link_libraries(dummy_main -Wl,--whole-archive bfcrt -Wl,--no-whole-archive)
target_link_libraries(dummy_main bfsyscall)
target_link_libraries(dummy_main bfunwind)
target_link_libraries(dummy_main c++)
target_link_libraries(dummy_main c++abi)
target_link_libraries(dummy_main c)
target_link_libraries(dummy_main pthread)
target_link_libraries(dummy_main bfsyscall)
target_link_libraries(dummy_main bfunwind)

# ------------------------------------------------------------------------------
# Install
# ------------------------------------------------------------------------------

install(TARGETS dummy_main DESTINATION ${BAREFLANK_SYSROOT_PATH}/bin)
