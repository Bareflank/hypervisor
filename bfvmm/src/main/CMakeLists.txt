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

if(NOT EXISTS ${CMAKE_BINARY_DIR}/null.cpp)
    file(WRITE
        ${CMAKE_BINARY_DIR}/null.cpp ""
    )
endif()

list(APPEND SOURCES
    main.cpp
)

add_library(bfvmm_main STATIC ${SOURCES})
add_executable(bfvmm ${CMAKE_BINARY_DIR}/null.cpp)

if(BUILD_SHARED_LIBS)
    target_link_libraries(bfvmm -Wl,--whole-archive bfvmm_main -Wl,--no-whole-archive)
    target_link_libraries(bfvmm bfvmm_vcpu_factory)
    target_link_libraries(bfvmm bfvmm_vcpu)
    target_link_libraries(bfvmm bfvmm_vcpu_manager)
    target_link_libraries(bfvmm bfvmm_exit_handler)
    target_link_libraries(bfvmm bfvmm_vmcs)
    target_link_libraries(bfvmm bfvmm_vmxon)
    target_link_libraries(bfvmm bfvmm_memory_manager)
    if(CMAKE_TOOLCHAIN_FILE)
        target_link_libraries(bfvmm bfvmm_support)
    endif()
    target_link_libraries(bfvmm bfvmm_serial)
    target_link_libraries(bfvmm bfvmm_debug_ring)
    target_link_libraries(bfvmm bfvmm_intrinsics)
endif()

if(BUILD_STATIC_LIBS)
    target_link_libraries(bfvmm -Wl,--whole-archive bfvmm_main -Wl,--no-whole-archive)
    target_link_libraries(bfvmm -Wl,--whole-archive bfvmm_vcpu_factory -Wl,--no-whole-archive)
    target_link_libraries(bfvmm -Wl,--whole-archive bfvmm_vcpu -Wl,--no-whole-archive)
    target_link_libraries(bfvmm -Wl,--whole-archive bfvmm_vcpu_manager -Wl,--no-whole-archive)
    target_link_libraries(bfvmm bfvmm_exit_handler)
    target_link_libraries(bfvmm bfvmm_vmcs)
    target_link_libraries(bfvmm bfvmm_vmxon)
    target_link_libraries(bfvmm -Wl,--whole-archive bfvmm_memory_manager  -Wl,--no-whole-archive)
    if(CMAKE_TOOLCHAIN_FILE)
        target_link_libraries(bfvmm bfvmm_support)
    endif()
    target_link_libraries(bfvmm bfvmm_serial)
    target_link_libraries(bfvmm bfvmm_debug_ring)
    target_link_libraries(bfvmm bfvmm_intrinsics)
endif()

# ------------------------------------------------------------------------------
# Install
# ------------------------------------------------------------------------------

install(TARGETS bfvmm DESTINATION ${INSTALL_BIN_DIR})
install(TARGETS bfvmm_main DESTINATION ${INSTALL_LIB_DIR})
