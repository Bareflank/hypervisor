# ------------------------------------------------------------------------------
# CMake Includes
# ------------------------------------------------------------------------------

include(${CMAKE_INSTALL_PREFIX}/cmake/CMakeGlobal_Includes.txt)

# ------------------------------------------------------------------------------
# Targets
# ------------------------------------------------------------------------------

list(APPEND SOURCES
    exit_handler_intel_x64.cpp
    exit_handler_intel_x64_entry.cpp
    exit_handler_intel_x64_unittests_containers.cpp
    exit_handler_intel_x64_unittests.cpp
    exit_handler_intel_x64_unittests_io.cpp
)

if(CMAKE_TOOLCHAIN_FILE)
    list(APPEND SOURCES exit_handler_intel_x64_support.asm)
else()
    list(APPEND SOURCES exit_handler_intel_x64_support_mock.cpp)
endif()

if(BUILD_SHARED_LIBS)
    add_library(bfvmm_exit_handler SHARED ${SOURCES})
    target_compile_definitions(bfvmm_exit_handler PRIVATE SHARED_EXIT_HANDLER)
endif()

if(BUILD_STATIC_LIBS)
    add_library(bfvmm_exit_handler STATIC ${SOURCES})
    target_compile_definitions(bfvmm_exit_handler PUBLIC STATIC_EXIT_HANDLER)
    target_compile_definitions(bfvmm_exit_handler PUBLIC STATIC_VMCS)
    target_compile_definitions(bfvmm_exit_handler PUBLIC STATIC_MEMORY_MANAGER)
    target_compile_definitions(bfvmm_exit_handler PUBLIC STATIC_INTRINSICS)
endif()

install(TARGETS bfvmm_exit_handler DESTINATION ${INSTALL_LIB_DIR})
