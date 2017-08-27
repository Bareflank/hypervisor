# ------------------------------------------------------------------------------
# CMake Includes
# ------------------------------------------------------------------------------

include(${CMAKE_INSTALL_PREFIX}/cmake/CMakeGlobal_Includes.txt)

# ------------------------------------------------------------------------------
# Targets
# ------------------------------------------------------------------------------

if(NOT WIN32)
    add_custom_command(OUTPUT bfvmcall_intel_x64.o
        COMMAND ${CMAKE_ASM_NASM_COMPILER} ${CMAKE_ASM_NASM_FLAGS} ${CMAKE_INSTALL_PREFIX}/src/bfvmcall_intel_x64.asm -f elf64 -o bfvmcall_intel_x64.o
        DEPENDS ${CMAKE_INSTALL_PREFIX}/src/bfvmcall_intel_x64.asm
    )
    add_executable(bfm main.cpp $<TARGET_OBJECTS:bfm_src> $<TARGET_OBJECTS:bfm_ioctl> bfvmcall_intel_x64.o)
else()
    add_custom_command(OUTPUT bfvmcall_intel_x64.obj
        COMMAND ${CMAKE_ASM_NASM_COMPILER} ${CMAKE_ASM_NASM_FLAGS} ${CMAKE_INSTALL_PREFIX}/src/bfvmcall_intel_x64.asm -f win64 -o bfvmcall_intel_x64.obj
        DEPENDS ${CMAKE_INSTALL_PREFIX}/src/bfvmcall_intel_x64.asm
    )
    add_executable(bfm main.cpp $<TARGET_OBJECTS:bfm_src> $<TARGET_OBJECTS:bfm_ioctl> bfvmcall_intel_x64.obj)
endif()

add_library(bfm_static STATIC main.cpp $<TARGET_OBJECTS:bfm_src> $<TARGET_OBJECTS:bfm_ioctl>)

target_compile_definitions(bfm PUBLIC STATIC_BFM_SRC)
target_compile_definitions(bfm PUBLIC STATIC_BFM_IOCTL)
target_compile_definitions(bfm PUBLIC MAIN=main)
target_compile_definitions(bfm PUBLIC ABORT=abort)

target_compile_definitions(bfm_static PUBLIC STATIC_BFM_SRC)
target_compile_definitions(bfm_static PUBLIC STATIC_BFM_IOCTL)

if(CYGWIN OR WIN32)
    target_link_libraries(bfm setupapi)
    target_link_libraries(bfm_static setupapi)
endif()

# ------------------------------------------------------------------------------
# Install
# ------------------------------------------------------------------------------

install(TARGETS bfm DESTINATION bin)
