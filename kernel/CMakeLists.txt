add_executable(kernel)

target_sources(kernel PRIVATE
    src/start.s
)

target_compile_options(kernel PRIVATE
    "-c"
    "-fpie"
    "$<$<OR:$<COMPILE_LANGUAGE:C>,$<COMPILE_LANGUAGE:CXX>>:-fno-builtin>"
    "$<$<OR:$<COMPILE_LANGUAGE:C>,$<COMPILE_LANGUAGE:CXX>>:-fno-common>"
    "$<$<OR:$<COMPILE_LANGUAGE:C>,$<COMPILE_LANGUAGE:CXX>>:-ffreestanding>"
    "$<$<OR:$<COMPILE_LANGUAGE:C>,$<COMPILE_LANGUAGE:CXX>>:-std=c++17>"
    "$<$<OR:$<COMPILE_LANGUAGE:C>,$<COMPILE_LANGUAGE:CXX>>:-fno-exceptions>"
    "$<$<OR:$<COMPILE_LANGUAGE:C>,$<COMPILE_LANGUAGE:CXX>>:-fno-rtti>"
    "$<$<OR:$<COMPILE_LANGUAGE:C>,$<COMPILE_LANGUAGE:CXX>>:-nostdlib>"
    "$<$<OR:$<COMPILE_LANGUAGE:C>,$<COMPILE_LANGUAGE:CXX>>:-nostdlibinc>"
    "$<$<STREQUAL:${HYPERVISOR_TARGET_ARCH},x86_64>:--target=x86_64-unknown-linux-gnu>"
    "$<$<STREQUAL:${HYPERVISOR_TARGET_ARCH},x86_64>:-march=core2>"
    "$<$<STREQUAL:${HYPERVISOR_TARGET_ARCH},AMD64>:--target=x86_64-unknown-linux-gnu>"
    "$<$<STREQUAL:${HYPERVISOR_TARGET_ARCH},AMD64>:-march=core2>"
    "$<$<STREQUAL:${HYPERVISOR_TARGET_ARCH},armv8a>:--target=aarch64-unknown-linux-gnu>"
    "$<$<STREQUAL:${HYPERVISOR_TARGET_ARCH},armv8a>:-march=armv8a>"
)

target_link_options(kernel PRIVATE
    "-static"
    "-nostdlib"
    "-ffreestanding"
    "-fuse-ld=lld"
    "-Wl,--no-dynamic-linker"
    "-Wl,-zmax-page-size=0x1000"
    "-Wl,-znoexecstack"
    "$<$<STREQUAL:${HYPERVISOR_TARGET_ARCH},x86_64>:--target=x86_64-unknown-linux-gnu>"
)

target_include_directories(kernel PRIVATE
    src
)

target_link_libraries(kernel bsl pal)

set_target_properties(kernel PROPERTIES
    SUFFIX ".vmm"
)

if(NOT HYPERVISOR_BUILD_KERNEL)
    set_target_properties(kernel PROPERTIES
        EXCLUDE_FROM_ALL ON
    )
endif()

set(CMAKE_INSTALL_MESSAGE NEVER)
install(TARGETS kernel DESTINATION bin/kernel)

add_library(kernel_headers INTERFACE)

target_include_directories(kernel_headers INTERFACE
    include
)
install(DIRECTORY include/ DESTINATION include/kernel)
