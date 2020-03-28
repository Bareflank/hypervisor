add_library(vmm OBJECT)

target_sources(vmm PRIVATE
    src/entry/start.s
)

target_compile_definitions(vmm PUBLIC
    "VMM"
    "$<$<CONFIG:RELEASE>:BUILD_RELEASE>"
    "$<$<CONFIG:DEBUG>:BUILD_DEBUG>"
    "$<$<CONFIG:TEST>:TEST>"
)

target_compile_options(vmm PUBLIC
    "-c"
    "-fpie"
    "$<$<OR:$<COMPILE_LANGUAGE:C>,$<COMPILE_LANGUAGE:CXX>>:-fno-builtin>"
    "$<$<OR:$<COMPILE_LANGUAGE:C>,$<COMPILE_LANGUAGE:CXX>>:-fno-common>"
    "$<$<OR:$<COMPILE_LANGUAGE:C>,$<COMPILE_LANGUAGE:CXX>>:-ffreestanding>"
    "$<$<STREQUAL:${HYPERVISOR_TARGET_ARCH},x86_64>:--target=x86_64-unknown-linux-gnu>"
    "$<$<STREQUAL:${HYPERVISOR_TARGET_ARCH},x86_64>:-march=core2>"
    "$<$<STREQUAL:${HYPERVISOR_TARGET_ARCH},AMD64>:--target=x86_64-unknown-linux-gnu>"
    "$<$<STREQUAL:${HYPERVISOR_TARGET_ARCH},AMD64>:-march=core2>"
    "$<$<STREQUAL:${HYPERVISOR_TARGET_ARCH},armv8a>:--target=aarch64-unknown-linux-gnu>"
    "$<$<STREQUAL:${HYPERVISOR_TARGET_ARCH},armv8a>:-march=armv8a>"
)

target_link_options(vmm PUBLIC
    "--target=x86_64-unknown-linux-gnu"
    "-static"
    "-nostdlib"
    "-ffreestanding"
    "-fuse-ld=lld"
    "-Wl,--no-dynamic-linker"
    "-Wl,-zmax-page-size=0x1000"
    "-Wl,-znoexecstack"
)

target_include_directories(vmm PUBLIC
    include
)

target_include_directories(vmm PRIVATE
    src
)

target_link_libraries(vmm bsl pal)

if(NOT HYPERVISOR_BUILD_VMM)
    set_target_properties(vmm PROPERTIES
        EXCLUDE_FROM_ALL ON
    )
endif()

set(CMAKE_INSTALL_MESSAGE NEVER)
install(TARGETS vmm DESTINATION lib/vmm)
install(DIRECTORY include/ DESTINATION include/vmm)

export(TARGETS vmm NAMESPACE bareflank:: FILE vmmConfig.cmake APPEND)
