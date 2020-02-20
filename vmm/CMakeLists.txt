add_library(vmm OBJECT)

target_sources(vmm PRIVATE
    src/entry/start.s
)

target_compile_definitions(vmm PUBLIC
    "VMM"
    ${TARGET_ARCH}
    ${TARGET_OS}
    ${CMAKE_BUILD_TYPE}
    "$<$<CONFIG:RELEASE>:BUILD_RELEASE>"
    "$<$<CONFIG:DEBUG>:BUILD_DEBUG>"
    "$<$<CONFIG:TEST>:TEST>"
)

target_compile_options(vmm PUBLIC
    "-c"
    "-fpie"
    "--target=x86_64-unknown-linux-gnu"
    "$<$<OR:$<COMPILE_LANGUAGE:C>,$<COMPILE_LANGUAGE:CXX>>:-fno-builtin>"
    "$<$<OR:$<COMPILE_LANGUAGE:C>,$<COMPILE_LANGUAGE:CXX>>:-fno-common>"
    "$<$<OR:$<COMPILE_LANGUAGE:C>,$<COMPILE_LANGUAGE:CXX>>:-ffreestanding>"
    "$<$<OR:$<COMPILE_LANGUAGE:C>,$<COMPILE_LANGUAGE:CXX>>:-fstack-protector-strong>"
    "$<$<OR:$<COMPILE_LANGUAGE:C>,$<COMPILE_LANGUAGE:CXX>>:-mno-red-zone>"
    "$<$<OR:$<COMPILE_LANGUAGE:C>,$<COMPILE_LANGUAGE:CXX>>:-mstackrealign>"
    "$<$<STREQUAL:${TARGET_ARCH},x86_64>:-march=core2>"
    "$<$<STREQUAL:${TARGET_ARCH},armv8a>:-march=armv8a>"
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

if(NOT BUILD_VMM)
    set_target_properties(vmm PROPERTIES
        EXCLUDE_FROM_ALL ON
    )
endif()

set(CMAKE_INSTALL_MESSAGE NEVER)
install(TARGETS vmm DESTINATION lib/vmm)
install(DIRECTORY include/ DESTINATION include/vmm)

export(TARGETS vmm NAMESPACE bareflank:: FILE vmmConfig.cmake APPEND)
