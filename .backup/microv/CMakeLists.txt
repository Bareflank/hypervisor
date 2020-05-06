add_library(microv OBJECT)

target_sources(microv PRIVATE
    src/junk_to_get_rid_of.cpp
    src/execute.cpp
    src/init_handler.cpp
    src/start.s
)

if(${HYPERVISOR_TARGET_ARCH} STREQUAL "x86_64")
    target_sources(microv PRIVATE
        src/x64/intel/intel_cpuid.cpp
        src/x64/intel/intel_instruction_pointer.cpp
    )
endif()

target_compile_definitions(microv PUBLIC
    # TODO: The bsl might need these defined?
    "BSL_BUILTIN_FILE=\"file\""
    "BSL_BUILTIN_FUNCTION=\"function\""
    "BSL_BUILTIN_LINE=0"
    "BSL_BUILTIN_MEMSET=nullptr"
    "BSL_BUILTIN_MEMCMP=0"
    "BSL_BUILTIN_STRNCMP=0"
    "BSL_BUILTIN_STRLEN=0U"
    "BSL_BUILTIN_CHAR_MEMCHR=0"
)

target_compile_options(microv PUBLIC
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
    "$<$<OR:$<COMPILE_LANGUAGE:C>,$<COMPILE_LANGUAGE:CXX>>:-mno-red-zone>"
    "$<$<STREQUAL:${HYPERVISOR_TARGET_ARCH},x86_64>:--target=x86_64-unknown-linux-gnu>"
    "$<$<STREQUAL:${HYPERVISOR_TARGET_ARCH},x86_64>:-march=core2>"
    "$<$<STREQUAL:${HYPERVISOR_TARGET_ARCH},AMD64>:--target=x86_64-unknown-linux-gnu>"
    "$<$<STREQUAL:${HYPERVISOR_TARGET_ARCH},AMD64>:-march=core2>"
    "$<$<STREQUAL:${HYPERVISOR_TARGET_ARCH},armv8a>:--target=aarch64-unknown-linux-gnu>"
    "$<$<STREQUAL:${HYPERVISOR_TARGET_ARCH},armv8a>:-march=armv8a>"
)

target_link_options(microv PUBLIC
    "-static"
    "-nostdlib"
    "-ffreestanding"
    "-fuse-ld=lld"
    "-Wl,--no-dynamic-linker"
    "-Wl,-zmax-page-size=0x1000"
    "-Wl,-znoexecstack"
    "$<$<STREQUAL:${HYPERVISOR_TARGET_ARCH},x86_64>:--target=x86_64-unknown-linux-gnu>"
    "$<$<STREQUAL:${HYPERVISOR_TARGET_ARCH},AMD64>:--target=x86_64-unknown-linux-gnu>"
    "$<$<STREQUAL:${HYPERVISOR_TARGET_ARCH},armv8a>:--target=aarch64-unknown-linux-gnu>"
)

target_include_directories(microv PUBLIC
    include
)

target_include_directories(microv PRIVATE
    src
)

target_link_libraries(microv bsl pal)

if(NOT HYPERVISOR_BUILD_MICROV_PLACEHOLDER)
    set_target_properties(microv PROPERTIES
        EXCLUDE_FROM_ALL ON
    )
endif()

set(CMAKE_INSTALL_MESSAGE NEVER)
install(TARGETS microv DESTINATION lib/microv)
install(DIRECTORY include/ DESTINATION include/microv)

add_subdirectory(example)
