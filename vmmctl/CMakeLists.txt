add_executable(vmmctl)

if (HYPERVISOR_TARGET_PLATFORM STREQUAL Windows)
    target_sources(vmmctl PRIVATE main/windows/main.cpp)
elseif (HYPERVISOR_TARGET_PLATFORM STREQUAL Linux)
    target_sources(vmmctl PRIVATE main/linux/main.cpp)
else()
    target_sources(vmmctl PRIVATE main/unsupported/null.cpp)

    message(WARNING
        "Excluding vmmctl component for unsupported target platform: "
        "${HYPERVISOR_TARGET_PLATFORM}"
    )

    set_target_properties(vmmctl PROPERTIES
        EXCLUDE_FROM_ALL ON
    )
endif()

target_link_libraries(vmmctl bsl)

target_include_directories(vmmctl PUBLIC
    include
)

target_include_directories(vmmctl PRIVATE
    src
)

if(CMAKE_HOST_SYSTEM_NAME STREQUAL "Windows")
    set_target_properties(vmmctl PROPERTIES
        SUFFIX ".exe"
    )
endif()

if(NOT HYPERVISOR_BUILD_VMMCTL)
    set_target_properties(vmmctl PROPERTIES
        EXCLUDE_FROM_ALL ON
    )
endif()

install(TARGETS vmmctl DESTINATION bin)
