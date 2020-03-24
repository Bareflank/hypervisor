add_executable(vmmctl)

if(TARGET_ARCH STREQUAL x86_64 OR TARGET_ARCH STREQUAL AMD64)
    if (TARGET_PLATFORM STREQUAL Windows)
        target_sources(vmmctl PRIVATE main/windows_late_launch/main.cpp)
    elseif (TARGET_PLATFORM STREQUAL Linux)
        target_sources(vmmctl PRIVATE main/linux_late_launch/main.cpp)
    elseif(TARGET_PLATFORM STREQUAL UEFI AND CMAKE_HOST_SYSTEM_NAME STREQUAL Windows)
        target_sources(vmmctl PRIVATE main/windows_uefi_launch/main.cpp)
    elseif(TARGET_PLATFORM STREQUAL UEFI AND CMAKE_HOST_SYSTEM_NAME STREQUAL Linux)
        target_sources(vmmctl PRIVATE main/linux_uefi_launch/main.cpp)
    else()
        target_sources(vmmctl PRIVATE main/unsupported/main.cpp)
    endif()
else()
    target_sources(vmmctl PRIVATE main/unsupported/main.cpp)
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

if(NOT BUILD_VMMCTL)
    set_target_properties(vmmctl PROPERTIES
        EXCLUDE_FROM_ALL ON
    )
endif()

install(TARGETS vmmctl DESTINATION bin)
