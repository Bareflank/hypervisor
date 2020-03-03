add_executable(vmmctl)

target_sources(vmmctl PRIVATE
    src/main.cpp
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
