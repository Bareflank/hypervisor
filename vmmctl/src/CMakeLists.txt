add_executable(vmmctl)

target_sources(vmmctl
    PRIVATE
        main.cpp
)

install(TARGETS vmmctl DESTINATION bin)
