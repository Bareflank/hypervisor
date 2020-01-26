add_library(vmm)

target_sources(vmm
    PRIVATE
        entry.cpp
)

install(TARGETS vmm DESTINATION lib)
