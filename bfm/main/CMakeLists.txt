# ------------------------------------------------------------------------------
# CMake Includes
# ------------------------------------------------------------------------------

include(${CMAKE_INSTALL_PREFIX}/cmake/CMakeGlobal_Includes.txt)

# ------------------------------------------------------------------------------
# Targets
# ------------------------------------------------------------------------------

add_executable(bfm main.cpp $<TARGET_OBJECTS:bfm_src> $<TARGET_OBJECTS:bfm_ioctl>)

if(CYGWIN STREQUAL "1")
    target_link_libraries(bfm setupapi)
endif()

target_compile_definitions(bfm PUBLIC STATIC_BFM_SRC)
target_compile_definitions(bfm PUBLIC STATIC_BFM_IOCTL)

# ------------------------------------------------------------------------------
# Install
# ------------------------------------------------------------------------------

install(TARGETS bfm DESTINATION bin)
