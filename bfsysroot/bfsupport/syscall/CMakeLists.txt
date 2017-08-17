# ------------------------------------------------------------------------------
# CMake Includes
# ------------------------------------------------------------------------------

include(${CMAKE_INSTALL_PREFIX}/cmake/CMakeGlobal_Includes.txt)

# ------------------------------------------------------------------------------
# Custom Flags
# ------------------------------------------------------------------------------

if(CMAKE_TOOLCHAIN_FILE)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fno-rtti")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fno-exceptions")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fno-sized-deallocation")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fno-use-cxa-atexit")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fno-stack-protector")
endif()

# ------------------------------------------------------------------------------
# Targets
# ------------------------------------------------------------------------------

if(BUILD_SHARED_LIBS)
    add_library(bfsyscall SHARED syscall.cpp)
    target_compile_definitions(bfsyscall PRIVATE SHARED_SYSCALL)
endif()

if(BUILD_STATIC_LIBS)
    add_library(bfsyscall STATIC syscall.cpp)
    target_compile_definitions(bfsyscall PUBLIC STATIC_SYSCALL)
endif()

# ------------------------------------------------------------------------------
# Install
# ------------------------------------------------------------------------------

install(TARGETS bfsyscall DESTINATION ${INSTALL_LIB_DIR})
