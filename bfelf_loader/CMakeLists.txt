cmake_minimum_required(VERSION 3.6)
project(bfelf_loader C CXX)

include(${CMAKE_INSTALL_PREFIX}/cmake/CMakeGlobal_Project.txt)

# ------------------------------------------------------------------------------
# Subdirectories
# ------------------------------------------------------------------------------

if(ENABLE_UNITTESTING AND BUILD_SHARED_LIBS)
    add_subdirectory(tests)
endif()

# ------------------------------------------------------------------------------
# Install
# ------------------------------------------------------------------------------

install(FILES include/bfelf_loader.h DESTINATION include)
