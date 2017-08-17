# ------------------------------------------------------------------------------
# CMake Includes
# ------------------------------------------------------------------------------

include(${CMAKE_INSTALL_PREFIX}/cmake/CMakeGlobal_Includes.txt)

# ------------------------------------------------------------------------------
# Targets
# ------------------------------------------------------------------------------

list(APPEND SOURCES
    map_ptr_x64.cpp
    memory_manager_x64.cpp
    page_table_entry_x64.cpp
    page_table_x64.cpp
    root_page_table_x64.cpp
)

if(BUILD_SHARED_LIBS)
    add_library(bfvmm_memory_manager SHARED ${SOURCES})
    target_compile_definitions(bfvmm_memory_manager PRIVATE SHARED_MEMORY_MANAGER)
    target_link_libraries(bfvmm_memory_manager bfvmm_intrinsics)
endif()

if(BUILD_STATIC_LIBS)
    add_library(bfvmm_memory_manager STATIC ${SOURCES})
    target_compile_definitions(bfvmm_memory_manager PUBLIC STATIC_MEMORY_MANAGER)
    target_compile_definitions(bfvmm_memory_manager PUBLIC STATIC_INTRINSICS)
endif()

install(TARGETS bfvmm_memory_manager DESTINATION ${INSTALL_LIB_DIR})
