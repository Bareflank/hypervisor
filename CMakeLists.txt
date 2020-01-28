cmake_minimum_required(VERSION 3.13)
project(hypervisor NONE)
include(${CMAKE_CURRENT_LIST_DIR}/cmake/init_project.cmake)

print_banner()

add_subproject(
    vmm
    SOURCE_DIR ${CMAKE_CURRENT_LIST_DIR}/vmm
    INSTALL_PREFIX ${VMM_PREFIX_PATH}
    # DEPENDS bsl pal
)

add_subproject(
    vmmctl
    SOURCE_DIR ${CMAKE_CURRENT_LIST_DIR}/vmmctl
    INSTALL_PREFIX ${HOST_PREFIX_PATH}
)

print_usage()
