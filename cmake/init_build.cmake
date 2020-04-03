include(${CMAKE_CURRENT_LIST_DIR}/color.cmake)
include(${CMAKE_CURRENT_LIST_DIR}/package.cmake)

include(${CMAKE_CURRENT_LIST_DIR}/function/hypervisor_print_banner.cmake)
include(${CMAKE_CURRENT_LIST_DIR}/function/hypervisor_print_usage.cmake)
include(${CMAKE_CURRENT_LIST_DIR}/function/hypervisor_add_config.cmake)

include(${CMAKE_CURRENT_LIST_DIR}/config/default.cmake)

include(FetchContent)
set(FETCHCONTENT_BASE_DIR ${CMAKE_BINARY_DIR}/depend)
set(FETCHCONTENT_UPDATES_DISCONNECTED ON)
set(FETCHCONTENT_QUIET ON)

include(${CMAKE_CURRENT_LIST_DIR}/depend/bsl.cmake)
include(${CMAKE_CURRENT_LIST_DIR}/depend/pal.cmake)
