# Init Subproject
#
# Initializes a sub project that was added to the build system through a
# higher-level super build
#

string(REPLACE ";" " " CMAKE_C_FLAGS "${CMAKE_C_FLAGS}")
string(REPLACE ";" " " CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS}")

include(${CMAKE_CURRENT_LIST_DIR}/function/silence_unused_cache_warning.cmake)
silence_unused_cache_warning()
