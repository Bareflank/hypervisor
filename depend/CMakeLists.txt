# TODO: Integrate a real import with this project using CMake's find_package
add_library(bsl INTERFACE)
target_include_directories(bsl INTERFACE bsl/include)
