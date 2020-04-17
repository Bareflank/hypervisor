message(STATUS "Adding dependency: bsl")

FetchContent_Declare(
    bsl
    GIT_REPOSITORY  https://github.com/bareflank/bsl.git
    GIT_TAG         55b98dc7c1d12a79e325d2a0bcd55b7b7e783ea3
)

FetchContent_GetProperties(bsl)

if(NOT bsl_POPULATED)
    set(BUILD_EXAMPLES OFF)
    set(BUILD_TESTS OFF)

    FetchContent_Populate(bsl)

    add_library(bsl INTERFACE)
    target_include_directories(bsl INTERFACE ${bsl_SOURCE_DIR}/include)
    # TODO: Use the following instead to add the bsl once it is stable
    # add_subdirectory(${bsl_SOURCE_DIR} ${bsl_BINARY_DIR})
endif()

