cmake_minimum_required(VERSION 3.6)
project(hypervisor C CXX)

set(DISABLE_OPTIONS ON)
set(DISABLE_TARGETS ON)

include(${CMAKE_SOURCE_DIR}/bfsdk/cmake/CMakeGlobal_Project.txt)

# ------------------------------------------------------------------------------
# Prefixes
# ------------------------------------------------------------------------------

set(BAREFLANK_INSTALL_PREFIX ${CMAKE_BINARY_DIR}/bfprefix)
set(BAREFLANK_INSTALL_TEST_PREFIX ${CMAKE_BINARY_DIR}/bfprefix_test)

# ------------------------------------------------------------------------------
# Toolchain File
# ------------------------------------------------------------------------------

find_program(NASM_BIN nasm)

if(NASM_BIN STREQUAL "NASM_BIN-NOTFOUND")
    message(FATAL_ERROR "Unable to find nasm, or nasm is not installed")
endif()

find_program(PYTHON_BIN python)

if(PYTHON_BIN STREQUAL "PYTHON_BIN-NOTFOUND")
    message(FATAL_ERROR "Unable to find python, or python is not installed")
endif()

find_program(GIT_BIN git)

if(GIT_BIN STREQUAL "GIT_BIN-NOTFOUND")
    message(FATAL_ERROR "Unable to find git, or git is not installed")
endif()

find_program(CLANG_BIN_40 clang-4.0)
find_program(CLANG_BIN_39 clang-3.9)
find_program(CLANG_BIN_38 clang-3.8)
find_program(CLANG_BIN clang)

if(NOT CLANG_BIN_40 STREQUAL "CLANG_BIN_40-NOTFOUND")
    set(CLANG_BIN ${CLANG_BIN_40})
    set(PREFERRED_VMM_TOOLCHAIN ${CMAKE_SOURCE_DIR}/bfsdk/cmake/CMakeToolchain_VMM_40.txt)
elseif(NOT CLANG_BIN_39 STREQUAL "CLANG_BIN_39-NOTFOUND")
    set(CLANG_BIN ${CLANG_BIN_39})
    set(PREFERRED_VMM_TOOLCHAIN ${CMAKE_SOURCE_DIR}/bfsdk/cmake/CMakeToolchain_VMM_39.txt)
elseif(NOT CLANG_BIN_38 STREQUAL "CLANG_BIN_38-NOTFOUND")
    set(CLANG_BIN ${CLANG_BIN_38})
    set(PREFERRED_VMM_TOOLCHAIN ${CMAKE_SOURCE_DIR}/bfsdk/cmake/CMakeToolchain_VMM_38.txt)
elseif(NOT CLANG_BIN STREQUAL "CLANG_BIN-NOTFOUND")
    set(PREFERRED_VMM_TOOLCHAIN ${CMAKE_SOURCE_DIR}/bfsdk/cmake/CMakeToolchain_VMM.txt)
else()
    message(FATAL_ERROR "Unable to find clang, or clang is not installed")
endif()

message(STATUS "Git: ${GIT_BIN}")
message(STATUS "Python: ${PYTHON_BIN}")
message(STATUS "Clang: ${CLANG_BIN}")
message(STATUS "Nasm: ${NASM_BIN}")
message(STATUS "Preferred VMM Toolchain: ${PREFERRED_VMM_TOOLCHAIN}")

set(VMM_TOOLCHAIN_FILE ${PREFERRED_VMM_TOOLCHAIN} CACHE STRING "")

# ------------------------------------------------------------------------------
# Download Newlib
# ------------------------------------------------------------------------------

ExternalProject_Add(
    newlib
    GIT_REPOSITORY      https://github.com/Bareflank/newlib.git
    GIT_TAG             v1.2
    GIT_SHALLOW         1
    PREFIX              ${CMAKE_BINARY_DIR}/newlib/prefix
    TMP_DIR             ${CMAKE_BINARY_DIR}/newlib/tmp
    STAMP_DIR           ${CMAKE_BINARY_DIR}/newlib/stamp
    DOWNLOAD_DIR        ${CMAKE_BINARY_DIR}/newlib/download
    SOURCE_DIR          ${CMAKE_BINARY_DIR}/newlib/src
    BINARY_DIR          ${CMAKE_BINARY_DIR}/newlib/build
    CONFIGURE_COMMAND   ""
    BUILD_COMMAND       ""
    INSTALL_COMMAND     ""
    UPDATE_DISCONNECTED ${UPDATE_DISCONNECTED}
)

# ------------------------------------------------------------------------------
# Download LLVM
# ------------------------------------------------------------------------------

ExternalProject_Add(
    llvm
    GIT_REPOSITORY      https://github.com/Bareflank/llvm.git
    GIT_TAG             v1.2
    GIT_SHALLOW         1
    PREFIX              ${CMAKE_BINARY_DIR}/llvm/prefix
    TMP_DIR             ${CMAKE_BINARY_DIR}/llvm/tmp
    STAMP_DIR           ${CMAKE_BINARY_DIR}/llvm/stamp
    DOWNLOAD_DIR        ${CMAKE_BINARY_DIR}/llvm/download
    SOURCE_DIR          ${CMAKE_BINARY_DIR}/llvm/src
    BINARY_DIR          ${CMAKE_BINARY_DIR}/llvm/build
    CONFIGURE_COMMAND   ""
    BUILD_COMMAND       ""
    INSTALL_COMMAND     ""
    UPDATE_DISCONNECTED ${UPDATE_DISCONNECTED}
)

# ------------------------------------------------------------------------------
# Download Libcxx
# ------------------------------------------------------------------------------

ExternalProject_Add(
    libcxx
    GIT_REPOSITORY      https://github.com/Bareflank/libcxx.git
    GIT_TAG             v1.2
    GIT_SHALLOW         1
    PREFIX              ${CMAKE_BINARY_DIR}/libcxx/prefix
    TMP_DIR             ${CMAKE_BINARY_DIR}/libcxx/tmp
    STAMP_DIR           ${CMAKE_BINARY_DIR}/libcxx/stamp
    DOWNLOAD_DIR        ${CMAKE_BINARY_DIR}/libcxx/download
    SOURCE_DIR          ${CMAKE_BINARY_DIR}/libcxx/src
    BINARY_DIR          ${CMAKE_BINARY_DIR}/libcxx/build
    CONFIGURE_COMMAND   ""
    BUILD_COMMAND       ""
    INSTALL_COMMAND     ""
    UPDATE_DISCONNECTED ${UPDATE_DISCONNECTED}
)

# ------------------------------------------------------------------------------
# Download Libcxxabi
# ------------------------------------------------------------------------------

ExternalProject_Add(
    libcxxabi
    GIT_REPOSITORY      https://github.com/Bareflank/libcxxabi.git
    GIT_TAG             v1.2
    GIT_SHALLOW         1
    PREFIX              ${CMAKE_BINARY_DIR}/libcxxabi/prefix
    TMP_DIR             ${CMAKE_BINARY_DIR}/libcxxabi/tmp
    STAMP_DIR           ${CMAKE_BINARY_DIR}/libcxxabi/stamp
    DOWNLOAD_DIR        ${CMAKE_BINARY_DIR}/libcxxabi/download
    SOURCE_DIR          ${CMAKE_BINARY_DIR}/libcxxabi/src
    BINARY_DIR          ${CMAKE_BINARY_DIR}/libcxxabi/build
    CONFIGURE_COMMAND   ""
    BUILD_COMMAND       ""
    INSTALL_COMMAND     ""
    UPDATE_DISCONNECTED ${UPDATE_DISCONNECTED}
)

# ------------------------------------------------------------------------------
# Binutils
# ------------------------------------------------------------------------------

list(APPEND BINUTILS_ARGS
    --prefix=${CMAKE_BINARY_DIR}/binutils/prefix
    --target=${BAREFLANK_TARGET}
    --disable-nls
    --disable-werror
    --with-sysroot
)

ExternalProject_Add(
    binutils
    URL                 http://ftp.gnu.org/gnu/binutils/binutils-2.28.tar.gz
    URL_MD5             d5d270fd0b698ed59ca5ade8e1b5059c
    PREFIX              ${CMAKE_BINARY_DIR}/binutils/prefix
    TMP_DIR             ${CMAKE_BINARY_DIR}/binutils/tmp
    STAMP_DIR           ${CMAKE_BINARY_DIR}/binutils/stamp
    DOWNLOAD_DIR        ${CMAKE_BINARY_DIR}/binutils/download
    SOURCE_DIR          ${CMAKE_BINARY_DIR}/binutils/src
    BINARY_DIR          ${CMAKE_BINARY_DIR}/binutils/build
    CONFIGURE_COMMAND   ${CMAKE_BINARY_DIR}/binutils/src/configure ${BINUTILS_ARGS}
    BUILD_COMMAND       make
    INSTALL_COMMAND     make install
    LOG_DOWNLOAD        1
    LOG_CONFIGURE       1
    LOG_BUILD           1
    LOG_INSTALL         1
)

ExternalProject_Add_Step(
    binutils
    prefix_install
    COMMAND ${CMAKE_COMMAND} -E copy_directory ${CMAKE_BINARY_DIR}/binutils/prefix/bin/ ${BAREFLANK_INSTALL_PREFIX}/bin/
    DEPENDEES install
)

# ------------------------------------------------------------------------------
# SDK
# ------------------------------------------------------------------------------
list(APPEND BFSDK_CMAKE_ARGS
    -DBAREFLANK_SOURCE_DIR=${CMAKE_SOURCE_DIR}
    -DBAREFLANK_BINARY_DIR=${CMAKE_BINARY_DIR}
    -DCMAKE_INSTALL_PREFIX=${BAREFLANK_INSTALL_PREFIX}
    -DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}
    -DENABLE_COVERAGE=${ENABLE_COVERAGE}
    -DENABLE_DYNAMIC_ASAN=${ENABLE_DYNAMIC_ASAN}
    -DENABLE_DYNAMIC_USAN=${ENABLE_DYNAMIC_USAN}
    -DENABLE_TIDY=${ENABLE_TIDY}
    -DENABLE_ASTYLE=${ENABLE_ASTYLE}
    -DENABLE_UNITTESTING=${ENABLE_UNITTESTING}
)

ExternalProject_Add(
    bfsdk
    CMAKE_ARGS          ${BFSDK_CMAKE_ARGS}
    PREFIX              ${CMAKE_BINARY_DIR}/bfsdk/prefix
    TMP_DIR             ${CMAKE_BINARY_DIR}/bfsdk/tmp
    STAMP_DIR           ${CMAKE_BINARY_DIR}/bfsdk/stamp
    DOWNLOAD_DIR        ${CMAKE_BINARY_DIR}/bfsdk/download
    SOURCE_DIR          ${CMAKE_SOURCE_DIR}/bfsdk
    BINARY_DIR          ${CMAKE_BINARY_DIR}/bfsdk/build
    UPDATE_COMMAND      ${CMAKE_COMMAND} -E echo "checking for updates"
    BUILD_COMMAND       ""
)

if(ENABLE_UNITTESTING)

    ExternalProject_Add_Step(
        bfsdk
        test_prefix_install
        COMMAND ${CMAKE_COMMAND} -E make_directory ${BAREFLANK_INSTALL_TEST_PREFIX}
        COMMAND ${CMAKE_COMMAND} -E create_symlink ${BAREFLANK_INSTALL_PREFIX}/bin ${BAREFLANK_INSTALL_TEST_PREFIX}/bin
        COMMAND ${CMAKE_COMMAND} -E create_symlink ${BAREFLANK_INSTALL_PREFIX}/cmake ${BAREFLANK_INSTALL_TEST_PREFIX}/cmake
        COMMAND ${CMAKE_COMMAND} -E create_symlink ${BAREFLANK_INSTALL_PREFIX}/include ${BAREFLANK_INSTALL_TEST_PREFIX}/include
        COMMAND ${CMAKE_COMMAND} -E create_symlink ${BAREFLANK_INSTALL_PREFIX}/lib ${BAREFLANK_INSTALL_TEST_PREFIX}/sdk_lib
        DEPENDEES install
    )

endif()

# ------------------------------------------------------------------------------
# Sysroot
# ------------------------------------------------------------------------------

list(APPEND BFSYSROOT_CMAKE_ARGS
    -DBAREFLANK_SOURCE_DIR=${CMAKE_SOURCE_DIR}
    -DBAREFLANK_BINARY_DIR=${CMAKE_BINARY_DIR}
    -DCMAKE_INSTALL_PREFIX=${BAREFLANK_INSTALL_PREFIX}
    -DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}
    -DCMAKE_TOOLCHAIN_FILE=${VMM_TOOLCHAIN_FILE}
    -DENABLE_COVERAGE=${ENABLE_COVERAGE}
    -DENABLE_DYNAMIC_ASAN=${ENABLE_DYNAMIC_ASAN}
    -DENABLE_DYNAMIC_USAN=${ENABLE_DYNAMIC_USAN}
    -DENABLE_TIDY=${ENABLE_TIDY}
    -DENABLE_ASTYLE=${ENABLE_ASTYLE}
    -DBUILD_SHARED_LIBS=${BAREFLANK_HOST_SHARED_LIBS}
    -DBUILD_STATIC_LIBS=${BAREFLANK_HOST_STATIC_LIBS}
)

ExternalProject_Add(
    bfsysroot
    CMAKE_ARGS          ${BFSYSROOT_CMAKE_ARGS}
    PREFIX              ${CMAKE_BINARY_DIR}/bfsysroot/prefix
    TMP_DIR             ${CMAKE_BINARY_DIR}/bfsysroot/tmp
    STAMP_DIR           ${CMAKE_BINARY_DIR}/bfsysroot/stamp
    DOWNLOAD_DIR        ${CMAKE_BINARY_DIR}/bfsysroot/download
    SOURCE_DIR          ${CMAKE_SOURCE_DIR}/bfsysroot
    BINARY_DIR          ${CMAKE_BINARY_DIR}/bfsysroot/build
    UPDATE_COMMAND      ${CMAKE_COMMAND} -E echo "checking for updates"
    INSTALL_COMMAND     ""
    DEPENDS             bfsdk newlib llvm libcxx libcxxabi binutils
)

# if(ENABLE_UNITTESTING)

#     list(APPEND TEST_BFSYSROOT_CMAKE_ARGS
#         -DBAREFLANK_SOURCE_DIR=${CMAKE_SOURCE_DIR}
#         -DBAREFLANK_BINARY_DIR=${CMAKE_BINARY_DIR}
#         -DCMAKE_INSTALL_PREFIX=${BAREFLANK_INSTALL_TEST_PREFIX}
#         -DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}
#         -DENABLE_COVERAGE=${ENABLE_COVERAGE}
#         -DENABLE_DYNAMIC_ASAN=${ENABLE_DYNAMIC_ASAN}
#         -DENABLE_DYNAMIC_USAN=${ENABLE_DYNAMIC_USAN}
#         -DENABLE_TIDY=${ENABLE_TIDY}
#         -DENABLE_ASTYLE=${ENABLE_ASTYLE}
#         -DENABLE_UNITTESTING=${ENABLE_UNITTESTING}
#         -DBUILD_SHARED_LIBS=${BAREFLANK_TEST_SHARED_LIBS}
#         -DBUILD_STATIC_LIBS=${BAREFLANK_TEST_STATIC_LIBS}
#     )

#     ExternalProject_Add(
#         test_bfsysroot
#         CMAKE_ARGS          ${TEST_BFSYSROOT_CMAKE_ARGS}
#         PREFIX              ${CMAKE_BINARY_DIR}/test_bfsysroot/prefix
#         TMP_DIR             ${CMAKE_BINARY_DIR}/test_bfsysroot/tmp
#         STAMP_DIR           ${CMAKE_BINARY_DIR}/test_bfsysroot/stamp
#         DOWNLOAD_DIR        ${CMAKE_BINARY_DIR}/test_bfsysroot/download
#         SOURCE_DIR          ${CMAKE_SOURCE_DIR}/bfsysroot
#         BINARY_DIR          ${CMAKE_BINARY_DIR}/test_bfsysroot/build
#         UPDATE_COMMAND      ${CMAKE_COMMAND} -E echo "checking for updates"
#         INSTALL_COMMAND     ""
#         DEPENDS             bfsysroot
#     )

# endif()

# ------------------------------------------------------------------------------
# ELF Loader
# ------------------------------------------------------------------------------

list(APPEND BFELF_LOADER_CMAKE_ARGS
    -DBAREFLANK_SOURCE_DIR=${CMAKE_SOURCE_DIR}
    -DBAREFLANK_BINARY_DIR=${CMAKE_BINARY_DIR}
    -DCMAKE_INSTALL_PREFIX=${BAREFLANK_INSTALL_PREFIX}
    -DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}
    -DENABLE_COVERAGE=${ENABLE_COVERAGE}
    -DENABLE_DYNAMIC_ASAN=${ENABLE_DYNAMIC_ASAN}
    -DENABLE_DYNAMIC_USAN=${ENABLE_DYNAMIC_USAN}
    -DENABLE_TIDY=${ENABLE_TIDY}
    -DENABLE_ASTYLE=${ENABLE_ASTYLE}
    -DENABLE_UNITTESTING=${ENABLE_UNITTESTING}
    -DBUILD_SHARED_LIBS=${BAREFLANK_HOST_SHARED_LIBS}
    -DBUILD_STATIC_LIBS=${BAREFLANK_HOST_STATIC_LIBS}
)

ExternalProject_Add(
    bfelf_loader
    CMAKE_ARGS          ${BFELF_LOADER_CMAKE_ARGS}
    PREFIX              ${CMAKE_BINARY_DIR}/bfelf_loader/prefix
    TMP_DIR             ${CMAKE_BINARY_DIR}/bfelf_loader/tmp
    STAMP_DIR           ${CMAKE_BINARY_DIR}/bfelf_loader/stamp
    DOWNLOAD_DIR        ${CMAKE_BINARY_DIR}/bfelf_loader/download
    SOURCE_DIR          ${CMAKE_SOURCE_DIR}/bfelf_loader
    BINARY_DIR          ${CMAKE_BINARY_DIR}/bfelf_loader/build
    UPDATE_COMMAND      ${CMAKE_COMMAND} -E echo "checking for updates"
    BUILD_COMMAND       ""
    DEPENDS             bfsdk bfsysroot
)

# ------------------------------------------------------------------------------
# BFM
# ------------------------------------------------------------------------------

list(APPEND BFM_CMAKE_ARGS
    -DBAREFLANK_SOURCE_DIR=${CMAKE_SOURCE_DIR}
    -DBAREFLANK_BINARY_DIR=${CMAKE_BINARY_DIR}
    -DCMAKE_INSTALL_PREFIX=${BAREFLANK_INSTALL_PREFIX}
    -DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}
    -DENABLE_COVERAGE=${ENABLE_COVERAGE}
    -DENABLE_DYNAMIC_ASAN=${ENABLE_DYNAMIC_ASAN}
    -DENABLE_DYNAMIC_USAN=${ENABLE_DYNAMIC_USAN}
    -DENABLE_TIDY=${ENABLE_TIDY}
    -DENABLE_ASTYLE=${ENABLE_ASTYLE}
    -DENABLE_UNITTESTING=${ENABLE_UNITTESTING}
)

if(ENABLE_EXTENDED_APIS)
    list(APPEND BFM_CMAKE_ARGS
        "-DCMAKE_CXX_FLAGS=${CMAKE_CXX_FLAGS} -DBFM_DEFAULT_VMM=eapis"
    )
endif()

ExternalProject_Add(
    bfm
    CMAKE_ARGS          ${BFM_CMAKE_ARGS}
    PREFIX              ${CMAKE_BINARY_DIR}/bfm/prefix
    TMP_DIR             ${CMAKE_BINARY_DIR}/bfm/tmp
    STAMP_DIR           ${CMAKE_BINARY_DIR}/bfm/stamp
    DOWNLOAD_DIR        ${CMAKE_BINARY_DIR}/bfm/download
    SOURCE_DIR          ${CMAKE_SOURCE_DIR}/bfm
    BINARY_DIR          ${CMAKE_BINARY_DIR}/bfm/build
    UPDATE_COMMAND      ${CMAKE_COMMAND} -E echo "checking for updates"
    BUILD_COMMAND       ""
    DEPENDS             bfsdk bfelf_loader
)

# ------------------------------------------------------------------------------
# VMM
# ------------------------------------------------------------------------------

list(APPEND BFVMM_CMAKE_ARGS
    -DBAREFLANK_SOURCE_DIR=${CMAKE_SOURCE_DIR}
    -DBAREFLANK_BINARY_DIR=${CMAKE_BINARY_DIR}
    -DCMAKE_INSTALL_PREFIX=${BAREFLANK_INSTALL_PREFIX}
    -DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}
    -DCMAKE_TOOLCHAIN_FILE=${VMM_TOOLCHAIN_FILE}
    -DENABLE_COVERAGE=${ENABLE_COVERAGE}
    -DENABLE_DYNAMIC_ASAN=${ENABLE_DYNAMIC_ASAN}
    -DENABLE_DYNAMIC_USAN=${ENABLE_DYNAMIC_USAN}
    -DENABLE_TIDY=${ENABLE_TIDY}
    -DENABLE_ASTYLE=${ENABLE_ASTYLE}
    -DBUILD_SHARED_LIBS=${BAREFLANK_HOST_SHARED_LIBS}
    -DBUILD_STATIC_LIBS=${BAREFLANK_HOST_STATIC_LIBS}
)

ExternalProject_Add(
    bfvmm
    CMAKE_ARGS          ${BFVMM_CMAKE_ARGS}
    PREFIX              ${CMAKE_BINARY_DIR}/bfvmm/prefix
    TMP_DIR             ${CMAKE_BINARY_DIR}/bfvmm/tmp
    STAMP_DIR           ${CMAKE_BINARY_DIR}/bfvmm/stamp
    DOWNLOAD_DIR        ${CMAKE_BINARY_DIR}/bfvmm/download
    SOURCE_DIR          ${CMAKE_SOURCE_DIR}/bfvmm
    BINARY_DIR          ${CMAKE_BINARY_DIR}/bfvmm/build
    UPDATE_COMMAND      ${CMAKE_COMMAND} -E echo "checking for updates"
    BUILD_COMMAND       ""
    DEPENDS             bfsdk bfsysroot
)

if(ENABLE_UNITTESTING)

    list(APPEND TEST_BFVMM_CMAKE_ARGS
        -DBAREFLANK_SOURCE_DIR=${CMAKE_SOURCE_DIR}
        -DBAREFLANK_BINARY_DIR=${CMAKE_BINARY_DIR}
        -DCMAKE_INSTALL_PREFIX=${BAREFLANK_INSTALL_TEST_PREFIX}
        -DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}
        -DENABLE_COVERAGE=${ENABLE_COVERAGE}
        -DENABLE_DYNAMIC_ASAN=${ENABLE_DYNAMIC_ASAN}
        -DENABLE_DYNAMIC_USAN=${ENABLE_DYNAMIC_USAN}
        -DENABLE_TIDY=${ENABLE_TIDY}
        -DENABLE_ASTYLE=${ENABLE_ASTYLE}
        -DENABLE_UNITTESTING=${ENABLE_UNITTESTING}
        -DBUILD_SHARED_LIBS=${BAREFLANK_TEST_SHARED_LIBS}
        -DBUILD_STATIC_LIBS=${BAREFLANK_TEST_STATIC_LIBS}
    )

    ExternalProject_Add(
        test_bfvmm
        CMAKE_ARGS          ${TEST_BFVMM_CMAKE_ARGS}
        PREFIX              ${CMAKE_BINARY_DIR}/test_bfvmm/prefix
        TMP_DIR             ${CMAKE_BINARY_DIR}/test_bfvmm/tmp
        STAMP_DIR           ${CMAKE_BINARY_DIR}/test_bfvmm/stamp
        DOWNLOAD_DIR        ${CMAKE_BINARY_DIR}/test_bfvmm/download
        SOURCE_DIR          ${CMAKE_SOURCE_DIR}/bfvmm
        BINARY_DIR          ${CMAKE_BINARY_DIR}/test_bfvmm/build
        UPDATE_COMMAND      ${CMAKE_COMMAND} -E echo "checking for updates"
        BUILD_COMMAND       ""
        DEPENDS             bfvmm
    )

endif()

# ------------------------------------------------------------------------------
# Driver
# ------------------------------------------------------------------------------

list(APPEND BFDRIVER_CMAKE_ARGS
    -DBAREFLANK_SOURCE_DIR=${CMAKE_SOURCE_DIR}
    -DBAREFLANK_BINARY_DIR=${CMAKE_BINARY_DIR}
    -DCMAKE_INSTALL_PREFIX=${BAREFLANK_INSTALL_PREFIX}
    -DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}
    -DENABLE_COVERAGE=${ENABLE_COVERAGE}
    -DENABLE_DYNAMIC_ASAN=${ENABLE_DYNAMIC_ASAN}
    -DENABLE_DYNAMIC_USAN=${ENABLE_DYNAMIC_USAN}
    -DENABLE_TIDY=${ENABLE_TIDY}
    -DENABLE_ASTYLE=${ENABLE_ASTYLE}
    -DENABLE_UNITTESTING=${ENABLE_UNITTESTING}
    -DBUILD_SHARED_LIBS=${BAREFLANK_TEST_SHARED_LIBS}
    -DBUILD_STATIC_LIBS=${BAREFLANK_TEST_STATIC_LIBS}
)

ExternalProject_Add(
    bfdriver
    CMAKE_ARGS          ${BFDRIVER_CMAKE_ARGS}
    PREFIX              ${CMAKE_BINARY_DIR}/bfdriver/prefix
    TMP_DIR             ${CMAKE_BINARY_DIR}/bfdriver/tmp
    STAMP_DIR           ${CMAKE_BINARY_DIR}/bfdriver/stamp
    DOWNLOAD_DIR        ${CMAKE_BINARY_DIR}/bfdriver/download
    SOURCE_DIR          ${CMAKE_SOURCE_DIR}/bfdriver
    BINARY_DIR          ${CMAKE_BINARY_DIR}/bfdriver/build
    UPDATE_COMMAND      ${CMAKE_COMMAND} -E echo "checking for updates"
    BUILD_COMMAND       ""
    INSTALL_COMMAND     ""
    DEPENDS             bfsdk bfelf_loader
)

# ------------------------------------------------------------------------------
# Extended APIs
# ------------------------------------------------------------------------------

if(ENABLE_EXTENDED_APIS)

    if(NOT EXTENDED_APIS_PATH)
        set(EXTENDED_APIS_URL "https://github.com/bareflank/extended_apis.git" CACHE STRING "")
        set(EXTENDED_APIS_TAG "master" CACHE STRING "")
        set(EXTENDED_APIS_PATH ${CMAKE_BINARY_DIR}/extended_apis/src CACHE PATH "")
    endif()

    message(STATUS "EXTENDED_APIS_PATH: ${EXTENDED_APIS_PATH}")
    if(EXTENDED_APIS_URL OR EXTENDED_APIS_TAG)
        message(STATUS "EXTENDED_APIS_URL: ${EXTENDED_APIS_URL}")
        message(STATUS "EXTENDED_APIS_TAG: ${EXTENDED_APIS_TAG}")
    endif()

    list(APPEND EXTENDED_APIS_CMAKE_ARGS
        -DBAREFLANK_SOURCE_DIR=${CMAKE_SOURCE_DIR}
        -DBAREFLANK_BINARY_DIR=${CMAKE_BINARY_DIR}
        -DCMAKE_INSTALL_PREFIX=${BAREFLANK_INSTALL_PREFIX}
        -DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}
        -DCMAKE_TOOLCHAIN_FILE=${VMM_TOOLCHAIN_FILE}
        -DENABLE_COVERAGE=${ENABLE_COVERAGE}
        -DENABLE_DYNAMIC_ASAN=${ENABLE_DYNAMIC_ASAN}
        -DENABLE_DYNAMIC_USAN=${ENABLE_DYNAMIC_USAN}
        -DENABLE_TIDY=${ENABLE_TIDY}
        -DENABLE_ASTYLE=${ENABLE_ASTYLE}
        -DENABLE_UNITTESTING=${ENABLE_UNITTESTING}
        -DBUILD_SHARED_LIBS=${BAREFLANK_HOST_SHARED_LIBS}
        -DBUILD_STATIC_LIBS=${BAREFLANK_HOST_STATIC_LIBS}
    )

    ExternalProject_Add(
        extended_apis
        GIT_REPOSITORY      ${EXTENDED_APIS_URL}
        GIT_TAG             ${EXTENDED_APIS_TAG}
        GIT_SHALLOW         1
        CMAKE_ARGS          ${EXTENDED_APIS_CMAKE_ARGS}
        PREFIX              ${CMAKE_BINARY_DIR}/extended_apis/prefix
        TMP_DIR             ${CMAKE_BINARY_DIR}/extended_apis/tmp
        STAMP_DIR           ${CMAKE_BINARY_DIR}/extended_apis/stamp
        DOWNLOAD_DIR        ${CMAKE_BINARY_DIR}/extended_apis/download
        SOURCE_DIR          ${EXTENDED_APIS_PATH}
        BINARY_DIR          ${CMAKE_BINARY_DIR}/extended_apis/build
        UPDATE_COMMAND      ${CMAKE_COMMAND} -E echo "checking for updates"
        UPDATE_DISCONNECTED ${UPDATE_DISCONNECTED}
        BUILD_COMMAND       ""
        DEPENDS             bfsdk bfvmm
    )

    if(ENABLE_UNITTESTING)

        list(APPEND TEST_EXTENDED_APIS_CMAKE_ARGS
            -DBAREFLANK_SOURCE_DIR=${CMAKE_SOURCE_DIR}
            -DBAREFLANK_BINARY_DIR=${CMAKE_BINARY_DIR}
            -DCMAKE_INSTALL_PREFIX=${BAREFLANK_INSTALL_TEST_PREFIX}
            -DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}
            -DENABLE_COVERAGE=${ENABLE_COVERAGE}
            -DENABLE_DYNAMIC_ASAN=${ENABLE_DYNAMIC_ASAN}
            -DENABLE_DYNAMIC_USAN=${ENABLE_DYNAMIC_USAN}
            -DENABLE_TIDY=${ENABLE_TIDY}
            -DENABLE_ASTYLE=${ENABLE_ASTYLE}
            -DENABLE_UNITTESTING=${ENABLE_UNITTESTING}
            -DBUILD_SHARED_LIBS=${BAREFLANK_HOST_SHARED_LIBS}
            -DBUILD_STATIC_LIBS=${BAREFLANK_HOST_STATIC_LIBS}
        )

        ExternalProject_Add(
            test_extended_apis
            CMAKE_ARGS          ${TEST_EXTENDED_APIS_CMAKE_ARGS}
            PREFIX              ${CMAKE_BINARY_DIR}/test_extended_apis/prefix
            TMP_DIR             ${CMAKE_BINARY_DIR}/test_extended_apis/tmp
            STAMP_DIR           ${CMAKE_BINARY_DIR}/test_extended_apis/stamp
            DOWNLOAD_DIR        ${CMAKE_BINARY_DIR}/test_extended_apis/download
            SOURCE_DIR          ${EXTENDED_APIS_PATH}
            BINARY_DIR          ${CMAKE_BINARY_DIR}/test_extended_apis/build
            UPDATE_COMMAND      ${CMAKE_COMMAND} -E echo "checking for updates"
            BUILD_COMMAND       ""
            DEPENDS             extended_apis test_bfvmm
        )

    endif()

endif()

# ------------------------------------------------------------------------------
# Clean
# ------------------------------------------------------------------------------

add_custom_target(distclean
    COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR}/bfdriver/build --target clean
    COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR}/bfelf_loader/build --target clean
    COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR}/bfm/build --target clean
    COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR}/bfsdk/build --target clean
    COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR}/bfsysroot/build --target distclean
    COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR}/bfvmm/build --target clean

    COMMAND ${CMAKE_COMMAND} -E remove_directory ${BAREFLANK_INSTALL_PREFIX}/include
    COMMAND ${CMAKE_COMMAND} -E remove_directory ${BAREFLANK_INSTALL_PREFIX}/lib
    COMMAND ${CMAKE_COMMAND} -E remove_directory ${BAREFLANK_INSTALL_PREFIX}/sysroots

    COMMAND ${CMAKE_COMMAND} -E remove_directory ${BAREFLANK_INSTALL_TEST_PREFIX}/include
    COMMAND ${CMAKE_COMMAND} -E remove_directory ${BAREFLANK_INSTALL_TEST_PREFIX}/lib
    COMMAND ${CMAKE_COMMAND} -E remove_directory ${BAREFLANK_INSTALL_TEST_PREFIX}/sysroots
)

if(ENABLE_UNITTESTING)
    add_custom_command(TARGET distclean COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR}/test_bfvmm/build --target clean)
    # add_custom_command(TARGET distclean COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR}/test_bfsysroot/build --target clean)
endif()

if(ENABLE_EXTENDED_APIS)
    add_custom_command(TARGET distclean COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR}/extended_apis/build --target clean)
    if(ENABLE_UNITTESTING)
        add_custom_command(TARGET distclean COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR}/test_extended_apis/build --target clean)
    endif()
endif()

# ------------------------------------------------------------------------------
# Test
# ------------------------------------------------------------------------------

if(ENABLE_UNITTESTING)

    if(POLICY CMP0037)
        cmake_policy(SET CMP0037 OLD)
    endif()

    add_custom_target(test
        # COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR}/bfdriver/build --target test
        COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR}/bfelf_loader/build --target test
        # COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR}/bfm/build --target test
        COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR}/bfsdk/build --target test
        # COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR}/test_bfsysroot/build --target test
        COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR}/test_bfvmm/build --target test
    )

    if(ENABLE_EXTENDED_APIS)
        add_custom_command(TARGET test COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR}/test_extended_apis/build --target test)
    endif()

endif()

# ------------------------------------------------------------------------------
# Tidy
# ------------------------------------------------------------------------------

if(ENABLE_TIDY)

    add_custom_target(tidy
        # COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR}/bfdriver/build --target tidy
        COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR}/bfvmm/build --target tidy
        # COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR}/bfm/build --target tidy
        COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR}/bfsdk/build --target tidy
        # COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR}/bfsysroot/build --target tidy
    )

    add_custom_target(tidy-all
        # COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR}/bfdriver/build --target tidy-all
        COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR}/bfelf_loader/build --target tidy-all
        # COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR}/bfm/build --target tidy-all
        COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR}/bfsdk/build --target tidy-all
        # COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR}/bfsysroot/build --target tidy-all
    )

    if(NOT ENABLE_UNITTESTING)
        add_custom_command(TARGET tidy COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR}/bfvmm/build --target tidy)
        add_custom_command(TARGET tidy COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR}/bfsysroot/build --target tidy)
        add_custom_command(TARGET tidy-all COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR}/bfvmm/build --target tidy-all)
        add_custom_command(TARGET tidy-all COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR}/bfsysroot/build --target tidy-all)
    else()
        add_custom_command(TARGET tidy COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR}/test_bfvmm/build --target tidy)
        # add_custom_command(TARGET tidy COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR}/test_bfsysroot/build --target tidy)
        add_custom_command(TARGET tidy-all COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR}/test_bfvmm/build --target tidy-all)
        # add_custom_command(TARGET tidy-all COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR}/test_bfsysroot/build --target tidy-all)
    endif()

    if(ENABLE_EXTENDED_APIS)
        if(NOT ENABLE_UNITTESTING)
            add_custom_command(TARGET tidy COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR}/extended_apis/build --target tidy)
            add_custom_command(TARGET tidy-all COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR}/extended_apis/build --target tidy-all)
        else()
            add_custom_command(TARGET tidy COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR}/test_extended_apis/build --target tidy)
            add_custom_command(TARGET tidy-all COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR}/test_extended_apis/build --target tidy-all)
        endif()
    endif()

endif()

# ------------------------------------------------------------------------------
# Astyle
# ------------------------------------------------------------------------------

if(ENABLE_ASTYLE)

    add_custom_target(format
        COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR}/bfdriver/build --target format
        COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR}/bfelf_loader/build --target format
        COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR}/bfm/build --target format
        COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR}/bfsdk/build --target format
        COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR}/bfsysroot/build --target format
    )

    add_custom_target(format-all
        COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR}/bfdriver/build --target format-all
        COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR}/bfelf_loader/build --target format-all
        COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR}/bfm/build --target format-all
        COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR}/bfsdk/build --target format-all
        COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR}/bfsysroot/build --target format-all
    )

    if(NOT ENABLE_UNITTESTING)
        add_custom_command(TARGET format COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR}/bfvmm/build --target format)
        add_custom_command(TARGET format COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR}/bfsysroot/build --target format)
        add_custom_command(TARGET format-all COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR}/bfvmm/build --target format-all)
        add_custom_command(TARGET format-all COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR}/bfsysroot/build --target format-all)
    else()
        add_custom_command(TARGET format COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR}/test_bfvmm/build --target format)
        # add_custom_command(TARGET format COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR}/test_bfsysroot/build --target format)
        add_custom_command(TARGET format-all COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR}/test_bfvmm/build --target format-all)
        # add_custom_command(TARGET format-all COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR}/test_bfsysroot/build --target format-all)
    endif()

    if(ENABLE_EXTENDED_APIS)
        if(NOT ENABLE_UNITTESTING)
            add_custom_command(TARGET format COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR}/extended_apis/build --target format)
            add_custom_command(TARGET format-all COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR}/extended_apis/build --target format-all)
        else()
            add_custom_command(TARGET format COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR}/test_extended_apis/build --target format)
            add_custom_command(TARGET format-all COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR}/test_extended_apis/build --target format-all)
        endif()
    endif()

endif()

# ------------------------------------------------------------------------------
# BFM Shortcuts
# ------------------------------------------------------------------------------

add_custom_target(quick COMMAND ${SUDO} ${BAREFLANK_INSTALL_PREFIX}/bin/bfm quick)
add_custom_target(stop COMMAND ${SUDO} ${BAREFLANK_INSTALL_PREFIX}/bin/bfm stop)
add_custom_target(unload COMMAND ${SUDO} ${BAREFLANK_INSTALL_PREFIX}/bin/bfm unload)
add_custom_target(dump COMMAND ${SUDO} ${BAREFLANK_INSTALL_PREFIX}/bin/bfm dump)
add_custom_target(status COMMAND ${SUDO} ${BAREFLANK_INSTALL_PREFIX}/bin/bfm status)

# ------------------------------------------------------------------------------
# Driver Shortcuts
# ------------------------------------------------------------------------------

add_custom_target(driver_build COMMAND make driver_build > /dev/null VERBATIM WORKING_DIRECTORY ${CMAKE_BINARY_DIR}/bfdriver/build)
add_custom_target(driver_load COMMAND make driver_load > /dev/null VERBATIM WORKING_DIRECTORY ${CMAKE_BINARY_DIR}/bfdriver/build)
add_custom_target(driver_unload COMMAND make driver_unload > /dev/null VERBATIM WORKING_DIRECTORY ${CMAKE_BINARY_DIR}/bfdriver/build)
add_custom_target(driver_clean COMMAND make driver_clean > /dev/null VERBATIM WORKING_DIRECTORY ${CMAKE_BINARY_DIR}/bfdriver/build)
add_custom_target(driver_quick DEPENDS driver_load driver_build)
