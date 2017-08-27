cmake_minimum_required(VERSION 3.6)
project(bfsdk C CXX)

include(${CMAKE_SOURCE_DIR}/cmake/CMakeGlobal_Project.txt)

# ------------------------------------------------------------------------------
# JSON
# ------------------------------------------------------------------------------

list(APPEND JSON_CMAKE_ARGS
    -DCMAKE_INSTALL_PREFIX=${CMAKE_INSTALL_PREFIX}
)

ExternalProject_Add(
    json
    GIT_REPOSITORY      https://github.com/Bareflank/json.git
    GIT_TAG             v1.2
    GIT_SHALLOW         1
    CMAKE_ARGS          ${JSON_CMAKE_ARGS}
    PREFIX              ${CMAKE_BINARY_DIR}/json/prefix
    TMP_DIR             ${CMAKE_BINARY_DIR}/json/tmp
    STAMP_DIR           ${CMAKE_BINARY_DIR}/json/stamp
    DOWNLOAD_DIR        ${CMAKE_BINARY_DIR}/json/download
    SOURCE_DIR          ${CMAKE_BINARY_DIR}/json/src
    BINARY_DIR          ${CMAKE_BINARY_DIR}/json/build
)

# ------------------------------------------------------------------------------
# GSL
# ------------------------------------------------------------------------------

list(APPEND GSL_CMAKE_ARGS
    -DCMAKE_INSTALL_PREFIX=${CMAKE_INSTALL_PREFIX}
)

ExternalProject_Add(
    gsl
    GIT_REPOSITORY      https://github.com/Bareflank/GSL.git
    GIT_TAG             v1.2
    GIT_SHALLOW         1
    CMAKE_ARGS          ${GSL_CMAKE_ARGS}
    PREFIX              ${CMAKE_BINARY_DIR}/gsl/prefix
    TMP_DIR             ${CMAKE_BINARY_DIR}/gsl/tmp
    STAMP_DIR           ${CMAKE_BINARY_DIR}/gsl/stamp
    DOWNLOAD_DIR        ${CMAKE_BINARY_DIR}/gsl/download
    SOURCE_DIR          ${CMAKE_BINARY_DIR}/gsl/src
    BINARY_DIR          ${CMAKE_BINARY_DIR}/gsl/build
)

# ------------------------------------------------------------------------------
# Catch
# ------------------------------------------------------------------------------

if(ENABLE_UNITTESTING)

    list(APPEND CATCH_CMAKE_ARGS
        -DCMAKE_INSTALL_PREFIX=${CMAKE_INSTALL_PREFIX}
    )

    ExternalProject_Add(
        catch
        GIT_REPOSITORY      https://github.com/Bareflank/Catch.git
        GIT_TAG             v1.2
        GIT_SHALLOW         1
        CMAKE_ARGS          ${CATCH_CMAKE_ARGS}
        PREFIX              ${CMAKE_BINARY_DIR}/catch/prefix
        TMP_DIR             ${CMAKE_BINARY_DIR}/catch/tmp
        STAMP_DIR           ${CMAKE_BINARY_DIR}/catch/stamp
        DOWNLOAD_DIR        ${CMAKE_BINARY_DIR}/catch/download
        SOURCE_DIR          ${CMAKE_BINARY_DIR}/catch/src
        BINARY_DIR          ${CMAKE_BINARY_DIR}/catch/build
    )

endif()

# ------------------------------------------------------------------------------
# Hippomocks
# ------------------------------------------------------------------------------

if(ENABLE_UNITTESTING)

    list(APPEND HIPPOMOCKS_CMAKE_ARGS
        -DCMAKE_INSTALL_PREFIX=${CMAKE_INSTALL_PREFIX}
    )

    ExternalProject_Add(
        hippomocks
        GIT_REPOSITORY      https://github.com/Bareflank/hippomocks.git
        GIT_TAG             v1.2
        GIT_SHALLOW         1
        CMAKE_ARGS          ${HIPPOMOCKS_CMAKE_ARGS}
        PREFIX              ${CMAKE_BINARY_DIR}/hippomocks/prefix
        TMP_DIR             ${CMAKE_BINARY_DIR}/hippomocks/tmp
        STAMP_DIR           ${CMAKE_BINARY_DIR}/hippomocks/stamp
        DOWNLOAD_DIR        ${CMAKE_BINARY_DIR}/hippomocks/download
        SOURCE_DIR          ${CMAKE_BINARY_DIR}/hippomocks/src
        BINARY_DIR          ${CMAKE_BINARY_DIR}/hippomocks/build
    )

endif()

# ------------------------------------------------------------------------------
# Astyle
# ------------------------------------------------------------------------------

if(ENABLE_ASTYLE)

    list(APPEND ASTYLE_CMAKE_ARGS
        -DCMAKE_INSTALL_PREFIX=${CMAKE_INSTALL_PREFIX}
        -DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}
    )

    ExternalProject_Add(
        astyle
        GIT_REPOSITORY      https://github.com/Bareflank/astyle.git
        GIT_TAG             v1.2
        GIT_SHALLOW         1
        CMAKE_ARGS          ${ASTYLE_CMAKE_ARGS}
        PREFIX              ${CMAKE_BINARY_DIR}/astyle/prefix
        TMP_DIR             ${CMAKE_BINARY_DIR}/astyle/tmp
        STAMP_DIR           ${CMAKE_BINARY_DIR}/astyle/stamp
        DOWNLOAD_DIR        ${CMAKE_BINARY_DIR}/astyle/download
        SOURCE_DIR          ${CMAKE_BINARY_DIR}/astyle/src
        BINARY_DIR          ${CMAKE_BINARY_DIR}/astyle/build
    )

endif()

# ------------------------------------------------------------------------------
# Subdirectories
# ------------------------------------------------------------------------------

if(ENABLE_UNITTESTING)
    add_subdirectory(tests)
endif()

# ------------------------------------------------------------------------------
# Install
# ------------------------------------------------------------------------------

install(FILES cmake/CMakeFlags_Native_GCC.txt DESTINATION cmake)
install(FILES cmake/CMakeFlags_Native_VS.txt DESTINATION cmake)
install(FILES cmake/CMakeFlags_VMM.txt DESTINATION cmake)
install(FILES cmake/CMakeGlobal_Includes.txt DESTINATION cmake)
install(FILES cmake/CMakeGlobal_Project.txt DESTINATION cmake)
install(FILES cmake/CMakeOption_ASan.txt DESTINATION cmake)
install(FILES cmake/CMakeOption_Coverage.txt DESTINATION cmake)
install(FILES cmake/CMakeOption_USan.txt DESTINATION cmake)
install(FILES cmake/CMakeTarget_Format.txt DESTINATION cmake)
install(FILES cmake/CMakeTarget_Tidy.txt DESTINATION cmake)
install(FILES cmake/CMakeToolchain_VMM.txt DESTINATION cmake)
install(FILES cmake/CMakeToolchain_VMM_38.txt DESTINATION cmake)
install(FILES cmake/CMakeToolchain_VMM_39.txt DESTINATION cmake)
install(FILES cmake/CMakeToolchain_VMM_40.txt DESTINATION cmake)

install(FILES include/bfaffinity.h DESTINATION include)
install(FILES include/bfbenchmark.h DESTINATION include)
install(FILES include/bfbitmanip.h DESTINATION include)
install(FILES include/bfbuffer.h DESTINATION include)
install(FILES include/bfconstants.h DESTINATION include)
install(FILES include/bfdebug.h DESTINATION include)
install(FILES include/bfdebugringinterface.h DESTINATION include)
install(FILES include/bfdriverinterface.h DESTINATION include)
install(FILES include/bfdwarf.h DESTINATION include)
install(FILES include/bfehframelist.h DESTINATION include)
install(FILES include/bferrorcodes.h DESTINATION include)
install(FILES include/bfexception.h DESTINATION include)
install(FILES include/bfexports.h DESTINATION include)
install(FILES include/bffile.h DESTINATION include)
install(FILES include/bfgsl.h DESTINATION include)
install(FILES include/bfjson.h DESTINATION include)
install(FILES include/bfmemory.h DESTINATION include)
install(FILES include/bfnewdelete.h DESTINATION include)
install(FILES include/bfplatform.h DESTINATION include)
install(FILES include/bfshuffle.h DESTINATION include)
install(FILES include/bfstd.h DESTINATION include)
install(FILES include/bfstring.h DESTINATION include)
install(FILES include/bfsupport.h DESTINATION include)
install(FILES include/bfthreadcontext.h DESTINATION include)
install(FILES include/bftypes.h DESTINATION include)
install(FILES include/bfupperlower.h DESTINATION include)
install(FILES include/bfvcpuid.h DESTINATION include)
install(FILES include/bfvector.h DESTINATION include)
install(FILES include/bfvmcallinterface.h DESTINATION include)

install(FILES src/bfvmcall_intel_x64.asm DESTINATION src)

install(PROGRAMS scripts/bareflank_astyle_format.sh DESTINATION bin)
install(PROGRAMS scripts/bareflank_clang_tidy.sh DESTINATION bin)
install(PROGRAMS scripts/compiler_wrapper.sh DESTINATION bin)

install_symlink(compiler_wrapper.sh ${CMAKE_INSTALL_PREFIX}/bin/x86_64-vmm-clang)
install_symlink(compiler_wrapper.sh ${CMAKE_INSTALL_PREFIX}/bin/x86_64-vmm-clang-3.8)
install_symlink(compiler_wrapper.sh ${CMAKE_INSTALL_PREFIX}/bin/x86_64-vmm-clang-3.9)
install_symlink(compiler_wrapper.sh ${CMAKE_INSTALL_PREFIX}/bin/x86_64-vmm-clang-4.0)
