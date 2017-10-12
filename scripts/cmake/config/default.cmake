# All configurable build properties for Bareflank are defined here, set to
# their default values.

# ------------------------------------------------------------------------------
# Cmake build attributes
# ------------------------------------------------------------------------------

set(CMAKE_BUILD_TYPE "Release"
    CACHE STRING
    "The type of build"
)
set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS
    "Release"
    "Debug"
)

# ------------------------------------------------------------------------------
# Build attributes
# ------------------------------------------------------------------------------


set(BUILD_SHARED_LIBS OFF
    CACHE BOOL
    "Build libraries as shared libraries"
)

set(BUILD_STATIC_LIBS ON
    CACHE BOOL
    "Build libraries as static libraries"
)

# ------------------------------------------------------------------------------
# Developer Features
# ------------------------------------------------------------------------------

set(ENABLE_UNITTESTING OFF
    CACHE BOOL
    "Enable unit testing"
)

set(ENABLE_ASAN OFF
    CACHE BOOL
    "Enable clang AddressSanitizer"
)

set(ENABLE_USAN OFF
    CACHE BOOL
    "Enable clang UndefinedBehaviorSanitizer"
)

set(ENABLE_COVERITY OFF
    CACHE BOOL
    "Enable coverity static analysis"
)

set(ENABLE_TIDY OFF
    CACHE BOOL
    "Enable clang-tidy"
)

set(ENABLE_ASTYLE OFF
    CACHE BOOL
    "Enable astyle formatting"
)

set(ENABLE_DEPEND_UPDATES OFF
    CACHE BOOL
    "Check dependencies for updates on every build"
)

# ------------------------------------------------------------------------------
# Toolchains
# ------------------------------------------------------------------------------

set(TOOLCHAIN_PATH_BINUTILS ${BF_DEFAULT_TOOLCHAIN_FILE}
    CACHE PATH
    "Path to a cmake toolchain file for building GNU binutils"
)

set(TOOLCHAIN_PATH_CATCH ${BF_DEFAULT_TOOLCHAIN_FILE}
    CACHE PATH
    "Path to a cmake toolchain file for building catch"
)

set(TOOLCHAIN_PATH_GSL ${BF_DEFAULT_TOOLCHAIN_FILE}
    CACHE PATH
    "Path to a cmake toolchain file for building C++ guidelines support library"
)

set(TOOLCHAIN_PATH_HIPPOMOCKS ${BF_DEFAULT_TOOLCHAIN_FILE}
    CACHE PATH
    "Path to a cmake toolchain file for building hippomocks"
)

set(TOOLCHAIN_PATH_JSON ${BF_DEFAULT_TOOLCHAIN_FILE}
    CACHE PATH
    "Path to a cmake toolchain file for building JSON"
)

set(TOOLCHAIN_PATH_LIBCXX ${BF_DEFAULT_VMM_TOOLCHAIN_FILE}
    CACHE PATH
    "Path to a cmake toolchain file for building libc++"
)

set(TOOLCHAIN_PATH_LIBCXXABI ${BF_DEFAULT_VMM_TOOLCHAIN_FILE}
    CACHE PATH
    "Path to a cmake toolchain file for building libc++abi"
)

set(TOOLCHAIN_PATH_NEWLIB ${BF_DEFAULT_VMM_TOOLCHAIN_FILE}
    CACHE PATH
    "Path to a cmake toolchain file for building newlib"
)

set(TOOLCHAIN_PATH_BFDRIVER ${BF_DEFAULT_KERNEL_TOOLCHAIN_FILE}
    CACHE PATH
    "Path to a cmake toolchain file for building bfdriver"
)

set(TOOLCHAIN_PATH_BFELF_LOADER ${BF_DEFAULT_VMM_TOOLCHAIN_FILE}
    CACHE PATH
    "Path to a cmake toolchain file for building bfelf_loader"
)

set(TOOLCHAIN_PATH_BFM ${BF_DEFAULT_TOOLCHAIN_FILE}
    CACHE PATH
    "Path to a cmake toolchain file for building bfm"
)

set(TOOLCHAIN_PATH_BFSDK ${BF_DEFAULT_TOOLCHAIN_FILE}
    CACHE PATH
    "Path to a cmake toolchain file for building bfsdk"
)

set(TOOLCHAIN_PATH_BFSYSROOT ${BF_DEFAULT_VMM_TOOLCHAIN_FILE}
    CACHE PATH
    "Path to a cmake toolchain file for building bfsysroot"
)

set(TOOLCHAIN_PATH_BFVMM ${BF_DEFAULT_VMM_TOOLCHAIN_FILE}
    CACHE PATH
    "Path to a cmake toolchain file for building bfvmm"
)

