/// @copyright
/// Copyright (C) 2020 Assured Information Security, Inc.
///
/// @copyright
/// Permission is hereby granted, free of charge, to any person obtaining a copy
/// of this software and associated documentation files (the "Software"), to deal
/// in the Software without restriction, including without limitation the rights
/// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
/// copies of the Software, and to permit persons to whom the Software is
/// furnished to do so, subject to the following conditions:
///
/// @copyright
/// The above copyright notice and this permission notice shall be included in
/// all copies or substantial portions of the Software.
///
/// @copyright
/// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
/// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
/// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
/// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
/// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
/// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
/// SOFTWARE.

#ifndef DUMMY_ERRC_TYPES_HPP
#define DUMMY_ERRC_TYPES_HPP

#include <bsl/convert.hpp>
#include <bsl/errc_type.hpp>

namespace mk
{
    /// @brief Defines the "fail initialize" case
    // We want our implementation to mimic C++ here.
    // NOLINTNEXTLINE(bsl-name-case)
    constexpr bsl::errc_type errc_fail_initialize{0x00FF0001_i32};

    /// @brief Defines the "fail initialize and release" case
    // We want our implementation to mimic C++ here.
    // NOLINTNEXTLINE(bsl-name-case)
    constexpr bsl::errc_type errc_fail_initialize_and_release{0x00FF0002_i32};

    /// @brief Defines the "fail release" case
    // We want our implementation to mimic C++ here.
    // NOLINTNEXTLINE(bsl-name-case)
    constexpr bsl::errc_type errc_fail_release{0x00FF0003_i32};

    /// @brief Defines the "vm_pool_t failure" case
    // We want our implementation to mimic C++ here.
    // NOLINTNEXTLINE(bsl-name-case)
    constexpr bsl::errc_type errc_vm_pool_failure{0x00FF0004_i32};

    /// @brief Defines the "vp_pool_t failure" case
    // We want our implementation to mimic C++ here.
    // NOLINTNEXTLINE(bsl-name-case)
    constexpr bsl::errc_type errc_vp_pool_failure{0x00FF0005_i32};

    /// @brief Defines the "vs_pool_t failure" case
    // We want our implementation to mimic C++ here.
    // NOLINTNEXTLINE(bsl-name-case)
    constexpr bsl::errc_type errc_vs_pool_failure{0x00FF0006_i32};

    /// @brief Defines the "ext pool failure" case
    // We want our implementation to mimic C++ here.
    // NOLINTNEXTLINE(bsl-name-case)
    constexpr bsl::errc_type errc_ext_pool_failure{0x00FF0007_i32};

    /// @brief Defines the "vm is deallocated failure" case
    // We want our implementation to mimic C++ here.
    // NOLINTNEXTLINE(bsl-name-case)
    constexpr bsl::errc_type errc_vm_is_deallocated_failure{0x00FF0008_i32};

    /// @brief Defines the "vm is allocated failure" case
    // We want our implementation to mimic C++ here.
    // NOLINTNEXTLINE(bsl-name-case)
    constexpr bsl::errc_type errc_vm_is_allocated_failure{0x00FF0009_i32};

    /// @brief Defines the "vm is zombie failure" case
    // We want our implementation to mimic C++ here.
    // NOLINTNEXTLINE(bsl-name-case)
    constexpr bsl::errc_type errc_vm_is_zombie_failure{0x00FF000A_i32};
}

#endif
