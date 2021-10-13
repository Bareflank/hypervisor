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

#ifndef MOCK_BASIC_IOCTL_HELPERS_HPP
#define MOCK_BASIC_IOCTL_HELPERS_HPP

#include <dump_vmm_args_t.hpp>
#include <start_vmm_args_t.hpp>
#include <stop_vmm_args_t.hpp>

#include <bsl/debug.hpp>
#include <bsl/expects.hpp>
#include <bsl/is_same.hpp>
#include <bsl/remove_cvref.hpp>
#include <bsl/safe_integral.hpp>
#include <bsl/typename.hpp>

namespace helpers
{
    /// <!-- description -->
    ///   @brief Defines storage for all of the types that are used
    ///     when data is read/written to the IOCTL interface.
    ///
    // NOLINTNEXTLINE(bsl-user-defined-type-names-match-header-name)
    struct ioctl_storage_t final
    {
        /// @brief store a start_vmm_args_t
        loader::start_vmm_args_t start_vmm_args;
        /// @brief store a stop_vmm_args_t
        loader::stop_vmm_args_t stop_vmm_args;
        /// @brief store a dump_vmm_args_t
        loader::dump_vmm_args_t dump_vmm_args;
        /// @brief store a safe_i64
        bsl::int64 i64;
    };

    /// <!-- description -->
    ///   @brief Sets the phys to virt translation in the provided map based
    ///     on the provided type T.
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the type of val to store
    ///   @param mut_store the ioctl_storage_t to store the pointer in
    ///   @param val the value to store
    ///
    template<typename T>
    constexpr void
    set_store(ioctl_storage_t &mut_store, T const &val) noexcept
    {
        if constexpr (bsl::is_same<bsl::remove_cvref_t<T>, loader::start_vmm_args_t>::value) {
            mut_store.start_vmm_args = val;
            return;
        }

        if constexpr (bsl::is_same<bsl::remove_cvref_t<T>, loader::stop_vmm_args_t>::value) {
            mut_store.stop_vmm_args = val;
            return;
        }

        if constexpr (bsl::is_same<bsl::remove_cvref_t<T>, loader::dump_vmm_args_t>::value) {
            mut_store.dump_vmm_args = val;
            return;
        }

        if constexpr (bsl::is_same<bsl::remove_cvref_t<T>, bsl::safe_i64>::value) {
            mut_store.i64 = val.get();
            return;
        }

        bsl::error() << "not implemented: " << bsl::type_name<T>() << bsl::endl;    // GRCOV_EXCLUDE
        bsl::expects(false);                                                        // GRCOV_EXCLUDE
    }

    /// <!-- description -->
    ///   @brief Returns a previously stored virt based on the provided
    ///     type T. Note that the type T must match the type T previously set.
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the type of val to get
    ///   @param store where to get the val from
    ///   @return Returns a previously stored value
    ///
    template<typename T>
    [[nodiscard]] constexpr auto
    get_store(ioctl_storage_t const &store) noexcept -> T
    {
        if constexpr (bsl::is_same<bsl::remove_cvref_t<T>, loader::start_vmm_args_t>::value) {
            return store.start_vmm_args;
        }

        if constexpr (bsl::is_same<bsl::remove_cvref_t<T>, loader::stop_vmm_args_t>::value) {
            return store.stop_vmm_args;
        }

        if constexpr (bsl::is_same<bsl::remove_cvref_t<T>, loader::dump_vmm_args_t>::value) {
            return store.dump_vmm_args;
        }

        if constexpr (bsl::is_same<bsl::remove_cvref_t<T>, bsl::safe_i64>::value) {
            return T{store.i64};
        }

        bsl::error() << "not implemented: " << bsl::type_name<T>() << bsl::endl;    // GRCOV_EXCLUDE
        bsl::expects(false);                                                        // GRCOV_EXCLUDE
        return {};                                                                  // GRCOV_EXCLUDE
    }
}

#endif
