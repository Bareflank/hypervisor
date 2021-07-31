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

// #include "../../src/<name>.hpp"

#include <bsl/convert.hpp>
#include <bsl/discard.hpp>
#include <bsl/errc_type.hpp>
#include <bsl/move.hpp>
#include <bsl/safe_integral.hpp>
#include <bsl/ut.hpp>

namespace
{
    /// NOTE:
    /// - The requirements unit test ensures that the code adhere to specific
    ///   C++ requirements including constinit, constness, constexpr and
    ///   noexcept. This is a quick double check to make sure that your code
    ///   meets all of these requirements. Note that not all of the code
    ///   needs to have all of these, but instead, this unit test ensures that
    ///   each function has these as intended, and forces you to give your
    ///   code a once over for these specific attributes.
    /// - Replace bsl::errc_type with your type. We keep this in place so
    ///   that it is easy to see how to use each of these patterns.
    ///

    /// NOTE:
    /// - The following verifies that our type can be initialized using the
    ///   C++20 constinit keyword. This ensures that if we need to create a
    ///   global version of this (or something that uses this code), it is
    ///   initialized at compile-time and not at runtime.
    ///

    /// @brief verify constinit it supported
    constinit bsl::errc_type const g_verify_constinit{};
}

/// <!-- description -->
///   @brief Main function for this unit test. If a call to bsl::ut_check() fails
///     the application will fast fail. If all calls to bsl::ut_check() pass, this
///     function will successfully return with bsl::exit_success.
///
/// <!-- inputs/outputs -->
///   @return Always returns bsl::exit_success.
///
[[nodiscard]] auto
main() noexcept -> bsl::exit_code
{
    /// NOTE:
    /// - This is really just here to make some compilers happy that we have
    ///   a global variable and that it is actually being used.
    ///

    bsl::ut_scenario{"verify supports constinit/constexpr"} = []() noexcept {
        bsl::discard(g_verify_constinit);
    };

    /// NOTE:
    /// - The following verifies that all functions are marked as noexcept.
    ///   This list should include not only all of the functions, but all
    ///   constructors as well.
    /// - It also verifies that certain functions are labeled as const,
    ///   which behavior.cpp should be doing as well. Basically, each
    ///   function should be checked for noexcept twice. One for const, and
    ///   one for non-const. This is because most of the time, functions
    ///   that have both const and non-const are actually two different
    ///   functions, so checking both ensures all forms are verified.
    ///

    bsl::ut_scenario{"verify noexcept"} = []() noexcept {
        bsl::ut_given{} = []() noexcept {
            bsl::errc_type mut_errc1{};
            bsl::errc_type mut_errc2{};
            bsl::errc_type const errc3{};
            bsl::errc_type const errc4{};
            constexpr auto the_answer{42_i32};
            bsl::ut_then{} = []() noexcept {
                /// NOTE:
                /// - Check constructors
                ///

                static_assert(noexcept(bsl::errc_type{}));
                static_assert(noexcept(bsl::errc_type{the_answer.get()}));

                /// NOTE:
                /// - Check non-const
                ///

                static_assert(noexcept(mut_errc1 = errc3));
                static_assert(noexcept(mut_errc1 = bsl::move(mut_errc2)));
                static_assert(noexcept(mut_errc1.get()));
                static_assert(noexcept(!mut_errc1));
                static_assert(noexcept(mut_errc1.success()));
                static_assert(noexcept(mut_errc1.failure()));
                static_assert(noexcept(mut_errc1 == errc4));
                static_assert(noexcept(mut_errc1 != errc4));

                /// NOTE:
                /// - Check const
                ///

                static_assert(noexcept(errc3.get()));
                static_assert(noexcept(!errc3));
                static_assert(noexcept(errc3.success()));
                static_assert(noexcept(errc3.failure()));
                static_assert(noexcept(errc3 == errc4));
                static_assert(noexcept(errc3 != errc4));
            };
        };
    };

    return bsl::ut_success();
}
