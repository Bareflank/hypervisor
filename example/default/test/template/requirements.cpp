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

    constinit bsl::errc_type const g_verify_constinit{};

    /// NOTE:
    /// - The following is used to ensure that each function is marked as
    ///   const as needed. Everything in the test_member_const function
    ///   should be marked as const. If it is not, it will not compile.
    ///   The test_member_nonconst function should have all of the functions
    ///   to ensure that everything is tested.
    /// - Also note that in this test we have two of our classes under test.
    ///   This is to support the == and != operator functions. These functions
    ///   are not member functions, but we add them to these tests anyways
    ///   as they have to use member functions, which adds an additional check
    ///   encase we are missing something, and it allows the non-const tests
    ///   to be the same as the noexcept tests.
    /// - The const test does not need to test constructors as that doesn't
    ///   make much sense, and it is expect that for some classes, not all of
    ///   the member functions will be in the const test as they will not be
    ///   marked as const. The non-const test should have every function
    ///   including the constructors.
    ///

    // NOLINTNEXTLINE(bsl-user-defined-type-names-match-header-name)
    class fixture_t final
    {
        bsl::errc_type m_errc1{};
        bsl::errc_type m_errc2{};

    public:
        [[nodiscard]] constexpr auto
        test_member_const() const noexcept -> bool
        {
            bsl::discard(m_errc1.get());
            bsl::discard(!m_errc1);
            bsl::discard(m_errc1.success());
            bsl::discard(m_errc1.failure());
            bsl::discard(m_errc1.is_checked());
            bsl::discard(m_errc1.is_unchecked());
            bsl::discard(m_errc1 == m_errc2);
            bsl::discard(m_errc1 != m_errc2);

            return true;
        }

        [[nodiscard]] constexpr auto
        test_member_nonconst() noexcept -> bool
        {
            constexpr auto the_answer{42_i32};

            bsl::discard(bsl::errc_type{});
            bsl::discard(bsl::errc_type{the_answer.get()});
            bsl::discard(bsl::errc_type{the_answer});
            bsl::discard(m_errc1.get());
            bsl::discard(!m_errc1);
            bsl::discard(m_errc1.success());
            bsl::discard(m_errc1.failure());
            bsl::discard(m_errc1.is_checked());
            bsl::discard(m_errc1.is_unchecked());
            bsl::discard(m_errc1 == m_errc2);
            bsl::discard(m_errc1 != m_errc2);

            return true;
        }
    };

    /// NOTE:
    /// - The following verifies that all of our code will compile as a
    ///   constexpr. If test_member_nonconst contains a call to all of the
    ///   functions in your class, the following will not compile if anything
    ///   in the class is not constexpr friendly.
    ///

    constexpr fixture_t FIXTURE1{};
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
        bsl::discard(FIXTURE1);
    };

    /// NOTE:
    /// - The following verifies that all functions are marked as noexcept.
    ///   This list should include not only all of the functions, but all
    ///   constructors as well.
    ///

    bsl::ut_scenario{"verify noexcept"} = []() noexcept {
        bsl::ut_given{} = []() noexcept {
            bsl::errc_type errc1{};
            bsl::errc_type errc2{};
            constexpr auto the_answer{42_i32};
            bsl::ut_then{} = []() noexcept {
                static_assert(noexcept(bsl::errc_type{}));
                static_assert(noexcept(bsl::errc_type{the_answer.get()}));
                static_assert(noexcept(bsl::errc_type{the_answer}));
                static_assert(noexcept(errc1.get()));
                static_assert(noexcept(!errc1));
                static_assert(noexcept(errc1.success()));
                static_assert(noexcept(errc1.failure()));
                static_assert(noexcept(errc1.is_checked()));
                static_assert(noexcept(errc1.is_unchecked()));
                static_assert(noexcept(errc1 == errc2));
                static_assert(noexcept(errc1 != errc2));
            };
        };
    };

    /// NOTE:
    /// - The following is what actually verifies constness. This can be
    ///   left as is in each test. It is important to note that we use a
    ///   static_assert here to ensure that the const functions are also
    ///   constexpr friendly as yet another verifier that this is working
    ///   correctly.
    ///

    bsl::ut_scenario{"verify constness"} = []() noexcept {
        bsl::ut_given{} = []() noexcept {
            fixture_t fixture2{};
            bsl::ut_then{} = [&]() noexcept {
                static_assert(FIXTURE1.test_member_const());
                bsl::ut_check(fixture2.test_member_nonconst());
            };
        };
    };

    /// NOTE:
    /// - The following a second version of this, designed to support
    ///   classes that are not constexpr friendly. Ideally, you will never
    ///   need this, but in some cases, this might be needed. The difference
    ///   is we use const instead of a global constexpr used in a static
    ///   assert.
    ///

    bsl::ut_scenario{"verify constness without using constexpr"} = []() noexcept {
        bsl::ut_given{} = []() noexcept {
            fixture_t fixture2{};
            fixture_t const fixture3{};
            bsl::ut_then{} = [&]() noexcept {
                bsl::ut_check(fixture3.test_member_const());
                bsl::ut_check(fixture2.test_member_nonconst());
            };
        };
    };

    return bsl::ut_success();
}
