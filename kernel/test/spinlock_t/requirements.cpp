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

#include "../../src/spinlock_t.hpp"

#include <tls_t.hpp>

#include <bsl/discard.hpp>
#include <bsl/ut.hpp>

namespace mk
{
    constinit spinlock_t const verify_constinit{};

    // Needed for requirements testing
    // NOLINTNEXTLINE(bsl-user-defined-type-names-match-header-name)
    class fixture_t final
    {
        spinlock_t spinlock{};

    public:
        [[nodiscard]] constexpr auto
        test_member_const() const noexcept -> bool
        {
            bsl::discard(spinlock.is_locked());

            return true;
        }

        [[nodiscard]] constexpr auto
        test_member_nonconst() noexcept -> bool
        {
            tls_t tls{};
            spinlock.lock(tls);
            spinlock.unlock(tls);
            bsl::discard(spinlock.is_locked());

            return true;
        }
    };

    constexpr fixture_t fixture1{};

    /// <!-- description -->
    ///   @brief Implements a yield for the spinlock
    ///
    extern "C" void
    yield() noexcept
    {}
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
    bsl::enable_color();
    mk::yield();

    bsl::ut_scenario{"verify supports constinit"} = []() {
        bsl::discard(mk::verify_constinit);
    };

    bsl::ut_scenario{"verify noexcept"} = []() {
        bsl::ut_given{} = []() {
            mk::spinlock_t spinlock{};
            mk::tls_t tls{};
            bsl::ut_then{} = []() {
                static_assert(noexcept(mk::spinlock_t{}));
                static_assert(noexcept(spinlock.lock(tls)));
                static_assert(noexcept(spinlock.unlock(tls)));
                static_assert(noexcept(spinlock.is_locked()));
            };
        };
    };

    bsl::ut_scenario{"verify constness"} = []() {
        bsl::ut_given{} = []() {
            mk::fixture_t fixture2{};
            bsl::ut_then{} = [&fixture2]() {
                static_assert(mk::fixture1.test_member_const());
                bsl::ut_check(fixture2.test_member_nonconst());
            };
        };
    };

    return bsl::ut_success();
}
