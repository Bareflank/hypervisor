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

#include "../../src/huge_pool_t.hpp"

#include <bsl/convert.hpp>
#include <bsl/discard.hpp>
#include <bsl/ut.hpp>

namespace
{
    constinit mk::huge_pool_t const g_verify_constinit{};

    // NOLINTNEXTLINE(bsl-user-defined-type-names-match-header-name)
    class fixture_t final
    {
        mk::huge_pool_t m_pool{};

    public:
        [[nodiscard]] constexpr auto
        test_member_const() const noexcept -> bool
        {
            bool b{};

            bsl::discard(m_pool.virt_to_phys<bool>(&b));
            bsl::discard(m_pool.phys_to_virt<bool>({}));
            m_pool.dump();

            return true;
        }

        [[nodiscard]] constexpr auto
        test_member_nonconst() noexcept -> bool
        {
            bsl::span<bsl::uint8> view{};
            mk::tls_t tls{};
            bool b{};

            bsl::discard(mk::huge_pool_t{});
            m_pool.initialize(view);
            bsl::discard(m_pool.allocate(tls, {}));
            m_pool.deallocate(tls, {});
            bsl::discard(m_pool.virt_to_phys<bool>(&b));
            bsl::discard(m_pool.phys_to_virt<bool>({}));
            m_pool.dump();

            return true;
        }
    };

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
    bsl::ut_scenario{"verify supports constinit/constexpr"} = []() noexcept {
        bsl::discard(g_verify_constinit);
        bsl::discard(FIXTURE1);
    };

    bsl::ut_scenario{"verify noexcept"} = []() noexcept {
        bsl::ut_given{} = []() noexcept {
            mk::huge_pool_t pool{};
            bsl::span<bsl::uint8> view{};
            mk::tls_t tls{};
            bool b{};
            bsl::ut_then{} = []() noexcept {
                static_assert(noexcept(mk::huge_pool_t{}));
                static_assert(noexcept(pool.initialize(view)));
                static_assert(noexcept(pool.allocate(tls, {})));
                static_assert(noexcept(pool.deallocate(tls, {})));
                static_assert(noexcept(pool.virt_to_phys<bool>(&b)));
                static_assert(noexcept(pool.phys_to_virt<bool>({})));
                static_assert(noexcept(pool.dump()));
            };
        };
    };

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
