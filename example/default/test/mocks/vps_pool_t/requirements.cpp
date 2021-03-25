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

#include "../../../mocks/vps_pool_t.hpp"

#include <bsl/discard.hpp>
#include <bsl/ut.hpp>

namespace
{
    constinit example::vps_pool_t const g_verify_constinit{};

    // NOLINTNEXTLINE(bsl-user-defined-type-names-match-header-name)
    class fixture_t final
    {
        example::vps_pool_t m_vps_pool{};

    public:
        [[nodiscard]] static constexpr auto
        test_member_const() noexcept -> bool
        {
            /// NOTE:
            /// - vps_pool_t does not contain const member functions
            ///

            return true;
        }

        [[nodiscard]] constexpr auto
        test_member_nonconst() noexcept -> bool
        {
            example::gs_t gs{};
            example::tls_t tls{};
            syscall::bf_syscall_t sys{};
            example::intrinsic_t intrinsic{};

            bsl::discard(example::vps_pool_t{});
            bsl::discard(m_vps_pool.initialize(gs, tls, sys, intrinsic));
            m_vps_pool.release(gs, tls, sys, intrinsic);
            bsl::discard(m_vps_pool.allocate(gs, tls, sys, intrinsic, {}, {}));

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
    bsl::ut_scenario{"verify supports constinit"} = []() noexcept {
        bsl::discard(g_verify_constinit);
    };

    bsl::ut_scenario{"verify noexcept"} = []() noexcept {
        bsl::ut_given{} = []() noexcept {
            example::vps_pool_t vps_pool{};
            example::gs_t gs{};
            example::tls_t tls{};
            syscall::bf_syscall_t sys{};
            example::intrinsic_t intrinsic{};
            bsl::ut_then{} = []() noexcept {
                static_assert(noexcept(example::vps_pool_t{}));
                static_assert(noexcept(vps_pool.initialize(gs, tls, sys, intrinsic)));
                static_assert(noexcept(vps_pool.release(gs, tls, sys, intrinsic)));
                static_assert(noexcept(vps_pool.allocate(gs, tls, sys, intrinsic, {}, {})));
            };
        };
    };

    bsl::ut_scenario{"verify constness"} = []() noexcept {
        bsl::ut_given{} = []() noexcept {
            fixture_t fixture2{};
            bsl::ut_then{} = [&]() noexcept {
                static_assert(FIXTURE1.test_member_const());
                bsl::ut_check(fixture2.test_member_nonconst());
            };
        };
    };

    return bsl::ut_success();
}
