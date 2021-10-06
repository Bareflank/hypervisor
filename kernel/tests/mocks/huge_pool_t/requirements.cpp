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

#include "../../../mocks/huge_pool_t.hpp"

#include <basic_page_4k_t.hpp>
#include <page_4k_t.hpp>

#include <bsl/array.hpp>
#include <bsl/convert.hpp>
#include <bsl/discard.hpp>
#include <bsl/safe_integral.hpp>
#include <bsl/ut.hpp>

namespace
{
    /// @brief used by most of the tests
    constexpr auto POOL_SIZE{4_umx};

    /// @brief verify constinit it supported
    constinit mk::huge_pool_t const g_verify_constinit{};
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
    };

    bsl::ut_scenario{"verify noexcept"} = []() noexcept {
        bsl::ut_given{} = []() noexcept {
            mk::huge_pool_t mut_huge_pool{};
            mk::huge_pool_t const huge_pool{};
            bsl::array<mk::page_4k_t, POOL_SIZE.get()> mut_pool{};
            bsl::span mut_view{mut_pool};
            bsl::ut_then{} = []() noexcept {
                static_assert(noexcept(mk::huge_pool_t{}));

                static_assert(noexcept(mut_huge_pool.initialize(mut_view)));
                static_assert(noexcept(mut_huge_pool.allocate({}, {})));
                static_assert(noexcept(mut_huge_pool.deallocate({}, {})));
                static_assert(noexcept(mut_huge_pool.size()));
                static_assert(noexcept(mut_huge_pool.allocated({})));
                static_assert(noexcept(mut_huge_pool.remaining({})));
                static_assert(noexcept(mut_huge_pool.virt_to_phys<lib::basic_page_4k_t>({})));
                static_assert(noexcept(mut_huge_pool.dump({})));

                static_assert(noexcept(huge_pool.size()));
                static_assert(noexcept(huge_pool.allocated({})));
                static_assert(noexcept(huge_pool.remaining({})));
                static_assert(noexcept(huge_pool.dump({})));
            };
        };
    };

    return bsl::ut_success();
}
