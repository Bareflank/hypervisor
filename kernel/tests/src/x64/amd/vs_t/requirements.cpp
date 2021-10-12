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

#include "../../../../../src/x64/amd/vs_t.hpp"

#include <intrinsic_t.hpp>
#include <page_pool_t.hpp>
#include <state_save_t.hpp>
#include <tls_t.hpp>
#include <vmexit_log_t.hpp>

#include <bsl/discard.hpp>
#include <bsl/ut.hpp>

namespace
{
    /// @brief verify constinit it supported
    constinit mk::vs_t const g_verify_constinit{};
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
            mk::vs_t mut_vs{};
            mk::vs_t const vs{};
            mk::tls_t mut_tls{};
            mk::page_pool_t mut_page_pool{};
            mk::intrinsic_t mut_intrinsic{};
            loader::state_save_t mut_state{};
            mk::vmexit_log_t mut_log{};
            bsl::ut_then{} = []() noexcept {
                static_assert(noexcept(mk::vs_t{}));

                static_assert(noexcept(mut_vs.initialize({})));
                static_assert(noexcept(mut_vs.release(mut_tls, mut_page_pool)));
                static_assert(noexcept(mut_vs.id()));
                static_assert(
                    noexcept(mut_vs.allocate(mut_tls, mut_page_pool, mut_intrinsic, {}, {}, {})));
                static_assert(noexcept(mut_vs.deallocate(mut_tls, mut_page_pool)));
                static_assert(noexcept(mut_vs.is_deallocated()));
                static_assert(noexcept(mut_vs.is_allocated()));
                static_assert(noexcept(mut_vs.set_active(mut_tls, mut_intrinsic)));
                static_assert(noexcept(mut_vs.set_inactive(mut_tls, mut_intrinsic)));
                static_assert(noexcept(mut_vs.is_active()));
                static_assert(noexcept(mut_vs.is_active_on_this_pp(mut_tls)));
                static_assert(noexcept(mut_vs.migrate(mut_tls, mut_intrinsic, {})));
                static_assert(noexcept(mut_vs.assigned_vm()));
                static_assert(noexcept(mut_vs.assigned_vp()));
                static_assert(noexcept(mut_vs.assigned_pp()));
                static_assert(
                    noexcept(mut_vs.state_save_to_vs(mut_tls, mut_intrinsic, &mut_state)));
                static_assert(
                    noexcept(mut_vs.vs_to_state_save(mut_tls, mut_intrinsic, &mut_state)));
                static_assert(noexcept(mut_vs.read(mut_tls, mut_intrinsic, {})));
                static_assert(noexcept(mut_vs.write(mut_tls, mut_intrinsic, {}, {})));
                static_assert(noexcept(mut_vs.run(mut_tls, mut_intrinsic, mut_log)));
                static_assert(noexcept(mut_vs.advance_ip(mut_tls, mut_intrinsic)));
                static_assert(noexcept(mut_vs.clear(mut_tls, mut_intrinsic)));
                static_assert(noexcept(mut_vs.tlb_flush(mut_tls, mut_intrinsic)));
                static_assert(noexcept(mut_vs.tlb_flush(mut_tls, mut_intrinsic, {})));
                static_assert(noexcept(mut_vs.dump(mut_tls, mut_intrinsic)));

                static_assert(noexcept(vs.id()));
                static_assert(noexcept(vs.is_deallocated()));
                static_assert(noexcept(vs.is_allocated()));
                static_assert(noexcept(vs.is_active()));
                static_assert(noexcept(vs.is_active_on_this_pp(mut_tls)));
                static_assert(noexcept(vs.assigned_vm()));
                static_assert(noexcept(vs.assigned_vp()));
                static_assert(noexcept(vs.assigned_pp()));
                static_assert(noexcept(vs.read(mut_tls, mut_intrinsic, {})));
                static_assert(noexcept(vs.dump(mut_tls, mut_intrinsic)));
            };
        };
    };

    return bsl::ut_success();
}
