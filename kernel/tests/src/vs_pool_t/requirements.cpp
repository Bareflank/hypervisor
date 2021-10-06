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

#include "../../../src/vs_pool_t.hpp"

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
    constinit mk::vs_pool_t const g_verify_constinit{};
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
            mk::vs_pool_t mut_vs_pool{};
            mk::vs_pool_t const vs_pool{};
            mk::tls_t mut_tls{};
            mk::page_pool_t mut_page_pool{};
            mk::intrinsic_t mut_intrinsic{};
            loader::state_save_t mut_state{};
            mk::vmexit_log_t mut_log{};
            bsl::ut_then{} = []() noexcept {
                static_assert(noexcept(mk::vs_pool_t{}));

                static_assert(noexcept(mut_vs_pool.initialize()));
                static_assert(noexcept(mut_vs_pool.release(mut_tls, mut_page_pool)));
                static_assert(noexcept(
                    mut_vs_pool.allocate(mut_tls, mut_page_pool, mut_intrinsic, {}, {}, {})));
                static_assert(noexcept(mut_vs_pool.deallocate(mut_tls, mut_page_pool, {})));
                static_assert(noexcept(mut_vs_pool.is_deallocated({})));
                static_assert(noexcept(mut_vs_pool.is_allocated({})));
                static_assert(noexcept(mut_vs_pool.set_active(mut_tls, mut_intrinsic, {})));
                static_assert(noexcept(mut_vs_pool.set_inactive(mut_tls, mut_intrinsic, {})));
                static_assert(noexcept(mut_vs_pool.is_active({})));
                static_assert(noexcept(mut_vs_pool.is_active_on_this_pp(mut_tls, {})));
                static_assert(noexcept(mut_vs_pool.migrate(mut_tls, mut_intrinsic, {}, {})));
                static_assert(noexcept(mut_vs_pool.assigned_vm({})));
                static_assert(noexcept(mut_vs_pool.assigned_vp({})));
                static_assert(noexcept(mut_vs_pool.assigned_pp({})));
                static_assert(noexcept(mut_vs_pool.vs_assigned_to_vm({})));
                static_assert(noexcept(mut_vs_pool.vs_assigned_to_vp({})));
                static_assert(noexcept(mut_vs_pool.vs_assigned_to_pp({})));
                static_assert(
                    noexcept(mut_vs_pool.state_save_to_vs(mut_tls, mut_intrinsic, &mut_state, {})));
                static_assert(
                    noexcept(mut_vs_pool.vs_to_state_save(mut_tls, mut_intrinsic, &mut_state, {})));
                static_assert(noexcept(mut_vs_pool.read(mut_tls, mut_intrinsic, {}, {})));
                static_assert(noexcept(mut_vs_pool.write(mut_tls, mut_intrinsic, {}, {}, {})));
                static_assert(noexcept(mut_vs_pool.run(mut_tls, mut_intrinsic, mut_log)));
                static_assert(noexcept(mut_vs_pool.advance_ip(mut_tls, mut_intrinsic, {})));
                static_assert(noexcept(mut_vs_pool.clear(mut_tls, mut_intrinsic, {})));
                static_assert(noexcept(mut_vs_pool.tlb_flush(mut_tls, mut_intrinsic, {})));
                static_assert(noexcept(mut_vs_pool.tlb_flush(mut_tls, mut_intrinsic, {}, {})));
                static_assert(noexcept(mut_vs_pool.dump(mut_tls, mut_intrinsic, {})));

                static_assert(noexcept(vs_pool.is_deallocated({})));
                static_assert(noexcept(vs_pool.is_allocated({})));
                static_assert(noexcept(vs_pool.is_active({})));
                static_assert(noexcept(vs_pool.is_active_on_this_pp(mut_tls, {})));
                static_assert(noexcept(vs_pool.assigned_vm({})));
                static_assert(noexcept(vs_pool.assigned_vp({})));
                static_assert(noexcept(vs_pool.assigned_pp({})));
                static_assert(noexcept(vs_pool.vs_assigned_to_vm({})));
                static_assert(noexcept(vs_pool.vs_assigned_to_vp({})));
                static_assert(noexcept(vs_pool.vs_assigned_to_pp({})));
                static_assert(noexcept(vs_pool.read(mut_tls, mut_intrinsic, {}, {})));
                static_assert(noexcept(vs_pool.dump(mut_tls, mut_intrinsic, {})));
            };
        };
    };

    return bsl::ut_success();
}
