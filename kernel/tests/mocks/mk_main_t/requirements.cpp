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

#include "../../../mocks/mk_main_t.hpp"

#include <ext_pool_t.hpp>
#include <huge_pool_t.hpp>
#include <intrinsic_t.hpp>
#include <mk_args_t.hpp>
#include <page_pool_t.hpp>
#include <root_page_table_t.hpp>
#include <tls_t.hpp>
#include <vm_pool_t.hpp>
#include <vmexit_log_t.hpp>
#include <vp_pool_t.hpp>
#include <vs_pool_t.hpp>

#include <bsl/ut.hpp>

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

    bsl::ut_scenario{"verify noexcept"} = []() noexcept {
        bsl::ut_given{} = []() noexcept {
            mk::mk_main_t mut_mk_main{};
            mk::tls_t mut_tls{};
            mk::page_pool_t mut_page_pool{};
            mk::huge_pool_t mut_huge_pool{};
            mk::intrinsic_t mut_intrinsic{};
            mk::vm_pool_t mut_vm_pool{};
            mk::vp_pool_t mut_vp_pool{};
            mk::vs_pool_t mut_vs_pool{};
            mk::ext_pool_t mut_ext_pool{};
            mk::root_page_table_t mut_system_rpt{};
            mk::vmexit_log_t mut_log{};
            loader::mk_args_t mut_args{};
            bsl::ut_then{} = []() noexcept {
                static_assert(noexcept(mut_mk_main.process(
                    mut_tls,
                    mut_page_pool,
                    mut_huge_pool,
                    mut_intrinsic,
                    mut_vm_pool,
                    mut_vp_pool,
                    mut_vs_pool,
                    mut_ext_pool,
                    mut_system_rpt,
                    mut_log,
                    mut_args)));
            };
        };
    };

    return bsl::ut_success();
}
