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

#include "../../../src/dispatch_syscall_bf_mem_op.hpp"

#include <bf_constants.hpp>
#include <ext_t.hpp>
#include <huge_pool_t.hpp>
#include <page_pool_t.hpp>
#include <tls_t.hpp>

#include <bsl/convert.hpp>
#include <bsl/safe_integral.hpp>
#include <bsl/ut.hpp>

namespace mk
{
    /// <!-- description -->
    ///   @brief Used to execute the actual checks. We put the checks in this
    ///     function so that we can validate the tests both at compile-time
    ///     and at run-time. If a bsl::ut_check fails, the tests will either
    ///     fail fast at run-time, or will produce a compile-time error.
    ///
    /// <!-- inputs/outputs -->
    ///   @return Always returns bsl::exit_success.
    ///
    [[nodiscard]] constexpr auto
    tests() noexcept -> bsl::exit_code
    {
        bsl::ut_scenario{"invalid_handle"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                huge_pool_t mut_huge_pool{};
                ext_t mut_ext{};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_ext.initialize({}, {}, {}, {}, {}));
                    mut_tls.ext = &mut_ext;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            dispatch_syscall_bf_mem_op(mut_tls, mut_page_pool, mut_huge_pool) !=
                            syscall::BF_STATUS_SUCCESS);
                    };
                };
            };
        };

        bsl::ut_scenario{"unknown syscall"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                huge_pool_t mut_huge_pool{};
                ext_t mut_ext{};
                constexpr auto syscall{0xFFFFFFFFFFFFFFFF_u64};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_ext.initialize({}, {}, {}, {}, {}));
                    mut_tls.ext_syscall = syscall.get();
                    mut_tls.ext_reg0 = bsl::to_u64(mut_ext.open_handle()).get();
                    mut_tls.ext = &mut_ext;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            dispatch_syscall_bf_mem_op(mut_tls, mut_page_pool, mut_huge_pool) !=
                            syscall::BF_STATUS_SUCCESS);
                    };
                };
            };
        };

        bsl::ut_scenario{"ALLOC_PAGE_IDX_VAL"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                huge_pool_t mut_huge_pool{};
                ext_t mut_ext{};
                constexpr auto syscall{syscall::BF_MEM_OP_ALLOC_PAGE_IDX_VAL};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_ext.initialize({}, {}, {}, {}, {}));
                    mut_tls.ext = &mut_ext;
                    mut_tls.ext_syscall = syscall.get();
                    mut_tls.ext_reg0 = bsl::to_u64(mut_ext.open_handle()).get();
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            dispatch_syscall_bf_mem_op(mut_tls, mut_page_pool, mut_huge_pool) ==
                            syscall::BF_STATUS_SUCCESS);
                    };
                };
            };
        };

        bsl::ut_scenario{"ALLOC_PAGE_IDX_VAL alloc fails"} = [&]() noexcept {
            bsl::ut_given_at_runtime{} = [&]() noexcept {
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                huge_pool_t mut_huge_pool{};
                ext_t mut_ext{};
                constexpr auto syscall{syscall::BF_MEM_OP_ALLOC_PAGE_IDX_VAL};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_ext.initialize({}, {}, {}, {}, {}));
                    mut_tls.ext = &mut_ext;
                    mut_tls.ext_syscall = syscall.get();
                    mut_tls.ext_reg0 = bsl::to_u64(mut_ext.open_handle()).get();
                    mut_tls.test_virt = bsl::safe_u64::failure();
                    mut_tls.test_phys = bsl::safe_u64::failure();
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            dispatch_syscall_bf_mem_op(mut_tls, mut_page_pool, mut_huge_pool) !=
                            syscall::BF_STATUS_SUCCESS);
                    };
                };
            };
        };

        bsl::ut_scenario{"ALLOC_HUGE_IDX_VAL"} = [&]() noexcept {
            bsl::ut_given_at_runtime{} = [&]() noexcept {
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                huge_pool_t mut_huge_pool{};
                ext_t mut_ext{};
                constexpr auto syscall{syscall::BF_MEM_OP_ALLOC_HUGE_IDX_VAL};
                constexpr auto size{0x2000_u64};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_ext.initialize({}, {}, {}, {}, {}));
                    mut_tls.ext = &mut_ext;
                    mut_tls.ext_syscall = syscall.get();
                    mut_tls.ext_reg0 = bsl::to_u64(mut_ext.open_handle()).get();
                    mut_tls.ext_reg1 = size.get();
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            dispatch_syscall_bf_mem_op(mut_tls, mut_page_pool, mut_huge_pool) ==
                            syscall::BF_STATUS_SUCCESS);
                    };
                };
            };
        };

        bsl::ut_scenario{"ALLOC_HUGE_IDX_VAL invalid size #1"} = [&]() noexcept {
            bsl::ut_given_at_runtime{} = [&]() noexcept {
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                huge_pool_t mut_huge_pool{};
                ext_t mut_ext{};
                constexpr auto syscall{syscall::BF_MEM_OP_ALLOC_HUGE_IDX_VAL};
                constexpr auto size{0x1000_u64};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_ext.initialize({}, {}, {}, {}, {}));
                    mut_tls.ext = &mut_ext;
                    mut_tls.ext_syscall = syscall.get();
                    mut_tls.ext_reg0 = bsl::to_u64(mut_ext.open_handle()).get();
                    mut_tls.ext_reg1 = size.get();
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            dispatch_syscall_bf_mem_op(mut_tls, mut_page_pool, mut_huge_pool) !=
                            syscall::BF_STATUS_SUCCESS);
                    };
                };
            };
        };

        bsl::ut_scenario{"ALLOC_HUGE_IDX_VAL invalid size #2"} = [&]() noexcept {
            bsl::ut_given_at_runtime{} = [&]() noexcept {
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                huge_pool_t mut_huge_pool{};
                ext_t mut_ext{};
                constexpr auto syscall{syscall::BF_MEM_OP_ALLOC_HUGE_IDX_VAL};
                constexpr auto size{HYPERVISOR_MK_HUGE_POOL_SIZE};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_ext.initialize({}, {}, {}, {}, {}));
                    mut_tls.ext = &mut_ext;
                    mut_tls.ext_syscall = syscall.get();
                    mut_tls.ext_reg0 = bsl::to_u64(mut_ext.open_handle()).get();
                    mut_tls.ext_reg1 = size.get();
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            dispatch_syscall_bf_mem_op(mut_tls, mut_page_pool, mut_huge_pool) !=
                            syscall::BF_STATUS_SUCCESS);
                    };
                };
            };
        };

        bsl::ut_scenario{"ALLOC_HUGE_IDX_VAL invalid size #3"} = [&]() noexcept {
            bsl::ut_given_at_runtime{} = [&]() noexcept {
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                huge_pool_t mut_huge_pool{};
                ext_t mut_ext{};
                constexpr auto syscall{syscall::BF_MEM_OP_ALLOC_HUGE_IDX_VAL};
                constexpr auto size{0x2042_u64};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_ext.initialize({}, {}, {}, {}, {}));
                    mut_tls.ext = &mut_ext;
                    mut_tls.ext_syscall = syscall.get();
                    mut_tls.ext_reg0 = bsl::to_u64(mut_ext.open_handle()).get();
                    mut_tls.ext_reg1 = size.get();
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            dispatch_syscall_bf_mem_op(mut_tls, mut_page_pool, mut_huge_pool) !=
                            syscall::BF_STATUS_SUCCESS);
                    };
                };
            };
        };

        bsl::ut_scenario{"ALLOC_HUGE_IDX_VAL alloc fails"} = [&]() noexcept {
            bsl::ut_given_at_runtime{} = [&]() noexcept {
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                huge_pool_t mut_huge_pool{};
                ext_t mut_ext{};
                constexpr auto syscall{syscall::BF_MEM_OP_ALLOC_HUGE_IDX_VAL};
                constexpr auto size{0x2000_u64};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_ext.initialize({}, {}, {}, {}, {}));
                    mut_tls.ext = &mut_ext;
                    mut_tls.ext_syscall = syscall.get();
                    mut_tls.ext_reg0 = bsl::to_u64(mut_ext.open_handle()).get();
                    mut_tls.ext_reg1 = size.get();
                    mut_tls.test_virt = bsl::safe_u64::failure();
                    mut_tls.test_phys = bsl::safe_u64::failure();
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            dispatch_syscall_bf_mem_op(mut_tls, mut_page_pool, mut_huge_pool) !=
                            syscall::BF_STATUS_SUCCESS);
                    };
                };
            };
        };

        return bsl::ut_success();
    }
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

    static_assert(mk::tests() == bsl::ut_success());
    return mk::tests();
}
