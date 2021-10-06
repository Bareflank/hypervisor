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

#include <bf_constants.hpp>
#include <bf_reg_t.hpp>
#include <intrinsic_t.hpp>
#include <page_pool_t.hpp>
#include <state_save_t.hpp>
#include <tls_t.hpp>
#include <vmexit_log_t.hpp>

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
        bsl::ut_scenario{"initialize"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                vs_pool_t mut_vs_pool{};
                bsl::ut_then{} = [&]() noexcept {
                    mut_vs_pool.initialize();
                };
            };
        };

        bsl::ut_scenario{"release"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                vs_pool_t mut_vs_pool{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                bsl::ut_when{} = [&]() noexcept {
                    mut_vs_pool.initialize();
                    bsl::ut_then{} = [&]() noexcept {
                        mut_vs_pool.release(mut_tls, mut_page_pool);
                    };
                };
            };
        };

        bsl::ut_scenario{"release without initialize"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                vs_pool_t mut_vs_pool{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                bsl::ut_then{} = [&]() noexcept {
                    mut_vs_pool.release(mut_tls, mut_page_pool);
                };
            };
        };

        bsl::ut_scenario{"release after allocate"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                vs_pool_t mut_vs_pool{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                intrinsic_t mut_intrinsic{};
                bsl::ut_when{} = [&]() noexcept {
                    mut_vs_pool.initialize();
                    bsl::ut_required_step(
                        mut_vs_pool.allocate(mut_tls, mut_page_pool, mut_intrinsic, {}, {}, {}));
                    bsl::ut_then{} = [&]() noexcept {
                        mut_vs_pool.release(mut_tls, mut_page_pool);
                    };
                };
            };
        };

        bsl::ut_scenario{"allocate"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                vs_pool_t mut_vs_pool{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                intrinsic_t mut_intrinsic{};
                constexpr auto vmid{1_u16};
                constexpr auto vpid{1_u16};
                constexpr auto ppid{1_u16};
                bsl::ut_when{} = [&]() noexcept {
                    mut_vs_pool.initialize();
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(syscall::BF_INVALID_ID == mut_vs_pool.assigned_vm({}));
                        bsl::ut_check(mut_vs_pool.vs_assigned_to_vm(vmid).is_invalid());
                        bsl::ut_check(mut_vs_pool.vs_assigned_to_vp(vpid).is_invalid());
                        bsl::ut_check(mut_vs_pool.vs_assigned_to_pp(ppid).is_invalid());
                        bsl::ut_check(mut_vs_pool.allocate(
                            mut_tls, mut_page_pool, mut_intrinsic, vmid, vpid, ppid));
                        bsl::ut_check(vmid == mut_vs_pool.assigned_vm({}));
                        bsl::ut_check(vpid == mut_vs_pool.assigned_vp({}));
                        bsl::ut_check(ppid == mut_vs_pool.assigned_pp({}));
                        bsl::ut_check(mut_vs_pool.vs_assigned_to_vm(vmid).is_zero());
                        bsl::ut_check(mut_vs_pool.vs_assigned_to_vp(vpid).is_zero());
                        bsl::ut_check(mut_vs_pool.vs_assigned_to_pp(ppid).is_zero());
                    };
                };
            };
        };

        bsl::ut_scenario{"allocate out of vss"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                vs_pool_t mut_vs_pool{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                intrinsic_t mut_intrinsic{};
                bsl::ut_when{} = [&]() noexcept {
                    mut_vs_pool.initialize();
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_vs_pool.allocate(
                            mut_tls, mut_page_pool, mut_intrinsic, {}, {}, {}));
                        bsl::ut_check(mut_vs_pool.allocate(
                            mut_tls, mut_page_pool, mut_intrinsic, {}, {}, {}));
                        bsl::ut_check(
                            mut_vs_pool.allocate(mut_tls, mut_page_pool, mut_intrinsic, {}, {}, {})
                                .is_invalid());
                    };
                };
            };
        };

        bsl::ut_scenario{"deallocate"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                vs_pool_t mut_vs_pool{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                intrinsic_t mut_intrinsic{};
                constexpr auto vmid{1_u16};
                constexpr auto vpid{1_u16};
                constexpr auto ppid{1_u16};
                bsl::ut_when{} = [&]() noexcept {
                    mut_vs_pool.initialize();
                    bsl::ut_required_step(mut_vs_pool.allocate(
                        mut_tls, mut_page_pool, mut_intrinsic, vmid, vpid, ppid));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(vmid == mut_vs_pool.assigned_vm({}));
                        bsl::ut_check(vpid == mut_vs_pool.assigned_vp({}));
                        bsl::ut_check(ppid == mut_vs_pool.assigned_pp({}));
                        mut_vs_pool.deallocate(mut_tls, mut_page_pool, {});
                        bsl::ut_check(vmid != mut_vs_pool.assigned_vm({}));
                        bsl::ut_check(vpid != mut_vs_pool.assigned_vp({}));
                        bsl::ut_check(ppid != mut_vs_pool.assigned_pp({}));
                    };
                };
            };
        };

        bsl::ut_scenario{"deallocate without allocate"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                vs_pool_t mut_vs_pool{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                bsl::ut_when{} = [&]() noexcept {
                    mut_vs_pool.initialize();
                    bsl::ut_then{} = [&]() noexcept {
                        mut_vs_pool.deallocate(mut_tls, mut_page_pool, {});
                    };
                };
            };
        };

        bsl::ut_scenario{"allocation status functions"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                vs_pool_t mut_vs_pool{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                intrinsic_t mut_intrinsic{};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_vs_pool.is_deallocated({}));
                        bsl::ut_check(!mut_vs_pool.is_allocated({}));
                    };

                    mut_vs_pool.initialize();
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_vs_pool.is_deallocated({}));
                        bsl::ut_check(!mut_vs_pool.is_allocated({}));
                    };

                    bsl::ut_required_step(
                        mut_vs_pool.allocate(mut_tls, mut_page_pool, mut_intrinsic, {}, {}, {}));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(!mut_vs_pool.is_deallocated({}));
                        bsl::ut_check(mut_vs_pool.is_allocated({}));
                    };

                    mut_vs_pool.deallocate(mut_tls, mut_page_pool, {});
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_vs_pool.is_deallocated({}));
                        bsl::ut_check(!mut_vs_pool.is_allocated({}));
                    };

                    bsl::ut_required_step(
                        mut_vs_pool.allocate(mut_tls, mut_page_pool, mut_intrinsic, {}, {}, {}));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(!mut_vs_pool.is_deallocated({}));
                        bsl::ut_check(mut_vs_pool.is_allocated({}));
                    };

                    mut_vs_pool.release(mut_tls, mut_page_pool);
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_vs_pool.is_deallocated({}));
                        bsl::ut_check(!mut_vs_pool.is_allocated({}));
                    };
                };
            };
        };

        bsl::ut_scenario{"set_active"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                vs_pool_t mut_vs_pool{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                intrinsic_t mut_intrinsic{};
                constexpr auto vsid{0_u16};
                bsl::ut_when{} = [&]() noexcept {
                    mut_vs_pool.initialize();
                    mut_tls.active_vsid = syscall::BF_INVALID_ID.get();
                    bsl::ut_required_step(
                        mut_vs_pool.allocate(mut_tls, mut_page_pool, mut_intrinsic, {}, {}, {}));
                    mut_vs_pool.set_active(mut_tls, mut_intrinsic, {});
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(vsid == mut_tls.active_vsid);
                    };
                };
            };
        };

        bsl::ut_scenario{"set_inactive"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                vs_pool_t mut_vs_pool{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                intrinsic_t mut_intrinsic{};
                constexpr auto vsid{0_u16};
                bsl::ut_when{} = [=]() mutable noexcept {
                    mut_vs_pool.initialize();
                    mut_tls.active_vsid = vsid.get();
                    bsl::ut_required_step(
                        mut_vs_pool.allocate(mut_tls, mut_page_pool, mut_intrinsic, {}, {}, {}));
                    mut_vs_pool.set_inactive(mut_tls, mut_intrinsic, {});
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(syscall::BF_INVALID_ID == mut_tls.active_vsid);
                    };
                };

                bsl::ut_when{} = [=]() mutable noexcept {
                    mut_vs_pool.initialize();
                    mut_tls.active_vsid = vsid.get();
                    bsl::ut_required_step(
                        mut_vs_pool.allocate(mut_tls, mut_page_pool, mut_intrinsic, {}, {}, {}));
                    mut_vs_pool.set_inactive(mut_tls, mut_intrinsic, syscall::BF_INVALID_ID);
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(syscall::BF_INVALID_ID != mut_tls.active_vsid);
                    };
                };
            };
        };

        bsl::ut_scenario{"active status functions"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                vs_pool_t mut_vs_pool{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                intrinsic_t mut_intrinsic{};
                constexpr auto ppid{0_u16};
                constexpr auto online_pps{2_u16};
                bsl::ut_when{} = [&]() noexcept {
                    mut_tls.online_pps = online_pps.get();
                    mut_tls.active_vsid = syscall::BF_INVALID_ID.get();

                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_vs_pool.is_active({}).is_invalid());
                        bsl::ut_check(!mut_vs_pool.is_active_on_this_pp(mut_tls, {}));
                    };

                    mut_vs_pool.initialize();
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_vs_pool.is_active({}).is_invalid());
                        bsl::ut_check(!mut_vs_pool.is_active_on_this_pp(mut_tls, {}));
                    };

                    bsl::ut_required_step(
                        mut_vs_pool.allocate(mut_tls, mut_page_pool, mut_intrinsic, {}, {}, {}));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_vs_pool.is_active({}).is_invalid());
                        bsl::ut_check(!mut_vs_pool.is_active_on_this_pp(mut_tls, {}));
                    };

                    mut_vs_pool.set_active(mut_tls, mut_intrinsic, {});
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(ppid == mut_vs_pool.is_active({}));
                        bsl::ut_check(mut_vs_pool.is_active_on_this_pp(mut_tls, {}));
                    };

                    mut_vs_pool.set_inactive(mut_tls, mut_intrinsic, {});
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_vs_pool.is_active({}).is_invalid());
                        bsl::ut_check(!mut_vs_pool.is_active_on_this_pp(mut_tls, {}));
                    };
                };
            };
        };

        bsl::ut_scenario{"migrate"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                vs_pool_t mut_vs_pool{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                intrinsic_t mut_intrinsic{};
                bsl::ut_when{} = [&]() noexcept {
                    mut_vs_pool.initialize();
                    bsl::ut_required_step(
                        mut_vs_pool.allocate(mut_tls, mut_page_pool, mut_intrinsic, {}, {}, {}));
                    bsl::ut_then{} = [&]() noexcept {
                        mut_vs_pool.migrate(mut_tls, mut_intrinsic, {}, {});
                    };
                };
            };
        };

        bsl::ut_scenario{"state_save_to_vs"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                vs_pool_t mut_vs_pool{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                intrinsic_t mut_intrinsic{};
                loader::state_save_t const state{};
                bsl::ut_when{} = [&]() noexcept {
                    mut_vs_pool.initialize();
                    bsl::ut_required_step(
                        mut_vs_pool.allocate(mut_tls, mut_page_pool, mut_intrinsic, {}, {}, {}));
                    bsl::ut_then{} = [&]() noexcept {
                        mut_vs_pool.state_save_to_vs(mut_tls, mut_intrinsic, &state, {});
                    };
                };
            };
        };

        bsl::ut_scenario{"vs_to_state_save"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                vs_pool_t mut_vs_pool{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                intrinsic_t mut_intrinsic{};
                loader::state_save_t mut_state{};
                bsl::ut_when{} = [&]() noexcept {
                    mut_vs_pool.initialize();
                    bsl::ut_required_step(
                        mut_vs_pool.allocate(mut_tls, mut_page_pool, mut_intrinsic, {}, {}, {}));
                    bsl::ut_then{} = [&]() noexcept {
                        mut_vs_pool.vs_to_state_save(mut_tls, mut_intrinsic, &mut_state, {});
                    };
                };
            };
        };

        bsl::ut_scenario{"read/write"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                vs_pool_t mut_vs_pool{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                intrinsic_t mut_intrinsic{};
                constexpr auto reg{syscall::bf_reg_t::bf_reg_t_dummy};
                constexpr auto val{42_u64};
                bsl::ut_when{} = [&]() noexcept {
                    mut_vs_pool.initialize();
                    bsl::ut_required_step(
                        mut_vs_pool.allocate(mut_tls, mut_page_pool, mut_intrinsic, {}, {}, {}));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_vs_pool.write(mut_tls, mut_intrinsic, reg, val, {}));
                        bsl::ut_check(val == mut_vs_pool.read(mut_tls, mut_intrinsic, reg, {}));
                    };
                };
            };
        };

        bsl::ut_scenario{"run"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                vs_pool_t mut_vs_pool{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                intrinsic_t mut_intrinsic{};
                vmexit_log_t mut_log{};
                bsl::ut_when{} = [&]() noexcept {
                    mut_vs_pool.initialize();
                    bsl::ut_required_step(
                        mut_vs_pool.allocate(mut_tls, mut_page_pool, mut_intrinsic, {}, {}, {}));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_vs_pool.run(mut_tls, mut_intrinsic, mut_log));
                    };
                };
            };
        };

        bsl::ut_scenario{"advance_ip"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                vs_pool_t mut_vs_pool{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                intrinsic_t mut_intrinsic{};
                bsl::ut_when{} = [&]() noexcept {
                    mut_vs_pool.initialize();
                    bsl::ut_required_step(
                        mut_vs_pool.allocate(mut_tls, mut_page_pool, mut_intrinsic, {}, {}, {}));
                    bsl::ut_then{} = [&]() noexcept {
                        mut_vs_pool.advance_ip(mut_tls, mut_intrinsic, {});
                    };
                };
            };
        };

        bsl::ut_scenario{"clear"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                vs_pool_t mut_vs_pool{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                intrinsic_t mut_intrinsic{};
                bsl::ut_when{} = [&]() noexcept {
                    mut_vs_pool.initialize();
                    bsl::ut_required_step(
                        mut_vs_pool.allocate(mut_tls, mut_page_pool, mut_intrinsic, {}, {}, {}));
                    bsl::ut_then{} = [&]() noexcept {
                        mut_vs_pool.clear(mut_tls, mut_intrinsic, {});
                    };
                };
            };
        };

        bsl::ut_scenario{"tlb_flush"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                vs_pool_t mut_vs_pool{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                intrinsic_t mut_intrinsic{};
                constexpr auto vmid{1_u16};
                constexpr auto vpid{1_u16};
                constexpr auto ppid{1_u16};
                bsl::ut_when{} = [&]() noexcept {
                    mut_vs_pool.initialize();
                    bsl::ut_required_step(mut_vs_pool.allocate(
                        mut_tls, mut_page_pool, mut_intrinsic, vmid, vpid, ppid));
                    bsl::ut_then{} = [&]() noexcept {
                        mut_vs_pool.tlb_flush(mut_tls, mut_intrinsic, vmid);
                        mut_tls.ppid = ppid.get();
                        mut_vs_pool.tlb_flush(mut_tls, mut_intrinsic, vmid);
                    };
                };
            };
        };

        bsl::ut_scenario{"tlb_flush"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                vs_pool_t mut_vs_pool{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                intrinsic_t mut_intrinsic{};
                bsl::ut_when{} = [&]() noexcept {
                    mut_vs_pool.initialize();
                    bsl::ut_required_step(
                        mut_vs_pool.allocate(mut_tls, mut_page_pool, mut_intrinsic, {}, {}, {}));
                    bsl::ut_then{} = [&]() noexcept {
                        mut_vs_pool.tlb_flush(mut_tls, mut_intrinsic, {}, {});
                    };
                };
            };
        };

        bsl::ut_scenario{"dump"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                vs_pool_t mut_vs_pool{};
                tls_t mut_tls{};
                intrinsic_t mut_intrinsic{};
                bsl::ut_then{} = [&]() noexcept {
                    mut_vs_pool.dump(mut_tls, mut_intrinsic, {});
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
