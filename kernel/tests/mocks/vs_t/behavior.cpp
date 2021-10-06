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

#include "../../../mocks/vs_t.hpp"

#include <bf_constants.hpp>
#include <bf_reg_t.hpp>
#include <intrinsic_t.hpp>
#include <page_pool_t.hpp>
#include <state_save_t.hpp>
#include <tls_t.hpp>
#include <vmexit_log_t.hpp>

#include <bsl/convert.hpp>
#include <bsl/errc_type.hpp>
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
                vs_t mut_vs{};
                constexpr auto id{1_u16};
                bsl::ut_then{} = [&]() noexcept {
                    mut_vs.initialize(id);
                    bsl::ut_check(id == mut_vs.id());
                };
            };
        };

        bsl::ut_scenario{"release"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                vs_t mut_vs{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                bsl::ut_when{} = [&]() noexcept {
                    mut_vs.initialize({});
                    bsl::ut_then{} = [&]() noexcept {
                        mut_vs.release(mut_tls, mut_page_pool);
                    };
                };
            };
        };

        bsl::ut_scenario{"release without initialize"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                vs_t mut_vs{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                bsl::ut_then{} = [&]() noexcept {
                    mut_vs.release(mut_tls, mut_page_pool);
                };
            };
        };

        bsl::ut_scenario{"release after allocate"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                vs_t mut_vs{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                intrinsic_t const intrinsic{};
                bsl::ut_when{} = [&]() noexcept {
                    mut_vs.initialize({});
                    bsl::ut_required_step(
                        mut_vs.allocate(mut_tls, mut_page_pool, intrinsic, {}, {}, {}));
                    bsl::ut_then{} = [&]() noexcept {
                        mut_vs.release(mut_tls, mut_page_pool);
                    };
                };
            };
        };

        bsl::ut_scenario{"allocate"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                vs_t mut_vs{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                intrinsic_t const intrinsic{};
                constexpr auto vmid{1_u16};
                constexpr auto vpid{1_u16};
                constexpr auto ppid{1_u16};
                bsl::ut_when{} = [&]() noexcept {
                    mut_vs.initialize({});
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            mut_vs.allocate(mut_tls, mut_page_pool, intrinsic, vmid, vpid, ppid));
                        bsl::ut_check(vmid == mut_vs.assigned_vm());
                        bsl::ut_check(vpid == mut_vs.assigned_vp());
                        bsl::ut_check(ppid == mut_vs.assigned_pp());
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        mut_vs.release(mut_tls, mut_page_pool);
                    };
                };
            };
        };

        bsl::ut_scenario{"deallocate"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                vs_t mut_vs{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                intrinsic_t const intrinsic{};
                constexpr auto vmid{1_u16};
                constexpr auto vpid{1_u16};
                constexpr auto ppid{1_u16};
                bsl::ut_when{} = [&]() noexcept {
                    mut_vs.initialize({});
                    bsl::ut_required_step(
                        mut_vs.allocate(mut_tls, mut_page_pool, intrinsic, vmid, vpid, ppid));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(vmid == mut_vs.assigned_vm());
                        bsl::ut_check(vpid == mut_vs.assigned_vp());
                        bsl::ut_check(ppid == mut_vs.assigned_pp());
                        mut_vs.deallocate(mut_tls, mut_page_pool);
                        bsl::ut_check(vmid != mut_vs.assigned_vm());
                        bsl::ut_check(vpid != mut_vs.assigned_vp());
                        bsl::ut_check(ppid != mut_vs.assigned_pp());
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        mut_vs.release(mut_tls, mut_page_pool);
                    };
                };
            };
        };

        bsl::ut_scenario{"deallocate with no allocate"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                vs_t mut_vs{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                bsl::ut_when{} = [&]() noexcept {
                    mut_vs.initialize({});
                    bsl::ut_then{} = [&]() noexcept {
                        mut_vs.deallocate(mut_tls, mut_page_pool);
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        mut_vs.release(mut_tls, mut_page_pool);
                    };
                };
            };
        };

        bsl::ut_scenario{"allocation status functions"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                vs_t mut_vs{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                intrinsic_t const intrinsic{};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_vs.is_deallocated());
                        bsl::ut_check(!mut_vs.is_allocated());
                    };

                    mut_vs.initialize({});
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_vs.is_deallocated());
                        bsl::ut_check(!mut_vs.is_allocated());
                    };

                    bsl::ut_required_step(
                        mut_vs.allocate(mut_tls, mut_page_pool, intrinsic, {}, {}, {}));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(!mut_vs.is_deallocated());
                        bsl::ut_check(mut_vs.is_allocated());
                    };

                    mut_vs.deallocate(mut_tls, mut_page_pool);
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_vs.is_deallocated());
                        bsl::ut_check(!mut_vs.is_allocated());
                    };

                    bsl::ut_required_step(
                        mut_vs.allocate(mut_tls, mut_page_pool, intrinsic, {}, {}, {}));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(!mut_vs.is_deallocated());
                        bsl::ut_check(mut_vs.is_allocated());
                    };

                    mut_vs.release(mut_tls, mut_page_pool);
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_vs.is_deallocated());
                        bsl::ut_check(!mut_vs.is_allocated());
                    };
                };
            };
        };

        bsl::ut_scenario{"set_active/set_inactive"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                vs_t mut_vs{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                intrinsic_t mut_intrinsic{};
                constexpr auto vsid{1_u16};
                bsl::ut_when{} = [&]() noexcept {
                    mut_vs.initialize(vsid);
                    mut_tls.active_vsid = syscall::BF_INVALID_ID.get();
                    bsl::ut_required_step(
                        mut_vs.allocate(mut_tls, mut_page_pool, mut_intrinsic, {}, {}, {}));
                    mut_vs.set_active(mut_tls, mut_intrinsic);
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(vsid == mut_tls.active_vsid);
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        mut_vs.set_inactive(mut_tls, mut_intrinsic);
                        mut_vs.release(mut_tls, mut_page_pool);
                    };
                };
            };
        };

        bsl::ut_scenario{"active status functions"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                vs_t mut_vs{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                intrinsic_t mut_intrinsic{};
                constexpr auto ppid{0_u16};
                constexpr auto online_pps{2_u16};
                bsl::ut_when{} = [&]() noexcept {
                    mut_tls.online_pps = online_pps.get();
                    mut_tls.active_vsid = syscall::BF_INVALID_ID.get();

                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_vs.is_active().is_invalid());
                        bsl::ut_check(!mut_vs.is_active_on_this_pp(mut_tls));
                    };

                    mut_vs.initialize({});
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_vs.is_active().is_invalid());
                        bsl::ut_check(!mut_vs.is_active_on_this_pp(mut_tls));
                    };

                    bsl::ut_required_step(
                        mut_vs.allocate(mut_tls, mut_page_pool, mut_intrinsic, {}, {}, {}));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_vs.is_active().is_invalid());
                        bsl::ut_check(!mut_vs.is_active_on_this_pp(mut_tls));
                    };

                    mut_vs.set_active(mut_tls, mut_intrinsic);
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(ppid == mut_vs.is_active());
                        bsl::ut_check(mut_vs.is_active_on_this_pp(mut_tls));
                    };

                    mut_vs.set_inactive(mut_tls, mut_intrinsic);
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_vs.is_active().is_invalid());
                        bsl::ut_check(!mut_vs.is_active_on_this_pp(mut_tls));
                    };

                    bsl::ut_cleanup{} = [&]() noexcept {
                        mut_vs.release(mut_tls, mut_page_pool);
                    };
                };
            };
        };

        bsl::ut_scenario{"migrate"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                vs_t mut_vs{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                intrinsic_t mut_intrinsic{};
                constexpr auto ppid0{0_u16};
                constexpr auto ppid1{1_u16};
                bsl::ut_when{} = [&]() noexcept {
                    mut_vs.initialize({});
                    bsl::ut_required_step(
                        mut_vs.allocate(mut_tls, mut_page_pool, mut_intrinsic, {}, {}, ppid0));
                    bsl::ut_then{} = [&]() noexcept {
                        mut_vs.migrate(mut_tls, mut_intrinsic, ppid1);
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        mut_vs.release(mut_tls, mut_page_pool);
                    };
                };
            };
        };

        bsl::ut_scenario{"state_save_to_vs"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                vs_t mut_vs{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                intrinsic_t mut_intrinsic{};
                loader::state_save_t const state{};
                constexpr auto vsid0{0x0_u16};
                constexpr auto vsid1{0x1_u16};
                bsl::ut_when{} = [&]() noexcept {
                    mut_vs.initialize(vsid0);
                    bsl::ut_required_step(
                        mut_vs.allocate(mut_tls, mut_page_pool, mut_intrinsic, {}, {}, {}));
                    bsl::ut_then{} = [&]() noexcept {
                        mut_vs.state_save_to_vs(mut_tls, mut_intrinsic, &state);
                        mut_tls.active_vsid = vsid1.get();
                        mut_vs.state_save_to_vs(mut_tls, mut_intrinsic, &state);
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        mut_vs.release(mut_tls, mut_page_pool);
                    };
                };
            };
        };

        bsl::ut_scenario{"state_save_to_vs"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                vs_t mut_vs{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                intrinsic_t mut_intrinsic{};
                loader::state_save_t mut_state{};
                constexpr auto vsid0{0x0_u16};
                constexpr auto vsid1{0x1_u16};
                bsl::ut_when{} = [&]() noexcept {
                    mut_vs.initialize(vsid0);
                    bsl::ut_required_step(
                        mut_vs.allocate(mut_tls, mut_page_pool, mut_intrinsic, {}, {}, {}));
                    bsl::ut_then{} = [&]() noexcept {
                        mut_vs.vs_to_state_save(mut_tls, mut_intrinsic, &mut_state);
                        mut_tls.active_vsid = vsid1.get();
                        mut_vs.vs_to_state_save(mut_tls, mut_intrinsic, &mut_state);
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        mut_vs.release(mut_tls, mut_page_pool);
                    };
                };
            };
        };

        bsl::ut_scenario{"read"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                vs_t mut_vs{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                intrinsic_t mut_intrinsic{};
                bsl::ut_when{} = [&]() noexcept {
                    mut_vs.initialize({});
                    bsl::ut_required_step(
                        mut_vs.allocate(mut_tls, mut_page_pool, mut_intrinsic, {}, {}, {}));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            mut_vs.read(mut_tls, mut_intrinsic, syscall::bf_reg_t::bf_reg_t_dummy));
                        bsl::ut_check(
                            mut_vs
                                .read(
                                    mut_tls, mut_intrinsic, syscall::bf_reg_t::bf_reg_t_unsupported)
                                .is_invalid());
                        bsl::ut_check(
                            mut_vs.read(mut_tls, mut_intrinsic, syscall::bf_reg_t::bf_reg_t_invalid)
                                .is_invalid());
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        mut_vs.release(mut_tls, mut_page_pool);
                    };
                };
            };
        };

        bsl::ut_scenario{"write"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                vs_t mut_vs{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                intrinsic_t mut_intrinsic{};
                bsl::ut_when{} = [&]() noexcept {
                    mut_vs.initialize({});
                    bsl::ut_required_step(
                        mut_vs.allocate(mut_tls, mut_page_pool, mut_intrinsic, {}, {}, {}));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_vs.write(
                            mut_tls, mut_intrinsic, syscall::bf_reg_t::bf_reg_t_dummy, {}));
                        bsl::ut_check(!mut_vs.write(
                            mut_tls, mut_intrinsic, syscall::bf_reg_t::bf_reg_t_unsupported, {}));
                        bsl::ut_check(!mut_vs.write(
                            mut_tls, mut_intrinsic, syscall::bf_reg_t::bf_reg_t_invalid, {}));
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        mut_vs.release(mut_tls, mut_page_pool);
                    };
                };
            };
        };

        bsl::ut_scenario{"run"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                vs_t mut_vs{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                intrinsic_t mut_intrinsic{};
                vmexit_log_t mut_log{};
                bsl::ut_when{} = [&]() noexcept {
                    mut_vs.initialize({});
                    bsl::ut_required_step(
                        mut_vs.allocate(mut_tls, mut_page_pool, mut_intrinsic, {}, {}, {}));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_vs.run(mut_tls, mut_intrinsic, mut_log));
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        mut_vs.release(mut_tls, mut_page_pool);
                    };
                };
            };
        };

        bsl::ut_scenario{"advance_ip"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                vs_t mut_vs{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                intrinsic_t mut_intrinsic{};
                bsl::ut_when{} = [&]() noexcept {
                    mut_vs.initialize({});
                    bsl::ut_required_step(
                        mut_vs.allocate(mut_tls, mut_page_pool, mut_intrinsic, {}, {}, {}));
                    bsl::ut_then{} = [&]() noexcept {
                        mut_vs.advance_ip(mut_tls, mut_intrinsic);
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        mut_vs.release(mut_tls, mut_page_pool);
                    };
                };
            };
        };

        bsl::ut_scenario{"clear"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                vs_t mut_vs{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                intrinsic_t mut_intrinsic{};
                bsl::ut_when{} = [&]() noexcept {
                    mut_vs.initialize({});
                    bsl::ut_required_step(
                        mut_vs.allocate(mut_tls, mut_page_pool, mut_intrinsic, {}, {}, {}));
                    bsl::ut_then{} = [&]() noexcept {
                        mut_vs.clear(mut_tls, mut_intrinsic);
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        mut_vs.release(mut_tls, mut_page_pool);
                    };
                };
            };
        };

        bsl::ut_scenario{"tlb_flush"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                vs_t mut_vs{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                intrinsic_t mut_intrinsic{};
                bsl::ut_when{} = [&]() noexcept {
                    mut_vs.initialize({});
                    bsl::ut_required_step(
                        mut_vs.allocate(mut_tls, mut_page_pool, mut_intrinsic, {}, {}, {}));
                    bsl::ut_then{} = [&]() noexcept {
                        mut_vs.tlb_flush(mut_tls, mut_intrinsic);
                        mut_vs.tlb_flush(mut_tls, mut_intrinsic, HYPERVISOR_PAGE_SIZE);
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        mut_vs.release(mut_tls, mut_page_pool);
                    };
                };
            };
        };

        bsl::ut_scenario{"dump"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                vs_t mut_vs{};
                tls_t mut_tls{};
                intrinsic_t mut_intrinsic{};
                bsl::ut_then{} = [&]() noexcept {
                    mut_vs.dump(mut_tls, mut_intrinsic);
                };
            };
        };

        bsl::ut_scenario{"dump active"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                vs_t mut_vs{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                intrinsic_t mut_intrinsic{};
                constexpr auto vsid0{0_u16};
                constexpr auto vsid1{1_u16};
                constexpr auto online_pps{2_u16};
                bsl::ut_when{} = [&]() noexcept {
                    mut_tls.online_pps = online_pps.get();
                    mut_tls.active_vsid = syscall::BF_INVALID_ID.get();
                    mut_vs.initialize({});
                    bsl::ut_required_step(
                        mut_vs.allocate(mut_tls, mut_page_pool, mut_intrinsic, {}, {}, {}));
                    mut_tls.active_vsid = vsid0.get();
                    bsl::ut_then{} = [&]() noexcept {
                        mut_vs.dump(mut_tls, mut_intrinsic);
                    };
                    mut_tls.active_vsid = vsid1.get();
                    bsl::ut_then{} = [&]() noexcept {
                        mut_vs.dump(mut_tls, mut_intrinsic);
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        mut_vs.release(mut_tls, mut_page_pool);
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
