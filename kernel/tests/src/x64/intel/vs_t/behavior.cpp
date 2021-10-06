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

#include "../../../../../src/x64/intel/vs_t.hpp"

#include <bf_constants.hpp>
#include <bf_reg_t.hpp>
#include <intrinsic_t.hpp>
#include <page_pool_t.hpp>
#include <state_save_t.hpp>
#include <tls_t.hpp>
#include <vmexit_log_t.hpp>

#include <bsl/convert.hpp>
#include <bsl/errc_type.hpp>
#include <bsl/safe_idx.hpp>
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
                intrinsic_t mut_intrinsic{};
                loader::state_save_t mut_state{};
                bsl::ut_when{} = [&]() noexcept {
                    mut_vs.initialize({});
                    mut_tls.mk_state = &mut_state;
                    bsl::ut_required_step(
                        mut_vs.allocate(mut_tls, mut_page_pool, mut_intrinsic, {}, {}, {}));
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
                intrinsic_t mut_intrinsic{};
                loader::state_save_t mut_state{};
                constexpr auto vmid{1_u16};
                constexpr auto vpid{1_u16};
                constexpr auto ppid{1_u16};
                bsl::ut_when{} = [&]() noexcept {
                    mut_vs.initialize({});
                    mut_tls.mk_state = &mut_state;
                    mut_tls.ppid = ppid.get();
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_vs.allocate(
                            mut_tls, mut_page_pool, mut_intrinsic, vmid, vpid, ppid));
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

        bsl::ut_scenario{"allocate vmcs fails"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                vs_t mut_vs{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                intrinsic_t mut_intrinsic{};
                loader::state_save_t mut_state{};
                bsl::ut_when{} = [&]() noexcept {
                    mut_vs.initialize({});
                    mut_tls.mk_state = &mut_state;
                    mut_page_pool.set_max(bsl::safe_umx::magic_0());
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            mut_vs.allocate(mut_tls, mut_page_pool, mut_intrinsic, {}, {}, {})
                                .is_invalid());
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
                intrinsic_t mut_intrinsic{};
                loader::state_save_t mut_state{};
                constexpr auto vmid{1_u16};
                constexpr auto vpid{1_u16};
                constexpr auto ppid{1_u16};
                bsl::ut_when{} = [&]() noexcept {
                    mut_vs.initialize({});
                    mut_tls.mk_state = &mut_state;
                    mut_tls.ppid = ppid.get();
                    bsl::ut_required_step(
                        mut_vs.allocate(mut_tls, mut_page_pool, mut_intrinsic, vmid, vpid, ppid));
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
                intrinsic_t mut_intrinsic{};
                loader::state_save_t mut_state{};
                bsl::ut_when{} = [&]() noexcept {
                    mut_tls.mk_state = &mut_state;
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
                        mut_vs.allocate(mut_tls, mut_page_pool, mut_intrinsic, {}, {}, {}));
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
                        mut_vs.allocate(mut_tls, mut_page_pool, mut_intrinsic, {}, {}, {}));
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
                loader::state_save_t mut_state{};
                constexpr auto vsid{1_u16};
                bsl::ut_when{} = [&]() noexcept {
                    mut_vs.initialize(vsid);
                    mut_tls.mk_state = &mut_state;
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
                loader::state_save_t mut_state{};
                constexpr auto ppid{0_u16};
                constexpr auto online_pps{2_u16};
                bsl::ut_when{} = [&]() noexcept {
                    mut_tls.online_pps = online_pps.get();
                    mut_tls.active_vsid = syscall::BF_INVALID_ID.get();
                    mut_tls.mk_state = &mut_state;

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
                loader::state_save_t mut_state{};
                constexpr auto ppid0{0_u16};
                constexpr auto ppid1{1_u16};
                bsl::ut_when{} = [&]() noexcept {
                    mut_vs.initialize({});
                    mut_tls.mk_state = &mut_state;
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
                loader::state_save_t mut_state{};
                constexpr auto vsid0{0x0_u16};
                constexpr auto vsid1{0x1_u16};
                constexpr auto es_selector{0x10_u16};
                bsl::ut_when{} = [&]() noexcept {
                    mut_vs.initialize(vsid0);
                    mut_tls.mk_state = &mut_state;
                    mut_tls.root_vp_state = &mut_state;
                    mut_state.es_selector = es_selector.get();
                    bsl::ut_required_step(
                        mut_vs.allocate(mut_tls, mut_page_pool, mut_intrinsic, {}, {}, {}));
                    bsl::ut_then{} = [&]() noexcept {
                        mut_vs.state_save_to_vs(mut_tls, mut_intrinsic, &mut_state);
                        mut_tls.active_vsid = vsid1.get();
                        mut_vs.state_save_to_vs(mut_tls, mut_intrinsic, &mut_state);
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
                constexpr auto es_selector{0x10_u64};
                using reg_t = syscall::bf_reg_t;
                bsl::ut_when{} = [&]() noexcept {
                    mut_vs.initialize(vsid0);
                    mut_tls.mk_state = &mut_state;
                    bsl::ut_required_step(
                        mut_vs.allocate(mut_tls, mut_page_pool, mut_intrinsic, {}, {}, {}));
                    bsl::ut_required_step(mut_vs.write(
                        mut_tls, mut_intrinsic, reg_t::bf_reg_t_es_selector, es_selector));
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
                loader::state_save_t mut_state{};
                constexpr auto vsid0{0x0_u16};
                constexpr auto vsid1{0x1_u16};
                constexpr auto error_idx0{0_idx};
                constexpr auto error_idx1{24_idx};
                constexpr auto error_idx2{122_idx};
                constexpr auto error_idx3{61_idx};
                constexpr auto error_idx4{163_idx};
                constexpr auto error_idx5{164_idx};
                bsl::ut_when{} = [&]() noexcept {
                    mut_vs.initialize(vsid0);
                    mut_tls.mk_state = &mut_state;
                    bsl::ut_required_step(
                        mut_vs.allocate(mut_tls, mut_page_pool, mut_intrinsic, {}, {}, {}));
                    bsl::ut_then{} = [&]() noexcept {
                        for (bsl::safe_idx mut_i{}; mut_i <= error_idx5; ++mut_i) {
                            auto const reg{static_cast<syscall::bf_reg_t>(mut_i.get())};
                            switch (mut_i.get()) {
                                case error_idx0.get():
                                    [[fallthrough]];
                                case error_idx1.get():
                                    [[fallthrough]];
                                case error_idx2.get():
                                    [[fallthrough]];
                                case error_idx3.get():
                                    [[fallthrough]];
                                case error_idx4.get():
                                    [[fallthrough]];
                                case error_idx5.get(): {
                                    bsl::ut_check(
                                        mut_vs.read(mut_tls, mut_intrinsic, reg).is_invalid());
                                    break;
                                }

                                default: {
                                    bsl::ut_check(mut_vs.read(mut_tls, mut_intrinsic, reg));
                                    break;
                                }
                            }
                        }
                        mut_tls.active_vsid = vsid1.get();
                        for (bsl::safe_idx mut_i{}; mut_i <= error_idx5; ++mut_i) {
                            auto const reg{static_cast<syscall::bf_reg_t>(mut_i.get())};
                            switch (mut_i.get()) {
                                case error_idx0.get():
                                    [[fallthrough]];
                                case error_idx1.get():
                                    [[fallthrough]];
                                case error_idx2.get():
                                    [[fallthrough]];
                                case error_idx3.get():
                                    [[fallthrough]];
                                case error_idx4.get():
                                    [[fallthrough]];
                                case error_idx5.get(): {
                                    bsl::ut_check(
                                        mut_vs.read(mut_tls, mut_intrinsic, reg).is_invalid());
                                    break;
                                }

                                default: {
                                    bsl::ut_check(mut_vs.read(mut_tls, mut_intrinsic, reg));
                                    break;
                                }
                            }
                        }
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
                loader::state_save_t mut_state{};
                constexpr auto vsid0{0x0_u16};
                constexpr auto vsid1{0x1_u16};
                constexpr auto error_idx0{0_idx};
                constexpr auto error_idx1{163_idx};
                constexpr auto error_idx2{164_idx};
                bsl::ut_when{} = [&]() noexcept {
                    mut_vs.initialize(vsid0);
                    mut_tls.mk_state = &mut_state;
                    bsl::ut_required_step(
                        mut_vs.allocate(mut_tls, mut_page_pool, mut_intrinsic, {}, {}, {}));
                    bsl::ut_then{} = [&]() noexcept {
                        for (bsl::safe_idx mut_i{}; mut_i <= error_idx2; ++mut_i) {
                            auto const reg{static_cast<syscall::bf_reg_t>(mut_i.get())};
                            switch (mut_i.get()) {
                                case error_idx0.get():
                                    [[fallthrough]];
                                case error_idx1.get():
                                    [[fallthrough]];
                                case error_idx2.get(): {
                                    bsl::ut_check(!mut_vs.write(mut_tls, mut_intrinsic, reg, {}));
                                    break;
                                }

                                default: {
                                    bsl::ut_check(mut_vs.write(mut_tls, mut_intrinsic, reg, {}));
                                    break;
                                }
                            }
                        }
                        mut_tls.active_vsid = vsid1.get();
                        for (bsl::safe_idx mut_i{}; mut_i <= error_idx2; ++mut_i) {
                            auto const reg{static_cast<syscall::bf_reg_t>(mut_i.get())};
                            switch (mut_i.get()) {
                                case error_idx0.get():
                                    [[fallthrough]];
                                case error_idx1.get():
                                    [[fallthrough]];
                                case error_idx2.get(): {
                                    bsl::ut_check(!mut_vs.write(mut_tls, mut_intrinsic, reg, {}));
                                    break;
                                }

                                default: {
                                    bsl::ut_check(mut_vs.write(mut_tls, mut_intrinsic, reg, {}));
                                    break;
                                }
                            }
                        }
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        mut_vs.release(mut_tls, mut_page_pool);
                    };
                };
            };
        };

        bsl::ut_scenario{"write overflow"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                vs_t mut_vs{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                intrinsic_t mut_intrinsic{};
                loader::state_save_t mut_state{};
                using reg_t = syscall::bf_reg_t;
                constexpr auto val{bsl::safe_u64::max_value()};
                bsl::ut_when{} = [&]() noexcept {
                    mut_vs.initialize({});
                    mut_tls.mk_state = &mut_state;
                    bsl::ut_required_step(
                        mut_vs.allocate(mut_tls, mut_page_pool, mut_intrinsic, {}, {}, {}));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(!mut_vs.write(
                            mut_tls,
                            mut_intrinsic,
                            reg_t::bf_reg_t_virtual_processor_identifier,
                            val));
                        bsl::ut_check(!mut_vs.write(
                            mut_tls,
                            mut_intrinsic,
                            reg_t::bf_reg_t_posted_interrupt_notification_vector,
                            val));
                        bsl::ut_check(
                            !mut_vs.write(mut_tls, mut_intrinsic, reg_t::bf_reg_t_eptp_index, val));
                        bsl::ut_check(!mut_vs.write(
                            mut_tls, mut_intrinsic, reg_t::bf_reg_t_es_selector, val));
                        bsl::ut_check(!mut_vs.write(
                            mut_tls, mut_intrinsic, reg_t::bf_reg_t_cs_selector, val));
                        bsl::ut_check(!mut_vs.write(
                            mut_tls, mut_intrinsic, reg_t::bf_reg_t_ss_selector, val));
                        bsl::ut_check(!mut_vs.write(
                            mut_tls, mut_intrinsic, reg_t::bf_reg_t_ds_selector, val));
                        bsl::ut_check(!mut_vs.write(
                            mut_tls, mut_intrinsic, reg_t::bf_reg_t_fs_selector, val));
                        bsl::ut_check(!mut_vs.write(
                            mut_tls, mut_intrinsic, reg_t::bf_reg_t_gs_selector, val));
                        bsl::ut_check(!mut_vs.write(
                            mut_tls, mut_intrinsic, reg_t::bf_reg_t_ldtr_selector, val));
                        bsl::ut_check(!mut_vs.write(
                            mut_tls, mut_intrinsic, reg_t::bf_reg_t_tr_selector, val));
                        bsl::ut_check(!mut_vs.write(
                            mut_tls, mut_intrinsic, reg_t::bf_reg_t_interrupt_status, val));
                        bsl::ut_check(
                            !mut_vs.write(mut_tls, mut_intrinsic, reg_t::bf_reg_t_pml_index, val));
                        bsl::ut_check(!mut_vs.write(
                            mut_tls,
                            mut_intrinsic,
                            reg_t::bf_reg_t_pin_based_vm_execution_ctls,
                            val));
                        bsl::ut_check(!mut_vs.write(
                            mut_tls,
                            mut_intrinsic,
                            reg_t::bf_reg_t_primary_proc_based_vm_execution_ctls,
                            val));
                        bsl::ut_check(!mut_vs.write(
                            mut_tls, mut_intrinsic, reg_t::bf_reg_t_exception_bitmap, val));
                        bsl::ut_check(!mut_vs.write(
                            mut_tls,
                            mut_intrinsic,
                            reg_t::bf_reg_t_page_fault_error_code_mask,
                            val));
                        bsl::ut_check(!mut_vs.write(
                            mut_tls,
                            mut_intrinsic,
                            reg_t::bf_reg_t_page_fault_error_code_match,
                            val));
                        bsl::ut_check(!mut_vs.write(
                            mut_tls, mut_intrinsic, reg_t::bf_reg_t_cr3_target_count, val));
                        bsl::ut_check(!mut_vs.write(
                            mut_tls, mut_intrinsic, reg_t::bf_reg_t_vmexit_ctls, val));
                        bsl::ut_check(!mut_vs.write(
                            mut_tls, mut_intrinsic, reg_t::bf_reg_t_vmexit_msr_store_count, val));
                        bsl::ut_check(!mut_vs.write(
                            mut_tls, mut_intrinsic, reg_t::bf_reg_t_vmexit_msr_load_count, val));
                        bsl::ut_check(!mut_vs.write(
                            mut_tls, mut_intrinsic, reg_t::bf_reg_t_vmentry_ctls, val));
                        bsl::ut_check(!mut_vs.write(
                            mut_tls, mut_intrinsic, reg_t::bf_reg_t_vmentry_msr_load_count, val));
                        bsl::ut_check(!mut_vs.write(
                            mut_tls,
                            mut_intrinsic,
                            reg_t::bf_reg_t_vmentry_interrupt_information_field,
                            val));
                        bsl::ut_check(!mut_vs.write(
                            mut_tls,
                            mut_intrinsic,
                            reg_t::bf_reg_t_vmentry_exception_error_code,
                            val));
                        bsl::ut_check(!mut_vs.write(
                            mut_tls,
                            mut_intrinsic,
                            reg_t::bf_reg_t_vmentry_instruction_length,
                            val));
                        bsl::ut_check(!mut_vs.write(
                            mut_tls, mut_intrinsic, reg_t::bf_reg_t_tpr_threshold, val));
                        bsl::ut_check(!mut_vs.write(
                            mut_tls,
                            mut_intrinsic,
                            reg_t::bf_reg_t_secondary_proc_based_vm_execution_ctls,
                            val));
                        bsl::ut_check(
                            !mut_vs.write(mut_tls, mut_intrinsic, reg_t::bf_reg_t_ple_gap, val));
                        bsl::ut_check(
                            !mut_vs.write(mut_tls, mut_intrinsic, reg_t::bf_reg_t_ple_window, val));
                        bsl::ut_check(!mut_vs.write(
                            mut_tls, mut_intrinsic, reg_t::bf_reg_t_vm_instruction_error, val));
                        bsl::ut_check(!mut_vs.write(
                            mut_tls, mut_intrinsic, reg_t::bf_reg_t_exit_reason, val));
                        bsl::ut_check(!mut_vs.write(
                            mut_tls,
                            mut_intrinsic,
                            reg_t::bf_reg_t_vmexit_interruption_information,
                            val));
                        bsl::ut_check(!mut_vs.write(
                            mut_tls,
                            mut_intrinsic,
                            reg_t::bf_reg_t_vmexit_interruption_error_code,
                            val));
                        bsl::ut_check(!mut_vs.write(
                            mut_tls,
                            mut_intrinsic,
                            reg_t::bf_reg_t_idt_vectoring_information_field,
                            val));
                        bsl::ut_check(!mut_vs.write(
                            mut_tls, mut_intrinsic, reg_t::bf_reg_t_idt_vectoring_error_code, val));
                        bsl::ut_check(!mut_vs.write(
                            mut_tls,
                            mut_intrinsic,
                            reg_t::bf_reg_t_vmexit_instruction_length,
                            val));
                        bsl::ut_check(!mut_vs.write(
                            mut_tls,
                            mut_intrinsic,
                            reg_t::bf_reg_t_vmexit_instruction_information,
                            val));
                        bsl::ut_check(
                            !mut_vs.write(mut_tls, mut_intrinsic, reg_t::bf_reg_t_es_limit, val));
                        bsl::ut_check(
                            !mut_vs.write(mut_tls, mut_intrinsic, reg_t::bf_reg_t_cs_limit, val));
                        bsl::ut_check(
                            !mut_vs.write(mut_tls, mut_intrinsic, reg_t::bf_reg_t_ss_limit, val));
                        bsl::ut_check(
                            !mut_vs.write(mut_tls, mut_intrinsic, reg_t::bf_reg_t_ds_limit, val));
                        bsl::ut_check(
                            !mut_vs.write(mut_tls, mut_intrinsic, reg_t::bf_reg_t_fs_limit, val));
                        bsl::ut_check(
                            !mut_vs.write(mut_tls, mut_intrinsic, reg_t::bf_reg_t_gs_limit, val));
                        bsl::ut_check(
                            !mut_vs.write(mut_tls, mut_intrinsic, reg_t::bf_reg_t_ldtr_limit, val));
                        bsl::ut_check(
                            !mut_vs.write(mut_tls, mut_intrinsic, reg_t::bf_reg_t_tr_limit, val));
                        bsl::ut_check(
                            !mut_vs.write(mut_tls, mut_intrinsic, reg_t::bf_reg_t_gdtr_limit, val));
                        bsl::ut_check(
                            !mut_vs.write(mut_tls, mut_intrinsic, reg_t::bf_reg_t_idtr_limit, val));
                        bsl::ut_check(
                            !mut_vs.write(mut_tls, mut_intrinsic, reg_t::bf_reg_t_es_attrib, val));
                        bsl::ut_check(
                            !mut_vs.write(mut_tls, mut_intrinsic, reg_t::bf_reg_t_cs_attrib, val));
                        bsl::ut_check(
                            !mut_vs.write(mut_tls, mut_intrinsic, reg_t::bf_reg_t_ss_attrib, val));
                        bsl::ut_check(
                            !mut_vs.write(mut_tls, mut_intrinsic, reg_t::bf_reg_t_ds_attrib, val));
                        bsl::ut_check(
                            !mut_vs.write(mut_tls, mut_intrinsic, reg_t::bf_reg_t_fs_attrib, val));
                        bsl::ut_check(
                            !mut_vs.write(mut_tls, mut_intrinsic, reg_t::bf_reg_t_gs_attrib, val));
                        bsl::ut_check(!mut_vs.write(
                            mut_tls, mut_intrinsic, reg_t::bf_reg_t_ldtr_attrib, val));
                        bsl::ut_check(
                            !mut_vs.write(mut_tls, mut_intrinsic, reg_t::bf_reg_t_tr_attrib, val));
                        bsl::ut_check(!mut_vs.write(
                            mut_tls, mut_intrinsic, reg_t::bf_reg_t_interruptibility_state, val));
                        bsl::ut_check(!mut_vs.write(
                            mut_tls, mut_intrinsic, reg_t::bf_reg_t_activity_state, val));
                        bsl::ut_check(
                            !mut_vs.write(mut_tls, mut_intrinsic, reg_t::bf_reg_t_smbase, val));
                        bsl::ut_check(!mut_vs.write(
                            mut_tls, mut_intrinsic, reg_t::bf_reg_t_sysenter_cs, val));
                        bsl::ut_check(!mut_vs.write(
                            mut_tls,
                            mut_intrinsic,
                            reg_t::bf_reg_t_vmx_preemption_timer_value,
                            val));
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        mut_vs.release(mut_tls, mut_page_pool);
                    };
                };
            };
        };

        bsl::ut_scenario{"write unrestricted mode"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                vs_t mut_vs{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                intrinsic_t mut_intrinsic{};
                loader::state_save_t mut_state{};
                using reg_t = syscall::bf_reg_t;
                constexpr auto msr{0x0000048B_u32};
                bsl::ut_when{} = [&]() noexcept {
                    mut_vs.initialize({});
                    mut_tls.mk_state = &mut_state;
                    bsl::ut_required_step(mut_intrinsic.wrmsr(msr, bsl::safe_u64::max_value()));
                    bsl::ut_required_step(
                        mut_vs.allocate(mut_tls, mut_page_pool, mut_intrinsic, {}, {}, {}));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_vs.write(
                            mut_tls,
                            mut_intrinsic,
                            reg_t::bf_reg_t_secondary_proc_based_vm_execution_ctls,
                            {}));
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
                loader::state_save_t mut_state{};
                vmexit_log_t mut_log{};
                bsl::ut_when{} = [&]() noexcept {
                    mut_vs.initialize({});
                    mut_tls.mk_state = &mut_state;
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
                loader::state_save_t mut_state{};
                bsl::ut_when{} = [&]() noexcept {
                    mut_vs.initialize({});
                    mut_tls.mk_state = &mut_state;
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
                loader::state_save_t mut_state{};
                bsl::ut_when{} = [&]() noexcept {
                    mut_vs.initialize({});
                    mut_tls.mk_state = &mut_state;
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

        bsl::ut_scenario{"clear not loaded"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                vs_t mut_vs{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                intrinsic_t mut_intrinsic{};
                loader::state_save_t mut_state{};
                constexpr auto vsid{0x1_u16};
                bsl::ut_when{} = [&]() noexcept {
                    mut_vs.initialize({});
                    mut_tls.mk_state = &mut_state;
                    bsl::ut_required_step(
                        mut_vs.allocate(mut_tls, mut_page_pool, mut_intrinsic, {}, {}, {}));
                    mut_tls.loaded_vsid = vsid.get();
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
                loader::state_save_t mut_state{};
                bsl::ut_when{} = [&]() noexcept {
                    mut_vs.initialize({});
                    mut_tls.mk_state = &mut_state;
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
                page_pool_t mut_page_pool{};
                intrinsic_t mut_intrinsic{};
                loader::state_save_t mut_state{};
                bsl::ut_when{} = [&]() noexcept {
                    mut_vs.initialize({});
                    mut_tls.mk_state = &mut_state;
                    bsl::ut_required_step(
                        mut_vs.allocate(mut_tls, mut_page_pool, mut_intrinsic, {}, {}, {}));
                    bsl::ut_then{} = [&]() noexcept {
                        mut_vs.dump(mut_tls, mut_intrinsic);
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
                loader::state_save_t mut_state{};
                constexpr auto vsid0{0_u16};
                constexpr auto vsid1{1_u16};
                constexpr auto online_pps{2_u16};
                using reg_t = syscall::bf_reg_t;
                constexpr auto val{1_u64};
                bsl::ut_when{} = [&]() noexcept {
                    mut_tls.online_pps = online_pps.get();
                    mut_tls.active_vsid = syscall::BF_INVALID_ID.get();
                    mut_vs.initialize({});
                    mut_tls.mk_state = &mut_state;
                    bsl::ut_required_step(
                        mut_vs.allocate(mut_tls, mut_page_pool, mut_intrinsic, {}, {}, {}));

                    mut_tls.active_vsid = vsid0.get();
                    bsl::ut_then{} = [&]() noexcept {
                        mut_vs.dump(mut_tls, mut_intrinsic);
                    };

                    bsl::ut_required_step(mut_vs.write(
                        mut_tls, mut_intrinsic, reg_t::bf_reg_t_virtual_processor_identifier, val));
                    bsl::ut_required_step(
                        mut_vs.read(
                            mut_tls, mut_intrinsic, reg_t::bf_reg_t_virtual_processor_identifier) ==
                        val);
                    bsl::ut_required_step(
                        mut_vs.write(mut_tls, mut_intrinsic, reg_t::bf_reg_t_es_limit, val));
                    bsl::ut_required_step(
                        mut_vs.write(mut_tls, mut_intrinsic, reg_t::bf_reg_t_es_base, val));

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
