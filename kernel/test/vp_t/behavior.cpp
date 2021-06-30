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

#include "../../src/vp_t.hpp"

#include <dummy_vm_pool_t.hpp>
#include <dummy_vps_pool_t.hpp>
#include <tls_t.hpp>

#include <bsl/ut.hpp>

namespace mk
{
    /// @brief defines the max number of VMs used in testing
    constexpr bsl::safe_uint16 INTEGRATION_MAX_PPS{bsl::to_u16(2)};

    /// @brief defines VMID0
    constexpr bsl::safe_uint16 VMID0{bsl::to_u16(0)};

    /// @brief defines PPID0
    constexpr bsl::safe_uint16 PPID0{bsl::to_u16(0)};
    /// @brief defines PPID1
    constexpr bsl::safe_uint16 PPID1{bsl::to_u16(1)};
    /// @brief defines PPID2
    constexpr bsl::safe_uint16 PPID2{bsl::to_u16(2)};

    /// @brief defines VPID0
    constexpr bsl::safe_uint16 VPID0{bsl::to_u16(0)};
    /// @brief defines VPID1
    constexpr bsl::safe_uint16 VPID1{bsl::to_u16(1)};

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
        bsl::ut_scenario{"initialize invalid id version #1"} = []() {
            bsl::ut_given{} = []() {
                vp_t vp{};
                tls_t tls{};
                bsl::ut_then{} = [&vp, &tls]() {
                    bsl::ut_check(!vp.initialize(tls, bsl::safe_uint16::failure()));
                };
            };
        };

        bsl::ut_scenario{"initialize invalid id version #2"} = []() {
            bsl::ut_given{} = []() {
                vp_t vp{};
                tls_t tls{};
                bsl::ut_then{} = [&vp, &tls]() {
                    bsl::ut_check(!vp.initialize(tls, syscall::BF_INVALID_ID));
                };
            };
        };

        bsl::ut_scenario{"initialize success"} = []() {
            bsl::ut_given{} = []() {
                vp_t vp{};
                tls_t tls{};
                bsl::ut_then{} = [&vp, &tls]() {
                    bsl::ut_check(vp.initialize(tls, VPID0));
                };
            };
        };

        bsl::ut_scenario{"initialize more than once failure"} = []() {
            bsl::ut_given{} = []() {
                vp_t vp{};
                tls_t tls{};
                bsl::ut_when{} = [&vp, &tls]() {
                    bsl::ut_required_step(vp.initialize(tls, VPID0));
                    bsl::ut_then{} = [&vp, &tls]() {
                        bsl::ut_check(!vp.initialize(tls, VPID0));
                    };
                };
            };
        };

        bsl::ut_scenario{"release success"} = []() {
            bsl::ut_given{} = []() {
                vp_t vp{};
                tls_t tls{};
                dummy_vps_pool_t vps_pool{};
                bsl::ut_when{} = [&vp, &tls, &vps_pool]() {
                    bsl::ut_required_step(vp.initialize(tls, VPID1));
                    bsl::ut_then{} = [&vp, &tls, &vps_pool]() {
                        bsl::ut_check(vp.release(tls, vps_pool));
                        bsl::ut_check(!vp.id());
                    };
                };
            };
        };

        bsl::ut_scenario{"release success after allocate"} = []() {
            bsl::ut_given{} = []() {
                vp_t vp{};
                tls_t tls{};
                dummy_vm_pool_t vm_pool{};
                dummy_vps_pool_t vps_pool{};
                bsl::ut_when{} = [&vp, &tls, &vm_pool, &vps_pool]() {
                    tls.online_pps = INTEGRATION_MAX_PPS.get();
                    bsl::ut_required_step(vp.initialize(tls, VPID1));
                    bsl::ut_required_step(vp.allocate(tls, vm_pool, VMID0, PPID0));
                    bsl::ut_then{} = [&vp, &tls, &vps_pool]() {
                        bsl::ut_check(vp.release(tls, vps_pool));
                        bsl::ut_check(!vp.id());
                        bsl::ut_check(!vp.is_allocated());
                        bsl::ut_check(!vp.assigned_vm());
                        bsl::ut_check(!vp.assigned_pp());
                    };
                };
            };
        };

        bsl::ut_scenario{"release of a zombie vp is ignored"} = []() {
            bsl::ut_given{} = []() {
                vp_t vp{};
                tls_t tls{};
                dummy_vps_pool_t vps_pool{};
                bsl::ut_when{} = [&vp, &tls, &vps_pool]() {
                    bsl::ut_required_step(vp.initialize(tls, VPID1));
                    vp.zombify();
                    bsl::ut_then{} = [&vp, &tls, &vps_pool]() {
                        bsl::ut_check(vp.release(tls, vps_pool));
                        bsl::ut_check(vp.id());
                        bsl::ut_check(vp.is_zombie());
                    };
                };
            };
        };

        bsl::ut_scenario{"release of a vp that is still assigned results in a zombie"} = []() {
            bsl::ut_given{} = []() {
                vp_t vp{};
                tls_t tls{};
                dummy_vps_pool_t vps_pool{};
                bsl::ut_when{} = [&vp, &tls, &vps_pool]() {
                    bsl::ut_required_step(vp.initialize(tls, VPID1));
                    tls.test_ret = errc_vps_pool_failure;
                    bsl::ut_then{} = [&vp, &tls, &vps_pool]() {
                        bsl::ut_check(!vp.release(tls, vps_pool));
                        bsl::ut_check(vp.id());
                        bsl::ut_check(vp.is_zombie());
                    };
                };
            };
        };

        bsl::ut_scenario{"release of a vp that is still active results in a zombie"} = []() {
            bsl::ut_given{} = []() {
                vp_t vp{};
                tls_t tls{};
                dummy_vm_pool_t vm_pool{};
                dummy_vps_pool_t vps_pool{};
                bsl::ut_when{} = [&vp, &tls, &vm_pool, &vps_pool]() {
                    tls.online_pps = INTEGRATION_MAX_PPS.get();
                    tls.active_vpid = syscall::BF_INVALID_ID.get();
                    bsl::ut_required_step(vp.initialize(tls, VPID1));
                    bsl::ut_required_step(vp.allocate(tls, vm_pool, VMID0, PPID0));
                    bsl::ut_required_step(vp.set_active(tls));
                    bsl::ut_then{} = [&vp, &tls, &vps_pool]() {
                        bsl::ut_check(!vp.release(tls, vps_pool));
                        bsl::ut_check(vp.id());
                        bsl::ut_check(vp.is_zombie());
                    };
                };
            };
        };

        bsl::ut_scenario{"allocate without initialize failure"} = []() {
            bsl::ut_given{} = []() {
                vp_t vp{};
                tls_t tls{};
                dummy_vm_pool_t vm_pool{};
                bsl::ut_then{} = [&vp, &tls, &vm_pool]() {
                    bsl::ut_check(!vp.allocate(tls, vm_pool, VMID0, PPID0));
                };
            };
        };

        bsl::ut_scenario{"allocate invalid vmid version #1"} = []() {
            bsl::ut_given{} = []() {
                vp_t vp{};
                tls_t tls{};
                dummy_vm_pool_t vm_pool{};
                bsl::ut_when{} = [&vp, &tls, &vm_pool]() {
                    tls.online_pps = INTEGRATION_MAX_PPS.get();
                    bsl::ut_required_step(vp.initialize(tls, VPID1));
                    bsl::ut_then{} = [&vp, &tls, &vm_pool]() {
                        bsl::ut_check(
                            !vp.allocate(tls, vm_pool, bsl::safe_uint16::failure(), PPID0));
                    };
                };
            };
        };

        bsl::ut_scenario{"allocate invalid vmid version #2"} = []() {
            bsl::ut_given{} = []() {
                vp_t vp{};
                tls_t tls{};
                dummy_vm_pool_t vm_pool{};
                bsl::ut_when{} = [&vp, &tls, &vm_pool]() {
                    tls.online_pps = INTEGRATION_MAX_PPS.get();
                    bsl::ut_required_step(vp.initialize(tls, VPID1));
                    bsl::ut_then{} = [&vp, &tls, &vm_pool]() {
                        bsl::ut_check(!vp.allocate(tls, vm_pool, syscall::BF_INVALID_ID, PPID0));
                    };
                };
            };
        };

        bsl::ut_scenario{"allocate invalid vmid version #3"} = []() {
            bsl::ut_given{} = []() {
                vp_t vp{};
                tls_t tls{};
                dummy_vm_pool_t vm_pool{};
                bsl::ut_when{} = [&vp, &tls, &vm_pool]() {
                    tls.online_pps = INTEGRATION_MAX_PPS.get();
                    bsl::ut_required_step(vp.initialize(tls, VPID1));
                    tls.test_ret = errc_vm_is_zombie_failure;
                    bsl::ut_then{} = [&vp, &tls, &vm_pool]() {
                        bsl::ut_check(!vp.allocate(tls, vm_pool, VMID0, PPID0));
                    };
                };
            };
        };

        bsl::ut_scenario{"allocate invalid vmid version #4"} = []() {
            bsl::ut_given{} = []() {
                vp_t vp{};
                tls_t tls{};
                dummy_vm_pool_t vm_pool{};
                bsl::ut_when{} = [&vp, &tls, &vm_pool]() {
                    tls.online_pps = INTEGRATION_MAX_PPS.get();
                    bsl::ut_required_step(vp.initialize(tls, VPID1));
                    tls.test_ret = errc_vm_is_deallocated_failure;
                    bsl::ut_then{} = [&vp, &tls, &vm_pool]() {
                        bsl::ut_check(!vp.allocate(tls, vm_pool, VMID0, PPID0));
                    };
                };
            };
        };

        bsl::ut_scenario{"allocate invalid ppid version #1"} = []() {
            bsl::ut_given{} = []() {
                vp_t vp{};
                tls_t tls{};
                dummy_vm_pool_t vm_pool{};
                bsl::ut_when{} = [&vp, &tls, &vm_pool]() {
                    tls.online_pps = INTEGRATION_MAX_PPS.get();
                    bsl::ut_required_step(vp.initialize(tls, VPID1));
                    bsl::ut_then{} = [&vp, &tls, &vm_pool]() {
                        bsl::ut_check(
                            !vp.allocate(tls, vm_pool, VMID0, bsl::safe_uint16::failure()));
                    };
                };
            };
        };

        bsl::ut_scenario{"allocate invalid ppid version #2"} = []() {
            bsl::ut_given{} = []() {
                vp_t vp{};
                tls_t tls{};
                dummy_vm_pool_t vm_pool{};
                bsl::ut_when{} = [&vp, &tls, &vm_pool]() {
                    tls.online_pps = INTEGRATION_MAX_PPS.get();
                    bsl::ut_required_step(vp.initialize(tls, VPID1));
                    bsl::ut_then{} = [&vp, &tls, &vm_pool]() {
                        bsl::ut_check(!vp.allocate(tls, vm_pool, VMID0, syscall::BF_INVALID_ID));
                    };
                };
            };
        };

        bsl::ut_scenario{"allocate invalid ppid version #3"} = []() {
            bsl::ut_given{} = []() {
                vp_t vp{};
                tls_t tls{};
                dummy_vm_pool_t vm_pool{};
                bsl::ut_when{} = [&vp, &tls, &vm_pool]() {
                    tls.online_pps = {};
                    bsl::ut_required_step(vp.initialize(tls, VPID1));
                    bsl::ut_then{} = [&vp, &tls, &vm_pool]() {
                        bsl::ut_check(!vp.allocate(tls, vm_pool, VMID0, PPID0));
                    };
                };
            };
        };

        bsl::ut_scenario{"allocate zombie failure"} = []() {
            bsl::ut_given{} = []() {
                vp_t vp{};
                tls_t tls{};
                dummy_vm_pool_t vm_pool{};
                bsl::ut_when{} = [&vp, &tls, &vm_pool]() {
                    tls.online_pps = INTEGRATION_MAX_PPS.get();
                    bsl::ut_required_step(vp.initialize(tls, VPID1));
                    vp.zombify();
                    bsl::ut_then{} = [&vp, &tls, &vm_pool]() {
                        bsl::ut_check(!vp.allocate(tls, vm_pool, VMID0, PPID0));
                    };
                };
            };
        };

        bsl::ut_scenario{"allocate more than once failure"} = []() {
            bsl::ut_given{} = []() {
                vp_t vp{};
                tls_t tls{};
                dummy_vm_pool_t vm_pool{};
                bsl::ut_when{} = [&vp, &tls, &vm_pool]() {
                    tls.online_pps = INTEGRATION_MAX_PPS.get();
                    bsl::ut_required_step(vp.initialize(tls, VPID0));
                    bsl::ut_required_step(vp.allocate(tls, vm_pool, VMID0, PPID0));
                    bsl::ut_then{} = [&vp, &tls, &vm_pool]() {
                        bsl::ut_check(!vp.allocate(tls, vm_pool, VMID0, PPID0));
                    };
                };
            };
        };

        bsl::ut_scenario{"deallocate not initialized failure"} = []() {
            bsl::ut_given{} = []() {
                vp_t vp{};
                tls_t tls{};
                dummy_vps_pool_t vps_pool{};
                bsl::ut_then{} = [&vp, &tls, &vps_pool]() {
                    bsl::ut_check(!vp.deallocate(tls, vps_pool));
                };
            };
        };

        bsl::ut_scenario{"deallocate zombie failure"} = []() {
            bsl::ut_given{} = []() {
                vp_t vp{};
                tls_t tls{};
                dummy_vm_pool_t vm_pool{};
                dummy_vps_pool_t vps_pool{};
                bsl::ut_when{} = [&vp, &tls, &vm_pool, &vps_pool]() {
                    tls.online_pps = INTEGRATION_MAX_PPS.get();
                    bsl::ut_required_step(vp.initialize(tls, VPID1));
                    bsl::ut_required_step(vp.allocate(tls, vm_pool, VMID0, PPID0));
                    vp.zombify();
                    bsl::ut_then{} = [&vp, &tls, &vps_pool]() {
                        bsl::ut_check(!vp.deallocate(tls, vps_pool));
                    };
                };
            };
        };

        bsl::ut_scenario{"deallocate already deallocated failure"} = []() {
            bsl::ut_given{} = []() {
                vp_t vp{};
                tls_t tls{};
                dummy_vm_pool_t vm_pool{};
                dummy_vps_pool_t vps_pool{};
                bsl::ut_when{} = [&vp, &tls, &vm_pool, &vps_pool]() {
                    tls.online_pps = INTEGRATION_MAX_PPS.get();
                    bsl::ut_required_step(vp.initialize(tls, VPID1));
                    bsl::ut_required_step(vp.allocate(tls, vm_pool, VMID0, PPID0));
                    bsl::ut_required_step(vp.deallocate(tls, vps_pool));
                    bsl::ut_then{} = [&vp, &tls, &vps_pool]() {
                        bsl::ut_check(!vp.deallocate(tls, vps_pool));
                    };
                };
            };
        };

        bsl::ut_scenario{"deallocate assigned failure results in zombie"} = []() {
            bsl::ut_given{} = []() {
                dummy_vm_pool_t vm_pool{};
                vp_t vp{};
                tls_t tls{};
                dummy_vps_pool_t vps_pool{};
                bsl::ut_when{} = [&vp, &tls, &vm_pool, &vps_pool]() {
                    tls.online_pps = INTEGRATION_MAX_PPS.get();
                    bsl::ut_required_step(vp.initialize(tls, VPID1));
                    bsl::ut_required_step(vp.allocate(tls, vm_pool, VMID0, PPID0));
                    tls.test_ret = errc_vps_pool_failure;
                    bsl::ut_then{} = [&vp, &tls, &vps_pool]() {
                        bsl::ut_check(!vp.deallocate(tls, vps_pool));
                        bsl::ut_check(vp.is_zombie());
                        bsl::ut_check(tls.state_reversal_required);
                    };
                };
            };
        };

        bsl::ut_scenario{"deallocate still active failure results in zombie"} = []() {
            bsl::ut_given{} = []() {
                vp_t vp{};
                tls_t tls{};
                dummy_vm_pool_t vm_pool{};
                dummy_vps_pool_t vps_pool{};
                bsl::ut_when{} = [&vp, &tls, &vm_pool, &vps_pool]() {
                    tls.online_pps = INTEGRATION_MAX_PPS.get();
                    tls.active_vpid = syscall::BF_INVALID_ID.get();
                    bsl::ut_required_step(vp.initialize(tls, VPID1));
                    bsl::ut_required_step(vp.allocate(tls, vm_pool, VMID0, PPID0));
                    bsl::ut_required_step(vp.set_active(tls));
                    bsl::ut_then{} = [&vp, &tls, &vps_pool]() {
                        bsl::ut_check(!vp.deallocate(tls, vps_pool));
                        bsl::ut_check(vp.is_zombie());
                        bsl::ut_check(tls.state_reversal_required);
                    };
                };
            };
        };

        bsl::ut_scenario{"deallocate success"} = []() {
            bsl::ut_given{} = []() {
                vp_t vp{};
                tls_t tls{};
                dummy_vm_pool_t vm_pool{};
                dummy_vps_pool_t vps_pool{};
                bsl::ut_when{} = [&vp, &tls, &vm_pool, &vps_pool]() {
                    tls.online_pps = INTEGRATION_MAX_PPS.get();
                    bsl::ut_required_step(vp.initialize(tls, VPID1));
                    bsl::ut_required_step(vp.allocate(tls, vm_pool, VMID0, PPID0));
                    bsl::ut_then{} = [&vp, &tls, &vps_pool]() {
                        bsl::ut_check(vp.deallocate(tls, vps_pool));
                        bsl::ut_check(tls.state_reversal_required);
                    };
                };
            };
        };

        bsl::ut_scenario{"zombify without initialize success"} = []() {
            bsl::ut_given{} = []() {
                vp_t vp{};
                bsl::ut_when{} = [&vp]() {
                    vp.zombify();
                    bsl::ut_then{} = [&vp]() {
                        bsl::ut_check(!vp.is_zombie());
                    };
                };
            };
        };

        bsl::ut_scenario{"zombify success"} = []() {
            bsl::ut_given{} = []() {
                vp_t vp{};
                tls_t tls{};
                bsl::ut_when{} = [&vp, &tls]() {
                    bsl::ut_required_step(vp.initialize(tls, VPID1));
                    vp.zombify();
                    bsl::ut_then{} = [&vp]() {
                        bsl::ut_check(vp.is_zombie());
                    };
                };
            };
        };

        bsl::ut_scenario{"zombify more than once is ignored"} = []() {
            bsl::ut_given{} = []() {
                vp_t vp{};
                tls_t tls{};
                bsl::ut_when{} = [&vp, &tls]() {
                    bsl::ut_required_step(vp.initialize(tls, VPID1));
                    vp.zombify();
                    vp.zombify();
                    bsl::ut_then{} = [&vp]() {
                        bsl::ut_check(vp.is_zombie());
                    };
                };
            };
        };

        bsl::ut_scenario{"status without initialize"} = []() {
            bsl::ut_given{} = []() {
                vp_t vp{};
                bsl::ut_then{} = [&vp]() {
                    bsl::ut_check(vp.is_deallocated());
                    bsl::ut_check(!vp.is_allocated());
                    bsl::ut_check(!vp.is_zombie());
                };
            };
        };

        bsl::ut_scenario{"status after initialize"} = []() {
            bsl::ut_given{} = []() {
                vp_t vp{};
                tls_t tls{};
                bsl::ut_when{} = [&vp, &tls]() {
                    bsl::ut_required_step(vp.initialize(tls, VPID1));
                    bsl::ut_then{} = [&vp]() {
                        bsl::ut_check(vp.is_deallocated());
                        bsl::ut_check(!vp.is_allocated());
                        bsl::ut_check(!vp.is_zombie());
                    };
                };
            };
        };

        bsl::ut_scenario{"status after allocation"} = []() {
            bsl::ut_given{} = []() {
                vp_t vp{};
                tls_t tls{};
                dummy_vm_pool_t vm_pool{};
                bsl::ut_when{} = [&vp, &tls, &vm_pool]() {
                    tls.online_pps = INTEGRATION_MAX_PPS.get();
                    bsl::ut_required_step(vp.initialize(tls, VPID1));
                    bsl::ut_required_step(vp.allocate(tls, vm_pool, VMID0, PPID0));
                    bsl::ut_then{} = [&vp]() {
                        bsl::ut_check(!vp.is_deallocated());
                        bsl::ut_check(vp.is_allocated());
                        bsl::ut_check(!vp.is_zombie());
                    };
                };
            };
        };

        bsl::ut_scenario{"status after deallocation"} = []() {
            bsl::ut_given{} = []() {
                vp_t vp{};
                tls_t tls{};
                dummy_vm_pool_t vm_pool{};
                dummy_vps_pool_t vps_pool{};
                bsl::ut_when{} = [&vp, &tls, &vm_pool, &vps_pool]() {
                    tls.online_pps = INTEGRATION_MAX_PPS.get();
                    bsl::ut_required_step(vp.initialize(tls, VPID1));
                    bsl::ut_required_step(vp.allocate(tls, vm_pool, VMID0, PPID0));
                    bsl::ut_required_step(vp.deallocate(tls, vps_pool));
                    bsl::ut_then{} = [&vp]() {
                        bsl::ut_check(vp.is_deallocated());
                        bsl::ut_check(!vp.is_allocated());
                        bsl::ut_check(!vp.is_zombie());
                    };
                };
            };
        };

        bsl::ut_scenario{"status after zombify"} = []() {
            bsl::ut_given{} = []() {
                vp_t vp{};
                tls_t tls{};
                bsl::ut_when{} = [&vp, &tls]() {
                    bsl::ut_required_step(vp.initialize(tls, VPID1));
                    vp.zombify();
                    bsl::ut_then{} = [&vp]() {
                        bsl::ut_check(!vp.is_deallocated());
                        bsl::ut_check(!vp.is_allocated());
                        bsl::ut_check(vp.is_zombie());
                    };
                };
            };
        };

        bsl::ut_scenario{"set_active without initialize failure"} = []() {
            bsl::ut_given{} = []() {
                vp_t vp{};
                tls_t tls{};
                bsl::ut_then{} = [&tls, &vp]() {
                    bsl::ut_check(!vp.set_active(tls));
                };
            };
        };

        bsl::ut_scenario{"set_active without allocate failure"} = []() {
            bsl::ut_given{} = []() {
                vp_t vp{};
                tls_t tls{};
                bsl::ut_when{} = [&tls, &vp]() {
                    tls.online_pps = INTEGRATION_MAX_PPS.get();
                    tls.active_vpid = syscall::BF_INVALID_ID.get();
                    bsl::ut_required_step(vp.initialize(tls, VPID1));
                    bsl::ut_then{} = [&tls, &vp]() {
                        bsl::ut_check(!vp.set_active(tls));
                    };
                };
            };
        };

        bsl::ut_scenario{"set_active zombie failure"} = []() {
            bsl::ut_given{} = []() {
                vp_t vp{};
                tls_t tls{};
                dummy_vm_pool_t vm_pool{};
                bsl::ut_when{} = [&vp, &tls, &vm_pool]() {
                    tls.online_pps = INTEGRATION_MAX_PPS.get();
                    tls.active_vpid = syscall::BF_INVALID_ID.get();
                    bsl::ut_required_step(vp.initialize(tls, VPID1));
                    bsl::ut_required_step(vp.allocate(tls, vm_pool, VMID0, PPID0));
                    vp.zombify();
                    bsl::ut_then{} = [&tls, &vp]() {
                        bsl::ut_check(!vp.set_active(tls));
                    };
                };
            };
        };

        bsl::ut_scenario{"set_active already active"} = []() {
            bsl::ut_given{} = []() {
                vp_t vp{};
                tls_t tls{};
                dummy_vm_pool_t vm_pool{};
                bsl::ut_when{} = [&vp, &tls, &vm_pool]() {
                    tls.online_pps = INTEGRATION_MAX_PPS.get();
                    tls.active_vpid = syscall::BF_INVALID_ID.get();
                    bsl::ut_required_step(vp.initialize(tls, VPID1));
                    bsl::ut_required_step(vp.allocate(tls, vm_pool, VMID0, PPID0));
                    bsl::ut_required_step(vp.set_active(tls));
                    bsl::ut_then{} = [&tls, &vp]() {
                        bsl::ut_check(!vp.set_active(tls));
                    };
                };
            };
        };

        bsl::ut_scenario{"set_active corrupt already active"} = []() {
            bsl::ut_given{} = []() {
                vp_t vp{};
                tls_t tls{};
                dummy_vm_pool_t vm_pool{};
                bsl::ut_when{} = [&vp, &tls, &vm_pool]() {
                    tls.online_pps = INTEGRATION_MAX_PPS.get();
                    tls.active_vpid = syscall::BF_INVALID_ID.get();
                    bsl::ut_required_step(vp.initialize(tls, VPID1));
                    bsl::ut_required_step(vp.allocate(tls, vm_pool, VMID0, PPID0));
                    bsl::ut_required_step(vp.set_active(tls));
                    tls.active_vpid = syscall::BF_INVALID_ID.get();
                    bsl::ut_then{} = [&tls, &vp]() {
                        bsl::ut_check(!vp.set_active(tls));
                    };
                };
            };
        };

        bsl::ut_scenario{"set_active another vp is active failure"} = []() {
            bsl::ut_given{} = []() {
                vp_t vp{};
                tls_t tls{};
                dummy_vm_pool_t vm_pool{};
                bsl::ut_when{} = [&vp, &tls, &vm_pool]() {
                    tls.online_pps = INTEGRATION_MAX_PPS.get();
                    tls.active_vpid = VPID0.get();
                    bsl::ut_required_step(vp.initialize(tls, VPID1));
                    bsl::ut_required_step(vp.allocate(tls, vm_pool, VMID0, PPID0));
                    bsl::ut_then{} = [&tls, &vp]() {
                        bsl::ut_check(!vp.set_active(tls));
                    };
                };
            };
        };

        bsl::ut_scenario{"set_active invalid active_vmid failure"} = []() {
            bsl::ut_given{} = []() {
                vp_t vp{};
                tls_t tls{};
                dummy_vm_pool_t vm_pool{};
                bsl::ut_when{} = [&vp, &tls, &vm_pool]() {
                    tls.online_pps = INTEGRATION_MAX_PPS.get();
                    tls.active_vpid = syscall::BF_INVALID_ID.get();
                    bsl::ut_required_step(vp.initialize(tls, VPID1));
                    bsl::ut_required_step(vp.allocate(tls, vm_pool, VMID0, PPID0));
                    tls.active_vmid = syscall::BF_INVALID_ID.get();
                    bsl::ut_then{} = [&tls, &vp]() {
                        bsl::ut_check(!vp.set_active(tls));
                    };
                };
            };
        };

        bsl::ut_scenario{"set_active invalid ppid failure"} = []() {
            bsl::ut_given{} = []() {
                vp_t vp{};
                tls_t tls{};
                dummy_vm_pool_t vm_pool{};
                bsl::ut_when{} = [&vp, &tls, &vm_pool]() {
                    tls.online_pps = INTEGRATION_MAX_PPS.get();
                    tls.active_vpid = syscall::BF_INVALID_ID.get();
                    tls.ppid = syscall::BF_INVALID_ID.get();
                    bsl::ut_required_step(vp.initialize(tls, VPID1));
                    bsl::ut_required_step(vp.allocate(tls, vm_pool, VMID0, PPID0));
                    bsl::ut_then{} = [&tls, &vp]() {
                        bsl::ut_check(!vp.set_active(tls));
                    };
                };
            };
        };

        bsl::ut_scenario{"set_active success"} = []() {
            bsl::ut_given{} = []() {
                vp_t vp{};
                tls_t tls{};
                dummy_vm_pool_t vm_pool{};
                bsl::ut_when{} = [&vp, &tls, &vm_pool]() {
                    tls.online_pps = INTEGRATION_MAX_PPS.get();
                    tls.active_vpid = syscall::BF_INVALID_ID.get();
                    bsl::ut_required_step(vp.initialize(tls, VPID1));
                    bsl::ut_required_step(vp.allocate(tls, vm_pool, VMID0, PPID0));
                    bsl::ut_then{} = [&tls, &vp]() {
                        bsl::ut_check(vp.set_active(tls));
                    };
                };
            };
        };

        bsl::ut_scenario{"set_inactive without initialize failure"} = []() {
            bsl::ut_given{} = []() {
                vp_t vp{};
                tls_t tls{};
                bsl::ut_then{} = [&tls, &vp]() {
                    bsl::ut_check(!vp.set_inactive(tls));
                };
            };
        };

        bsl::ut_scenario{"set_inactive without activate failure"} = []() {
            bsl::ut_given{} = []() {
                vp_t vp{};
                tls_t tls{};
                bsl::ut_when{} = [&tls, &vp]() {
                    tls.online_pps = INTEGRATION_MAX_PPS.get();
                    tls.active_vpid = syscall::BF_INVALID_ID.get();
                    bsl::ut_required_step(vp.initialize(tls, VPID1));
                    bsl::ut_then{} = [&tls, &vp]() {
                        bsl::ut_check(!vp.set_inactive(tls));
                    };
                };
            };
        };

        bsl::ut_scenario{"set_inactive zombie is allowed"} = []() {
            bsl::ut_given{} = []() {
                vp_t vp{};
                tls_t tls{};
                dummy_vm_pool_t vm_pool{};
                bsl::ut_when{} = [&vp, &tls, &vm_pool]() {
                    tls.online_pps = INTEGRATION_MAX_PPS.get();
                    tls.active_vpid = syscall::BF_INVALID_ID.get();
                    bsl::ut_required_step(vp.initialize(tls, VPID1));
                    bsl::ut_required_step(vp.allocate(tls, vm_pool, VMID0, PPID0));
                    bsl::ut_required_step(vp.set_active(tls));
                    vp.zombify();
                    bsl::ut_then{} = [&tls, &vp]() {
                        bsl::ut_check(vp.set_inactive(tls));
                    };
                };
            };
        };

        bsl::ut_scenario{"set_inactive already inactive"} = []() {
            bsl::ut_given{} = []() {
                vp_t vp{};
                tls_t tls{};
                dummy_vm_pool_t vm_pool{};
                bsl::ut_when{} = [&vp, &tls, &vm_pool]() {
                    tls.online_pps = INTEGRATION_MAX_PPS.get();
                    tls.active_vpid = syscall::BF_INVALID_ID.get();
                    bsl::ut_required_step(vp.initialize(tls, VPID1));
                    bsl::ut_required_step(vp.allocate(tls, vm_pool, VMID0, PPID0));
                    bsl::ut_required_step(vp.set_active(tls));
                    tls.active_vpid = syscall::BF_INVALID_ID.get();
                    bsl::ut_then{} = [&tls, &vp]() {
                        bsl::ut_check(!vp.set_inactive(tls));
                    };
                };
            };
        };

        bsl::ut_scenario{"set_inactive active vp is not this vp"} = []() {
            bsl::ut_given{} = []() {
                vp_t vp{};
                tls_t tls{};
                dummy_vm_pool_t vm_pool{};
                bsl::ut_when{} = [&vp, &tls, &vm_pool]() {
                    tls.online_pps = INTEGRATION_MAX_PPS.get();
                    tls.active_vpid = syscall::BF_INVALID_ID.get();
                    bsl::ut_required_step(vp.initialize(tls, VPID1));
                    bsl::ut_required_step(vp.allocate(tls, vm_pool, VMID0, PPID0));
                    bsl::ut_required_step(vp.set_active(tls));
                    tls.active_vpid = VPID0.get();
                    bsl::ut_then{} = [&tls, &vp]() {
                        bsl::ut_check(!vp.set_inactive(tls));
                    };
                };
            };
        };

        bsl::ut_scenario{"set_inactive invalid ppid failure"} = []() {
            bsl::ut_given{} = []() {
                vp_t vp{};
                tls_t tls{};
                dummy_vm_pool_t vm_pool{};
                bsl::ut_when{} = [&vp, &tls, &vm_pool]() {
                    tls.online_pps = INTEGRATION_MAX_PPS.get();
                    tls.active_vpid = syscall::BF_INVALID_ID.get();
                    bsl::ut_required_step(vp.initialize(tls, VPID1));
                    bsl::ut_required_step(vp.allocate(tls, vm_pool, VMID0, PPID0));
                    bsl::ut_required_step(vp.set_active(tls));
                    tls.ppid = syscall::BF_INVALID_ID.get();
                    bsl::ut_then{} = [&tls, &vp]() {
                        bsl::ut_check(!vp.set_inactive(tls));
                    };
                };
            };
        };

        bsl::ut_scenario{"set_inactive more than once failure"} = []() {
            bsl::ut_given{} = []() {
                vp_t vp{};
                tls_t tls{};
                dummy_vm_pool_t vm_pool{};
                bsl::ut_when{} = [&vp, &tls, &vm_pool]() {
                    tls.online_pps = INTEGRATION_MAX_PPS.get();
                    tls.active_vpid = syscall::BF_INVALID_ID.get();
                    bsl::ut_required_step(vp.initialize(tls, VPID1));
                    bsl::ut_required_step(vp.allocate(tls, vm_pool, VMID0, PPID0));
                    bsl::ut_required_step(vp.set_active(tls));
                    bsl::ut_required_step(vp.set_inactive(tls));
                    bsl::ut_then{} = [&tls, &vp]() {
                        bsl::ut_check(!vp.set_inactive(tls));
                    };
                };
            };
        };

        bsl::ut_scenario{"set_inactive corrupt active vp"} = []() {
            bsl::ut_given{} = []() {
                vp_t vp{};
                tls_t tls{};
                dummy_vm_pool_t vm_pool{};
                bsl::ut_when{} = [&vp, &tls, &vm_pool]() {
                    tls.online_pps = INTEGRATION_MAX_PPS.get();
                    tls.active_vpid = syscall::BF_INVALID_ID.get();
                    bsl::ut_required_step(vp.initialize(tls, VPID1));
                    bsl::ut_required_step(vp.allocate(tls, vm_pool, VMID0, PPID0));
                    bsl::ut_required_step(vp.set_active(tls));
                    bsl::ut_required_step(vp.set_inactive(tls));
                    tls.active_vpid = VPID1.get();
                    bsl::ut_then{} = [&tls, &vp]() {
                        bsl::ut_check(!vp.set_inactive(tls));
                    };
                };
            };
        };

        bsl::ut_scenario{"set_inactive success"} = []() {
            bsl::ut_given{} = []() {
                vp_t vp{};
                tls_t tls{};
                dummy_vm_pool_t vm_pool{};
                bsl::ut_when{} = [&vp, &tls, &vm_pool]() {
                    tls.online_pps = INTEGRATION_MAX_PPS.get();
                    tls.active_vpid = syscall::BF_INVALID_ID.get();
                    bsl::ut_required_step(vp.initialize(tls, VPID1));
                    bsl::ut_required_step(vp.allocate(tls, vm_pool, VMID0, PPID0));
                    bsl::ut_required_step(vp.set_active(tls));
                    bsl::ut_then{} = [&tls, &vp]() {
                        bsl::ut_check(vp.set_inactive(tls));
                    };
                };
            };
        };

        bsl::ut_scenario{"is_active reports true"} = []() {
            bsl::ut_given{} = []() {
                vp_t vp{};
                tls_t tls{};
                dummy_vm_pool_t vm_pool{};
                bsl::ut_when{} = [&vp, &tls, &vm_pool]() {
                    tls.online_pps = INTEGRATION_MAX_PPS.get();
                    tls.active_vpid = syscall::BF_INVALID_ID.get();
                    bsl::ut_required_step(vp.initialize(tls, VPID1));
                    bsl::ut_required_step(vp.allocate(tls, vm_pool, VMID0, PPID0));
                    bsl::ut_required_step(vp.set_active(tls));
                    bsl::ut_then{} = [&tls, &vp]() {
                        bsl::ut_check(vp.is_active(tls) == tls.ppid);
                    };
                };
            };
        };

        bsl::ut_scenario{"is_active reports false"} = []() {
            bsl::ut_given{} = []() {
                vp_t vp{};
                tls_t tls{};
                dummy_vm_pool_t vm_pool{};
                bsl::ut_when{} = [&vp, &tls, &vm_pool]() {
                    tls.online_pps = INTEGRATION_MAX_PPS.get();
                    tls.active_vpid = syscall::BF_INVALID_ID.get();
                    bsl::ut_required_step(vp.initialize(tls, VPID1));
                    bsl::ut_required_step(vp.allocate(tls, vm_pool, VMID0, PPID0));
                    bsl::ut_then{} = [&tls, &vp]() {
                        bsl::ut_check(!vp.is_active(tls));
                    };
                };
            };
        };

        bsl::ut_scenario{"is_active reports false with corrupt online_pps"} = []() {
            bsl::ut_given{} = []() {
                vp_t vp{};
                tls_t tls{};
                dummy_vm_pool_t vm_pool{};
                bsl::ut_when{} = [&vp, &tls, &vm_pool]() {
                    tls.online_pps = syscall::BF_INVALID_ID.get();
                    tls.active_vpid = syscall::BF_INVALID_ID.get();
                    bsl::ut_required_step(vp.initialize(tls, VPID1));
                    bsl::ut_required_step(vp.allocate(tls, vm_pool, VMID0, PPID0));
                    bsl::ut_then{} = [&tls, &vp]() {
                        bsl::ut_check(!vp.is_active(tls));
                    };
                };
            };
        };

        bsl::ut_scenario{"is_active_on_current_pp reports true"} = []() {
            bsl::ut_given{} = []() {
                vp_t vp{};
                tls_t tls{};
                dummy_vm_pool_t vm_pool{};
                bsl::ut_when{} = [&vp, &tls, &vm_pool]() {
                    tls.online_pps = INTEGRATION_MAX_PPS.get();
                    tls.active_vpid = syscall::BF_INVALID_ID.get();
                    bsl::ut_required_step(vp.initialize(tls, VPID1));
                    bsl::ut_required_step(vp.allocate(tls, vm_pool, VMID0, PPID0));
                    bsl::ut_required_step(vp.set_active(tls));
                    bsl::ut_then{} = [&tls, &vp]() {
                        bsl::ut_check(vp.is_active_on_current_pp(tls));
                    };
                };
            };
        };

        bsl::ut_scenario{"is_active_on_current_pp reports false"} = []() {
            bsl::ut_given{} = []() {
                vp_t vp{};
                tls_t tls{};
                dummy_vm_pool_t vm_pool{};
                bsl::ut_when{} = [&vp, &tls, &vm_pool]() {
                    tls.online_pps = INTEGRATION_MAX_PPS.get();
                    tls.active_vpid = syscall::BF_INVALID_ID.get();
                    bsl::ut_required_step(vp.initialize(tls, VPID1));
                    bsl::ut_required_step(vp.allocate(tls, vm_pool, VMID0, PPID0));
                    bsl::ut_then{} = [&tls, &vp]() {
                        bsl::ut_check(!vp.is_active_on_current_pp(tls));
                    };
                };
            };
        };

        bsl::ut_scenario{"is_active_on_current_pp reports false with corrupt online_pps"} = []() {
            bsl::ut_given{} = []() {
                vp_t vp{};
                tls_t tls{};
                dummy_vm_pool_t vm_pool{};
                bsl::ut_when{} = [&vp, &tls, &vm_pool]() {
                    tls.online_pps = syscall::BF_INVALID_ID.get();
                    tls.active_vpid = syscall::BF_INVALID_ID.get();
                    bsl::ut_required_step(vp.initialize(tls, VPID1));
                    bsl::ut_required_step(vp.allocate(tls, vm_pool, VMID0, PPID0));
                    bsl::ut_then{} = [&tls, &vp]() {
                        bsl::ut_check(!vp.is_active_on_current_pp(tls));
                    };
                };
            };
        };

        bsl::ut_scenario{"is_active_on_current_pp reports false with corrupt online_pps"} = []() {
            bsl::ut_given{} = []() {
                vp_t vp{};
                tls_t tls{};
                dummy_vm_pool_t vm_pool{};
                bsl::ut_when{} = [&vp, &tls, &vm_pool]() {
                    tls.online_pps = syscall::BF_INVALID_ID.get();
                    tls.active_vpid = syscall::BF_INVALID_ID.get();
                    bsl::ut_required_step(vp.initialize(tls, VPID1));
                    bsl::ut_required_step(vp.allocate(tls, vm_pool, VMID0, PPID0));
                    bsl::ut_then{} = [&tls, &vp]() {
                        bsl::ut_check(!vp.is_active_on_current_pp(tls));
                    };
                };
            };
        };

        bsl::ut_scenario{"migrate without initialize failure"} = []() {
            bsl::ut_given{} = []() {
                vp_t vp{};
                tls_t tls{};
                bsl::ut_when{} = [&tls, &vp]() {
                    bsl::ut_then{} = [&tls, &vp]() {
                        bsl::ut_check(!vp.migrate(tls, PPID1));
                    };
                };
            };
        };

        bsl::ut_scenario{"migrate without allocate failure"} = []() {
            bsl::ut_given{} = []() {
                vp_t vp{};
                tls_t tls{};
                bsl::ut_when{} = [&tls, &vp]() {
                    tls.online_pps = INTEGRATION_MAX_PPS.get();
                    bsl::ut_required_step(vp.initialize(tls, VPID1));
                    bsl::ut_then{} = [&tls, &vp]() {
                        bsl::ut_check(!vp.migrate(tls, PPID1));
                    };
                };
            };
        };

        bsl::ut_scenario{"migrate invalid ppid failure version #1"} = []() {
            bsl::ut_given{} = []() {
                vp_t vp{};
                tls_t tls{};
                dummy_vm_pool_t vm_pool{};
                bsl::ut_when{} = [&vp, &tls, &vm_pool]() {
                    tls.online_pps = INTEGRATION_MAX_PPS.get();
                    bsl::ut_required_step(vp.initialize(tls, VPID1));
                    bsl::ut_required_step(vp.allocate(tls, vm_pool, VMID0, PPID0));
                    bsl::ut_then{} = [&tls, &vp]() {
                        bsl::ut_check(!vp.migrate(tls, bsl::safe_uint16::failure()));
                    };
                };
            };
        };

        bsl::ut_scenario{"migrate invalid ppid failure version #2"} = []() {
            bsl::ut_given{} = []() {
                vp_t vp{};
                tls_t tls{};
                dummy_vm_pool_t vm_pool{};
                bsl::ut_when{} = [&vp, &tls, &vm_pool]() {
                    tls.online_pps = INTEGRATION_MAX_PPS.get();
                    bsl::ut_required_step(vp.initialize(tls, VPID1));
                    bsl::ut_required_step(vp.allocate(tls, vm_pool, VMID0, PPID0));
                    bsl::ut_then{} = [&tls, &vp]() {
                        bsl::ut_check(!vp.migrate(tls, syscall::BF_INVALID_ID));
                    };
                };
            };
        };

        bsl::ut_scenario{"migrate invalid ppid failure version #3"} = []() {
            bsl::ut_given{} = []() {
                vp_t vp{};
                tls_t tls{};
                dummy_vm_pool_t vm_pool{};
                bsl::ut_when{} = [&vp, &tls, &vm_pool]() {
                    tls.online_pps = INTEGRATION_MAX_PPS.get();
                    bsl::ut_required_step(vp.initialize(tls, VPID1));
                    bsl::ut_required_step(vp.allocate(tls, vm_pool, VMID0, PPID0));
                    bsl::ut_then{} = [&tls, &vp]() {
                        bsl::ut_check(!vp.migrate(tls, PPID2));
                    };
                };
            };
        };

        bsl::ut_scenario{"migrate already assigned to ppid failure"} = []() {
            bsl::ut_given{} = []() {
                vp_t vp{};
                tls_t tls{};
                dummy_vm_pool_t vm_pool{};
                bsl::ut_when{} = [&vp, &tls, &vm_pool]() {
                    tls.online_pps = INTEGRATION_MAX_PPS.get();
                    bsl::ut_required_step(vp.initialize(tls, VPID1));
                    bsl::ut_required_step(vp.allocate(tls, vm_pool, VMID0, PPID0));
                    bsl::ut_then{} = [&tls, &vp]() {
                        bsl::ut_check(!vp.migrate(tls, PPID0));
                    };
                };
            };
        };

        bsl::ut_scenario{"migrate active failure"} = []() {
            bsl::ut_given{} = []() {
                vp_t vp{};
                tls_t tls{};
                dummy_vm_pool_t vm_pool{};
                bsl::ut_when{} = [&vp, &tls, &vm_pool]() {
                    tls.online_pps = INTEGRATION_MAX_PPS.get();
                    tls.active_vpid = syscall::BF_INVALID_ID.get();
                    bsl::ut_required_step(vp.initialize(tls, VPID1));
                    bsl::ut_required_step(vp.allocate(tls, vm_pool, VMID0, PPID0));
                    bsl::ut_required_step(vp.set_active(tls));
                    bsl::ut_then{} = [&tls, &vp]() {
                        bsl::ut_check(!vp.migrate(tls, PPID1));
                    };
                };
            };
        };

        bsl::ut_scenario{"migrate success"} = []() {
            bsl::ut_given{} = []() {
                vp_t vp{};
                tls_t tls{};
                dummy_vm_pool_t vm_pool{};
                bsl::ut_when{} = [&vp, &tls, &vm_pool]() {
                    tls.online_pps = INTEGRATION_MAX_PPS.get();
                    bsl::ut_required_step(vp.initialize(tls, VPID1));
                    bsl::ut_required_step(vp.allocate(tls, vm_pool, VMID0, PPID0));
                    bsl::ut_then{} = [&tls, &vp]() {
                        bsl::ut_check(vp.migrate(tls, PPID1));
                    };
                };
            };
        };

        bsl::ut_scenario{"assigned_vm without allocation"} = []() {
            bsl::ut_given{} = []() {
                vp_t vp{};
                tls_t tls{};
                bsl::ut_when{} = [&vp, &tls]() {
                    bsl::ut_required_step(vp.initialize(tls, VPID1));
                    bsl::ut_then{} = [&vp]() {
                        bsl::ut_check(!vp.assigned_vm());
                    };
                };
            };
        };

        bsl::ut_scenario{"assigned_vm after allocation"} = []() {
            bsl::ut_given{} = []() {
                vp_t vp{};
                tls_t tls{};
                dummy_vm_pool_t vm_pool{};
                bsl::ut_when{} = [&vp, &tls, &vm_pool]() {
                    tls.online_pps = INTEGRATION_MAX_PPS.get();
                    bsl::ut_required_step(vp.initialize(tls, VPID1));
                    bsl::ut_required_step(vp.allocate(tls, vm_pool, VMID0, PPID0));
                    bsl::ut_then{} = [&vp]() {
                        bsl::ut_check(vp.assigned_vm() == VMID0);
                    };
                };
            };
        };

        bsl::ut_scenario{"assigned_pp without allocation"} = []() {
            bsl::ut_given{} = []() {
                vp_t vp{};
                tls_t tls{};
                bsl::ut_when{} = [&vp, &tls]() {
                    bsl::ut_required_step(vp.initialize(tls, VPID1));
                    bsl::ut_then{} = [&vp]() {
                        bsl::ut_check(!vp.assigned_pp());
                    };
                };
            };
        };

        bsl::ut_scenario{"assigned_pp after allocation"} = []() {
            bsl::ut_given{} = []() {
                vp_t vp{};
                tls_t tls{};
                dummy_vm_pool_t vm_pool{};
                bsl::ut_when{} = [&vp, &tls, &vm_pool]() {
                    tls.online_pps = INTEGRATION_MAX_PPS.get();
                    bsl::ut_required_step(vp.initialize(tls, VPID1));
                    bsl::ut_required_step(vp.allocate(tls, vm_pool, VMID0, PPID0));
                    bsl::ut_then{} = [&vp]() {
                        bsl::ut_check(vp.assigned_pp() == PPID0);
                    };
                };
            };
        };

        bsl::ut_scenario{"assigned_pp after migration"} = []() {
            bsl::ut_given{} = []() {
                vp_t vp{};
                tls_t tls{};
                dummy_vm_pool_t vm_pool{};
                bsl::ut_when{} = [&vp, &tls, &vm_pool]() {
                    tls.online_pps = INTEGRATION_MAX_PPS.get();
                    bsl::ut_required_step(vp.initialize(tls, VPID1));
                    bsl::ut_required_step(vp.allocate(tls, vm_pool, VMID0, PPID0));
                    bsl::ut_required_step(vp.migrate(tls, PPID1));
                    bsl::ut_then{} = [&vp]() {
                        bsl::ut_check(vp.assigned_pp() == PPID1);
                    };
                };
            };
        };

        bsl::ut_scenario{"dump without initialize"} = []() {
            bsl::ut_given{} = []() {
                vp_t vp{};
                tls_t tls{};
                bsl::ut_then{} = [&tls, &vp]() {
                    vp.dump(tls);
                };
            };
        };

        bsl::ut_scenario{"dump with initialize"} = []() {
            bsl::ut_given{} = []() {
                vp_t vp{};
                tls_t tls{};
                bsl::ut_when{} = [&tls, &vp]() {
                    bsl::ut_required_step(vp.initialize(tls, VPID1));
                    bsl::ut_then{} = [&tls, &vp]() {
                        vp.dump(tls);
                    };
                };
            };
        };

        bsl::ut_scenario{"dump with allocate"} = []() {
            bsl::ut_given{} = []() {
                vp_t vp{};
                tls_t tls{};
                dummy_vm_pool_t vm_pool{};
                bsl::ut_when{} = [&vp, &tls, &vm_pool]() {
                    tls.online_pps = INTEGRATION_MAX_PPS.get();
                    bsl::ut_required_step(vp.initialize(tls, VPID1));
                    bsl::ut_required_step(vp.allocate(tls, vm_pool, VMID0, PPID0));
                    bsl::ut_then{} = [&tls, &vp]() {
                        vp.dump(tls);
                    };
                };
            };
        };

        bsl::ut_scenario{"dump with active"} = []() {
            bsl::ut_given{} = []() {
                vp_t vp{};
                tls_t tls{};
                dummy_vm_pool_t vm_pool{};
                bsl::ut_when{} = [&vp, &tls, &vm_pool]() {
                    tls.online_pps = INTEGRATION_MAX_PPS.get();
                    tls.active_vpid = syscall::BF_INVALID_ID.get();
                    bsl::ut_required_step(vp.initialize(tls, VPID1));
                    bsl::ut_required_step(vp.allocate(tls, vm_pool, VMID0, PPID0));
                    bsl::ut_required_step(vp.set_active(tls));
                    bsl::ut_then{} = [&tls, &vp]() {
                        vp.dump(tls);
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
