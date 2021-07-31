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

#include "../../../src/vm_t.hpp"

#include <dummy_ext_pool_t.hpp>
#include <dummy_vm_t.hpp>
#include <dummy_vp_pool_t.hpp>

#include <bsl/ut.hpp>

namespace mk
{
    /// @brief defines the max number of PPs used in testing
    constexpr bsl::safe_u16 INTEGRATION_MAX_PPS{bsl::to_u16(3)};

    /// @brief defines VMID0
    constexpr bsl::safe_u16 VMID0{bsl::to_u16(0)};
    /// @brief defines VMID1
    constexpr bsl::safe_u16 VMID1{bsl::to_u16(1)};

    /// <!-- description -->
    ///   @brief Implements a yield for the spinlock
    ///
    extern "C" void
    yield() noexcept
    {}

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
        bsl::ut_scenario{"initialize invalid id version #1"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                vm_t<bsl::to_umx(INTEGRATION_MAX_PPS).get()> vm{};
                tls_t tls{};
                bsl::ut_then{} = [&vm, &tls]() {
                    bsl::ut_check(!vm.initialize(tls, bsl::safe_u16::failure()));
                };
            };
        };

        bsl::ut_scenario{"initialize invalid id version #2"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                vm_t<bsl::to_umx(INTEGRATION_MAX_PPS).get()> vm{};
                tls_t tls{};
                bsl::ut_then{} = [&vm, &tls]() {
                    bsl::ut_check(!vm.initialize(tls, syscall::BF_INVALID_ID));
                };
            };
        };

        bsl::ut_scenario{"initialize success"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                vm_t<bsl::to_umx(INTEGRATION_MAX_PPS).get()> vm{};
                tls_t tls{};
                bsl::ut_then{} = [&vm, &tls]() {
                    bsl::ut_check(vm.initialize(tls, VMID0));
                };
            };
        };

        bsl::ut_scenario{"initialize more than once failure"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                vm_t<bsl::to_umx(INTEGRATION_MAX_PPS).get()> vm{};
                tls_t tls{};
                bsl::ut_when{} = [&vm, &tls]() {
                    bsl::ut_required_step(vm.initialize(tls, VMID0));
                    bsl::ut_then{} = [&vm, &tls]() {
                        bsl::ut_check(!vm.initialize(tls, VMID0));
                    };
                };
            };
        };

        bsl::ut_scenario{"release of the root VM is ignored"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                vm_t<bsl::to_umx(INTEGRATION_MAX_PPS).get()> vm{};
                tls_t tls{};
                dummy_ext_pool_t ext_pool{};
                dummy_vp_pool_t vp_pool{};
                bsl::ut_when{} = [&vm, &tls, &ext_pool, &vp_pool]() {
                    bsl::ut_required_step(vm.initialize(tls, VMID0));
                    bsl::ut_then{} = [&vm, &tls, &ext_pool, &vp_pool]() {
                        bsl::ut_check(vm.release(tls, ext_pool, vp_pool));
                        bsl::ut_check(vm.id());
                    };
                };
            };
        };

        bsl::ut_scenario{"release success"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                vm_t<bsl::to_umx(INTEGRATION_MAX_PPS).get()> vm{};
                tls_t tls{};
                dummy_ext_pool_t ext_pool{};
                dummy_vp_pool_t vp_pool{};
                bsl::ut_when{} = [&vm, &tls, &ext_pool, &vp_pool]() {
                    bsl::ut_required_step(vm.initialize(tls, VMID1));
                    bsl::ut_then{} = [&vm, &tls, &ext_pool, &vp_pool]() {
                        bsl::ut_check(vm.release(tls, ext_pool, vp_pool));
                        bsl::ut_check(!vm.id());
                    };
                };
            };
        };

        bsl::ut_scenario{"release success after allocate"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                vm_t<bsl::to_umx(INTEGRATION_MAX_PPS).get()> vm{};
                tls_t tls{};
                dummy_ext_pool_t ext_pool{};
                dummy_vp_pool_t vp_pool{};
                bsl::ut_when{} = [&vm, &tls, &ext_pool, &vp_pool]() {
                    bsl::ut_required_step(vm.initialize(tls, VMID1));
                    bsl::ut_required_step(vm.allocate(tls, ext_pool));
                    bsl::ut_then{} = [&vm, &tls, &ext_pool, &vp_pool]() {
                        bsl::ut_check(vm.release(tls, ext_pool, vp_pool));
                        bsl::ut_check(!vm.id());
                        bsl::ut_check(!vm.is_allocated());
                    };
                };
            };
        };

        bsl::ut_scenario{"release of a zombie vm is ignored"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                vm_t<bsl::to_umx(INTEGRATION_MAX_PPS).get()> vm{};
                tls_t tls{};
                dummy_ext_pool_t ext_pool{};
                dummy_vp_pool_t vp_pool{};
                bsl::ut_when{} = [&vm, &tls, &ext_pool, &vp_pool]() {
                    bsl::ut_required_step(vm.initialize(tls, VMID1));
                    vm.zombify();
                    bsl::ut_then{} = [&vm, &tls, &ext_pool, &vp_pool]() {
                        bsl::ut_check(vm.release(tls, ext_pool, vp_pool));
                        bsl::ut_check(vm.id());
                        bsl::ut_check(vm.is_zombie());
                    };
                };
            };
        };

        bsl::ut_scenario{"release of a vm that is still assigned results in a zombie"} =
            []() noexcept {
                bsl::ut_given{} = []() noexcept {
                    vm_t<bsl::to_umx(INTEGRATION_MAX_PPS).get()> vm{};
                    tls_t tls{};
                    dummy_ext_pool_t ext_pool{};
                    dummy_vp_pool_t vp_pool{};
                    bsl::ut_when{} = [&vm, &tls, &ext_pool, &vp_pool]() {
                        bsl::ut_required_step(vm.initialize(tls, VMID1));
                        tls.test_ret = errc_vp_pool_failure;
                        bsl::ut_then{} = [&vm, &tls, &ext_pool, &vp_pool]() {
                            bsl::ut_check(!vm.release(tls, ext_pool, vp_pool));
                            bsl::ut_check(vm.id());
                            bsl::ut_check(vm.is_zombie());
                        };
                    };
                };
            };

        bsl::ut_scenario{"release of a vm that is still active results in a zombie"} =
            []() noexcept {
                bsl::ut_given{} = []() noexcept {
                    vm_t<bsl::to_umx(INTEGRATION_MAX_PPS).get()> vm{};
                    tls_t tls{};
                    dummy_ext_pool_t ext_pool{};
                    dummy_vp_pool_t vp_pool{};
                    bsl::ut_when{} = [&vm, &tls, &ext_pool, &vp_pool]() {
                        tls.online_pps = INTEGRATION_MAX_PPS.get();
                        tls.active_vmid = syscall::BF_INVALID_ID.get();
                        bsl::ut_required_step(vm.initialize(tls, VMID1));
                        bsl::ut_required_step(vm.allocate(tls, ext_pool));
                        bsl::ut_required_step(vm.set_active(tls));
                        bsl::ut_then{} = [&vm, &tls, &ext_pool, &vp_pool]() {
                            bsl::ut_check(!vm.release(tls, ext_pool, vp_pool));
                            bsl::ut_check(vm.id());
                            bsl::ut_check(vm.is_zombie());
                        };
                    };
                };
            };

        bsl::ut_scenario{"release with extension failure results in zombie"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                vm_t<bsl::to_umx(INTEGRATION_MAX_PPS).get()> vm{};
                tls_t tls{};
                dummy_ext_pool_t ext_pool{};
                dummy_vp_pool_t vp_pool{};
                bsl::ut_when{} = [&vm, &tls, &ext_pool, &vp_pool]() {
                    bsl::ut_required_step(vm.initialize(tls, VMID1));
                    tls.test_ret = errc_ext_pool_failure;
                    bsl::ut_then{} = [&vm, &tls, &ext_pool, &vp_pool]() {
                        bsl::ut_check(!vm.release(tls, ext_pool, vp_pool));
                        bsl::ut_check(vm.id());
                        bsl::ut_check(vm.is_zombie());
                    };
                };
            };
        };

        bsl::ut_scenario{"allocate without initialize failure"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                vm_t<bsl::to_umx(INTEGRATION_MAX_PPS).get()> vm{};
                tls_t tls{};
                dummy_ext_pool_t ext_pool{};
                bsl::ut_then{} = [&vm, &tls, &ext_pool]() {
                    bsl::ut_check(!vm.allocate(tls, ext_pool));
                };
            };
        };

        bsl::ut_scenario{"allocate zombie failure"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                vm_t<bsl::to_umx(INTEGRATION_MAX_PPS).get()> vm{};
                tls_t tls{};
                dummy_ext_pool_t ext_pool{};
                bsl::ut_when{} = [&vm, &tls, &ext_pool]() {
                    bsl::ut_required_step(vm.initialize(tls, VMID1));
                    vm.zombify();
                    bsl::ut_then{} = [&vm, &tls, &ext_pool]() {
                        bsl::ut_check(!vm.allocate(tls, ext_pool));
                    };
                };
            };
        };

        bsl::ut_scenario{"allocate with extension failure"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                vm_t<bsl::to_umx(INTEGRATION_MAX_PPS).get()> vm{};
                tls_t tls{};
                dummy_ext_pool_t ext_pool{};
                bsl::ut_when{} = [&vm, &tls, &ext_pool]() {
                    bsl::ut_required_step(vm.initialize(tls, VMID1));
                    tls.test_ret = errc_ext_pool_failure;
                    bsl::ut_then{} = [&vm, &tls, &ext_pool]() {
                        bsl::ut_check(!vm.allocate(tls, ext_pool));
                        bsl::ut_check(tls.state_reversal_required);
                        bsl::ut_check(tls.log_vmid == VMID1);
                    };
                };
            };
        };

        bsl::ut_scenario{"allocate success"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                vm_t<bsl::to_umx(INTEGRATION_MAX_PPS).get()> vm{};
                tls_t tls{};
                dummy_ext_pool_t ext_pool{};
                bsl::ut_when{} = [&vm, &tls, &ext_pool]() {
                    bsl::ut_required_step(vm.initialize(tls, VMID1));
                    bsl::ut_then{} = [&vm, &tls, &ext_pool]() {
                        bsl::ut_check(vm.allocate(tls, ext_pool));
                        bsl::ut_check(tls.state_reversal_required);
                        bsl::ut_check(tls.log_vmid == VMID1);
                    };
                };
            };
        };

        bsl::ut_scenario{"allocate more than once failure"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                vm_t<bsl::to_umx(INTEGRATION_MAX_PPS).get()> vm{};
                tls_t tls{};
                dummy_ext_pool_t ext_pool{};
                bsl::ut_when{} = [&vm, &tls, &ext_pool]() {
                    bsl::ut_required_step(vm.initialize(tls, VMID0));
                    bsl::ut_required_step(vm.allocate(tls, ext_pool));
                    bsl::ut_then{} = [&vm, &tls, &ext_pool]() {
                        bsl::ut_check(!vm.allocate(tls, ext_pool));
                    };
                };
            };
        };

        bsl::ut_scenario{"deallocate not initialized failure"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                vm_t<bsl::to_umx(INTEGRATION_MAX_PPS).get()> vm{};
                tls_t tls{};
                dummy_ext_pool_t ext_pool{};
                dummy_vp_pool_t vp_pool{};
                bsl::ut_then{} = [&vm, &tls, &ext_pool, &vp_pool]() {
                    bsl::ut_check(!vm.deallocate(tls, ext_pool, vp_pool));
                };
            };
        };

        bsl::ut_scenario{"deallocate root vm failure"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                vm_t<bsl::to_umx(INTEGRATION_MAX_PPS).get()> vm{};
                tls_t tls{};
                dummy_ext_pool_t ext_pool{};
                dummy_vp_pool_t vp_pool{};
                bsl::ut_when{} = [&vm, &tls, &ext_pool, &vp_pool]() {
                    bsl::ut_required_step(vm.initialize(tls, VMID0));
                    bsl::ut_required_step(vm.allocate(tls, ext_pool));
                    bsl::ut_then{} = [&vm, &tls, &ext_pool, &vp_pool]() {
                        bsl::ut_check(!vm.deallocate(tls, ext_pool, vp_pool));
                    };
                };
            };
        };

        bsl::ut_scenario{"deallocate zombie failure"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                vm_t<bsl::to_umx(INTEGRATION_MAX_PPS).get()> vm{};
                tls_t tls{};
                dummy_ext_pool_t ext_pool{};
                dummy_vp_pool_t vp_pool{};
                bsl::ut_when{} = [&vm, &tls, &ext_pool, &vp_pool]() {
                    bsl::ut_required_step(vm.initialize(tls, VMID1));
                    bsl::ut_required_step(vm.allocate(tls, ext_pool));
                    vm.zombify();
                    bsl::ut_then{} = [&vm, &tls, &ext_pool, &vp_pool]() {
                        bsl::ut_check(!vm.deallocate(tls, ext_pool, vp_pool));
                    };
                };
            };
        };

        bsl::ut_scenario{"deallocate already deallocated failure"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                vm_t<bsl::to_umx(INTEGRATION_MAX_PPS).get()> vm{};
                tls_t tls{};
                dummy_ext_pool_t ext_pool{};
                dummy_vp_pool_t vp_pool{};
                bsl::ut_when{} = [&vm, &tls, &ext_pool, &vp_pool]() {
                    bsl::ut_required_step(vm.initialize(tls, VMID1));
                    bsl::ut_required_step(vm.allocate(tls, ext_pool));
                    bsl::ut_required_step(vm.deallocate(tls, ext_pool, vp_pool));
                    bsl::ut_then{} = [&vm, &tls, &ext_pool, &vp_pool]() {
                        bsl::ut_check(!vm.deallocate(tls, ext_pool, vp_pool));
                    };
                };
            };
        };

        bsl::ut_scenario{"deallocate assigned failure results in zombie"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                vm_t<bsl::to_umx(INTEGRATION_MAX_PPS).get()> vm{};
                tls_t tls{};
                dummy_ext_pool_t ext_pool{};
                dummy_vp_pool_t vp_pool{};
                bsl::ut_when{} = [&vm, &tls, &ext_pool, &vp_pool]() {
                    bsl::ut_required_step(vm.initialize(tls, VMID1));
                    bsl::ut_required_step(vm.allocate(tls, ext_pool));
                    tls.test_ret = errc_vp_pool_failure;
                    bsl::ut_then{} = [&vm, &tls, &ext_pool, &vp_pool]() {
                        bsl::ut_check(!vm.deallocate(tls, ext_pool, vp_pool));
                        bsl::ut_check(vm.is_zombie());
                        bsl::ut_check(tls.state_reversal_required);
                    };
                };
            };
        };

        bsl::ut_scenario{"deallocate still active failure results in zombie"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                vm_t<bsl::to_umx(INTEGRATION_MAX_PPS).get()> vm{};
                tls_t tls{};
                dummy_ext_pool_t ext_pool{};
                dummy_vp_pool_t vp_pool{};
                bsl::ut_when{} = [&vm, &tls, &ext_pool, &vp_pool]() {
                    tls.online_pps = INTEGRATION_MAX_PPS.get();
                    tls.active_vmid = syscall::BF_INVALID_ID.get();
                    bsl::ut_required_step(vm.initialize(tls, VMID1));
                    bsl::ut_required_step(vm.allocate(tls, ext_pool));
                    bsl::ut_required_step(vm.set_active(tls));
                    bsl::ut_then{} = [&vm, &tls, &ext_pool, &vp_pool]() {
                        bsl::ut_check(!vm.deallocate(tls, ext_pool, vp_pool));
                        bsl::ut_check(vm.is_zombie());
                        bsl::ut_check(tls.state_reversal_required);
                    };
                };
            };
        };

        bsl::ut_scenario{"deallocate with extension failure results in zombie"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                vm_t<bsl::to_umx(INTEGRATION_MAX_PPS).get()> vm{};
                tls_t tls{};
                dummy_ext_pool_t ext_pool{};
                dummy_vp_pool_t vp_pool{};
                bsl::ut_when{} = [&vm, &tls, &ext_pool, &vp_pool]() {
                    bsl::ut_required_step(vm.initialize(tls, VMID1));
                    bsl::ut_required_step(vm.allocate(tls, ext_pool));
                    tls.test_ret = errc_ext_pool_failure;
                    bsl::ut_then{} = [&vm, &tls, &ext_pool, &vp_pool]() {
                        bsl::ut_check(!vm.deallocate(tls, ext_pool, vp_pool));
                        bsl::ut_check(vm.is_zombie());
                        bsl::ut_check(tls.state_reversal_required);
                    };
                };
            };
        };

        bsl::ut_scenario{"deallocate success"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                vm_t<bsl::to_umx(INTEGRATION_MAX_PPS).get()> vm{};
                tls_t tls{};
                dummy_ext_pool_t ext_pool{};
                dummy_vp_pool_t vp_pool{};
                bsl::ut_when{} = [&vm, &tls, &ext_pool, &vp_pool]() {
                    bsl::ut_required_step(vm.initialize(tls, VMID1));
                    bsl::ut_required_step(vm.allocate(tls, ext_pool));
                    bsl::ut_then{} = [&vm, &tls, &ext_pool, &vp_pool]() {
                        bsl::ut_check(vm.deallocate(tls, ext_pool, vp_pool));
                        bsl::ut_check(tls.state_reversal_required);
                    };
                };
            };
        };

        bsl::ut_scenario{"zombify without initialize success"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                vm_t<bsl::to_umx(INTEGRATION_MAX_PPS).get()> vm{};
                bsl::ut_when{} = [&vm]() {
                    vm.zombify();
                    bsl::ut_then{} = [&vm]() {
                        bsl::ut_check(!vm.is_zombie());
                    };
                };
            };
        };

        bsl::ut_scenario{"zombify success"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                vm_t<bsl::to_umx(INTEGRATION_MAX_PPS).get()> vm{};
                tls_t tls{};
                bsl::ut_when{} = [&vm, &tls]() {
                    bsl::ut_required_step(vm.initialize(tls, VMID1));
                    vm.zombify();
                    bsl::ut_then{} = [&vm]() {
                        bsl::ut_check(vm.is_zombie());
                    };
                };
            };
        };

        bsl::ut_scenario{"zombify root vm is ignored"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                vm_t<bsl::to_umx(INTEGRATION_MAX_PPS).get()> vm{};
                tls_t tls{};
                bsl::ut_when{} = [&vm, &tls]() {
                    bsl::ut_required_step(vm.initialize(tls, VMID0));
                    vm.zombify();
                    bsl::ut_then{} = [&vm]() {
                        bsl::ut_check(!vm.is_zombie());
                    };
                };
            };
        };

        bsl::ut_scenario{"zombify more than once is ignored"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                vm_t<bsl::to_umx(INTEGRATION_MAX_PPS).get()> vm{};
                tls_t tls{};
                bsl::ut_when{} = [&vm, &tls]() {
                    bsl::ut_required_step(vm.initialize(tls, VMID1));
                    vm.zombify();
                    vm.zombify();
                    bsl::ut_then{} = [&vm]() {
                        bsl::ut_check(vm.is_zombie());
                    };
                };
            };
        };

        bsl::ut_scenario{"status without initialize"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                vm_t<bsl::to_umx(INTEGRATION_MAX_PPS).get()> vm{};
                bsl::ut_then{} = [&vm]() {
                    bsl::ut_check(vm.is_deallocated());
                    bsl::ut_check(!vm.is_allocated());
                    bsl::ut_check(!vm.is_zombie());
                };
            };
        };

        bsl::ut_scenario{"status after initialize"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                vm_t<bsl::to_umx(INTEGRATION_MAX_PPS).get()> vm{};
                tls_t tls{};
                bsl::ut_when{} = [&vm, &tls]() {
                    bsl::ut_required_step(vm.initialize(tls, VMID1));
                    bsl::ut_then{} = [&vm]() {
                        bsl::ut_check(vm.is_deallocated());
                        bsl::ut_check(!vm.is_allocated());
                        bsl::ut_check(!vm.is_zombie());
                    };
                };
            };
        };

        bsl::ut_scenario{"status after allocation"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                vm_t<bsl::to_umx(INTEGRATION_MAX_PPS).get()> vm{};
                tls_t tls{};
                dummy_ext_pool_t ext_pool{};
                bsl::ut_when{} = [&vm, &tls, &ext_pool]() {
                    bsl::ut_required_step(vm.initialize(tls, VMID1));
                    bsl::ut_required_step(vm.allocate(tls, ext_pool));
                    bsl::ut_then{} = [&vm]() {
                        bsl::ut_check(!vm.is_deallocated());
                        bsl::ut_check(vm.is_allocated());
                        bsl::ut_check(!vm.is_zombie());
                    };
                };
            };
        };

        bsl::ut_scenario{"status after deallocation"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                vm_t<bsl::to_umx(INTEGRATION_MAX_PPS).get()> vm{};
                tls_t tls{};
                dummy_ext_pool_t ext_pool{};
                dummy_vp_pool_t vp_pool{};
                bsl::ut_when{} = [&vm, &tls, &ext_pool, &vp_pool]() {
                    bsl::ut_required_step(vm.initialize(tls, VMID1));
                    bsl::ut_required_step(vm.allocate(tls, ext_pool));
                    bsl::ut_required_step(vm.deallocate(tls, ext_pool, vp_pool));
                    bsl::ut_then{} = [&vm]() {
                        bsl::ut_check(vm.is_deallocated());
                        bsl::ut_check(!vm.is_allocated());
                        bsl::ut_check(!vm.is_zombie());
                    };
                };
            };
        };

        bsl::ut_scenario{"status after zombify"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                vm_t<bsl::to_umx(INTEGRATION_MAX_PPS).get()> vm{};
                tls_t tls{};
                bsl::ut_when{} = [&vm, &tls]() {
                    bsl::ut_required_step(vm.initialize(tls, VMID1));
                    vm.zombify();
                    bsl::ut_then{} = [&vm]() {
                        bsl::ut_check(!vm.is_deallocated());
                        bsl::ut_check(!vm.is_allocated());
                        bsl::ut_check(vm.is_zombie());
                    };
                };
            };
        };

        bsl::ut_scenario{"set_active without initialize failure"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                vm_t<bsl::to_umx(INTEGRATION_MAX_PPS).get()> vm{};
                tls_t tls{};
                bsl::ut_then{} = [&tls, &vm]() {
                    bsl::ut_check(!vm.set_active(tls));
                };
            };
        };

        bsl::ut_scenario{"set_active without allocate failure"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                vm_t<bsl::to_umx(INTEGRATION_MAX_PPS).get()> vm{};
                tls_t tls{};
                bsl::ut_when{} = [&tls, &vm]() {
                    tls.online_pps = INTEGRATION_MAX_PPS.get();
                    tls.active_vmid = syscall::BF_INVALID_ID.get();
                    bsl::ut_required_step(vm.initialize(tls, VMID1));
                    bsl::ut_then{} = [&tls, &vm]() {
                        bsl::ut_check(!vm.set_active(tls));
                    };
                };
            };
        };

        bsl::ut_scenario{"set_active zombie failure"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                vm_t<bsl::to_umx(INTEGRATION_MAX_PPS).get()> vm{};
                tls_t tls{};
                dummy_ext_pool_t ext_pool{};
                bsl::ut_when{} = [&vm, &tls, &ext_pool]() {
                    tls.online_pps = INTEGRATION_MAX_PPS.get();
                    tls.active_vmid = syscall::BF_INVALID_ID.get();
                    bsl::ut_required_step(vm.initialize(tls, VMID1));
                    bsl::ut_required_step(vm.allocate(tls, ext_pool));
                    vm.zombify();
                    bsl::ut_then{} = [&tls, &vm]() {
                        bsl::ut_check(!vm.set_active(tls));
                    };
                };
            };
        };

        bsl::ut_scenario{"set_active already active"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                vm_t<bsl::to_umx(INTEGRATION_MAX_PPS).get()> vm{};
                tls_t tls{};
                dummy_ext_pool_t ext_pool{};
                bsl::ut_when{} = [&vm, &tls, &ext_pool]() {
                    tls.online_pps = INTEGRATION_MAX_PPS.get();
                    tls.active_vmid = syscall::BF_INVALID_ID.get();
                    bsl::ut_required_step(vm.initialize(tls, VMID1));
                    bsl::ut_required_step(vm.allocate(tls, ext_pool));
                    bsl::ut_required_step(vm.set_active(tls));
                    bsl::ut_then{} = [&tls, &vm]() {
                        bsl::ut_check(!vm.set_active(tls));
                    };
                };
            };
        };

        bsl::ut_scenario{"set_active corrupt already active"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                vm_t<bsl::to_umx(INTEGRATION_MAX_PPS).get()> vm{};
                tls_t tls{};
                dummy_ext_pool_t ext_pool{};
                bsl::ut_when{} = [&vm, &tls, &ext_pool]() {
                    tls.online_pps = INTEGRATION_MAX_PPS.get();
                    tls.active_vmid = syscall::BF_INVALID_ID.get();
                    bsl::ut_required_step(vm.initialize(tls, VMID1));
                    bsl::ut_required_step(vm.allocate(tls, ext_pool));
                    bsl::ut_required_step(vm.set_active(tls));
                    tls.active_vmid = syscall::BF_INVALID_ID.get();
                    bsl::ut_then{} = [&tls, &vm]() {
                        bsl::ut_check(!vm.set_active(tls));
                    };
                };
            };
        };

        bsl::ut_scenario{"set_active another vm is active failure"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                vm_t<bsl::to_umx(INTEGRATION_MAX_PPS).get()> vm{};
                tls_t tls{};
                dummy_ext_pool_t ext_pool{};
                bsl::ut_when{} = [&vm, &tls, &ext_pool]() {
                    tls.online_pps = INTEGRATION_MAX_PPS.get();
                    tls.active_vmid = VMID0.get();
                    bsl::ut_required_step(vm.initialize(tls, VMID1));
                    bsl::ut_required_step(vm.allocate(tls, ext_pool));
                    bsl::ut_then{} = [&tls, &vm]() {
                        bsl::ut_check(!vm.set_active(tls));
                    };
                };
            };
        };

        bsl::ut_scenario{"set_active invalid ppid failure"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                vm_t<bsl::to_umx(INTEGRATION_MAX_PPS).get()> vm{};
                tls_t tls{};
                dummy_ext_pool_t ext_pool{};
                bsl::ut_when{} = [&vm, &tls, &ext_pool]() {
                    tls.online_pps = INTEGRATION_MAX_PPS.get();
                    tls.active_vmid = syscall::BF_INVALID_ID.get();
                    tls.ppid = syscall::BF_INVALID_ID.get();
                    bsl::ut_required_step(vm.initialize(tls, VMID1));
                    bsl::ut_required_step(vm.allocate(tls, ext_pool));
                    bsl::ut_then{} = [&tls, &vm]() {
                        bsl::ut_check(!vm.set_active(tls));
                    };
                };
            };
        };

        bsl::ut_scenario{"set_active success"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                vm_t<bsl::to_umx(INTEGRATION_MAX_PPS).get()> vm{};
                tls_t tls{};
                dummy_ext_pool_t ext_pool{};
                bsl::ut_when{} = [&vm, &tls, &ext_pool]() {
                    tls.online_pps = INTEGRATION_MAX_PPS.get();
                    tls.active_vmid = syscall::BF_INVALID_ID.get();
                    bsl::ut_required_step(vm.initialize(tls, VMID1));
                    bsl::ut_required_step(vm.allocate(tls, ext_pool));
                    bsl::ut_then{} = [&tls, &vm]() {
                        bsl::ut_check(vm.set_active(tls));
                    };
                };
            };
        };

        bsl::ut_scenario{"set_inactive without initialize failure"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                vm_t<bsl::to_umx(INTEGRATION_MAX_PPS).get()> vm{};
                tls_t tls{};
                bsl::ut_then{} = [&tls, &vm]() {
                    bsl::ut_check(!vm.set_inactive(tls));
                };
            };
        };

        bsl::ut_scenario{"set_inactive without activate failure"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                vm_t<bsl::to_umx(INTEGRATION_MAX_PPS).get()> vm{};
                tls_t tls{};
                bsl::ut_when{} = [&tls, &vm]() {
                    tls.online_pps = INTEGRATION_MAX_PPS.get();
                    tls.active_vmid = syscall::BF_INVALID_ID.get();
                    bsl::ut_required_step(vm.initialize(tls, VMID1));
                    bsl::ut_then{} = [&tls, &vm]() {
                        bsl::ut_check(!vm.set_inactive(tls));
                    };
                };
            };
        };

        bsl::ut_scenario{"set_inactive zombie is allowed"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                vm_t<bsl::to_umx(INTEGRATION_MAX_PPS).get()> vm{};
                tls_t tls{};
                dummy_ext_pool_t ext_pool{};
                bsl::ut_when{} = [&vm, &tls, &ext_pool]() {
                    tls.online_pps = INTEGRATION_MAX_PPS.get();
                    tls.active_vmid = syscall::BF_INVALID_ID.get();
                    bsl::ut_required_step(vm.initialize(tls, VMID1));
                    bsl::ut_required_step(vm.allocate(tls, ext_pool));
                    bsl::ut_required_step(vm.set_active(tls));
                    vm.zombify();
                    bsl::ut_then{} = [&tls, &vm]() {
                        bsl::ut_check(vm.set_inactive(tls));
                    };
                };
            };
        };

        bsl::ut_scenario{"set_inactive already inactive"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                vm_t<bsl::to_umx(INTEGRATION_MAX_PPS).get()> vm{};
                tls_t tls{};
                dummy_ext_pool_t ext_pool{};
                bsl::ut_when{} = [&vm, &tls, &ext_pool]() {
                    tls.online_pps = INTEGRATION_MAX_PPS.get();
                    tls.active_vmid = syscall::BF_INVALID_ID.get();
                    bsl::ut_required_step(vm.initialize(tls, VMID1));
                    bsl::ut_required_step(vm.allocate(tls, ext_pool));
                    bsl::ut_required_step(vm.set_active(tls));
                    tls.active_vmid = syscall::BF_INVALID_ID.get();
                    bsl::ut_then{} = [&tls, &vm]() {
                        bsl::ut_check(!vm.set_inactive(tls));
                    };
                };
            };
        };

        bsl::ut_scenario{"set_inactive active vm is not this vm"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                vm_t<bsl::to_umx(INTEGRATION_MAX_PPS).get()> vm{};
                tls_t tls{};
                dummy_ext_pool_t ext_pool{};
                bsl::ut_when{} = [&vm, &tls, &ext_pool]() {
                    tls.online_pps = INTEGRATION_MAX_PPS.get();
                    tls.active_vmid = syscall::BF_INVALID_ID.get();
                    bsl::ut_required_step(vm.initialize(tls, VMID1));
                    bsl::ut_required_step(vm.allocate(tls, ext_pool));
                    bsl::ut_required_step(vm.set_active(tls));
                    tls.active_vmid = VMID0.get();
                    bsl::ut_then{} = [&tls, &vm]() {
                        bsl::ut_check(!vm.set_inactive(tls));
                    };
                };
            };
        };

        bsl::ut_scenario{"set_inactive invalid ppid failure"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                vm_t<bsl::to_umx(INTEGRATION_MAX_PPS).get()> vm{};
                tls_t tls{};
                dummy_ext_pool_t ext_pool{};
                bsl::ut_when{} = [&vm, &tls, &ext_pool]() {
                    tls.online_pps = INTEGRATION_MAX_PPS.get();
                    tls.active_vmid = syscall::BF_INVALID_ID.get();
                    bsl::ut_required_step(vm.initialize(tls, VMID1));
                    bsl::ut_required_step(vm.allocate(tls, ext_pool));
                    bsl::ut_required_step(vm.set_active(tls));
                    tls.ppid = syscall::BF_INVALID_ID.get();
                    bsl::ut_then{} = [&tls, &vm]() {
                        bsl::ut_check(!vm.set_inactive(tls));
                    };
                };
            };
        };

        bsl::ut_scenario{"set_inactive more than once failure"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                vm_t<bsl::to_umx(INTEGRATION_MAX_PPS).get()> vm{};
                tls_t tls{};
                dummy_ext_pool_t ext_pool{};
                bsl::ut_when{} = [&vm, &tls, &ext_pool]() {
                    tls.online_pps = INTEGRATION_MAX_PPS.get();
                    tls.active_vmid = syscall::BF_INVALID_ID.get();
                    bsl::ut_required_step(vm.initialize(tls, VMID1));
                    bsl::ut_required_step(vm.allocate(tls, ext_pool));
                    bsl::ut_required_step(vm.set_active(tls));
                    bsl::ut_required_step(vm.set_inactive(tls));
                    bsl::ut_then{} = [&tls, &vm]() {
                        bsl::ut_check(!vm.set_inactive(tls));
                    };
                };
            };
        };

        bsl::ut_scenario{"set_inactive corrupt active vm"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                vm_t<bsl::to_umx(INTEGRATION_MAX_PPS).get()> vm{};
                tls_t tls{};
                dummy_ext_pool_t ext_pool{};
                bsl::ut_when{} = [&vm, &tls, &ext_pool]() {
                    tls.online_pps = INTEGRATION_MAX_PPS.get();
                    tls.active_vmid = syscall::BF_INVALID_ID.get();
                    bsl::ut_required_step(vm.initialize(tls, VMID1));
                    bsl::ut_required_step(vm.allocate(tls, ext_pool));
                    bsl::ut_required_step(vm.set_active(tls));
                    bsl::ut_required_step(vm.set_inactive(tls));
                    tls.active_vmid = VMID1.get();
                    bsl::ut_then{} = [&tls, &vm]() {
                        bsl::ut_check(!vm.set_inactive(tls));
                    };
                };
            };
        };

        bsl::ut_scenario{"set_inactive success"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                vm_t<bsl::to_umx(INTEGRATION_MAX_PPS).get()> vm{};
                tls_t tls{};
                dummy_ext_pool_t ext_pool{};
                bsl::ut_when{} = [&vm, &tls, &ext_pool]() {
                    tls.online_pps = INTEGRATION_MAX_PPS.get();
                    tls.active_vmid = syscall::BF_INVALID_ID.get();
                    bsl::ut_required_step(vm.initialize(tls, VMID1));
                    bsl::ut_required_step(vm.allocate(tls, ext_pool));
                    bsl::ut_required_step(vm.set_active(tls));
                    bsl::ut_then{} = [&tls, &vm]() {
                        bsl::ut_check(vm.set_inactive(tls));
                    };
                };
            };
        };

        bsl::ut_scenario{"is_active reports true"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                vm_t<bsl::to_umx(INTEGRATION_MAX_PPS).get()> vm{};
                tls_t tls{};
                dummy_ext_pool_t ext_pool{};
                bsl::ut_when{} = [&vm, &tls, &ext_pool]() {
                    tls.online_pps = INTEGRATION_MAX_PPS.get();
                    tls.active_vmid = syscall::BF_INVALID_ID.get();
                    bsl::ut_required_step(vm.initialize(tls, VMID1));
                    bsl::ut_required_step(vm.allocate(tls, ext_pool));
                    bsl::ut_required_step(vm.set_active(tls));
                    bsl::ut_then{} = [&tls, &vm]() {
                        bsl::ut_check(vm.is_active(tls) == tls.ppid);
                    };
                };
            };
        };

        bsl::ut_scenario{"is_active reports false"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                vm_t<bsl::to_umx(INTEGRATION_MAX_PPS).get()> vm{};
                tls_t tls{};
                dummy_ext_pool_t ext_pool{};
                bsl::ut_when{} = [&vm, &tls, &ext_pool]() {
                    tls.online_pps = INTEGRATION_MAX_PPS.get();
                    tls.active_vmid = syscall::BF_INVALID_ID.get();
                    bsl::ut_required_step(vm.initialize(tls, VMID1));
                    bsl::ut_required_step(vm.allocate(tls, ext_pool));
                    bsl::ut_then{} = [&tls, &vm]() {
                        bsl::ut_check(!vm.is_active(tls));
                    };
                };
            };
        };

        bsl::ut_scenario{"is_active reports false with corrupt online_pps"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                vm_t<bsl::to_umx(INTEGRATION_MAX_PPS).get()> vm{};
                tls_t tls{};
                dummy_ext_pool_t ext_pool{};
                bsl::ut_when{} = [&vm, &tls, &ext_pool]() {
                    tls.online_pps = syscall::BF_INVALID_ID.get();
                    tls.active_vmid = syscall::BF_INVALID_ID.get();
                    bsl::ut_required_step(vm.initialize(tls, VMID1));
                    bsl::ut_required_step(vm.allocate(tls, ext_pool));
                    bsl::ut_then{} = [&tls, &vm]() {
                        bsl::ut_check(!vm.is_active(tls));
                    };
                };
            };
        };

        bsl::ut_scenario{"is_active reports false with no online_pps"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                vm_t<bsl::to_umx(INTEGRATION_MAX_PPS).get()> vm{};
                tls_t tls{};
                dummy_ext_pool_t ext_pool{};
                bsl::ut_when{} = [&vm, &tls, &ext_pool]() {
                    tls.active_vmid = syscall::BF_INVALID_ID.get();
                    bsl::ut_required_step(vm.initialize(tls, VMID1));
                    bsl::ut_required_step(vm.allocate(tls, ext_pool));
                    bsl::ut_then{} = [&tls, &vm]() {
                        bsl::ut_check(!vm.is_active(tls));
                    };
                };
            };
        };

        bsl::ut_scenario{"is_active_on_current_pp reports true"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                vm_t<bsl::to_umx(INTEGRATION_MAX_PPS).get()> vm{};
                tls_t tls{};
                dummy_ext_pool_t ext_pool{};
                bsl::ut_when{} = [&vm, &tls, &ext_pool]() {
                    tls.online_pps = INTEGRATION_MAX_PPS.get();
                    tls.active_vmid = syscall::BF_INVALID_ID.get();
                    bsl::ut_required_step(vm.initialize(tls, VMID1));
                    bsl::ut_required_step(vm.allocate(tls, ext_pool));
                    bsl::ut_required_step(vm.set_active(tls));
                    bsl::ut_then{} = [&tls, &vm]() {
                        bsl::ut_check(vm.is_active_on_current_pp(tls));
                    };
                };
            };
        };

        bsl::ut_scenario{"is_active_on_current_pp reports false"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                vm_t<bsl::to_umx(INTEGRATION_MAX_PPS).get()> vm{};
                tls_t tls{};
                dummy_ext_pool_t ext_pool{};
                bsl::ut_when{} = [&vm, &tls, &ext_pool]() {
                    tls.online_pps = INTEGRATION_MAX_PPS.get();
                    tls.active_vmid = syscall::BF_INVALID_ID.get();
                    bsl::ut_required_step(vm.initialize(tls, VMID1));
                    bsl::ut_required_step(vm.allocate(tls, ext_pool));
                    bsl::ut_then{} = [&tls, &vm]() {
                        bsl::ut_check(!vm.is_active_on_current_pp(tls));
                    };
                };
            };
        };

        bsl::ut_scenario{"is_active_on_current_pp invalid ppid"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                vm_t<bsl::to_umx(INTEGRATION_MAX_PPS).get()> vm{};
                tls_t tls{};
                dummy_ext_pool_t ext_pool{};
                bsl::ut_when{} = [&vm, &tls, &ext_pool]() {
                    tls.online_pps = INTEGRATION_MAX_PPS.get();
                    tls.active_vmid = syscall::BF_INVALID_ID.get();
                    bsl::ut_required_step(vm.initialize(tls, VMID1));
                    bsl::ut_required_step(vm.allocate(tls, ext_pool));
                    bsl::ut_required_step(vm.set_active(tls));
                    tls.ppid = syscall::BF_INVALID_ID.get();
                    bsl::ut_then{} = [&tls, &vm]() {
                        bsl::ut_check(!vm.is_active_on_current_pp(tls));
                    };
                };
            };
        };

        bsl::ut_scenario{"is_active_on_current_pp reports false with corrupt online_pps"} =
            []() noexcept {
                bsl::ut_given{} = []() noexcept {
                    vm_t<bsl::to_umx(INTEGRATION_MAX_PPS).get()> vm{};
                    tls_t tls{};
                    dummy_ext_pool_t ext_pool{};
                    bsl::ut_when{} = [&vm, &tls, &ext_pool]() {
                        tls.online_pps = syscall::BF_INVALID_ID.get();
                        tls.active_vmid = syscall::BF_INVALID_ID.get();
                        bsl::ut_required_step(vm.initialize(tls, VMID1));
                        bsl::ut_required_step(vm.allocate(tls, ext_pool));
                        bsl::ut_then{} = [&tls, &vm]() {
                            bsl::ut_check(!vm.is_active_on_current_pp(tls));
                        };
                    };
                };
            };

        bsl::ut_scenario{"dump without initialize"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                vm_t<bsl::to_umx(INTEGRATION_MAX_PPS).get()> vm{};
                tls_t tls{};
                bsl::ut_then{} = [&tls, &vm]() {
                    vm.dump(tls);
                };
            };
        };

        bsl::ut_scenario{"dump with initialize"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                vm_t<bsl::to_umx(INTEGRATION_MAX_PPS).get()> vm{};
                tls_t tls{};
                bsl::ut_when{} = [&tls, &vm]() {
                    bsl::ut_required_step(vm.initialize(tls, VMID1));
                    bsl::ut_then{} = [&tls, &vm]() {
                        vm.dump(tls);
                    };
                };
            };
        };

        bsl::ut_scenario{"dump with allocate"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                vm_t<bsl::to_umx(INTEGRATION_MAX_PPS).get()> vm{};
                tls_t tls{};
                dummy_ext_pool_t ext_pool{};
                bsl::ut_when{} = [&vm, &tls, &ext_pool]() {
                    bsl::ut_required_step(vm.initialize(tls, VMID1));
                    bsl::ut_required_step(vm.allocate(tls, ext_pool));
                    bsl::ut_then{} = [&tls, &vm]() {
                        vm.dump(tls);
                    };
                };
            };
        };

        bsl::ut_scenario{"dump with active"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                vm_t<bsl::to_umx(INTEGRATION_MAX_PPS).get()> vm{};
                tls_t tls{};
                dummy_ext_pool_t ext_pool{};
                bsl::ut_when{} = [&vm, &tls, &ext_pool]() {
                    tls.online_pps = INTEGRATION_MAX_PPS.get();
                    tls.active_vmid = syscall::BF_INVALID_ID.get();
                    bsl::ut_required_step(vm.initialize(tls, VMID1));
                    bsl::ut_required_step(vm.allocate(tls, ext_pool));
                    bsl::ut_required_step(vm.set_active(tls));
                    bsl::ut_then{} = [&tls, &vm]() {
                        vm.dump(tls);
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
    mk::yield();

    static_assert(mk::tests() == bsl::ut_success());
    return mk::tests();
}
