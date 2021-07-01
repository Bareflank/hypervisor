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

#include "../../../src/vp_pool_t.hpp"

#include <dummy_errc_types.hpp>
#include <dummy_vp_t.hpp>

#include <bsl/ut.hpp>

namespace mk
{
    /// @brief defines the max number of VMs used in testing
    constexpr bsl::safe_uintmax INTEGRATION_MAX_VPS{bsl::to_umax(3)};

    /// @brief defines VMID0
    constexpr bsl::safe_uint16 VMID0{bsl::to_u16(0)};
    /// @brief defines VMID1
    constexpr bsl::safe_uint16 VMID1{bsl::to_u16(1)};

    /// @brief defines PPID0
    constexpr bsl::safe_uint16 PPID0{bsl::to_u16(0)};

    /// @brief defines VPID0
    constexpr bsl::safe_uint16 VPID0{bsl::to_u16(0)};
    /// @brief defines VPID1
    constexpr bsl::safe_uint16 VPID1{bsl::to_u16(1)};
    /// @brief defines VPID2
    constexpr bsl::safe_uint16 VPID2{bsl::to_u16(2)};

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
        bsl::ut_scenario{"initialize vp_t reports success"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                vp_pool_t<dummy_vp_t, INTEGRATION_MAX_VPS.get()> pool{};
                tls_t tls{};
                bsl::ut_then{} = [&pool, &tls]() {
                    bsl::ut_check(pool.initialize(tls, bsl::dontcare));
                };
            };
        };

        bsl::ut_scenario{"initialize vp_t reports failure"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                vp_pool_t<dummy_vp_t, INTEGRATION_MAX_VPS.get()> pool{};
                tls_t tls{};
                bsl::ut_when{} = [&pool, &tls]() {
                    tls.test_ret = errc_fail_initialize;
                    bsl::ut_then{} = [&pool, &tls]() {
                        bsl::ut_check(!pool.initialize(tls, bsl::dontcare));
                    };
                };
            };
        };

        bsl::ut_scenario{"initialize vp_t and release report failure"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                vp_pool_t<dummy_vp_t, INTEGRATION_MAX_VPS.get()> pool{};
                tls_t tls{};
                bsl::ut_when{} = [&pool, &tls]() {
                    tls.test_ret = errc_fail_initialize_and_release;
                    bsl::ut_then{} = [&pool, &tls]() {
                        bsl::ut_check(!pool.initialize(tls, bsl::dontcare));
                    };
                };
            };
        };

        bsl::ut_scenario{"release without initialize"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                vp_pool_t<dummy_vp_t, INTEGRATION_MAX_VPS.get()> pool{};
                tls_t tls{};
                bsl::ut_then{} = [&pool, &tls]() {
                    bsl::ut_check(pool.release(tls, bsl::dontcare));
                };
            };
        };

        bsl::ut_scenario{"release with initialize"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                vp_pool_t<dummy_vp_t, INTEGRATION_MAX_VPS.get()> pool{};
                tls_t tls{};
                bsl::ut_when{} = [&pool, &tls]() {
                    bsl::ut_required_step(pool.initialize(tls, bsl::dontcare));
                    bsl::ut_then{} = [&pool, &tls]() {
                        bsl::ut_check(pool.release(tls, bsl::dontcare));
                    };
                };
            };
        };

        bsl::ut_scenario{"release with initialize and vp_t reports failure"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                vp_pool_t<dummy_vp_t, INTEGRATION_MAX_VPS.get()> pool{};
                tls_t tls{};
                bsl::ut_when{} = [&pool, &tls]() {
                    bsl::ut_required_step(pool.initialize(tls, bsl::dontcare));
                    tls.test_ret = errc_fail_release;
                    bsl::ut_then{} = [&pool, &tls]() {
                        bsl::ut_check(!pool.release(tls, bsl::dontcare));
                    };
                };
            };
        };

        bsl::ut_scenario{"allocate all vps"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                vp_pool_t<dummy_vp_t, INTEGRATION_MAX_VPS.get()> pool{};
                tls_t tls{};
                bsl::ut_when{} = [&pool, &tls]() {
                    bsl::ut_required_step(pool.initialize(tls, bsl::dontcare));
                    bsl::ut_then{} = [&pool, &tls]() {
                        bsl::ut_check(pool.allocate(tls, bsl::dontcare, VMID0, PPID0) == VPID0);
                        bsl::ut_check(pool.allocate(tls, bsl::dontcare, VMID0, PPID0) == VPID1);
                        bsl::ut_check(pool.allocate(tls, bsl::dontcare, VMID0, PPID0) == VPID2);
                        bsl::ut_check(!pool.allocate(tls, bsl::dontcare, VMID0, PPID0));
                    };
                };
            };
        };

        bsl::ut_scenario{"allocate vp_t reports failure"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                vp_pool_t<dummy_vp_t, INTEGRATION_MAX_VPS.get()> pool{};
                tls_t tls{};
                bsl::ut_when{} = [&pool, &tls]() {
                    bsl::ut_required_step(pool.initialize(tls, bsl::dontcare));
                    tls.test_ret = bsl::errc_failure;
                    bsl::ut_then{} = [&pool, &tls]() {
                        bsl::ut_check(!pool.allocate(tls, bsl::dontcare, VMID0, PPID0));
                    };
                };
            };
        };

        bsl::ut_scenario{"deallocate invalid id"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                vp_pool_t<dummy_vp_t, INTEGRATION_MAX_VPS.get()> pool{};
                tls_t tls{};
                bsl::ut_when{} = [&pool, &tls]() {
                    bsl::ut_required_step(pool.initialize(tls, bsl::dontcare));
                    bsl::ut_then{} = [&pool, &tls]() {
                        bsl::ut_check(!pool.deallocate(tls, bsl::dontcare, syscall::BF_INVALID_ID));
                    };
                };
            };
        };

        bsl::ut_scenario{"deallocate vp_t reports failure"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                vp_pool_t<dummy_vp_t, INTEGRATION_MAX_VPS.get()> pool{};
                tls_t tls{};
                bsl::ut_when{} = [&pool, &tls]() {
                    bsl::ut_required_step(pool.initialize(tls, bsl::dontcare));
                    auto const vpid{pool.allocate(tls, bsl::dontcare, VMID0, PPID0)};
                    tls.test_ret = bsl::errc_failure;
                    bsl::ut_then{} = [&pool, &tls, &vpid]() {
                        bsl::ut_check(!pool.deallocate(tls, bsl::dontcare, vpid));
                    };
                };
            };
        };

        bsl::ut_scenario{"deallocate success"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                vp_pool_t<dummy_vp_t, INTEGRATION_MAX_VPS.get()> pool{};
                tls_t tls{};
                bsl::ut_when{} = [&pool, &tls]() {
                    bsl::ut_required_step(pool.initialize(tls, bsl::dontcare));
                    auto const vpid{pool.allocate(tls, bsl::dontcare, VMID0, PPID0)};
                    bsl::ut_then{} = [&pool, &tls, &vpid]() {
                        bsl::ut_check(pool.deallocate(tls, bsl::dontcare, vpid));
                    };
                };
            };
        };

        bsl::ut_scenario{"zombify invalid id"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                vp_pool_t<dummy_vp_t, INTEGRATION_MAX_VPS.get()> pool{};
                bsl::ut_then{} = [&pool]() {
                    bsl::ut_check(!pool.zombify(syscall::BF_INVALID_ID));
                };
            };
        };

        bsl::ut_scenario{"zombify success"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                vp_pool_t<dummy_vp_t, INTEGRATION_MAX_VPS.get()> pool{};
                bsl::ut_then{} = [&pool]() {
                    bsl::ut_check(pool.zombify(VPID1));
                };
            };
        };

        bsl::ut_scenario{"status invalid id"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                vp_pool_t<dummy_vp_t, INTEGRATION_MAX_VPS.get()> pool{};
                tls_t tls{};
                bsl::ut_when{} = [&pool, &tls]() {
                    bsl::ut_required_step(pool.initialize(tls, bsl::dontcare));
                    bsl::ut_then{} = [&pool, &tls]() {
                        bsl::ut_check(!pool.is_allocated(tls, syscall::BF_INVALID_ID));
                        bsl::ut_check(!pool.is_deallocated(tls, syscall::BF_INVALID_ID));
                        bsl::ut_check(!pool.is_zombie(tls, syscall::BF_INVALID_ID));
                    };
                };
            };
        };

        bsl::ut_scenario{"status after initialize"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                vp_pool_t<dummy_vp_t, INTEGRATION_MAX_VPS.get()> pool{};
                tls_t tls{};
                bsl::ut_when{} = [&pool, &tls]() {
                    bsl::ut_required_step(pool.initialize(tls, bsl::dontcare));
                    bsl::ut_then{} = [&pool, &tls]() {
                        bsl::ut_check(!pool.is_allocated(tls, VPID0));
                        bsl::ut_check(pool.is_deallocated(tls, VPID0));
                        bsl::ut_check(!pool.is_zombie(tls, VPID0));
                    };
                };
            };
        };

        bsl::ut_scenario{"status after allocate"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                vp_pool_t<dummy_vp_t, INTEGRATION_MAX_VPS.get()> pool{};
                tls_t tls{};
                bsl::ut_when{} = [&pool, &tls]() {
                    bsl::ut_required_step(pool.initialize(tls, bsl::dontcare));
                    auto const vpid{pool.allocate(tls, bsl::dontcare, VMID0, PPID0)};
                    bsl::ut_then{} = [&pool, &tls, &vpid]() {
                        bsl::ut_check(pool.is_allocated(tls, vpid));
                        bsl::ut_check(!pool.is_deallocated(tls, vpid));
                        bsl::ut_check(!pool.is_zombie(tls, vpid));
                    };
                };
            };
        };

        bsl::ut_scenario{"status after deallocate"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                vp_pool_t<dummy_vp_t, INTEGRATION_MAX_VPS.get()> pool{};
                tls_t tls{};
                bsl::ut_when{} = [&pool, &tls]() {
                    bsl::ut_required_step(pool.initialize(tls, bsl::dontcare));
                    auto const vpid{pool.allocate(tls, bsl::dontcare, VMID0, PPID0)};
                    bsl::ut_required_step(pool.deallocate(tls, bsl::dontcare, vpid));
                    bsl::ut_then{} = [&pool, &tls, &vpid]() {
                        bsl::ut_check(!pool.is_allocated(tls, vpid));
                        bsl::ut_check(pool.is_deallocated(tls, vpid));
                        bsl::ut_check(!pool.is_zombie(tls, vpid));
                    };
                };
            };
        };

        bsl::ut_scenario{"status after zombify"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                vp_pool_t<dummy_vp_t, INTEGRATION_MAX_VPS.get()> pool{};
                tls_t tls{};
                bsl::ut_when{} = [&pool, &tls]() {
                    bsl::ut_required_step(pool.initialize(tls, bsl::dontcare));
                    bsl::ut_required_step(pool.zombify(VPID1));
                    bsl::ut_then{} = [&pool, &tls]() {
                        bsl::ut_check(!pool.is_allocated(tls, VPID1));
                        bsl::ut_check(!pool.is_deallocated(tls, VPID1));
                        bsl::ut_check(pool.is_zombie(tls, VPID1));
                    };
                };
            };
        };

        bsl::ut_scenario{"is_assigned_to_vm invalid id"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                vp_pool_t<dummy_vp_t, INTEGRATION_MAX_VPS.get()> pool{};
                tls_t tls{};
                bsl::ut_then{} = [&pool, &tls]() {
                    bsl::ut_check(!pool.is_assigned_to_vm(tls, syscall::BF_INVALID_ID));
                };
            };
        };

        bsl::ut_scenario{"is_assigned_to_vm id with error code"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                vp_pool_t<dummy_vp_t, INTEGRATION_MAX_VPS.get()> pool{};
                tls_t tls{};
                bsl::ut_then{} = [&pool, &tls]() {
                    bsl::ut_check(!pool.is_assigned_to_vm(tls, bsl::safe_uint16::failure()));
                };
            };
        };

        bsl::ut_scenario{"is_assigned_to_vm without initialize"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                vp_pool_t<dummy_vp_t, INTEGRATION_MAX_VPS.get()> pool{};
                tls_t tls{};
                bsl::ut_then{} = [&pool, &tls]() {
                    bsl::ut_check(!pool.is_assigned_to_vm(tls, VMID0));
                };
            };
        };

        bsl::ut_scenario{"is_assigned_to_vm nothing assigned"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                vp_pool_t<dummy_vp_t, INTEGRATION_MAX_VPS.get()> pool{};
                tls_t tls{};
                bsl::ut_when{} = [&pool, &tls]() {
                    bsl::ut_required_step(pool.initialize(tls, bsl::dontcare));
                    bsl::ut_then{} = [&pool, &tls]() {
                        bsl::ut_check(!pool.is_assigned_to_vm(tls, VMID0));
                    };
                };
            };
        };

        bsl::ut_scenario{"is_assigned_to_vm assigned"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                vp_pool_t<dummy_vp_t, INTEGRATION_MAX_VPS.get()> pool{};
                tls_t tls{};
                bsl::ut_when{} = [&pool, &tls]() {
                    bsl::ut_required_step(pool.initialize(tls, bsl::dontcare));
                    bsl::ut_required_step(pool.allocate(tls, bsl::dontcare, VMID0, PPID0));
                    bsl::ut_required_step(pool.allocate(tls, bsl::dontcare, VMID0, PPID0));
                    bsl::ut_required_step(pool.deallocate(tls, bsl::dontcare, VPID0));
                    bsl::ut_then{} = [&pool, &tls]() {
                        bsl::ut_check(pool.is_assigned_to_vm(tls, VMID0) == VPID1);
                    };
                };
            };
        };

        bsl::ut_scenario{"is_assigned_to_vm assigned but wrong query"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                vp_pool_t<dummy_vp_t, INTEGRATION_MAX_VPS.get()> pool{};
                tls_t tls{};
                bsl::ut_when{} = [&pool, &tls]() {
                    bsl::ut_required_step(pool.initialize(tls, bsl::dontcare));
                    bsl::ut_required_step(pool.allocate(tls, bsl::dontcare, VMID0, PPID0));
                    bsl::ut_required_step(pool.allocate(tls, bsl::dontcare, VMID0, PPID0));
                    bsl::ut_required_step(pool.deallocate(tls, bsl::dontcare, VPID0));
                    bsl::ut_then{} = [&pool, &tls]() {
                        bsl::ut_check(!pool.is_assigned_to_vm(tls, VMID1));
                    };
                };
            };
        };

        bsl::ut_scenario{"set_active invalid id"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                vp_pool_t<dummy_vp_t, INTEGRATION_MAX_VPS.get()> pool{};
                tls_t tls{};
                bsl::ut_then{} = [&pool, &tls]() {
                    bsl::ut_check(!pool.set_active(tls, syscall::BF_INVALID_ID));
                };
            };
        };

        bsl::ut_scenario{"set_active vp_t reports failure"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                vp_pool_t<dummy_vp_t, INTEGRATION_MAX_VPS.get()> pool{};
                tls_t tls{};
                bsl::ut_when{} = [&pool, &tls]() {
                    tls.test_ret = bsl::errc_failure;
                    bsl::ut_then{} = [&pool, &tls]() {
                        bsl::ut_check(!pool.set_active(tls, VPID0));
                    };
                };
            };
        };

        bsl::ut_scenario{"set_active success"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                vp_pool_t<dummy_vp_t, INTEGRATION_MAX_VPS.get()> pool{};
                tls_t tls{};
                bsl::ut_then{} = [&pool, &tls]() {
                    bsl::ut_check(pool.set_active(tls, VPID0));
                };
            };
        };

        bsl::ut_scenario{"set_inactive invalid id"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                vp_pool_t<dummy_vp_t, INTEGRATION_MAX_VPS.get()> pool{};
                tls_t tls{};
                bsl::ut_then{} = [&pool, &tls]() {
                    bsl::ut_check(!pool.set_inactive(tls, syscall::BF_INVALID_ID));
                };
            };
        };

        bsl::ut_scenario{"set_inactive vp_t reports failure"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                vp_pool_t<dummy_vp_t, INTEGRATION_MAX_VPS.get()> pool{};
                tls_t tls{};
                bsl::ut_when{} = [&pool, &tls]() {
                    tls.test_ret = bsl::errc_failure;
                    bsl::ut_then{} = [&pool, &tls]() {
                        bsl::ut_check(!pool.set_inactive(tls, VPID0));
                    };
                };
            };
        };

        bsl::ut_scenario{"set_inactive success"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                vp_pool_t<dummy_vp_t, INTEGRATION_MAX_VPS.get()> pool{};
                tls_t tls{};
                bsl::ut_then{} = [&pool, &tls]() {
                    bsl::ut_check(pool.set_inactive(tls, VPID0));
                };
            };
        };

        bsl::ut_scenario{"is_active invalid id"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                vp_pool_t<dummy_vp_t, INTEGRATION_MAX_VPS.get()> pool{};
                tls_t tls{};
                bsl::ut_then{} = [&pool, &tls]() {
                    bsl::ut_check(!pool.is_active(tls, syscall::BF_INVALID_ID));
                };
            };
        };

        bsl::ut_scenario{"is_active success"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                vp_pool_t<dummy_vp_t, INTEGRATION_MAX_VPS.get()> pool{};
                tls_t tls{};
                bsl::ut_then{} = [&pool, &tls]() {
                    bsl::ut_check(!pool.is_active(tls, VPID0));
                };

                bsl::ut_when{} = [&pool, &tls]() {
                    bsl::ut_check(pool.set_active(tls, VPID0));
                    bsl::ut_then{} = [&pool, &tls]() {
                        bsl::ut_check(pool.is_active(tls, VPID0));
                    };
                };

                bsl::ut_when{} = [&pool, &tls]() {
                    bsl::ut_check(pool.set_inactive(tls, VPID0));
                    bsl::ut_then{} = [&pool, &tls]() {
                        bsl::ut_check(!pool.is_active(tls, VPID0));
                    };
                };
            };
        };

        bsl::ut_scenario{"is_active_on_current_pp invalid id"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                vp_pool_t<dummy_vp_t, INTEGRATION_MAX_VPS.get()> pool{};
                tls_t tls{};
                bsl::ut_then{} = [&pool, &tls]() {
                    bsl::ut_check(!pool.is_active_on_current_pp(tls, syscall::BF_INVALID_ID));
                };
            };
        };

        bsl::ut_scenario{"is_active_on_current_pp success"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                vp_pool_t<dummy_vp_t, INTEGRATION_MAX_VPS.get()> pool{};
                tls_t tls{};
                bsl::ut_then{} = [&pool, &tls]() {
                    bsl::ut_check(!pool.is_active_on_current_pp(tls, VPID0));
                };

                bsl::ut_when{} = [&pool, &tls]() {
                    bsl::ut_check(pool.set_active(tls, VPID0));
                    bsl::ut_then{} = [&pool, &tls]() {
                        bsl::ut_check(pool.is_active_on_current_pp(tls, VPID0));
                    };
                };

                bsl::ut_when{} = [&pool, &tls]() {
                    bsl::ut_check(pool.set_inactive(tls, VPID0));
                    bsl::ut_then{} = [&pool, &tls]() {
                        bsl::ut_check(!pool.is_active_on_current_pp(tls, VPID0));
                    };
                };
            };
        };

        bsl::ut_scenario{"migrate invalid id"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                vp_pool_t<dummy_vp_t, INTEGRATION_MAX_VPS.get()> pool{};
                tls_t tls{};
                bsl::ut_then{} = [&pool, &tls]() {
                    bsl::ut_check(!pool.migrate(tls, PPID0, syscall::BF_INVALID_ID));
                };
            };
        };

        bsl::ut_scenario{"migrate vp_t reports failure"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                vp_pool_t<dummy_vp_t, INTEGRATION_MAX_VPS.get()> pool{};
                tls_t tls{};
                bsl::ut_when{} = [&pool, &tls]() {
                    tls.test_ret = bsl::errc_failure;
                    bsl::ut_then{} = [&pool, &tls]() {
                        bsl::ut_check(!pool.migrate(tls, PPID0, VPID0));
                    };
                };
            };
        };

        bsl::ut_scenario{"migrate success"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                vp_pool_t<dummy_vp_t, INTEGRATION_MAX_VPS.get()> pool{};
                tls_t tls{};
                bsl::ut_then{} = [&pool, &tls]() {
                    bsl::ut_check(pool.migrate(tls, PPID0, VPID0));
                };
            };
        };

        bsl::ut_scenario{"assigned_vm invalid id"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                vp_pool_t<dummy_vp_t, INTEGRATION_MAX_VPS.get()> pool{};
                tls_t tls{};
                bsl::ut_when{} = [&pool, &tls]() {
                    bsl::ut_required_step(pool.initialize(tls, bsl::dontcare));
                    bsl::ut_then{} = [&pool]() {
                        bsl::ut_check(!pool.assigned_vm(syscall::BF_INVALID_ID));
                    };
                };
            };
        };

        bsl::ut_scenario{"assigned_vm unassigned"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                vp_pool_t<dummy_vp_t, INTEGRATION_MAX_VPS.get()> pool{};
                tls_t tls{};
                bsl::ut_when{} = [&pool, &tls]() {
                    bsl::ut_required_step(pool.initialize(tls, bsl::dontcare));
                    bsl::ut_then{} = [&pool]() {
                        bsl::ut_check(!pool.assigned_vm(VPID0));
                    };
                };
            };
        };

        bsl::ut_scenario{"assigned_vm success"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                vp_pool_t<dummy_vp_t, INTEGRATION_MAX_VPS.get()> pool{};
                tls_t tls{};
                bsl::ut_when{} = [&pool, &tls]() {
                    bsl::ut_required_step(pool.initialize(tls, bsl::dontcare));
                    bsl::ut_required_step(pool.allocate(tls, bsl::dontcare, VMID0, PPID0));
                    bsl::ut_then{} = [&pool]() {
                        bsl::ut_check(pool.assigned_vm(VPID0) == VMID0);
                    };
                };
            };
        };

        bsl::ut_scenario{"assigned_pp invalid id"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                vp_pool_t<dummy_vp_t, INTEGRATION_MAX_VPS.get()> pool{};
                tls_t tls{};
                bsl::ut_when{} = [&pool, &tls]() {
                    bsl::ut_required_step(pool.initialize(tls, bsl::dontcare));
                    bsl::ut_then{} = [&pool]() {
                        bsl::ut_check(!pool.assigned_pp(syscall::BF_INVALID_ID));
                    };
                };
            };
        };

        bsl::ut_scenario{"assigned_pp unassigned"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                vp_pool_t<dummy_vp_t, INTEGRATION_MAX_VPS.get()> pool{};
                tls_t tls{};
                bsl::ut_when{} = [&pool, &tls]() {
                    bsl::ut_required_step(pool.initialize(tls, bsl::dontcare));
                    bsl::ut_then{} = [&pool]() {
                        bsl::ut_check(!pool.assigned_pp(VPID0));
                    };
                };
            };
        };

        bsl::ut_scenario{"assigned_pp success"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                vp_pool_t<dummy_vp_t, INTEGRATION_MAX_VPS.get()> pool{};
                tls_t tls{};
                bsl::ut_when{} = [&pool, &tls]() {
                    bsl::ut_required_step(pool.initialize(tls, bsl::dontcare));
                    bsl::ut_required_step(pool.allocate(tls, bsl::dontcare, VMID0, PPID0));
                    bsl::ut_then{} = [&pool]() {
                        bsl::ut_check(pool.assigned_pp(VPID0) == PPID0);
                    };
                };
            };
        };

        bsl::ut_scenario{"dump invalid id"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                vp_pool_t<dummy_vp_t, INTEGRATION_MAX_VPS.get()> pool{};
                tls_t tls{};
                bsl::ut_then{} = [&pool, &tls]() {
                    pool.dump(tls, syscall::BF_INVALID_ID);
                };
            };
        };

        bsl::ut_scenario{"dump success"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                vp_pool_t<dummy_vp_t, INTEGRATION_MAX_VPS.get()> pool{};
                tls_t tls{};
                bsl::ut_then{} = [&pool, &tls]() {
                    pool.dump(tls, VPID0);
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
