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

#include "../../../src/vm_pool_t.hpp"

#include <dummy_errc_types.hpp>
#include <dummy_vm_t.hpp>

#include <bsl/ut.hpp>

namespace mk
{
    /// @brief defines the 3 max VMs used in testing
    constexpr bsl::safe_uintmax INTEGRATION_MAX_VMS{bsl::to_umax(3)};

    /// @brief defines VMID0
    constexpr bsl::safe_uint16 VMID0{bsl::to_u16(0)};
    /// @brief defines VMID1
    constexpr bsl::safe_uint16 VMID1{bsl::to_u16(1)};
    /// @brief defines VMID2
    constexpr bsl::safe_uint16 VMID2{bsl::to_u16(2)};

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
        bsl::ut_scenario{"initialize vm_t reports success"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                vm_pool_t<dummy_vm_t, INTEGRATION_MAX_VMS.get()> pool{};
                tls_t tls{};
                bsl::ut_then{} = [&pool, &tls]() {
                    bsl::ut_check(pool.initialize(tls, bsl::dontcare, bsl::dontcare));
                };
            };
        };

        bsl::ut_scenario{"initialize vm_t reports failure"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                vm_pool_t<dummy_vm_t, INTEGRATION_MAX_VMS.get()> pool{};
                tls_t tls{};
                bsl::ut_when{} = [&pool, &tls]() {
                    tls.test_ret = errc_fail_initialize;
                    bsl::ut_then{} = [&pool, &tls]() {
                        bsl::ut_check(!pool.initialize(tls, bsl::dontcare, bsl::dontcare));
                    };
                };
            };
        };

        bsl::ut_scenario{"initialize vm_t and release report failure"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                vm_pool_t<dummy_vm_t, INTEGRATION_MAX_VMS.get()> pool{};
                tls_t tls{};
                bsl::ut_when{} = [&pool, &tls]() {
                    tls.test_ret = errc_fail_initialize_and_release;
                    bsl::ut_then{} = [&pool, &tls]() {
                        bsl::ut_check(!pool.initialize(tls, bsl::dontcare, bsl::dontcare));
                    };
                };
            };
        };

        bsl::ut_scenario{"release without initialize"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                vm_pool_t<dummy_vm_t, INTEGRATION_MAX_VMS.get()> pool{};
                tls_t tls{};
                bsl::ut_then{} = [&pool, &tls]() {
                    bsl::ut_check(pool.release(tls, bsl::dontcare, bsl::dontcare));
                };
            };
        };

        bsl::ut_scenario{"release with initialize"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                vm_pool_t<dummy_vm_t, INTEGRATION_MAX_VMS.get()> pool{};
                tls_t tls{};
                bsl::ut_when{} = [&pool, &tls]() {
                    bsl::ut_required_step(pool.initialize(tls, bsl::dontcare, bsl::dontcare));
                    bsl::ut_then{} = [&pool, &tls]() {
                        bsl::ut_check(pool.release(tls, bsl::dontcare, bsl::dontcare));
                    };
                };
            };
        };

        bsl::ut_scenario{"release with initialize and vm_t reports failure"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                vm_pool_t<dummy_vm_t, INTEGRATION_MAX_VMS.get()> pool{};
                tls_t tls{};
                bsl::ut_when{} = [&pool, &tls]() {
                    bsl::ut_required_step(pool.initialize(tls, bsl::dontcare, bsl::dontcare));
                    tls.test_ret = errc_fail_release;
                    bsl::ut_then{} = [&pool, &tls]() {
                        bsl::ut_check(!pool.release(tls, bsl::dontcare, bsl::dontcare));
                    };
                };
            };
        };

        bsl::ut_scenario{"allocate all vms"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                vm_pool_t<dummy_vm_t, INTEGRATION_MAX_VMS.get()> pool{};
                tls_t tls{};
                bsl::ut_when{} = [&pool, &tls]() {
                    bsl::ut_required_step(pool.initialize(tls, bsl::dontcare, bsl::dontcare));
                    bsl::ut_then{} = [&pool, &tls]() {
                        bsl::ut_check(pool.allocate(tls, bsl::dontcare) == VMID0);
                        bsl::ut_check(pool.allocate(tls, bsl::dontcare) == VMID1);
                        bsl::ut_check(pool.allocate(tls, bsl::dontcare) == VMID2);
                        bsl::ut_check(!pool.allocate(tls, bsl::dontcare));
                    };
                };
            };
        };

        bsl::ut_scenario{"allocate vm_t reports failure"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                vm_pool_t<dummy_vm_t, INTEGRATION_MAX_VMS.get()> pool{};
                tls_t tls{};
                bsl::ut_when{} = [&pool, &tls]() {
                    bsl::ut_required_step(pool.initialize(tls, bsl::dontcare, bsl::dontcare));
                    tls.test_ret = bsl::errc_failure;
                    bsl::ut_then{} = [&pool, &tls]() {
                        bsl::ut_check(!pool.allocate(tls, bsl::dontcare));
                    };
                };
            };
        };

        bsl::ut_scenario{"deallocate invalid id"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                vm_pool_t<dummy_vm_t, INTEGRATION_MAX_VMS.get()> pool{};
                tls_t tls{};
                bsl::ut_when{} = [&pool, &tls]() {
                    bsl::ut_required_step(pool.initialize(tls, bsl::dontcare, bsl::dontcare));
                    bsl::ut_then{} = [&pool, &tls]() {
                        bsl::ut_check(!pool.deallocate(
                            tls, bsl::dontcare, bsl::dontcare, syscall::BF_INVALID_ID));
                    };
                };
            };
        };

        bsl::ut_scenario{"deallocate vm_t reports failure"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                vm_pool_t<dummy_vm_t, INTEGRATION_MAX_VMS.get()> pool{};
                tls_t tls{};
                bsl::ut_when{} = [&pool, &tls]() {
                    bsl::ut_required_step(pool.initialize(tls, bsl::dontcare, bsl::dontcare));
                    auto const vmid{pool.allocate(tls, bsl::dontcare)};
                    tls.test_ret = bsl::errc_failure;
                    bsl::ut_then{} = [&pool, &tls, &vmid]() {
                        bsl::ut_check(!pool.deallocate(tls, bsl::dontcare, bsl::dontcare, vmid));
                    };
                };
            };
        };

        bsl::ut_scenario{"deallocate success"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                vm_pool_t<dummy_vm_t, INTEGRATION_MAX_VMS.get()> pool{};
                tls_t tls{};
                bsl::ut_when{} = [&pool, &tls]() {
                    bsl::ut_required_step(pool.initialize(tls, bsl::dontcare, bsl::dontcare));
                    auto const vmid{pool.allocate(tls, bsl::dontcare)};
                    bsl::ut_then{} = [&pool, &tls, &vmid]() {
                        bsl::ut_check(pool.deallocate(tls, bsl::dontcare, bsl::dontcare, vmid));
                    };
                };
            };
        };

        bsl::ut_scenario{"zombify invalid id"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                vm_pool_t<dummy_vm_t, INTEGRATION_MAX_VMS.get()> pool{};
                bsl::ut_then{} = [&pool]() {
                    bsl::ut_check(!pool.zombify(syscall::BF_INVALID_ID));
                };
            };
        };

        bsl::ut_scenario{"zombify success"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                vm_pool_t<dummy_vm_t, INTEGRATION_MAX_VMS.get()> pool{};
                bsl::ut_then{} = [&pool]() {
                    bsl::ut_check(pool.zombify(VMID1));
                };
            };
        };

        bsl::ut_scenario{"status invalid id"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                vm_pool_t<dummy_vm_t, INTEGRATION_MAX_VMS.get()> pool{};
                tls_t tls{};
                bsl::ut_when{} = [&pool, &tls]() {
                    bsl::ut_required_step(pool.initialize(tls, bsl::dontcare, bsl::dontcare));
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
                vm_pool_t<dummy_vm_t, INTEGRATION_MAX_VMS.get()> pool{};
                tls_t tls{};
                bsl::ut_when{} = [&pool, &tls]() {
                    bsl::ut_required_step(pool.initialize(tls, bsl::dontcare, bsl::dontcare));
                    bsl::ut_then{} = [&pool, &tls]() {
                        bsl::ut_check(!pool.is_allocated(tls, VMID0));
                        bsl::ut_check(pool.is_deallocated(tls, VMID0));
                        bsl::ut_check(!pool.is_zombie(tls, VMID0));
                    };
                };
            };
        };

        bsl::ut_scenario{"status after allocate"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                vm_pool_t<dummy_vm_t, INTEGRATION_MAX_VMS.get()> pool{};
                tls_t tls{};
                bsl::ut_when{} = [&pool, &tls]() {
                    bsl::ut_required_step(pool.initialize(tls, bsl::dontcare, bsl::dontcare));
                    auto const vmid{pool.allocate(tls, bsl::dontcare)};
                    bsl::ut_then{} = [&pool, &tls, &vmid]() {
                        bsl::ut_check(pool.is_allocated(tls, vmid));
                        bsl::ut_check(!pool.is_deallocated(tls, vmid));
                        bsl::ut_check(!pool.is_zombie(tls, vmid));
                    };
                };
            };
        };

        bsl::ut_scenario{"status after deallocate"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                vm_pool_t<dummy_vm_t, INTEGRATION_MAX_VMS.get()> pool{};
                tls_t tls{};
                bsl::ut_when{} = [&pool, &tls]() {
                    bsl::ut_required_step(pool.initialize(tls, bsl::dontcare, bsl::dontcare));
                    auto const vmid{pool.allocate(tls, bsl::dontcare)};
                    bsl::ut_required_step(pool.deallocate(tls, bsl::dontcare, bsl::dontcare, vmid));
                    bsl::ut_then{} = [&pool, &tls, &vmid]() {
                        bsl::ut_check(!pool.is_allocated(tls, vmid));
                        bsl::ut_check(pool.is_deallocated(tls, vmid));
                        bsl::ut_check(!pool.is_zombie(tls, vmid));
                    };
                };
            };
        };

        bsl::ut_scenario{"status after zombify"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                vm_pool_t<dummy_vm_t, INTEGRATION_MAX_VMS.get()> pool{};
                tls_t tls{};
                bsl::ut_when{} = [&pool, &tls]() {
                    bsl::ut_required_step(pool.initialize(tls, bsl::dontcare, bsl::dontcare));
                    bsl::ut_required_step(pool.zombify(VMID1));
                    bsl::ut_then{} = [&pool, &tls]() {
                        bsl::ut_check(!pool.is_allocated(tls, VMID1));
                        bsl::ut_check(!pool.is_deallocated(tls, VMID1));
                        bsl::ut_check(pool.is_zombie(tls, VMID1));
                    };
                };
            };
        };

        bsl::ut_scenario{"set_active invalid id"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                vm_pool_t<dummy_vm_t, INTEGRATION_MAX_VMS.get()> pool{};
                tls_t tls{};
                bsl::ut_then{} = [&pool, &tls]() {
                    bsl::ut_check(!pool.set_active(tls, syscall::BF_INVALID_ID));
                };
            };
        };

        bsl::ut_scenario{"set_active vm_t reports failure"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                vm_pool_t<dummy_vm_t, INTEGRATION_MAX_VMS.get()> pool{};
                tls_t tls{};
                bsl::ut_when{} = [&pool, &tls]() {
                    tls.test_ret = bsl::errc_failure;
                    bsl::ut_then{} = [&pool, &tls]() {
                        bsl::ut_check(!pool.set_active(tls, VMID0));
                    };
                };
            };
        };

        bsl::ut_scenario{"set_active success"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                vm_pool_t<dummy_vm_t, INTEGRATION_MAX_VMS.get()> pool{};
                tls_t tls{};
                bsl::ut_then{} = [&pool, &tls]() {
                    bsl::ut_check(pool.set_active(tls, VMID0));
                };
            };
        };

        bsl::ut_scenario{"set_inactive invalid id"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                vm_pool_t<dummy_vm_t, INTEGRATION_MAX_VMS.get()> pool{};
                tls_t tls{};
                bsl::ut_then{} = [&pool, &tls]() {
                    bsl::ut_check(!pool.set_inactive(tls, syscall::BF_INVALID_ID));
                };
            };
        };

        bsl::ut_scenario{"set_inactive vm_t reports failure"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                vm_pool_t<dummy_vm_t, INTEGRATION_MAX_VMS.get()> pool{};
                tls_t tls{};
                bsl::ut_when{} = [&pool, &tls]() {
                    tls.test_ret = bsl::errc_failure;
                    bsl::ut_then{} = [&pool, &tls]() {
                        bsl::ut_check(!pool.set_inactive(tls, VMID0));
                    };
                };
            };
        };

        bsl::ut_scenario{"set_inactive success"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                vm_pool_t<dummy_vm_t, INTEGRATION_MAX_VMS.get()> pool{};
                tls_t tls{};
                bsl::ut_then{} = [&pool, &tls]() {
                    bsl::ut_check(pool.set_inactive(tls, VMID0));
                };
            };
        };

        bsl::ut_scenario{"is_active invalid id"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                vm_pool_t<dummy_vm_t, INTEGRATION_MAX_VMS.get()> pool{};
                tls_t tls{};
                bsl::ut_when{} = [&pool, &tls]() {
                    bsl::ut_check(!pool.is_active(tls, syscall::BF_INVALID_ID));
                };
            };
        };

        bsl::ut_scenario{"is_active success"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                vm_pool_t<dummy_vm_t, INTEGRATION_MAX_VMS.get()> pool{};
                tls_t tls{};
                bsl::ut_then{} = [&pool, &tls]() {
                    bsl::ut_check(!pool.is_active(tls, VMID0));
                };

                bsl::ut_when{} = [&pool, &tls]() {
                    bsl::ut_check(pool.set_active(tls, VMID0));
                    bsl::ut_then{} = [&pool, &tls]() {
                        bsl::ut_check(pool.is_active(tls, VMID0));
                    };
                };

                bsl::ut_when{} = [&pool, &tls]() {
                    bsl::ut_check(pool.set_inactive(tls, VMID0));
                    bsl::ut_then{} = [&pool, &tls]() {
                        bsl::ut_check(!pool.is_active(tls, VMID0));
                    };
                };
            };
        };

        bsl::ut_scenario{"is_active_on_current_pp invalid id"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                vm_pool_t<dummy_vm_t, INTEGRATION_MAX_VMS.get()> pool{};
                tls_t tls{};
                bsl::ut_then{} = [&pool, &tls]() {
                    bsl::ut_check(!pool.is_active_on_current_pp(tls, syscall::BF_INVALID_ID));
                };
            };
        };

        bsl::ut_scenario{"is_active_on_current_pp success"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                vm_pool_t<dummy_vm_t, INTEGRATION_MAX_VMS.get()> pool{};
                tls_t tls{};
                bsl::ut_then{} = [&pool, &tls]() {
                    bsl::ut_check(!pool.is_active_on_current_pp(tls, VMID0));
                };

                bsl::ut_when{} = [&pool, &tls]() {
                    bsl::ut_check(pool.set_active(tls, VMID0));
                    bsl::ut_then{} = [&pool, &tls]() {
                        bsl::ut_check(pool.is_active_on_current_pp(tls, VMID0));
                    };
                };

                bsl::ut_when{} = [&pool, &tls]() {
                    bsl::ut_check(pool.set_inactive(tls, VMID0));
                    bsl::ut_then{} = [&pool, &tls]() {
                        bsl::ut_check(!pool.is_active_on_current_pp(tls, VMID0));
                    };
                };
            };
        };

        bsl::ut_scenario{"dump invalid id"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                vm_pool_t<dummy_vm_t, INTEGRATION_MAX_VMS.get()> pool{};
                tls_t tls{};
                bsl::ut_then{} = [&pool, &tls]() {
                    pool.dump(tls, syscall::BF_INVALID_ID);
                };
            };
        };

        bsl::ut_scenario{"dump success"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                vm_pool_t<dummy_vm_t, INTEGRATION_MAX_VMS.get()> pool{};
                tls_t tls{};
                bsl::ut_then{} = [&pool, &tls]() {
                    pool.dump(tls, VMID0);
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
