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

#include "../../../mocks/vm_t.hpp"

#include <bf_constants.hpp>
#include <ext_pool_t.hpp>
#include <page_pool_t.hpp>
#include <tls_t.hpp>

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
                vm_t mut_vm{};
                bsl::ut_then{} = [&]() noexcept {
                    mut_vm.initialize({});
                };
            };
        };

        bsl::ut_scenario{"release"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                vm_t mut_vm{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                ext_pool_t mut_ext_pool{};
                bsl::ut_when{} = [&]() noexcept {
                    mut_vm.initialize({});
                    bsl::ut_then{} = [&]() noexcept {
                        mut_vm.release(mut_tls, mut_page_pool, mut_ext_pool);
                    };
                };
            };
        };

        bsl::ut_scenario{"release without initialize"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                vm_t mut_vm{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                ext_pool_t mut_ext_pool{};
                bsl::ut_then{} = [&]() noexcept {
                    mut_vm.release(mut_tls, mut_page_pool, mut_ext_pool);
                };
            };
        };

        bsl::ut_scenario{"release after allocate"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                vm_t mut_vm{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                ext_pool_t mut_ext_pool{};
                bsl::ut_when{} = [&]() noexcept {
                    mut_vm.initialize({});
                    bsl::ut_required_step(mut_vm.allocate(mut_tls, mut_page_pool, mut_ext_pool));
                    bsl::ut_then{} = [&]() noexcept {
                        mut_vm.release(mut_tls, mut_page_pool, mut_ext_pool);
                    };
                };
            };
        };

        bsl::ut_scenario{"allocate"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                vm_t mut_vm{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                ext_pool_t mut_ext_pool{};
                bsl::ut_when{} = [&]() noexcept {
                    mut_vm.initialize({});
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_vm.allocate(mut_tls, mut_page_pool, mut_ext_pool));
                    };
                };
            };
        };

        bsl::ut_scenario{"allocate fails"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                vm_t mut_vm{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                ext_pool_t mut_ext_pool{};
                bsl::ut_when{} = [&]() noexcept {
                    mut_vm.initialize({});
                    mut_tls.test_ret = UNIT_TEST_VM_FAIL_ALLOCATE;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            mut_vm.allocate(mut_tls, mut_page_pool, mut_ext_pool).is_invalid());
                    };
                };
            };
        };

        bsl::ut_scenario{"deallocate"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                vm_t mut_vm{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                ext_pool_t mut_ext_pool{};
                bsl::ut_when{} = [&]() noexcept {
                    mut_vm.initialize({});
                    bsl::ut_required_step(mut_vm.allocate(mut_tls, mut_page_pool, mut_ext_pool));
                    bsl::ut_then{} = [&]() noexcept {
                        mut_vm.deallocate(mut_tls, mut_page_pool, mut_ext_pool);
                    };
                };
            };
        };

        bsl::ut_scenario{"deallocate without allocate"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                vm_t mut_vm{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                ext_pool_t mut_ext_pool{};
                bsl::ut_when{} = [&]() noexcept {
                    mut_vm.initialize({});
                    bsl::ut_then{} = [&]() noexcept {
                        mut_vm.deallocate(mut_tls, mut_page_pool, mut_ext_pool);
                    };
                };
            };
        };

        bsl::ut_scenario{"allocation status functions"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                vm_t mut_vm{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                ext_pool_t mut_ext_pool{};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_vm.is_deallocated());
                        bsl::ut_check(!mut_vm.is_allocated());
                    };

                    mut_vm.initialize({});
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_vm.is_deallocated());
                        bsl::ut_check(!mut_vm.is_allocated());
                    };

                    bsl::ut_required_step(mut_vm.allocate(mut_tls, mut_page_pool, mut_ext_pool));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(!mut_vm.is_deallocated());
                        bsl::ut_check(mut_vm.is_allocated());
                    };

                    mut_vm.deallocate(mut_tls, mut_page_pool, mut_ext_pool);
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_vm.is_deallocated());
                        bsl::ut_check(!mut_vm.is_allocated());
                    };

                    bsl::ut_required_step(mut_vm.allocate(mut_tls, mut_page_pool, mut_ext_pool));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(!mut_vm.is_deallocated());
                        bsl::ut_check(mut_vm.is_allocated());
                    };

                    mut_vm.release(mut_tls, mut_page_pool, mut_ext_pool);
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_vm.is_deallocated());
                        bsl::ut_check(!mut_vm.is_allocated());
                    };
                };
            };
        };

        bsl::ut_scenario{"set_active"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                vm_t mut_vm{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                ext_pool_t mut_ext_pool{};
                constexpr auto vmid{1_u16};
                bsl::ut_when{} = [&]() noexcept {
                    mut_vm.initialize(vmid);
                    mut_tls.active_vmid = syscall::BF_INVALID_ID.get();
                    bsl::ut_required_step(mut_vm.allocate(mut_tls, mut_page_pool, mut_ext_pool));
                    mut_vm.set_active(mut_tls);
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(vmid == mut_tls.active_vmid);
                    };
                };
            };
        };

        bsl::ut_scenario{"set_inactive"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                vm_t mut_vm{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                ext_pool_t mut_ext_pool{};
                constexpr auto vmid{1_u16};
                bsl::ut_when{} = [&]() noexcept {
                    mut_vm.initialize(vmid);
                    mut_tls.active_vmid = vmid.get();
                    bsl::ut_required_step(mut_vm.allocate(mut_tls, mut_page_pool, mut_ext_pool));
                    mut_vm.set_inactive(mut_tls);
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(syscall::BF_INVALID_ID == mut_tls.active_vmid);
                    };
                };
            };
        };

        bsl::ut_scenario{"active status functions"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                vm_t mut_vm{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                ext_pool_t mut_ext_pool{};
                constexpr auto ppid0{0_u16};
                constexpr auto ppid1{1_u16};
                constexpr auto online_pps{2_u16};
                bsl::ut_when{} = [&]() noexcept {
                    mut_tls.online_pps = online_pps.get();

                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_vm.is_active(mut_tls).is_invalid());
                        bsl::ut_check(!mut_vm.is_active_on_this_pp(mut_tls));
                    };

                    mut_vm.initialize({});
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_vm.is_active(mut_tls).is_invalid());
                        bsl::ut_check(!mut_vm.is_active_on_this_pp(mut_tls));
                    };

                    bsl::ut_required_step(mut_vm.allocate(mut_tls, mut_page_pool, mut_ext_pool));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_vm.is_active(mut_tls).is_invalid());
                        bsl::ut_check(!mut_vm.is_active_on_this_pp(mut_tls));
                    };

                    mut_tls.ppid = ppid0.get();
                    mut_tls.active_vmid = syscall::BF_INVALID_ID.get();
                    mut_vm.set_active(mut_tls);
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(ppid0 == mut_vm.is_active(mut_tls));
                        bsl::ut_check(mut_vm.is_active_on_this_pp(mut_tls));
                    };

                    mut_tls.ppid = ppid1.get();
                    mut_tls.active_vmid = syscall::BF_INVALID_ID.get();
                    mut_vm.set_active(mut_tls);
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(ppid0 == mut_vm.is_active(mut_tls));
                        bsl::ut_check(mut_vm.is_active_on_this_pp(mut_tls));
                    };

                    mut_tls.ppid = ppid0.get();
                    mut_tls.active_vmid = {};
                    mut_vm.set_inactive(mut_tls);
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(ppid1 == mut_vm.is_active(mut_tls));
                        bsl::ut_check(!mut_vm.is_active_on_this_pp(mut_tls));
                    };

                    mut_tls.ppid = ppid1.get();
                    mut_tls.active_vmid = {};
                    mut_vm.set_inactive(mut_tls);
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_vm.is_active(mut_tls).is_invalid());
                        bsl::ut_check(!mut_vm.is_active_on_this_pp(mut_tls));
                    };
                };
            };
        };

        bsl::ut_scenario{"dump"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                vm_t mut_vm{};
                bsl::ut_then{} = [&]() noexcept {
                    mut_vm.dump({});
                };
            };
        };

        bsl::ut_scenario{"dump active"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                vm_t mut_vm{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                ext_pool_t mut_ext_pool{};
                constexpr auto online_pps{2_u16};
                bsl::ut_when{} = [&]() noexcept {
                    mut_tls.online_pps = online_pps.get();
                    mut_tls.active_vmid = syscall::BF_INVALID_ID.get();
                    mut_vm.initialize({});
                    bsl::ut_required_step(mut_vm.allocate(mut_tls, mut_page_pool, mut_ext_pool));
                    mut_vm.set_active(mut_tls);

                    bsl::ut_then{} = [&]() noexcept {
                        mut_vm.dump(mut_tls);
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
