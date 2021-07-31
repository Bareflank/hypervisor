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

#include "../../../MOCK/page_pool_t.hpp"

#include <ext_tcb_t.hpp>
#include <page_t.hpp>
#include <x64/pdpt_t.hpp>
#include <x64/pdt_t.hpp>
#include <x64/pml4t_t.hpp>
#include <x64/pt_t.hpp>

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
    template<typename T>
    [[maybe_unused]] constexpr auto
    tests() noexcept -> bsl::exit_code
    {
        bsl::ut_scenario{"allocate invalid tag"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                page_pool_t mut_page_pool{};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(mut_page_pool.allocate<T>({}, "") == nullptr);
                };
            };
        };

        bsl::ut_scenario{"allocate after set_allocate"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                page_pool_t mut_page_pool{};
                T mut_virt{};
                T *pmut_mut_virt0{};
                T *pmut_mut_virt1{};
                T *pmut_mut_virt2{};
                constexpr auto phys{0xFF000_umx};
                bsl::ut_when{} = [&]() noexcept {
                    mut_page_pool.set_allocate("42", &mut_virt, phys);
                    mut_page_pool.set_allocate<T>("null", {}, phys);
                    pmut_mut_virt0 = mut_page_pool.allocate<T>({}, "42");
                    pmut_mut_virt1 = mut_page_pool.allocate<T>({}, "23");
                    pmut_mut_virt2 = mut_page_pool.allocate<T>({}, "null");
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(&mut_virt == pmut_mut_virt0);
                        bsl::ut_check(&mut_virt != pmut_mut_virt1);
                        bsl::ut_check(nullptr != pmut_mut_virt1);
                        bsl::ut_check(nullptr == pmut_mut_virt2);
                        bsl::ut_check(mut_page_pool.allocated({}, "42") == HYPERVISOR_PAGE_SIZE);
                        bsl::ut_check(mut_page_pool.allocated({}, "23") == HYPERVISOR_PAGE_SIZE);
                        bsl::ut_check(mut_page_pool.virt_to_phys(pmut_mut_virt0) == phys);
                        bsl::ut_check(mut_page_pool.phys_to_virt<T>(phys) == pmut_mut_virt0);
                        bsl::ut_cleanup{} = [&]() noexcept {
                            mut_page_pool.deallocate({}, pmut_mut_virt0, "42");
                            mut_page_pool.deallocate({}, pmut_mut_virt1, "23");
                        };
                    };
                };
            };
        };

        bsl::ut_scenario{"allocate max tags failure"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                page_pool_t mut_page_pool{};
                T *pmut_mut_virt0{};
                T *pmut_mut_virt1{};
                T *pmut_mut_virt2{};
                T *pmut_mut_virt3{};
                T *pmut_mut_virt4{};
                T *pmut_mut_virt5{};
                T *pmut_mut_virt6{};
                T *pmut_mut_virt7{};
                T *pmut_mut_virt8{};
                T *pmut_mut_virt9{};
                bsl::ut_when{} = [&]() noexcept {
                    pmut_mut_virt0 = mut_page_pool.allocate<T>({}, "0");
                    pmut_mut_virt1 = mut_page_pool.allocate<T>({}, "1");
                    pmut_mut_virt2 = mut_page_pool.allocate<T>({}, "2");
                    pmut_mut_virt3 = mut_page_pool.allocate<T>({}, "3");
                    pmut_mut_virt4 = mut_page_pool.allocate<T>({}, "4");
                    pmut_mut_virt5 = mut_page_pool.allocate<T>({}, "5");
                    pmut_mut_virt6 = mut_page_pool.allocate<T>({}, "6");
                    pmut_mut_virt7 = mut_page_pool.allocate<T>({}, "7");
                    pmut_mut_virt8 = mut_page_pool.allocate<T>({}, "8");
                    pmut_mut_virt9 = mut_page_pool.allocate<T>({}, "9");
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_page_pool.allocate<T>({}, "42") == nullptr);
                        bsl::ut_cleanup{} = [&]() noexcept {
                            mut_page_pool.deallocate({}, pmut_mut_virt0, "0");
                            mut_page_pool.deallocate({}, pmut_mut_virt1, "1");
                            mut_page_pool.deallocate({}, pmut_mut_virt2, "2");
                            mut_page_pool.deallocate({}, pmut_mut_virt3, "3");
                            mut_page_pool.deallocate({}, pmut_mut_virt4, "4");
                            mut_page_pool.deallocate({}, pmut_mut_virt5, "5");
                            mut_page_pool.deallocate({}, pmut_mut_virt6, "6");
                            mut_page_pool.deallocate({}, pmut_mut_virt7, "7");
                            mut_page_pool.deallocate({}, pmut_mut_virt8, "8");
                            mut_page_pool.deallocate({}, pmut_mut_virt9, "9");
                        };
                    };
                };
            };
        };

        bsl::ut_scenario{"allocate success"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                page_pool_t mut_page_pool{};
                T *pmut_mut_virt0{};
                T *pmut_mut_virt1{};
                T *pmut_mut_virt2{};
                T *pmut_mut_virt3{};
                constexpr auto expected{(HYPERVISOR_PAGE_SIZE * 2_umx).checked()};
                bsl::ut_when{} = [&]() noexcept {
                    pmut_mut_virt0 = mut_page_pool.allocate<T>({}, "42");
                    pmut_mut_virt1 = mut_page_pool.allocate<T>({}, "42");
                    pmut_mut_virt2 = mut_page_pool.allocate<T>({}, "23");
                    pmut_mut_virt3 = mut_page_pool.allocate<T>({}, "23");
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(nullptr != pmut_mut_virt0);
                        bsl::ut_check(nullptr != pmut_mut_virt1);
                        bsl::ut_check(nullptr != pmut_mut_virt2);
                        bsl::ut_check(nullptr != pmut_mut_virt3);
                        bsl::ut_check(mut_page_pool.allocated({}, "42") == expected);
                        bsl::ut_check(mut_page_pool.allocated({}, "23") == expected);
                        bsl::ut_cleanup{} = [&]() noexcept {
                            mut_page_pool.deallocate({}, pmut_mut_virt0, "42");
                            mut_page_pool.deallocate({}, pmut_mut_virt1, "42");
                            mut_page_pool.deallocate({}, pmut_mut_virt2, "23");
                            mut_page_pool.deallocate({}, pmut_mut_virt3, "23");
                        };
                    };
                };
            };
        };

        bsl::ut_scenario{"deallocate invalid virt does not crash"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                page_pool_t mut_page_pool{};
                bsl::ut_then{} = [&]() noexcept {
                    mut_page_pool.deallocate<T>({}, nullptr, "42");
                };
            };
        };

        bsl::ut_scenario{"deallocate invalid tag does not crash"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                page_pool_t mut_page_pool{};
                T mut_page{};
                bsl::ut_then{} = [&]() noexcept {
                    mut_page_pool.deallocate<T>({}, &mut_page, "42");
                };
            };
        };

        bsl::ut_scenario{"deallocate success"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                page_pool_t mut_page_pool{};
                T *pmut_mut_virt0{};
                T *pmut_mut_virt1{};
                T *pmut_mut_virt2{};
                T *pmut_mut_virt3{};
                constexpr auto expected{(HYPERVISOR_PAGE_SIZE * 2_umx).checked()};
                bsl::ut_when{} = [&]() noexcept {
                    pmut_mut_virt0 = mut_page_pool.allocate<T>({}, "42");
                    pmut_mut_virt1 = mut_page_pool.allocate<T>({}, "42");
                    pmut_mut_virt2 = mut_page_pool.allocate<T>({}, "23");
                    pmut_mut_virt3 = mut_page_pool.allocate<T>({}, "23");
                    bsl::ut_required_step(nullptr != pmut_mut_virt0);
                    bsl::ut_required_step(nullptr != pmut_mut_virt1);
                    bsl::ut_required_step(nullptr != pmut_mut_virt2);
                    bsl::ut_required_step(nullptr != pmut_mut_virt3);
                    bsl::ut_required_step(mut_page_pool.allocated({}, "42") == expected);
                    bsl::ut_required_step(mut_page_pool.allocated({}, "23") == expected);
                    bsl::ut_then{} = [&]() noexcept {
                        mut_page_pool.deallocate({}, pmut_mut_virt0, "42");
                        bsl::ut_check(mut_page_pool.allocated({}, "42") == HYPERVISOR_PAGE_SIZE);
                        mut_page_pool.deallocate({}, pmut_mut_virt1, "42");
                        bsl::ut_check(mut_page_pool.allocated({}, "42").is_zero());
                        mut_page_pool.deallocate({}, pmut_mut_virt2, "23");
                        bsl::ut_check(mut_page_pool.allocated({}, "23") == HYPERVISOR_PAGE_SIZE);
                        mut_page_pool.deallocate({}, pmut_mut_virt3, "23");
                        bsl::ut_check(mut_page_pool.allocated({}, "23").is_zero());
                    };
                };
            };
        };

        bsl::ut_scenario{"deallocate success (reverse order)"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                page_pool_t mut_page_pool{};
                T *pmut_mut_virt0{};
                T *pmut_mut_virt1{};
                T *pmut_mut_virt2{};
                T *pmut_mut_virt3{};
                constexpr auto expected{(HYPERVISOR_PAGE_SIZE * 2_umx).checked()};
                bsl::ut_when{} = [&]() noexcept {
                    pmut_mut_virt0 = mut_page_pool.allocate<T>({}, "42");
                    pmut_mut_virt1 = mut_page_pool.allocate<T>({}, "42");
                    pmut_mut_virt2 = mut_page_pool.allocate<T>({}, "23");
                    pmut_mut_virt3 = mut_page_pool.allocate<T>({}, "23");
                    bsl::ut_required_step(nullptr != pmut_mut_virt0);
                    bsl::ut_required_step(nullptr != pmut_mut_virt1);
                    bsl::ut_required_step(nullptr != pmut_mut_virt2);
                    bsl::ut_required_step(nullptr != pmut_mut_virt3);
                    bsl::ut_required_step(mut_page_pool.allocated({}, "42") == expected);
                    bsl::ut_required_step(mut_page_pool.allocated({}, "23") == expected);
                    bsl::ut_then{} = [&]() noexcept {
                        mut_page_pool.deallocate({}, pmut_mut_virt3, "23");
                        bsl::ut_check(mut_page_pool.allocated({}, "23") == HYPERVISOR_PAGE_SIZE);
                        mut_page_pool.deallocate({}, pmut_mut_virt2, "23");
                        bsl::ut_check(mut_page_pool.allocated({}, "23").is_zero());
                        mut_page_pool.deallocate({}, pmut_mut_virt1, "42");
                        bsl::ut_check(mut_page_pool.allocated({}, "42") == HYPERVISOR_PAGE_SIZE);
                        mut_page_pool.deallocate({}, pmut_mut_virt0, "42");
                        bsl::ut_check(mut_page_pool.allocated({}, "42").is_zero());
                    };
                };
            };
        };

        bsl::ut_scenario{"allocated"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                page_pool_t mut_page_pool{};
                T *pmut_mut_virt0{};
                T *pmut_mut_virt1{};
                constexpr auto expected{(HYPERVISOR_PAGE_SIZE * 2_umx).checked()};
                bsl::ut_when{} = [&]() noexcept {
                    pmut_mut_virt0 = mut_page_pool.allocate<T>({}, "42");
                    pmut_mut_virt1 = mut_page_pool.allocate<T>({}, "42");
                    bsl::ut_required_step(nullptr != pmut_mut_virt0);
                    bsl::ut_required_step(nullptr != pmut_mut_virt1);
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_page_pool.allocated({}, "42") == expected);
                        bsl::ut_cleanup{} = [&]() noexcept {
                            mut_page_pool.deallocate({}, pmut_mut_virt0, "42");
                            mut_page_pool.deallocate({}, pmut_mut_virt1, "42");
                        };
                    };
                    bsl::ut_then_at_runtime{} = [&]() noexcept {
                        bsl::ut_check(mut_page_pool.allocated({}, "42").is_zero());
                        bsl::ut_check(!mut_page_pool.allocated({}, "23"));
                    };
                };
            };
        };

        bsl::ut_scenario{"virt_to_phys"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                page_pool_t mut_page_pool{};
                T const virt{};
                T *pmut_mut_virt0{};
                bsl::ut_when{} = [&]() noexcept {
                    pmut_mut_virt0 = mut_page_pool.allocate<T>({}, "42");
                    bsl::ut_required_step(nullptr != pmut_mut_virt0);
                    bsl::ut_then{"allocated by mut_page_pool success"} = [&]() noexcept {
                        bsl::ut_check(mut_page_pool.virt_to_phys(pmut_mut_virt0));
                    };
                    bsl::ut_then_at_runtime{"not allocated by mut_page_pool failure"} =
                        [&]() noexcept {
                            bsl::ut_check(!mut_page_pool.virt_to_phys(&virt));
                        };
                    bsl::ut_then_at_runtime{"nullptr failure"} = [&]() noexcept {
                        bsl::ut_check(!mut_page_pool.virt_to_phys<T>(nullptr));
                    };
                    constexpr auto my_bad_phys{bsl::safe_umx::failure()};
                    mut_page_pool.set_virt_to_phys(pmut_mut_virt0, my_bad_phys);
                    bsl::ut_then{"my bad phys fails"} = [&]() noexcept {
                        bsl::ut_check(!mut_page_pool.virt_to_phys(pmut_mut_virt0));
                    };
                    constexpr auto my_good_phys{42_umx};
                    mut_page_pool.set_virt_to_phys(pmut_mut_virt0, my_good_phys);
                    bsl::ut_then{"my good phys succeeds"} = [&]() noexcept {
                        bsl::ut_check(mut_page_pool.virt_to_phys(pmut_mut_virt0) == my_good_phys);
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        mut_page_pool.deallocate({}, pmut_mut_virt0, "42");
                    };
                };
            };
        };

        bsl::ut_scenario{"virt_to_phys (const version)"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                page_pool_t mut_page_pool{};
                T mut_virt{};
                T *pmut_mut_virt0{};
                bsl::ut_when{} = [&]() noexcept {
                    pmut_mut_virt0 = mut_page_pool.allocate<T>({}, "42");
                    bsl::ut_required_step(nullptr != pmut_mut_virt0);
                    bsl::ut_then{"allocated by mut_page_pool success"} = [&]() noexcept {
                        bsl::ut_check(mut_page_pool.virt_to_phys<T const>(pmut_mut_virt0));
                    };
                    bsl::ut_then_at_runtime{"not allocated by mut_page_pool failure"} =
                        [&]() noexcept {
                            bsl::ut_check(!mut_page_pool.virt_to_phys<T const>(&mut_virt));
                        };
                    bsl::ut_then_at_runtime{"nullptr failure"} = [&]() noexcept {
                        bsl::ut_check(!mut_page_pool.virt_to_phys<T const>(nullptr));
                    };
                    constexpr auto my_bad_phys{bsl::safe_umx::failure()};
                    mut_page_pool.set_virt_to_phys(pmut_mut_virt0, my_bad_phys);
                    bsl::ut_then{"my bad phys fails"} = [&]() noexcept {
                        bsl::ut_check(!mut_page_pool.virt_to_phys<T const>(pmut_mut_virt0));
                    };
                    constexpr auto my_good_phys{42_umx};
                    mut_page_pool.set_virt_to_phys(pmut_mut_virt0, my_good_phys);
                    bsl::ut_then{"my good phys succeeds"} = [&]() noexcept {
                        bsl::ut_check(
                            mut_page_pool.virt_to_phys<T const>(pmut_mut_virt0) == my_good_phys);
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        mut_page_pool.deallocate({}, pmut_mut_virt0, "42");
                    };
                };
            };
        };

        bsl::ut_scenario{"phys_to_virt"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                page_pool_t mut_page_pool{};
                T *pmut_mut_virt0{};
                bsl::safe_umx mut_phys{};
                bsl::ut_when{} = [&]() noexcept {
                    pmut_mut_virt0 = mut_page_pool.allocate<T>({}, "42");
                    bsl::ut_required_step(nullptr != pmut_mut_virt0);
                    mut_phys = mut_page_pool.virt_to_phys(pmut_mut_virt0);
                    bsl::ut_required_step(!mut_phys.is_zero_or_invalid());
                    bsl::ut_then{"allocated by mut_page_pool success"} = [&]() noexcept {
                        bsl::ut_check(mut_page_pool.phys_to_virt<T>(mut_phys) == pmut_mut_virt0);
                    };
                    bsl::ut_then_at_runtime{"not allocated by mut_page_pool failure"} =
                        [&]() noexcept {
                            constexpr auto bad_phys{0xFFFFFFFFFFFFFFFF_umx};
                            bsl::ut_check(mut_page_pool.phys_to_virt<T>(bad_phys) == nullptr);
                        };
                    bsl::ut_then_at_runtime{"invalid failure"} = [&]() noexcept {
                        constexpr auto bad_phys{bsl::safe_umx::failure()};
                        bsl::ut_check(mut_page_pool.phys_to_virt<T>(bad_phys) == nullptr);
                    };
                    bsl::ut_then_at_runtime{"nullptr failure"} = [&]() noexcept {
                        constexpr auto bad_phys{0_umx};
                        bsl::ut_check(mut_page_pool.phys_to_virt<T>(bad_phys) == nullptr);
                    };
                    mut_page_pool.set_phys_to_virt<T>(mut_phys, nullptr);
                    bsl::ut_then{"my bad phys fails"} = [&]() noexcept {
                        bsl::ut_check(mut_page_pool.phys_to_virt<T>(mut_phys) == nullptr);
                    };
                    mut_page_pool.set_phys_to_virt(mut_phys, pmut_mut_virt0);
                    bsl::ut_then{"my good phys succeeds"} = [&]() noexcept {
                        bsl::ut_check(mut_page_pool.phys_to_virt<T>(mut_phys) == pmut_mut_virt0);
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        mut_page_pool.deallocate({}, pmut_mut_virt0, "42");
                    };
                };
            };
        };

        bsl::ut_scenario{"phys_to_virt (const version)"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                page_pool_t mut_page_pool{};
                T *pmut_mut_virt0{};
                bsl::safe_umx mut_phys{};
                bsl::ut_when{} = [&]() noexcept {
                    pmut_mut_virt0 = mut_page_pool.allocate<T>({}, "42");
                    bsl::ut_required_step(nullptr != pmut_mut_virt0);
                    mut_phys = mut_page_pool.virt_to_phys(pmut_mut_virt0);
                    bsl::ut_required_step(!mut_phys.is_zero_or_invalid());
                    bsl::ut_then{"allocated by mut_page_pool success"} = [&]() noexcept {
                        bsl::ut_check(
                            mut_page_pool.phys_to_virt<T const>(mut_phys) == pmut_mut_virt0);
                    };
                    bsl::ut_then_at_runtime{"not allocated by mut_page_pool failure"} =
                        [&]() noexcept {
                            constexpr auto bad_phys{0xFFFFFFFFFFFFFFFF_umx};
                            bsl::ut_check(mut_page_pool.phys_to_virt<T const>(bad_phys) == nullptr);
                        };
                    bsl::ut_then_at_runtime{"invalid failure"} = [&]() noexcept {
                        constexpr auto bad_phys{bsl::safe_umx::failure()};
                        bsl::ut_check(mut_page_pool.phys_to_virt<T const>(bad_phys) == nullptr);
                    };
                    bsl::ut_then_at_runtime{"nullptr failure"} = [&]() noexcept {
                        constexpr auto bad_phys{0_umx};
                        bsl::ut_check(mut_page_pool.phys_to_virt<T const>(bad_phys) == nullptr);
                    };
                    mut_page_pool.set_phys_to_virt<T>(mut_phys, nullptr);
                    bsl::ut_then{"my bad phys fails"} = [&]() noexcept {
                        bsl::ut_check(mut_page_pool.phys_to_virt<T const>(mut_phys) == nullptr);
                    };
                    mut_page_pool.set_phys_to_virt(mut_phys, pmut_mut_virt0);
                    bsl::ut_then{"my good phys succeeds"} = [&]() noexcept {
                        bsl::ut_check(
                            mut_page_pool.phys_to_virt<T const>(mut_phys) == pmut_mut_virt0);
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        mut_page_pool.deallocate({}, pmut_mut_virt0, "42");
                    };
                };
            };
        };

        bsl::ut_scenario{"quiet dump"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                page_pool_t const pool{};
                bsl::ut_then{} = [&]() noexcept {
                    pool.dump();
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

    static_assert(mk::tests<mk::page_t>() == bsl::ut_success());
    static_assert(mk::tests<mk::ext_tcb_t>() == bsl::ut_success());
    static_assert(mk::tests<mk::pml4t_t>() == bsl::ut_success());
    static_assert(mk::tests<mk::pdpt_t>() == bsl::ut_success());
    static_assert(mk::tests<mk::pdt_t>() == bsl::ut_success());
    static_assert(mk::tests<mk::pt_t>() == bsl::ut_success());

    mk::tests<mk::page_t>();
    mk::tests<mk::ext_tcb_t>();
    mk::tests<mk::pml4t_t>();
    mk::tests<mk::pdpt_t>();
    mk::tests<mk::pdt_t>();
    mk::tests<mk::pt_t>();

    return bsl::ut_success();
}
