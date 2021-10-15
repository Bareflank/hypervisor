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

#include "../../../mocks/basic_root_page_table_t.hpp"

#include <basic_alloc_page_t.hpp>
#include <basic_page_4k_t.hpp>
#include <basic_page_pool_t.hpp>
#include <basic_page_table_t.hpp>
#include <intrinsic_t.hpp>
#include <l0e_t.hpp>
#include <l1e_t.hpp>
#include <l2e_t.hpp>
#include <l3e_t.hpp>
#include <tls_t.hpp>

#include <bsl/convert.hpp>
#include <bsl/discard.hpp>
#include <bsl/dontcare_t.hpp>
#include <bsl/errc_type.hpp>
#include <bsl/safe_integral.hpp>
#include <bsl/ut.hpp>

namespace lib
{
    /// @brief defines the page_pool_t used by the microkernel
    using page_pool_t = lib::basic_page_pool_t<tls_t>;

    /// @brief defines the root_page_table_t used by the microkernel
    using root_page_table_t = lib::basic_root_page_table_t<
        tls_t,
        bsl::dontcare_t,
        page_pool_t,
        intrinsic_t,
        l3e_t,
        l2e_t,
        l1e_t,
        l0e_t>;

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
        bsl::ut_scenario{"initialize allocate fails"} = [&]() noexcept {
            bsl::ut_given_at_runtime{} = [&]() noexcept {
                root_page_table_t mut_rpt{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                constexpr auto phys{0x1000_u64};
                bsl::ut_when{} = [&]() noexcept {
                    mut_page_pool.set_allocate<helpers::l3t_t>(nullptr, phys);
                    mut_tls.test_ret = UNIT_TEST_RPT_FAIL_INITIALIZE;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(!mut_rpt.initialize(mut_tls, mut_page_pool));
                    };
                };
            };
        };

        bsl::ut_scenario{"initialize success"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                root_page_table_t mut_rpt{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(mut_rpt.initialize(mut_tls, mut_page_pool));
                    bsl::ut_cleanup{} = [&]() noexcept {
                        mut_rpt.release(mut_tls, mut_page_pool);
                    };
                };
            };
        };

        bsl::ut_scenario{"release without initialize"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                root_page_table_t mut_rpt{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                bsl::ut_then{} = [&]() noexcept {
                    mut_rpt.release(mut_tls, mut_page_pool);
                };
            };
        };

        bsl::ut_scenario{"release success"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                root_page_table_t mut_rpt{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(mut_rpt.initialize(mut_tls, mut_page_pool));
                    bsl::ut_cleanup{} = [&]() noexcept {
                        mut_rpt.release(mut_tls, mut_page_pool);
                    };
                };
            };
        };

        bsl::ut_scenario{"is_initialized"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                root_page_table_t mut_rpt{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(!mut_rpt.is_initialized());
                    };
                    bsl::ut_required_step(mut_rpt.initialize(mut_tls, mut_page_pool));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_rpt.is_initialized());
                    };
                    mut_rpt.release(mut_tls, mut_page_pool);
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(!mut_rpt.is_initialized());
                    };
                };
            };
        };

        bsl::ut_scenario{"activate"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                root_page_table_t mut_rpt{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                intrinsic_t mut_intrinsic{};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_rpt.initialize(mut_tls, mut_page_pool));
                    mut_rpt.activate(mut_tls, mut_intrinsic);
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_tls.active_rpt == &mut_rpt);
                        bsl::ut_check(mut_intrinsic.rpt().is_pos());
                        bsl::ut_cleanup{} = [&]() noexcept {
                            mut_rpt.release(mut_tls, mut_page_pool);
                        };
                    };
                };
            };
        };

        bsl::ut_scenario{"is_inactive"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                root_page_table_t mut_rpt{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                intrinsic_t mut_intrinsic{};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_rpt.is_inactive(mut_tls));
                    };

                    bsl::ut_required_step(mut_rpt.initialize(mut_tls, mut_page_pool));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_rpt.is_inactive(mut_tls));
                    };

                    mut_rpt.activate(mut_tls, mut_intrinsic);
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(!mut_rpt.is_inactive(mut_tls));
                    };

                    bsl::ut_cleanup{} = [&]() noexcept {
                        mut_rpt.release(mut_tls, mut_page_pool);
                    };
                };
            };
        };

        bsl::ut_scenario{"spa"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                root_page_table_t mut_rpt{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_rpt.initialize(mut_tls, mut_page_pool));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_rpt.spa().is_valid_and_checked());
                        bsl::ut_check(mut_rpt.spa().is_pos());
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        mut_rpt.release(mut_tls, mut_page_pool);
                    };
                };
            };
        };

        bsl::ut_scenario{"map 4k page"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                root_page_table_t mut_rpt{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                constexpr auto virt{0x1000_u64};
                constexpr auto phys{0x1000_u64};
                constexpr auto flgs{0x0_u64};
                bool const explicit_unmap{};
                bsl::dontcare_t mut_sys{};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_rpt.initialize(mut_tls, mut_page_pool));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_rpt.map<l0e_t>(
                            mut_tls, mut_page_pool, virt, phys, flgs, explicit_unmap, mut_sys));
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        mut_rpt.release(mut_tls, mut_page_pool);
                    };
                };
            };
        };

        bsl::ut_scenario{"map 4k page fails"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                root_page_table_t mut_rpt{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                constexpr auto virt{0x0_u64};
                constexpr auto phys{0x1000_u64};
                constexpr auto flgs{0x0_u64};
                bool const explicit_unmap{};
                bsl::dontcare_t mut_sys{};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_rpt.initialize(mut_tls, mut_page_pool));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(!mut_rpt.map<l0e_t>(
                            mut_tls, mut_page_pool, virt, phys, flgs, explicit_unmap, mut_sys));
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        mut_rpt.release(mut_tls, mut_page_pool);
                    };
                };
            };
        };

        bsl::ut_scenario{"map 2m page"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                root_page_table_t mut_rpt{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                constexpr auto virt{0x200000_u64};
                constexpr auto phys{0x200000_u64};
                constexpr auto flgs{0x0_u64};
                bool const explicit_unmap{};
                bsl::dontcare_t mut_sys{};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_rpt.initialize(mut_tls, mut_page_pool));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_rpt.map<l1e_t>(
                            mut_tls, mut_page_pool, virt, phys, flgs, explicit_unmap, mut_sys));
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        mut_rpt.release(mut_tls, mut_page_pool);
                    };
                };
            };
        };

        bsl::ut_scenario{"map 2m page fails"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                root_page_table_t mut_rpt{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                constexpr auto virt{0x0_u64};
                constexpr auto phys{0x200000_u64};
                constexpr auto flgs{0x0_u64};
                bool const explicit_unmap{};
                bsl::dontcare_t mut_sys{};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_rpt.initialize(mut_tls, mut_page_pool));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(!mut_rpt.map<l1e_t>(
                            mut_tls, mut_page_pool, virt, phys, flgs, explicit_unmap, mut_sys));
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        mut_rpt.release(mut_tls, mut_page_pool);
                    };
                };
            };
        };

        bsl::ut_scenario{"map 1g page"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                root_page_table_t mut_rpt{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                constexpr auto virt{0x40000000_u64};
                constexpr auto phys{0x40000000_u64};
                constexpr auto flgs{0x0_u64};
                bool const explicit_unmap{};
                bsl::dontcare_t mut_sys{};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_rpt.initialize(mut_tls, mut_page_pool));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_rpt.map<l2e_t>(
                            mut_tls, mut_page_pool, virt, phys, flgs, explicit_unmap, mut_sys));
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        mut_rpt.release(mut_tls, mut_page_pool);
                    };
                };
            };
        };

        bsl::ut_scenario{"map 1g page fails"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                root_page_table_t mut_rpt{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                constexpr auto virt{0x0_u64};
                constexpr auto phys{0x40000000_u64};
                constexpr auto flgs{0x0_u64};
                bool const explicit_unmap{};
                bsl::dontcare_t mut_sys{};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_rpt.initialize(mut_tls, mut_page_pool));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(!mut_rpt.map<l2e_t>(
                            mut_tls, mut_page_pool, virt, phys, flgs, explicit_unmap, mut_sys));
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        mut_rpt.release(mut_tls, mut_page_pool);
                    };
                };
            };
        };

        bsl::ut_scenario{"allocate_page"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                root_page_table_t mut_rpt{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                constexpr auto virt{0x1000_u64};
                constexpr auto flgs{0x0_u64};
                bsl::dontcare_t mut_sys{};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_rpt.initialize(mut_tls, mut_page_pool));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            nullptr != mut_rpt.allocate_page<basic_page_4k_t>(
                                           mut_tls, mut_page_pool, virt, flgs, mut_sys));
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        mut_rpt.release(mut_tls, mut_page_pool);
                    };
                };
            };
        };

        bsl::ut_scenario{"allocate_page fails"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                root_page_table_t mut_rpt{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                constexpr auto virt{0x0_u64};
                constexpr auto flgs{0x0_u64};
                bsl::dontcare_t mut_sys{};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_rpt.initialize(mut_tls, mut_page_pool));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            nullptr == mut_rpt.allocate_page<basic_page_4k_t>(
                                           mut_tls, mut_page_pool, virt, flgs, mut_sys));
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        mut_rpt.release(mut_tls, mut_page_pool);
                    };
                };
            };
        };

        bsl::ut_scenario{"allocate_page<offset>"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                root_page_table_t mut_rpt{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                constexpr auto offs{0x1000_u64};
                bsl::dontcare_t mut_sys{};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_rpt.initialize(mut_tls, mut_page_pool));
                    auto const page{
                        mut_rpt.allocate_page<offs.get()>(mut_tls, mut_page_pool, mut_sys)};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(page.virt.is_valid());
                        bsl::ut_check(page.phys.is_valid());
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        mut_rpt.release(mut_tls, mut_page_pool);
                    };
                };
            };
        };

        bsl::ut_scenario{"allocate_page<offset> fails"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                root_page_table_t mut_rpt{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                constexpr auto offs{0x1000_u64};
                bsl::dontcare_t mut_sys{};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_rpt.initialize(mut_tls, mut_page_pool));
                    mut_tls.test_virt = bsl::safe_u64::failure();
                    auto const page{
                        mut_rpt.allocate_page<offs.get()>(mut_tls, mut_page_pool, mut_sys)};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(page.virt.is_invalid());
                        bsl::ut_check(page.phys.is_invalid());
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        mut_rpt.release(mut_tls, mut_page_pool);
                    };
                };
            };
        };

        bsl::ut_scenario{"unmap"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                root_page_table_t mut_rpt{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                bsl::dontcare_t mut_sys{};
                constexpr auto virt1{0x1000_u64};
                constexpr auto virt2{0x200000_u64};
                constexpr auto virt3{0x40000000_u64};
                constexpr auto phys1{0x1000_u64};
                constexpr auto phys2{0x200000_u64};
                constexpr auto phys3{0x40000000_u64};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_rpt.initialize(mut_tls, mut_page_pool));
                    bsl::ut_required_step(
                        mut_rpt.map<l0e_t>(mut_tls, mut_page_pool, virt1, phys1, {}, {}, mut_sys));
                    bsl::ut_required_step(
                        mut_rpt.map<l1e_t>(mut_tls, mut_page_pool, virt2, phys2, {}, {}, mut_sys));
                    bsl::ut_required_step(
                        mut_rpt.map<l2e_t>(mut_tls, mut_page_pool, virt3, phys3, {}, {}, mut_sys));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_rpt.unmap<l0e_t>(mut_tls, mut_page_pool, virt1));
                        bsl::ut_check(mut_rpt.unmap<l1e_t>(mut_tls, mut_page_pool, virt2));
                        bsl::ut_check(mut_rpt.unmap<l2e_t>(mut_tls, mut_page_pool, virt3));
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        mut_rpt.release(mut_tls, mut_page_pool);
                    };
                };
            };
        };

        bsl::ut_scenario{"unmap fails"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                root_page_table_t mut_rpt{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                bsl::dontcare_t mut_sys{};
                constexpr auto virt1{0x1000_u64};
                constexpr auto virt2{0x200000_u64};
                constexpr auto virt3{0x40000000_u64};
                constexpr auto phys1{0x1000_u64};
                constexpr auto phys2{0x200000_u64};
                constexpr auto phys3{0x40000000_u64};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_rpt.initialize(mut_tls, mut_page_pool));
                    bsl::ut_required_step(
                        mut_rpt.map<l0e_t>(mut_tls, mut_page_pool, virt1, phys1, {}, {}, mut_sys));
                    bsl::ut_required_step(
                        mut_rpt.map<l1e_t>(mut_tls, mut_page_pool, virt2, phys2, {}, {}, mut_sys));
                    bsl::ut_required_step(
                        mut_rpt.map<l2e_t>(mut_tls, mut_page_pool, virt3, phys3, {}, {}, mut_sys));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(!mut_rpt.unmap<l0e_t>(mut_tls, mut_page_pool, {}));
                        bsl::ut_check(!mut_rpt.unmap<l1e_t>(mut_tls, mut_page_pool, {}));
                        bsl::ut_check(!mut_rpt.unmap<l2e_t>(mut_tls, mut_page_pool, {}));
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        mut_rpt.release(mut_tls, mut_page_pool);
                    };
                };
            };
        };

        bsl::ut_scenario{"entries"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                root_page_table_t mut_rpt{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                bsl::dontcare_t mut_sys{};
                constexpr auto virt1{0x1000_u64};
                constexpr auto virt2{0x200000_u64};
                constexpr auto virt3{0x40000000_u64};
                constexpr auto phys1{0x1000_u64};
                constexpr auto phys2{0x200000_u64};
                constexpr auto phys3{0x40000000_u64};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_rpt.initialize(mut_tls, mut_page_pool));
                    bsl::ut_required_step(
                        mut_rpt.map<l0e_t>(mut_tls, mut_page_pool, virt1, phys1, {}, {}, mut_sys));
                    bsl::ut_required_step(
                        mut_rpt.map<l1e_t>(mut_tls, mut_page_pool, virt2, phys2, {}, {}, mut_sys));
                    bsl::ut_required_step(
                        mut_rpt.map<l2e_t>(mut_tls, mut_page_pool, virt3, phys3, {}, {}, mut_sys));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::discard(mut_rpt.entries<l0e_t>(mut_tls, mut_page_pool, virt1));
                        bsl::discard(mut_rpt.entries<l1e_t>(mut_tls, mut_page_pool, virt2));
                        bsl::discard(mut_rpt.entries<l2e_t>(mut_tls, mut_page_pool, virt3));
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        mut_rpt.release(mut_tls, mut_page_pool);
                    };
                };
            };
        };

        bsl::ut_scenario{"add_tables"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                root_page_table_t mut_rpt{};
                root_page_table_t const rpt_src{};
                basic_page_table_t<l3e_t> const l3e_src{};
                bsl::ut_then{} = [&]() noexcept {
                    mut_rpt.add_tables({}, rpt_src);
                    mut_rpt.add_tables({}, &l3e_src);
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

    static_assert(lib::tests() == bsl::ut_success());
    return lib::tests();
}
