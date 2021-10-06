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

#include "../../../src/basic_root_page_table_t.hpp"

#include <basic_alloc_page_t.hpp>
#include <basic_entries_t.hpp>
#include <basic_page_4k_t.hpp>
#include <basic_page_pool_t.hpp>
#include <intrinsic_t.hpp>
#include <l0e_t.hpp>
#include <l1e_t.hpp>
#include <l2e_t.hpp>
#include <l3e_t.hpp>
#include <tls_t.hpp>

#include <bsl/array.hpp>
#include <bsl/convert.hpp>
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
        constexpr auto enabled{bsl::safe_u64::magic_1()};
        constexpr auto disabled{bsl::safe_u64::magic_0()};

        bsl::ut_scenario{"initialize allocate fails"} = [&]() noexcept {
            bsl::ut_given_at_runtime{} = [&]() noexcept {
                root_page_table_t mut_rpt{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                constexpr auto phys{0x1000_u64};
                bsl::ut_when{} = [&]() noexcept {
                    mut_page_pool.set_allocate<helpers::l3t_t>(nullptr, phys);
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
                constexpr auto virt{0x0_u64};
                constexpr auto phys{0x1000_u64};
                constexpr auto flgs{0x0_u64};
                bool const explicit_unmap{};
                bsl::dontcare_t mut_sys{};
                constexpr auto expected_phys{0x1_u64};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_rpt.initialize(mut_tls, mut_page_pool));
                    bsl::ut_required_step(mut_rpt.map<l0e_t>(
                        mut_tls, mut_page_pool, virt, phys, flgs, explicit_unmap, mut_sys));
                    auto const ents{mut_rpt.entries<l0e_t>(mut_tls, mut_page_pool, {})};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(nullptr != ents.l0e);
                        bsl::ut_check(ents.l0e->auto_release == disabled);
                        bsl::ut_check(ents.l0e->points_to_block == enabled);
                        bsl::ut_check(ents.l0e->alias == disabled);
                        bsl::ut_check(ents.l0e->phys == expected_phys);
                        bsl::ut_check(ents.l0e->explicit_unmap == disabled);
                        bsl::ut_check(nullptr != ents.l1e);
                        bsl::ut_check(ents.l1e->auto_release == disabled);
                        bsl::ut_check(ents.l1e->points_to_block == disabled);
                        bsl::ut_check(ents.l1e->alias == disabled);
                        bsl::ut_check(ents.l1e->explicit_unmap == disabled);
                        bsl::ut_check(nullptr != ents.l2e);
                        bsl::ut_check(ents.l2e->auto_release == disabled);
                        bsl::ut_check(ents.l2e->points_to_block == disabled);
                        bsl::ut_check(ents.l2e->alias == disabled);
                        bsl::ut_check(ents.l2e->explicit_unmap == disabled);
                        bsl::ut_check(nullptr != ents.l3e);
                        bsl::ut_check(ents.l3e->auto_release == disabled);
                        bsl::ut_check(ents.l3e->points_to_block == disabled);
                        bsl::ut_check(ents.l3e->alias == disabled);
                        bsl::ut_check(ents.l3e->explicit_unmap == disabled);
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
                constexpr auto virt{0x0_u64};
                constexpr auto phys{0x200000_u64};
                constexpr auto flgs{0x0_u64};
                bool const explicit_unmap{};
                bsl::dontcare_t mut_sys{};
                constexpr auto expected_phys{0x200_u64};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_rpt.initialize(mut_tls, mut_page_pool));
                    bsl::ut_required_step(mut_rpt.map<l1e_t>(
                        mut_tls, mut_page_pool, virt, phys, flgs, explicit_unmap, mut_sys));
                    auto const ents{mut_rpt.entries<l1e_t>(mut_tls, mut_page_pool, {})};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(nullptr == ents.l0e);
                        bsl::ut_check(nullptr != ents.l1e);
                        bsl::ut_check(ents.l1e->auto_release == disabled);
                        bsl::ut_check(ents.l1e->points_to_block == enabled);
                        bsl::ut_check(ents.l1e->alias == disabled);
                        bsl::ut_check(ents.l1e->phys == expected_phys);
                        bsl::ut_check(ents.l1e->explicit_unmap == disabled);
                        bsl::ut_check(nullptr != ents.l2e);
                        bsl::ut_check(ents.l2e->auto_release == disabled);
                        bsl::ut_check(ents.l2e->points_to_block == disabled);
                        bsl::ut_check(ents.l2e->alias == disabled);
                        bsl::ut_check(ents.l2e->explicit_unmap == disabled);
                        bsl::ut_check(nullptr != ents.l3e);
                        bsl::ut_check(ents.l3e->auto_release == disabled);
                        bsl::ut_check(ents.l3e->points_to_block == disabled);
                        bsl::ut_check(ents.l3e->alias == disabled);
                        bsl::ut_check(ents.l3e->explicit_unmap == disabled);
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
                constexpr auto virt{0x0_u64};
                constexpr auto phys{0x40000000_u64};
                constexpr auto flgs{0x0_u64};
                bool const explicit_unmap{};
                bsl::dontcare_t mut_sys{};
                constexpr auto expected_phys{0x40000_u64};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_rpt.initialize(mut_tls, mut_page_pool));
                    bsl::ut_required_step(mut_rpt.map<l2e_t>(
                        mut_tls, mut_page_pool, virt, phys, flgs, explicit_unmap, mut_sys));
                    auto const ents{mut_rpt.entries<l2e_t>(mut_tls, mut_page_pool, {})};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(nullptr == ents.l0e);
                        bsl::ut_check(nullptr == ents.l1e);
                        bsl::ut_check(nullptr != ents.l2e);
                        bsl::ut_check(ents.l2e->auto_release == disabled);
                        bsl::ut_check(ents.l2e->points_to_block == enabled);
                        bsl::ut_check(ents.l2e->alias == disabled);
                        bsl::ut_check(ents.l2e->phys == expected_phys);
                        bsl::ut_check(ents.l2e->explicit_unmap == disabled);
                        bsl::ut_check(nullptr != ents.l3e);
                        bsl::ut_check(ents.l3e->auto_release == disabled);
                        bsl::ut_check(ents.l3e->points_to_block == disabled);
                        bsl::ut_check(ents.l3e->alias == disabled);
                        bsl::ut_check(ents.l3e->explicit_unmap == disabled);
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        mut_rpt.release(mut_tls, mut_page_pool);
                    };
                };
            };
        };

        bsl::ut_scenario{"map 4k page twice"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                root_page_table_t mut_rpt{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                constexpr auto virt{0x0_u64};
                constexpr auto phys{0x0_u64};
                constexpr auto flgs{0x0_u64};
                bool const explicit_unmap{};
                bsl::dontcare_t mut_sys{};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_rpt.initialize(mut_tls, mut_page_pool));
                    bsl::ut_required_step(mut_rpt.map<l0e_t>(
                        mut_tls, mut_page_pool, virt, phys, flgs, explicit_unmap, mut_sys));
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

        bsl::ut_scenario{"map 2m page twice"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                root_page_table_t mut_rpt{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                constexpr auto virt{0x0_u64};
                constexpr auto phys{0x0_u64};
                constexpr auto flgs{0x0_u64};
                bool const explicit_unmap{};
                bsl::dontcare_t mut_sys{};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_rpt.initialize(mut_tls, mut_page_pool));
                    bsl::ut_required_step(mut_rpt.map<l1e_t>(
                        mut_tls, mut_page_pool, virt, phys, flgs, explicit_unmap, mut_sys));
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

        bsl::ut_scenario{"map 1g page twice"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                root_page_table_t mut_rpt{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                constexpr auto virt{0x0_u64};
                constexpr auto phys{0x0_u64};
                constexpr auto flgs{0x0_u64};
                bool const explicit_unmap{};
                bsl::dontcare_t mut_sys{};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_rpt.initialize(mut_tls, mut_page_pool));
                    bsl::ut_required_step(mut_rpt.map<l2e_t>(
                        mut_tls, mut_page_pool, virt, phys, flgs, explicit_unmap, mut_sys));
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

        bsl::ut_scenario{"map 4k page on already mapped 1g page"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                root_page_table_t mut_rpt{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                constexpr auto virt{0x0_u64};
                constexpr auto phys{0x0_u64};
                constexpr auto flgs{0x0_u64};
                bool const explicit_unmap{};
                bsl::dontcare_t mut_sys{};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_rpt.initialize(mut_tls, mut_page_pool));
                    bsl::ut_required_step(mut_rpt.map<l2e_t>(
                        mut_tls, mut_page_pool, virt, phys, flgs, explicit_unmap, mut_sys));
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

        bsl::ut_scenario{"map 2m page on already mapped 1g page"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                root_page_table_t mut_rpt{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                constexpr auto virt{0x0_u64};
                constexpr auto phys{0x0_u64};
                constexpr auto flgs{0x0_u64};
                bool const explicit_unmap{};
                bsl::dontcare_t mut_sys{};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_rpt.initialize(mut_tls, mut_page_pool));
                    bsl::ut_required_step(mut_rpt.map<l2e_t>(
                        mut_tls, mut_page_pool, virt, phys, flgs, explicit_unmap, mut_sys));
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

        bsl::ut_scenario{"map 2m page on already mapped 4k page"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                root_page_table_t mut_rpt{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                constexpr auto virt{0x0_u64};
                constexpr auto phys{0x0_u64};
                constexpr auto flgs{0x0_u64};
                bool const explicit_unmap{};
                bsl::dontcare_t mut_sys{};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_rpt.initialize(mut_tls, mut_page_pool));
                    bsl::ut_required_step(mut_rpt.map<l0e_t>(
                        mut_tls, mut_page_pool, virt, phys, flgs, explicit_unmap, mut_sys));
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

        bsl::ut_scenario{"map 1g page on already mapped 4k page"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                root_page_table_t mut_rpt{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                constexpr auto virt{0x0_u64};
                constexpr auto phys{0x0_u64};
                constexpr auto flgs{0x0_u64};
                bool const explicit_unmap{};
                bsl::dontcare_t mut_sys{};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_rpt.initialize(mut_tls, mut_page_pool));
                    bsl::ut_required_step(mut_rpt.map<l0e_t>(
                        mut_tls, mut_page_pool, virt, phys, flgs, explicit_unmap, mut_sys));
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

        bsl::ut_scenario{"map 4k page add_table (l2t_t) fails"} = [&]() noexcept {
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
                    mut_page_pool.set_allocate<helpers::l2t_t>(nullptr, phys);
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

        bsl::ut_scenario{"map 4k page add_table (l1t_t) fails"} = [&]() noexcept {
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
                    mut_page_pool.set_allocate<helpers::l1t_t>(nullptr, phys);
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

        bsl::ut_scenario{"map 4k page add_table (l0t_t) fails"} = [&]() noexcept {
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
                    mut_page_pool.set_allocate<helpers::l0t_t>(nullptr, phys);
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

        bsl::ut_scenario{"map 2m page add_table (l2t_t) fails"} = [&]() noexcept {
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
                    mut_page_pool.set_allocate<helpers::l2t_t>(nullptr, phys);
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

        bsl::ut_scenario{"map 2m page add_table (l1t_t) fails"} = [&]() noexcept {
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
                    mut_page_pool.set_allocate<helpers::l1t_t>(nullptr, phys);
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

        bsl::ut_scenario{"map 1g page add_table (l2t_t) fails"} = [&]() noexcept {
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
                    mut_page_pool.set_allocate<helpers::l2t_t>(nullptr, phys);
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

        bsl::ut_scenario{"map 4k page as explicit unmap"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                root_page_table_t mut_rpt{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                constexpr auto virt{0x0_u64};
                constexpr auto phys{0x0_u64};
                constexpr auto flgs{0x0_u64};
                bool const explicit_unmap{true};
                bsl::dontcare_t mut_sys{};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_rpt.initialize(mut_tls, mut_page_pool));
                    bsl::ut_required_step(mut_rpt.map<l0e_t>(
                        mut_tls, mut_page_pool, virt, phys, flgs, explicit_unmap, mut_sys));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_rpt.unmap<l0e_t>(mut_tls, mut_page_pool, virt));
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        mut_rpt.release(mut_tls, mut_page_pool);
                    };
                };
            };
        };

        bsl::ut_scenario{"map 2m page as explicit unmap"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                root_page_table_t mut_rpt{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                constexpr auto virt{0x0_u64};
                constexpr auto phys{0x0_u64};
                constexpr auto flgs{0x0_u64};
                bool const explicit_unmap{true};
                bsl::dontcare_t mut_sys{};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_rpt.initialize(mut_tls, mut_page_pool));
                    bsl::ut_required_step(mut_rpt.map<l1e_t>(
                        mut_tls, mut_page_pool, virt, phys, flgs, explicit_unmap, mut_sys));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_rpt.unmap<l1e_t>(mut_tls, mut_page_pool, virt));
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        mut_rpt.release(mut_tls, mut_page_pool);
                    };
                };
            };
        };

        bsl::ut_scenario{"map 1g page as explicit unmap"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                root_page_table_t mut_rpt{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                constexpr auto virt{0x0_u64};
                constexpr auto phys{0x0_u64};
                constexpr auto flgs{0x0_u64};
                bool const explicit_unmap{true};
                bsl::dontcare_t mut_sys{};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_rpt.initialize(mut_tls, mut_page_pool));
                    bsl::ut_required_step(mut_rpt.map<l2e_t>(
                        mut_tls, mut_page_pool, virt, phys, flgs, explicit_unmap, mut_sys));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_rpt.unmap<l2e_t>(mut_tls, mut_page_pool, virt));
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        mut_rpt.release(mut_tls, mut_page_pool);
                    };
                };
            };
        };

        bsl::ut_scenario{"map 4k adjacent 2m"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                root_page_table_t mut_rpt{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                bsl::dontcare_t mut_sys{};
                constexpr auto virt{0x1000_u64};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_rpt.initialize(mut_tls, mut_page_pool));
                    bsl::ut_required_step(
                        mut_rpt.map<l1e_t>(mut_tls, mut_page_pool, {}, {}, {}, {}, mut_sys));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            !mut_rpt.map<l0e_t>(mut_tls, mut_page_pool, virt, {}, {}, {}, mut_sys));
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        mut_rpt.release(mut_tls, mut_page_pool);
                    };
                };
            };
        };

        bsl::ut_scenario{"map 4k adjacent 1g"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                root_page_table_t mut_rpt{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                bsl::dontcare_t mut_sys{};
                constexpr auto virt{0x1000_u64};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_rpt.initialize(mut_tls, mut_page_pool));
                    bsl::ut_required_step(
                        mut_rpt.map<l2e_t>(mut_tls, mut_page_pool, {}, {}, {}, {}, mut_sys));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            !mut_rpt.map<l0e_t>(mut_tls, mut_page_pool, virt, {}, {}, {}, mut_sys));
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        mut_rpt.release(mut_tls, mut_page_pool);
                    };
                };
            };
        };

        bsl::ut_scenario{"map 2m adjacent 1g"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                root_page_table_t mut_rpt{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                bsl::dontcare_t mut_sys{};
                constexpr auto virt{0x200000_umx};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_rpt.initialize(mut_tls, mut_page_pool));
                    bsl::ut_required_step(
                        mut_rpt.map<l2e_t>(mut_tls, mut_page_pool, {}, {}, {}, {}, mut_sys));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            !mut_rpt.map<l0e_t>(mut_tls, mut_page_pool, virt, {}, {}, {}, mut_sys));
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        mut_rpt.release(mut_tls, mut_page_pool);
                    };
                };
            };
        };

        bsl::ut_scenario{"map 4k reserved l3e"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                root_page_table_t mut_rpt{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                bsl::dontcare_t mut_sys{};
                helpers::l3t_t l3t{};
                constexpr auto phys{0x000FFFFF00000000_u64};
                bsl::ut_when{} = [&]() noexcept {
                    mut_page_pool.set_allocate<helpers::l3t_t>(&l3t, phys);
                    bsl::ut_required_step(mut_rpt.initialize(mut_tls, mut_page_pool));
                    l3t.entries.front().alias = bsl::safe_u64::magic_1().get();
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            !mut_rpt.map<l0e_t>(mut_tls, mut_page_pool, {}, {}, {}, {}, mut_sys));
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        l3t.entries.front().alias = {};
                        mut_rpt.release(mut_tls, mut_page_pool);
                    };
                };
            };
        };

        bsl::ut_scenario{"map 2m reserved l3e"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                root_page_table_t mut_rpt{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                bsl::dontcare_t mut_sys{};
                helpers::l3t_t l3t{};
                constexpr auto phys{0x000FFFFF00000000_u64};
                bsl::ut_when{} = [&]() noexcept {
                    mut_page_pool.set_allocate<helpers::l3t_t>(&l3t, phys);
                    bsl::ut_required_step(mut_rpt.initialize(mut_tls, mut_page_pool));
                    l3t.entries.front().alias = bsl::safe_u64::magic_1().get();
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            !mut_rpt.map<l1e_t>(mut_tls, mut_page_pool, {}, {}, {}, {}, mut_sys));
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        l3t.entries.front().alias = {};
                        mut_rpt.release(mut_tls, mut_page_pool);
                    };
                };
            };
        };

        bsl::ut_scenario{"map 1g reserved l3e"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                root_page_table_t mut_rpt{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                bsl::dontcare_t mut_sys{};
                helpers::l3t_t l3t{};
                constexpr auto phys{0x000FFFFF00000000_u64};
                bsl::ut_when{} = [&]() noexcept {
                    mut_page_pool.set_allocate<helpers::l3t_t>(&l3t, phys);
                    bsl::ut_required_step(mut_rpt.initialize(mut_tls, mut_page_pool));
                    l3t.entries.front().alias = bsl::safe_u64::magic_1().get();
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            !mut_rpt.map<l2e_t>(mut_tls, mut_page_pool, {}, {}, {}, {}, mut_sys));
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        l3t.entries.front().alias = {};
                        mut_rpt.release(mut_tls, mut_page_pool);
                    };
                };
            };
        };

        bsl::ut_scenario{"map 4k reserved l2e"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                root_page_table_t mut_rpt{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                bsl::dontcare_t mut_sys{};
                helpers::l2t_t l2t{};
                constexpr auto phys{0x000FFFFF00000000_u64};
                bsl::ut_when{} = [&]() noexcept {
                    mut_page_pool.set_allocate<helpers::l2t_t>(&l2t, phys);
                    bsl::ut_required_step(mut_rpt.initialize(mut_tls, mut_page_pool));
                    l2t.entries.front().alias = bsl::safe_u64::magic_1().get();
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            !mut_rpt.map<l0e_t>(mut_tls, mut_page_pool, {}, {}, {}, {}, mut_sys));
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        l2t.entries.front().alias = {};
                        mut_rpt.release(mut_tls, mut_page_pool);
                    };
                };
            };
        };

        bsl::ut_scenario{"map 2m reserved l2e"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                root_page_table_t mut_rpt{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                bsl::dontcare_t mut_sys{};
                helpers::l2t_t l2t{};
                constexpr auto phys{0x000FFFFF00000000_u64};
                bsl::ut_when{} = [&]() noexcept {
                    mut_page_pool.set_allocate<helpers::l2t_t>(&l2t, phys);
                    bsl::ut_required_step(mut_rpt.initialize(mut_tls, mut_page_pool));
                    l2t.entries.front().alias = bsl::safe_u64::magic_1().get();
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            !mut_rpt.map<l1e_t>(mut_tls, mut_page_pool, {}, {}, {}, {}, mut_sys));
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        l2t.entries.front().alias = {};
                        mut_rpt.release(mut_tls, mut_page_pool);
                    };
                };
            };
        };

        bsl::ut_scenario{"map 1g reserved l2e"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                root_page_table_t mut_rpt{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                bsl::dontcare_t mut_sys{};
                helpers::l2t_t l2t{};
                constexpr auto phys{0x000FFFFF00000000_u64};
                bsl::ut_when{} = [&]() noexcept {
                    mut_page_pool.set_allocate<helpers::l2t_t>(&l2t, phys);
                    bsl::ut_required_step(mut_rpt.initialize(mut_tls, mut_page_pool));
                    l2t.entries.front().alias = bsl::safe_u64::magic_1().get();
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            !mut_rpt.map<l2e_t>(mut_tls, mut_page_pool, {}, {}, {}, {}, mut_sys));
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        l2t.entries.front().alias = {};
                        mut_rpt.release(mut_tls, mut_page_pool);
                    };
                };
            };
        };

        bsl::ut_scenario{"map 4k reserved l1e"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                root_page_table_t mut_rpt{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                bsl::dontcare_t mut_sys{};
                helpers::l1t_t l1t{};
                constexpr auto phys{0x000FFFFF00000000_u64};
                bsl::ut_when{} = [&]() noexcept {
                    mut_page_pool.set_allocate<helpers::l1t_t>(&l1t, phys);
                    bsl::ut_required_step(mut_rpt.initialize(mut_tls, mut_page_pool));
                    l1t.entries.front().alias = bsl::safe_u64::magic_1().get();
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            !mut_rpt.map<l0e_t>(mut_tls, mut_page_pool, {}, {}, {}, {}, mut_sys));
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        l1t.entries.front().alias = {};
                        mut_rpt.release(mut_tls, mut_page_pool);
                    };
                };
            };
        };

        bsl::ut_scenario{"map 2m reserved l1e"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                root_page_table_t mut_rpt{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                bsl::dontcare_t mut_sys{};
                helpers::l1t_t l1t{};
                constexpr auto phys{0x000FFFFF00000000_u64};
                bsl::ut_when{} = [&]() noexcept {
                    mut_page_pool.set_allocate<helpers::l1t_t>(&l1t, phys);
                    bsl::ut_required_step(mut_rpt.initialize(mut_tls, mut_page_pool));
                    l1t.entries.front().alias = bsl::safe_u64::magic_1().get();
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            !mut_rpt.map<l1e_t>(mut_tls, mut_page_pool, {}, {}, {}, {}, mut_sys));
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        l1t.entries.front().alias = {};
                        mut_rpt.release(mut_tls, mut_page_pool);
                    };
                };
            };
        };

        bsl::ut_scenario{"map 4k reserved l0e"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                root_page_table_t mut_rpt{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                bsl::dontcare_t mut_sys{};
                helpers::l0t_t l0t{};
                constexpr auto phys{0x000FFFFF00000000_u64};
                bsl::ut_when{} = [&]() noexcept {
                    mut_page_pool.set_allocate<helpers::l0t_t>(&l0t, phys);
                    bsl::ut_required_step(mut_rpt.initialize(mut_tls, mut_page_pool));
                    l0t.entries.front().alias = bsl::safe_u64::magic_1().get();
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            !mut_rpt.map<l0e_t>(mut_tls, mut_page_pool, {}, {}, {}, {}, mut_sys));
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        l0t.entries.front().alias = {};
                        mut_rpt.release(mut_tls, mut_page_pool);
                    };
                };
            };
        };

        bsl::ut_scenario{"map 4k unknown l3e"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                root_page_table_t mut_rpt{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                bsl::dontcare_t mut_sys{};
                helpers::l3t_t l3t{};
                constexpr auto phys{0x000FFFFF00000000_u64};
                bsl::ut_when{} = [&]() noexcept {
                    mut_page_pool.set_allocate<helpers::l3t_t>(&l3t, phys);
                    bsl::ut_required_step(mut_rpt.initialize(mut_tls, mut_page_pool));
                    l3t.entries.front().u = bsl::safe_u64::magic_1().get();
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            !mut_rpt.map<l0e_t>(mut_tls, mut_page_pool, {}, {}, {}, {}, mut_sys));
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        l3t.entries.front().u = {};
                        mut_rpt.release(mut_tls, mut_page_pool);
                    };
                };
            };
        };

        bsl::ut_scenario{"map 2m unknown l3e"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                root_page_table_t mut_rpt{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                bsl::dontcare_t mut_sys{};
                helpers::l3t_t l3t{};
                constexpr auto phys{0x000FFFFF00000000_u64};
                bsl::ut_when{} = [&]() noexcept {
                    mut_page_pool.set_allocate<helpers::l3t_t>(&l3t, phys);
                    bsl::ut_required_step(mut_rpt.initialize(mut_tls, mut_page_pool));
                    l3t.entries.front().u = bsl::safe_u64::magic_1().get();
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            !mut_rpt.map<l1e_t>(mut_tls, mut_page_pool, {}, {}, {}, {}, mut_sys));
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        l3t.entries.front().u = {};
                        mut_rpt.release(mut_tls, mut_page_pool);
                    };
                };
            };
        };

        bsl::ut_scenario{"map 1g unknown l3e"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                root_page_table_t mut_rpt{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                bsl::dontcare_t mut_sys{};
                helpers::l3t_t l3t{};
                constexpr auto phys{0x000FFFFF00000000_u64};
                bsl::ut_when{} = [&]() noexcept {
                    mut_page_pool.set_allocate<helpers::l3t_t>(&l3t, phys);
                    bsl::ut_required_step(mut_rpt.initialize(mut_tls, mut_page_pool));
                    l3t.entries.front().u = bsl::safe_u64::magic_1().get();
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            !mut_rpt.map<l2e_t>(mut_tls, mut_page_pool, {}, {}, {}, {}, mut_sys));
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        l3t.entries.front().u = {};
                        mut_rpt.release(mut_tls, mut_page_pool);
                    };
                };
            };
        };

        bsl::ut_scenario{"map 4k unknown l2e"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                root_page_table_t mut_rpt{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                bsl::dontcare_t mut_sys{};
                helpers::l2t_t l2t{};
                constexpr auto phys{0x000FFFFF00000000_u64};
                bsl::ut_when{} = [&]() noexcept {
                    mut_page_pool.set_allocate<helpers::l2t_t>(&l2t, phys);
                    bsl::ut_required_step(mut_rpt.initialize(mut_tls, mut_page_pool));
                    l2t.entries.front().u = bsl::safe_u64::magic_1().get();
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            !mut_rpt.map<l0e_t>(mut_tls, mut_page_pool, {}, {}, {}, {}, mut_sys));
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        l2t.entries.front().u = {};
                        mut_rpt.release(mut_tls, mut_page_pool);
                    };
                };
            };
        };

        bsl::ut_scenario{"map 2m unknown l2e"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                root_page_table_t mut_rpt{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                bsl::dontcare_t mut_sys{};
                helpers::l2t_t l2t{};
                constexpr auto phys{0x000FFFFF00000000_u64};
                bsl::ut_when{} = [&]() noexcept {
                    mut_page_pool.set_allocate<helpers::l2t_t>(&l2t, phys);
                    bsl::ut_required_step(mut_rpt.initialize(mut_tls, mut_page_pool));
                    l2t.entries.front().u = bsl::safe_u64::magic_1().get();
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            !mut_rpt.map<l1e_t>(mut_tls, mut_page_pool, {}, {}, {}, {}, mut_sys));
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        l2t.entries.front().u = {};
                        mut_rpt.release(mut_tls, mut_page_pool);
                    };
                };
            };
        };

        bsl::ut_scenario{"map 1g unknown l2e"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                root_page_table_t mut_rpt{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                bsl::dontcare_t mut_sys{};
                helpers::l2t_t l2t{};
                constexpr auto phys{0x000FFFFF00000000_u64};
                bsl::ut_when{} = [&]() noexcept {
                    mut_page_pool.set_allocate<helpers::l2t_t>(&l2t, phys);
                    bsl::ut_required_step(mut_rpt.initialize(mut_tls, mut_page_pool));
                    l2t.entries.front().u = bsl::safe_u64::magic_1().get();
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            !mut_rpt.map<l2e_t>(mut_tls, mut_page_pool, {}, {}, {}, {}, mut_sys));
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        l2t.entries.front().u = {};
                        mut_rpt.release(mut_tls, mut_page_pool);
                    };
                };
            };
        };

        bsl::ut_scenario{"map 4k unknown l1e"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                root_page_table_t mut_rpt{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                bsl::dontcare_t mut_sys{};
                helpers::l1t_t l1t{};
                constexpr auto phys{0x000FFFFF00000000_u64};
                bsl::ut_when{} = [&]() noexcept {
                    mut_page_pool.set_allocate<helpers::l1t_t>(&l1t, phys);
                    bsl::ut_required_step(mut_rpt.initialize(mut_tls, mut_page_pool));
                    l1t.entries.front().u = bsl::safe_u64::magic_1().get();
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            !mut_rpt.map<l0e_t>(mut_tls, mut_page_pool, {}, {}, {}, {}, mut_sys));
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        l1t.entries.front().u = {};
                        mut_rpt.release(mut_tls, mut_page_pool);
                    };
                };
            };
        };

        bsl::ut_scenario{"map 2m unknown l1e"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                root_page_table_t mut_rpt{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                bsl::dontcare_t mut_sys{};
                helpers::l1t_t l1t{};
                constexpr auto phys{0x000FFFFF00000000_u64};
                bsl::ut_when{} = [&]() noexcept {
                    mut_page_pool.set_allocate<helpers::l1t_t>(&l1t, phys);
                    bsl::ut_required_step(mut_rpt.initialize(mut_tls, mut_page_pool));
                    l1t.entries.front().u = bsl::safe_u64::magic_1().get();
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            !mut_rpt.map<l1e_t>(mut_tls, mut_page_pool, {}, {}, {}, {}, mut_sys));
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        l1t.entries.front().u = {};
                        mut_rpt.release(mut_tls, mut_page_pool);
                    };
                };
            };
        };

        bsl::ut_scenario{"map 4k unknown l0e"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                root_page_table_t mut_rpt{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                bsl::dontcare_t mut_sys{};
                helpers::l0t_t l0t{};
                constexpr auto phys{0x000FFFFF00000000_u64};
                bsl::ut_when{} = [&]() noexcept {
                    mut_page_pool.set_allocate<helpers::l0t_t>(&l0t, phys);
                    bsl::ut_required_step(mut_rpt.initialize(mut_tls, mut_page_pool));
                    l0t.entries.front().u = bsl::safe_u64::magic_1().get();
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            !mut_rpt.map<l0e_t>(mut_tls, mut_page_pool, {}, {}, {}, {}, mut_sys));
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        l0t.entries.front().u = {};
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
                constexpr auto virt{0x0_u64};
                constexpr auto flgs{0x0_u64};
                bsl::dontcare_t mut_sys{};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_rpt.initialize(mut_tls, mut_page_pool));
                    bsl::ut_required_step(
                        nullptr != mut_rpt.allocate_page<basic_page_4k_t>(
                                       mut_tls, mut_page_pool, virt, flgs, mut_sys));
                    auto const ents{mut_rpt.entries<l0e_t>(mut_tls, mut_page_pool, {})};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(nullptr != ents.l0e);
                        bsl::ut_check(ents.l0e->auto_release == enabled);
                        bsl::ut_check(ents.l0e->points_to_block == enabled);
                        bsl::ut_check(ents.l0e->alias == disabled);
                        bsl::ut_check(ents.l0e->explicit_unmap == disabled);
                        bsl::ut_check(nullptr != ents.l1e);
                        bsl::ut_check(ents.l1e->auto_release == disabled);
                        bsl::ut_check(ents.l1e->points_to_block == disabled);
                        bsl::ut_check(ents.l1e->alias == disabled);
                        bsl::ut_check(ents.l1e->explicit_unmap == disabled);
                        bsl::ut_check(nullptr != ents.l2e);
                        bsl::ut_check(ents.l2e->auto_release == disabled);
                        bsl::ut_check(ents.l2e->points_to_block == disabled);
                        bsl::ut_check(ents.l2e->alias == disabled);
                        bsl::ut_check(ents.l2e->explicit_unmap == disabled);
                        bsl::ut_check(nullptr != ents.l3e);
                        bsl::ut_check(ents.l3e->auto_release == disabled);
                        bsl::ut_check(ents.l3e->points_to_block == disabled);
                        bsl::ut_check(ents.l3e->alias == disabled);
                        bsl::ut_check(ents.l3e->explicit_unmap == disabled);
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        mut_rpt.release(mut_tls, mut_page_pool);
                    };
                };
            };
        };

        bsl::ut_scenario{"allocate_page allocation fails"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                root_page_table_t mut_rpt{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                constexpr auto virt{0x0_u64};
                constexpr auto phys{0x1000_u64};
                constexpr auto flgs{0x0_u64};
                bsl::dontcare_t mut_sys{};
                bsl::ut_when{} = [&]() noexcept {
                    mut_page_pool.set_allocate<basic_page_4k_t>(nullptr, phys);
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

        bsl::ut_scenario{"allocate_page add_table (l2t_t) fails"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                root_page_table_t mut_rpt{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                constexpr auto virt{0x0_u64};
                constexpr auto phys{0x1000_u64};
                constexpr auto flgs{0x0_u64};
                bsl::dontcare_t mut_sys{};
                bsl::ut_when{} = [&]() noexcept {
                    mut_page_pool.set_allocate<helpers::l2t_t>(nullptr, phys);
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

        bsl::ut_scenario{"allocate_page add_table (l1t_t) fails"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                root_page_table_t mut_rpt{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                constexpr auto virt{0x0_u64};
                constexpr auto phys{0x1000_u64};
                constexpr auto flgs{0x0_u64};
                bsl::dontcare_t mut_sys{};
                bsl::ut_when{} = [&]() noexcept {
                    mut_page_pool.set_allocate<helpers::l1t_t>(nullptr, phys);
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

        bsl::ut_scenario{"allocate_page add_table (l0t_t) fails"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                root_page_table_t mut_rpt{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                constexpr auto virt{0x0_u64};
                constexpr auto phys{0x1000_u64};
                constexpr auto flgs{0x0_u64};
                bsl::dontcare_t mut_sys{};
                bsl::ut_when{} = [&]() noexcept {
                    mut_page_pool.set_allocate<helpers::l0t_t>(nullptr, phys);
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

        bsl::ut_scenario{"allocate_page twice"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                root_page_table_t mut_rpt{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                constexpr auto virt{0x0_u64};
                constexpr auto flgs{0x0_u64};
                bsl::dontcare_t mut_sys{};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_rpt.initialize(mut_tls, mut_page_pool));
                    bsl::ut_required_step(
                        nullptr != mut_rpt.allocate_page<basic_page_4k_t>(
                                       mut_tls, mut_page_pool, virt, flgs, mut_sys));
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
                    auto const ents{mut_rpt.entries<l0e_t>(mut_tls, mut_page_pool, page.virt)};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(nullptr != ents.l0e);
                        bsl::ut_check(ents.l0e->auto_release == enabled);
                        bsl::ut_check(ents.l0e->points_to_block == enabled);
                        bsl::ut_check(ents.l0e->alias == disabled);
                        bsl::ut_check(ents.l0e->explicit_unmap == disabled);
                        bsl::ut_check(nullptr != ents.l1e);
                        bsl::ut_check(ents.l1e->auto_release == disabled);
                        bsl::ut_check(ents.l1e->points_to_block == disabled);
                        bsl::ut_check(ents.l1e->alias == disabled);
                        bsl::ut_check(ents.l1e->explicit_unmap == disabled);
                        bsl::ut_check(nullptr != ents.l2e);
                        bsl::ut_check(ents.l2e->auto_release == disabled);
                        bsl::ut_check(ents.l2e->points_to_block == disabled);
                        bsl::ut_check(ents.l2e->alias == disabled);
                        bsl::ut_check(ents.l2e->explicit_unmap == disabled);
                        bsl::ut_check(nullptr != ents.l3e);
                        bsl::ut_check(ents.l3e->auto_release == disabled);
                        bsl::ut_check(ents.l3e->points_to_block == disabled);
                        bsl::ut_check(ents.l3e->alias == disabled);
                        bsl::ut_check(ents.l3e->explicit_unmap == disabled);
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        mut_rpt.release(mut_tls, mut_page_pool);
                    };
                };
            };
        };

        bsl::ut_scenario{"allocate_page<offset> allocation fails"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                root_page_table_t mut_rpt{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                constexpr auto offs{0x1000_u64};
                constexpr auto phys{0x1000_u64};
                bsl::dontcare_t mut_sys{};
                bsl::ut_when{} = [&]() noexcept {
                    mut_page_pool.set_allocate<basic_page_4k_t>(nullptr, phys);
                    bsl::ut_required_step(mut_rpt.initialize(mut_tls, mut_page_pool));
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

        bsl::ut_scenario{"allocate_page<offset> add_table (l2t_t) fails"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                root_page_table_t mut_rpt{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                constexpr auto offs{0x1000_u64};
                constexpr auto phys{0x1000_u64};
                bsl::dontcare_t mut_sys{};
                bsl::ut_when{} = [&]() noexcept {
                    mut_page_pool.set_allocate<helpers::l2t_t>(nullptr, phys);
                    bsl::ut_required_step(mut_rpt.initialize(mut_tls, mut_page_pool));
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

        bsl::ut_scenario{"allocate_page<offset> add_table (l1t_t) fails"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                root_page_table_t mut_rpt{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                constexpr auto offs{0x1000_u64};
                constexpr auto phys{0x1000_u64};
                bsl::dontcare_t mut_sys{};
                bsl::ut_when{} = [&]() noexcept {
                    mut_page_pool.set_allocate<helpers::l1t_t>(nullptr, phys);
                    bsl::ut_required_step(mut_rpt.initialize(mut_tls, mut_page_pool));
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

        bsl::ut_scenario{"allocate_page<offset> add_table (l0t_t) fails"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                root_page_table_t mut_rpt{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                constexpr auto offs{0x1000_u64};
                constexpr auto phys{0x1000_u64};
                bsl::dontcare_t mut_sys{};
                bsl::ut_when{} = [&]() noexcept {
                    mut_page_pool.set_allocate<helpers::l0t_t>(nullptr, phys);
                    bsl::ut_required_step(mut_rpt.initialize(mut_tls, mut_page_pool));
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

        bsl::ut_scenario{"unmap 4k"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                root_page_table_t mut_rpt{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                bsl::dontcare_t mut_sys{};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_rpt.initialize(mut_tls, mut_page_pool));
                    bsl::ut_required_step(
                        mut_rpt.map<l0e_t>(mut_tls, mut_page_pool, {}, {}, {}, {}, mut_sys));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_rpt.unmap<l0e_t>(mut_tls, mut_page_pool, {}));
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        mut_rpt.release(mut_tls, mut_page_pool);
                    };
                };
            };
        };

        bsl::ut_scenario{"unmap 2m"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                root_page_table_t mut_rpt{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                bsl::dontcare_t mut_sys{};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_rpt.initialize(mut_tls, mut_page_pool));
                    bsl::ut_required_step(
                        mut_rpt.map<l1e_t>(mut_tls, mut_page_pool, {}, {}, {}, {}, mut_sys));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_rpt.unmap<l1e_t>(mut_tls, mut_page_pool, {}));
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        mut_rpt.release(mut_tls, mut_page_pool);
                    };
                };
            };
        };

        bsl::ut_scenario{"unmap 1g"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                root_page_table_t mut_rpt{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                bsl::dontcare_t mut_sys{};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_rpt.initialize(mut_tls, mut_page_pool));
                    bsl::ut_required_step(
                        mut_rpt.map<l2e_t>(mut_tls, mut_page_pool, {}, {}, {}, {}, mut_sys));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_rpt.unmap<l2e_t>(mut_tls, mut_page_pool, {}));
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        mut_rpt.release(mut_tls, mut_page_pool);
                    };
                };
            };
        };

        bsl::ut_scenario{"unmap allocated 4k"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                root_page_table_t mut_rpt{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                bsl::dontcare_t mut_sys{};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_rpt.initialize(mut_tls, mut_page_pool));
                    bsl::ut_required_step(
                        nullptr != mut_rpt.allocate_page<basic_page_4k_t>(
                                       mut_tls, mut_page_pool, {}, {}, mut_sys));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_rpt.unmap<l0e_t>(mut_tls, mut_page_pool, {}));
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        mut_rpt.release(mut_tls, mut_page_pool);
                    };
                };
            };
        };

        bsl::ut_scenario{"unmap 1 of 2 4k"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                root_page_table_t mut_rpt{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                bsl::dontcare_t mut_sys{};
                constexpr auto virt0{0x0000_u64};
                constexpr auto virt1{0x1000_u64};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_rpt.initialize(mut_tls, mut_page_pool));
                    bsl::ut_required_step(
                        mut_rpt.map<l0e_t>(mut_tls, mut_page_pool, virt0, {}, {}, {}, mut_sys));
                    bsl::ut_required_step(
                        mut_rpt.map<l0e_t>(mut_tls, mut_page_pool, virt1, {}, {}, {}, mut_sys));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_rpt.unmap<l0e_t>(mut_tls, mut_page_pool, {}));
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        mut_rpt.release(mut_tls, mut_page_pool);
                    };
                };
            };
        };

        bsl::ut_scenario{"unmap 1 of 2 2m"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                root_page_table_t mut_rpt{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                bsl::dontcare_t mut_sys{};
                constexpr auto virt0{0x000000_u64};
                constexpr auto virt1{0x200000_u64};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_rpt.initialize(mut_tls, mut_page_pool));
                    bsl::ut_required_step(
                        mut_rpt.map<l1e_t>(mut_tls, mut_page_pool, virt0, {}, {}, {}, mut_sys));
                    bsl::ut_required_step(
                        mut_rpt.map<l1e_t>(mut_tls, mut_page_pool, virt1, {}, {}, {}, mut_sys));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_rpt.unmap<l1e_t>(mut_tls, mut_page_pool, {}));
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        mut_rpt.release(mut_tls, mut_page_pool);
                    };
                };
            };
        };

        bsl::ut_scenario{"unmap 1 of 2 1g"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                root_page_table_t mut_rpt{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                bsl::dontcare_t mut_sys{};
                constexpr auto virt0{0x00000000_u64};
                constexpr auto virt1{0x40000000_umx};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_rpt.initialize(mut_tls, mut_page_pool));
                    bsl::ut_required_step(
                        mut_rpt.map<l2e_t>(mut_tls, mut_page_pool, virt0, {}, {}, {}, mut_sys));
                    bsl::ut_required_step(
                        mut_rpt.map<l2e_t>(mut_tls, mut_page_pool, virt1, {}, {}, {}, mut_sys));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_rpt.unmap<l2e_t>(mut_tls, mut_page_pool, {}));
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        mut_rpt.release(mut_tls, mut_page_pool);
                    };
                };
            };
        };

        bsl::ut_scenario{"map 4k, unmap 1g"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                root_page_table_t mut_rpt{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                bsl::dontcare_t mut_sys{};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_rpt.initialize(mut_tls, mut_page_pool));
                    bsl::ut_required_step(
                        mut_rpt.map<l0e_t>(mut_tls, mut_page_pool, {}, {}, {}, {}, mut_sys));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(!mut_rpt.unmap<l2e_t>(mut_tls, mut_page_pool, {}));
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        mut_rpt.release(mut_tls, mut_page_pool);
                    };
                };
            };
        };

        bsl::ut_scenario{"map 4k, unmap 2m"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                root_page_table_t mut_rpt{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                bsl::dontcare_t mut_sys{};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_rpt.initialize(mut_tls, mut_page_pool));
                    bsl::ut_required_step(
                        mut_rpt.map<l0e_t>(mut_tls, mut_page_pool, {}, {}, {}, {}, mut_sys));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(!mut_rpt.unmap<l2e_t>(mut_tls, mut_page_pool, {}));
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        mut_rpt.release(mut_tls, mut_page_pool);
                    };
                };
            };
        };

        bsl::ut_scenario{"map 2m, unmap 1g"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                root_page_table_t mut_rpt{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                bsl::dontcare_t mut_sys{};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_rpt.initialize(mut_tls, mut_page_pool));
                    bsl::ut_required_step(
                        mut_rpt.map<l1e_t>(mut_tls, mut_page_pool, {}, {}, {}, {}, mut_sys));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(!mut_rpt.unmap<l2e_t>(mut_tls, mut_page_pool, {}));
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        mut_rpt.release(mut_tls, mut_page_pool);
                    };
                };
            };
        };

        bsl::ut_scenario{"map 2m, unmap 4k"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                root_page_table_t mut_rpt{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                bsl::dontcare_t mut_sys{};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_rpt.initialize(mut_tls, mut_page_pool));
                    bsl::ut_required_step(
                        mut_rpt.map<l1e_t>(mut_tls, mut_page_pool, {}, {}, {}, {}, mut_sys));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(!mut_rpt.unmap<l0e_t>(mut_tls, mut_page_pool, {}));
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        mut_rpt.release(mut_tls, mut_page_pool);
                    };
                };
            };
        };

        bsl::ut_scenario{"map 1g, unmap 2m"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                root_page_table_t mut_rpt{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                bsl::dontcare_t mut_sys{};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_rpt.initialize(mut_tls, mut_page_pool));
                    bsl::ut_required_step(
                        mut_rpt.map<l2e_t>(mut_tls, mut_page_pool, {}, {}, {}, {}, mut_sys));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(!mut_rpt.unmap<l1e_t>(mut_tls, mut_page_pool, {}));
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        mut_rpt.release(mut_tls, mut_page_pool);
                    };
                };
            };
        };

        bsl::ut_scenario{"map 1g, unmap 4k"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                root_page_table_t mut_rpt{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                bsl::dontcare_t mut_sys{};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_rpt.initialize(mut_tls, mut_page_pool));
                    bsl::ut_required_step(
                        mut_rpt.map<l2e_t>(mut_tls, mut_page_pool, {}, {}, {}, {}, mut_sys));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(!mut_rpt.unmap<l0e_t>(mut_tls, mut_page_pool, {}));
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        mut_rpt.release(mut_tls, mut_page_pool);
                    };
                };
            };
        };

        bsl::ut_scenario{"unmap never mapped 4k"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                root_page_table_t mut_rpt{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_rpt.initialize(mut_tls, mut_page_pool));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(!mut_rpt.unmap<l0e_t>(mut_tls, mut_page_pool, {}));
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        mut_rpt.release(mut_tls, mut_page_pool);
                    };
                };
            };
        };

        bsl::ut_scenario{"unmap never mapped 2m"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                root_page_table_t mut_rpt{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_rpt.initialize(mut_tls, mut_page_pool));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(!mut_rpt.unmap<l1e_t>(mut_tls, mut_page_pool, {}));
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        mut_rpt.release(mut_tls, mut_page_pool);
                    };
                };
            };
        };

        bsl::ut_scenario{"unmap never mapped 1g"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                root_page_table_t mut_rpt{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_rpt.initialize(mut_tls, mut_page_pool));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(!mut_rpt.unmap<l2e_t>(mut_tls, mut_page_pool, {}));
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        mut_rpt.release(mut_tls, mut_page_pool);
                    };
                };
            };
        };

        bsl::ut_scenario{"entries 4k"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                root_page_table_t mut_rpt{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                bsl::dontcare_t mut_sys{};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_rpt.initialize(mut_tls, mut_page_pool));
                    bsl::ut_required_step(
                        mut_rpt.map<l0e_t>(mut_tls, mut_page_pool, {}, {}, {}, {}, mut_sys));
                    auto const ents{mut_rpt.entries<l0e_t>(mut_tls, mut_page_pool, {})};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(nullptr != ents.l3e);
                        bsl::ut_check(nullptr != ents.l2e);
                        bsl::ut_check(nullptr != ents.l1e);
                        bsl::ut_check(nullptr != ents.l0e);
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        mut_rpt.release(mut_tls, mut_page_pool);
                    };
                };
            };
        };

        bsl::ut_scenario{"entries 2m"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                root_page_table_t mut_rpt{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                bsl::dontcare_t mut_sys{};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_rpt.initialize(mut_tls, mut_page_pool));
                    bsl::ut_required_step(
                        mut_rpt.map<l1e_t>(mut_tls, mut_page_pool, {}, {}, {}, {}, mut_sys));
                    auto const ents{mut_rpt.entries<l1e_t>(mut_tls, mut_page_pool, {})};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(nullptr != ents.l3e);
                        bsl::ut_check(nullptr != ents.l2e);
                        bsl::ut_check(nullptr != ents.l1e);
                        bsl::ut_check(nullptr == ents.l0e);
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        mut_rpt.release(mut_tls, mut_page_pool);
                    };
                };
            };
        };

        bsl::ut_scenario{"entries 1g"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                root_page_table_t mut_rpt{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                bsl::dontcare_t mut_sys{};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_rpt.initialize(mut_tls, mut_page_pool));
                    bsl::ut_required_step(
                        mut_rpt.map<l2e_t>(mut_tls, mut_page_pool, {}, {}, {}, {}, mut_sys));
                    auto const ents{mut_rpt.entries<l2e_t>(mut_tls, mut_page_pool, {})};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(nullptr != ents.l3e);
                        bsl::ut_check(nullptr != ents.l2e);
                        bsl::ut_check(nullptr == ents.l1e);
                        bsl::ut_check(nullptr == ents.l0e);
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        mut_rpt.release(mut_tls, mut_page_pool);
                    };
                };
            };
        };

        bsl::ut_scenario{"entries map 4k, get 1g"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                root_page_table_t mut_rpt{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                bsl::dontcare_t mut_sys{};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_rpt.initialize(mut_tls, mut_page_pool));
                    bsl::ut_required_step(
                        mut_rpt.map<l0e_t>(mut_tls, mut_page_pool, {}, {}, {}, {}, mut_sys));
                    auto const ents{mut_rpt.entries<l2e_t>(mut_tls, mut_page_pool, {})};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(nullptr == ents.l3e);
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        mut_rpt.release(mut_tls, mut_page_pool);
                    };
                };
            };
        };

        bsl::ut_scenario{"entries map 4k, get 2m"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                root_page_table_t mut_rpt{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                bsl::dontcare_t mut_sys{};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_rpt.initialize(mut_tls, mut_page_pool));
                    bsl::ut_required_step(
                        mut_rpt.map<l0e_t>(mut_tls, mut_page_pool, {}, {}, {}, {}, mut_sys));
                    auto const ents{mut_rpt.entries<l1e_t>(mut_tls, mut_page_pool, {})};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(nullptr == ents.l3e);
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        mut_rpt.release(mut_tls, mut_page_pool);
                    };
                };
            };
        };

        bsl::ut_scenario{"entries map 2m, get 1g"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                root_page_table_t mut_rpt{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                bsl::dontcare_t mut_sys{};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_rpt.initialize(mut_tls, mut_page_pool));
                    bsl::ut_required_step(
                        mut_rpt.map<l1e_t>(mut_tls, mut_page_pool, {}, {}, {}, {}, mut_sys));
                    auto const ents{mut_rpt.entries<l2e_t>(mut_tls, mut_page_pool, {})};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(nullptr == ents.l3e);
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        mut_rpt.release(mut_tls, mut_page_pool);
                    };
                };
            };
        };

        bsl::ut_scenario{"entries map 2m, get 4k"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                root_page_table_t mut_rpt{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                bsl::dontcare_t mut_sys{};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_rpt.initialize(mut_tls, mut_page_pool));
                    bsl::ut_required_step(
                        mut_rpt.map<l1e_t>(mut_tls, mut_page_pool, {}, {}, {}, {}, mut_sys));
                    auto const ents{mut_rpt.entries<l0e_t>(mut_tls, mut_page_pool, {})};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(nullptr == ents.l3e);
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        mut_rpt.release(mut_tls, mut_page_pool);
                    };
                };
            };
        };

        bsl::ut_scenario{"entries map 1g, get 2m"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                root_page_table_t mut_rpt{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                bsl::dontcare_t mut_sys{};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_rpt.initialize(mut_tls, mut_page_pool));
                    bsl::ut_required_step(
                        mut_rpt.map<l2e_t>(mut_tls, mut_page_pool, {}, {}, {}, {}, mut_sys));
                    auto const ents{mut_rpt.entries<l1e_t>(mut_tls, mut_page_pool, {})};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(nullptr == ents.l3e);
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        mut_rpt.release(mut_tls, mut_page_pool);
                    };
                };
            };
        };

        bsl::ut_scenario{"entries map 1g, get 4k"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                root_page_table_t mut_rpt{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                bsl::dontcare_t mut_sys{};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_rpt.initialize(mut_tls, mut_page_pool));
                    bsl::ut_required_step(
                        mut_rpt.map<l2e_t>(mut_tls, mut_page_pool, {}, {}, {}, {}, mut_sys));
                    auto const ents{mut_rpt.entries<l0e_t>(mut_tls, mut_page_pool, {})};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(nullptr == ents.l3e);
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        mut_rpt.release(mut_tls, mut_page_pool);
                    };
                };
            };
        };

        bsl::ut_scenario{"entries 4k never mapped"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                root_page_table_t mut_rpt{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_rpt.initialize(mut_tls, mut_page_pool));
                    auto const ents{mut_rpt.entries<l0e_t>(mut_tls, mut_page_pool, {})};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(nullptr == ents.l3e);
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        mut_rpt.release(mut_tls, mut_page_pool);
                    };
                };
            };
        };

        bsl::ut_scenario{"entries 2m never mapped"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                root_page_table_t mut_rpt{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_rpt.initialize(mut_tls, mut_page_pool));
                    auto const ents{mut_rpt.entries<l1e_t>(mut_tls, mut_page_pool, {})};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(nullptr == ents.l3e);
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        mut_rpt.release(mut_tls, mut_page_pool);
                    };
                };
            };
        };

        bsl::ut_scenario{"entries 1g never mapped"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                root_page_table_t mut_rpt{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_rpt.initialize(mut_tls, mut_page_pool));
                    auto const ents{mut_rpt.entries<l2e_t>(mut_tls, mut_page_pool, {})};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(nullptr == ents.l3e);
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        mut_rpt.release(mut_tls, mut_page_pool);
                    };
                };
            };
        };

        bsl::ut_scenario{"entries map 4k adjacent, never mapped 4k"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                root_page_table_t mut_rpt{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                bsl::dontcare_t mut_sys{};
                constexpr auto virt{0x1000_u64};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_rpt.initialize(mut_tls, mut_page_pool));
                    bsl::ut_required_step(
                        mut_rpt.map<l0e_t>(mut_tls, mut_page_pool, {}, {}, {}, {}, mut_sys));
                    auto const ents{mut_rpt.entries<l0e_t>(mut_tls, mut_page_pool, virt)};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(nullptr == ents.l3e);
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        mut_rpt.release(mut_tls, mut_page_pool);
                    };
                };
            };
        };

        bsl::ut_scenario{"entries map 4k adjacent, never mapped 2m"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                root_page_table_t mut_rpt{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                bsl::dontcare_t mut_sys{};
                constexpr auto virt{0x200000_u64};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_rpt.initialize(mut_tls, mut_page_pool));
                    bsl::ut_required_step(
                        mut_rpt.map<l0e_t>(mut_tls, mut_page_pool, {}, {}, {}, {}, mut_sys));
                    auto const ents{mut_rpt.entries<l1e_t>(mut_tls, mut_page_pool, virt)};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(nullptr == ents.l3e);
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        mut_rpt.release(mut_tls, mut_page_pool);
                    };
                };
            };
        };

        bsl::ut_scenario{"entries map 4k adjacent, never mapped 1g"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                root_page_table_t mut_rpt{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                bsl::dontcare_t mut_sys{};
                constexpr auto virt{0x40000000_u64};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_rpt.initialize(mut_tls, mut_page_pool));
                    bsl::ut_required_step(
                        mut_rpt.map<l0e_t>(mut_tls, mut_page_pool, {}, {}, {}, {}, mut_sys));
                    auto const ents{mut_rpt.entries<l2e_t>(mut_tls, mut_page_pool, virt)};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(nullptr == ents.l3e);
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        mut_rpt.release(mut_tls, mut_page_pool);
                    };
                };
            };
        };

        bsl::ut_scenario{"entries map 2m adjacent, never mapped 4k"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                root_page_table_t mut_rpt{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                bsl::dontcare_t mut_sys{};
                constexpr auto virt{0x1000_u64};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_rpt.initialize(mut_tls, mut_page_pool));
                    bsl::ut_required_step(
                        mut_rpt.map<l1e_t>(mut_tls, mut_page_pool, {}, {}, {}, {}, mut_sys));
                    auto const ents{mut_rpt.entries<l0e_t>(mut_tls, mut_page_pool, virt)};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(nullptr == ents.l3e);
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        mut_rpt.release(mut_tls, mut_page_pool);
                    };
                };
            };
        };

        bsl::ut_scenario{"entries map 2m adjacent, never mapped 2m"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                root_page_table_t mut_rpt{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                bsl::dontcare_t mut_sys{};
                constexpr auto virt{0x200000_u64};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_rpt.initialize(mut_tls, mut_page_pool));
                    bsl::ut_required_step(
                        mut_rpt.map<l1e_t>(mut_tls, mut_page_pool, {}, {}, {}, {}, mut_sys));
                    auto const ents{mut_rpt.entries<l1e_t>(mut_tls, mut_page_pool, virt)};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(nullptr == ents.l3e);
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        mut_rpt.release(mut_tls, mut_page_pool);
                    };
                };
            };
        };

        bsl::ut_scenario{"entries map 2m adjacent, never mapped 1g"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                root_page_table_t mut_rpt{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                bsl::dontcare_t mut_sys{};
                constexpr auto virt{0x40000000_u64};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_rpt.initialize(mut_tls, mut_page_pool));
                    bsl::ut_required_step(
                        mut_rpt.map<l1e_t>(mut_tls, mut_page_pool, {}, {}, {}, {}, mut_sys));
                    auto const ents{mut_rpt.entries<l2e_t>(mut_tls, mut_page_pool, virt)};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(nullptr == ents.l3e);
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        mut_rpt.release(mut_tls, mut_page_pool);
                    };
                };
            };
        };

        bsl::ut_scenario{"entries map 1g adjacent, never mapped 4k"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                root_page_table_t mut_rpt{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                bsl::dontcare_t mut_sys{};
                constexpr auto virt{0x1000_u64};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_rpt.initialize(mut_tls, mut_page_pool));
                    bsl::ut_required_step(
                        mut_rpt.map<l2e_t>(mut_tls, mut_page_pool, {}, {}, {}, {}, mut_sys));
                    auto const ents{mut_rpt.entries<l0e_t>(mut_tls, mut_page_pool, virt)};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(nullptr == ents.l3e);
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        mut_rpt.release(mut_tls, mut_page_pool);
                    };
                };
            };
        };

        bsl::ut_scenario{"entries map 1g adjacent, never mapped 2m"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                root_page_table_t mut_rpt{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                bsl::dontcare_t mut_sys{};
                constexpr auto virt{0x200000_u64};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_rpt.initialize(mut_tls, mut_page_pool));
                    bsl::ut_required_step(
                        mut_rpt.map<l2e_t>(mut_tls, mut_page_pool, {}, {}, {}, {}, mut_sys));
                    auto const ents{mut_rpt.entries<l1e_t>(mut_tls, mut_page_pool, virt)};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(nullptr == ents.l3e);
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        mut_rpt.release(mut_tls, mut_page_pool);
                    };
                };
            };
        };

        bsl::ut_scenario{"entries map 1g adjacent, never mapped 1g"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                root_page_table_t mut_rpt{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                bsl::dontcare_t mut_sys{};
                constexpr auto virt{0x40000000_u64};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_rpt.initialize(mut_tls, mut_page_pool));
                    bsl::ut_required_step(
                        mut_rpt.map<l2e_t>(mut_tls, mut_page_pool, {}, {}, {}, {}, mut_sys));
                    auto const ents{mut_rpt.entries<l2e_t>(mut_tls, mut_page_pool, virt)};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(nullptr == ents.l3e);
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        mut_rpt.release(mut_tls, mut_page_pool);
                    };
                };
            };
        };

        bsl::ut_scenario{"entries map 4k adjacent (2m), never mapped 4k"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                root_page_table_t mut_rpt{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                bsl::dontcare_t mut_sys{};
                constexpr auto virt{0x200000_u64};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_rpt.initialize(mut_tls, mut_page_pool));
                    bsl::ut_required_step(
                        mut_rpt.map<l0e_t>(mut_tls, mut_page_pool, {}, {}, {}, {}, mut_sys));
                    auto const ents{mut_rpt.entries<l0e_t>(mut_tls, mut_page_pool, virt)};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(nullptr == ents.l3e);
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        mut_rpt.release(mut_tls, mut_page_pool);
                    };
                };
            };
        };

        bsl::ut_scenario{"entries map 4k adjacent (2m), never mapped 2m"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                root_page_table_t mut_rpt{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                bsl::dontcare_t mut_sys{};
                constexpr auto virt{0x200000_u64};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_rpt.initialize(mut_tls, mut_page_pool));
                    bsl::ut_required_step(
                        mut_rpt.map<l0e_t>(mut_tls, mut_page_pool, {}, {}, {}, {}, mut_sys));
                    auto const ents{mut_rpt.entries<l1e_t>(mut_tls, mut_page_pool, virt)};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(nullptr == ents.l3e);
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        mut_rpt.release(mut_tls, mut_page_pool);
                    };
                };
            };
        };

        bsl::ut_scenario{"entries map 4k adjacent (1g), never mapped 4k"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                root_page_table_t mut_rpt{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                bsl::dontcare_t mut_sys{};
                constexpr auto virt{0x40000000_u64};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_rpt.initialize(mut_tls, mut_page_pool));
                    bsl::ut_required_step(
                        mut_rpt.map<l0e_t>(mut_tls, mut_page_pool, {}, {}, {}, {}, mut_sys));
                    auto const ents{mut_rpt.entries<l0e_t>(mut_tls, mut_page_pool, virt)};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(nullptr == ents.l3e);
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        mut_rpt.release(mut_tls, mut_page_pool);
                    };
                };
            };
        };

        bsl::ut_scenario{"entries map 4k adjacent (1g), never mapped 2m"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                root_page_table_t mut_rpt{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                bsl::dontcare_t mut_sys{};
                constexpr auto virt{0x40000000_u64};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_rpt.initialize(mut_tls, mut_page_pool));
                    bsl::ut_required_step(
                        mut_rpt.map<l0e_t>(mut_tls, mut_page_pool, {}, {}, {}, {}, mut_sys));
                    auto const ents{mut_rpt.entries<l1e_t>(mut_tls, mut_page_pool, virt)};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(nullptr == ents.l3e);
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        mut_rpt.release(mut_tls, mut_page_pool);
                    };
                };
            };
        };

        bsl::ut_scenario{"entries map 4k adjacent (1g), never mapped 1g"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                root_page_table_t mut_rpt{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                bsl::dontcare_t mut_sys{};
                constexpr auto virt{0x40000000_u64};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_rpt.initialize(mut_tls, mut_page_pool));
                    bsl::ut_required_step(
                        mut_rpt.map<l0e_t>(mut_tls, mut_page_pool, {}, {}, {}, {}, mut_sys));
                    auto const ents{mut_rpt.entries<l2e_t>(mut_tls, mut_page_pool, virt)};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(nullptr == ents.l3e);
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        mut_rpt.release(mut_tls, mut_page_pool);
                    };
                };
            };
        };

        bsl::ut_scenario{"entries map 2m adjacent (2m), never mapped 4k"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                root_page_table_t mut_rpt{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                bsl::dontcare_t mut_sys{};
                constexpr auto virt{0x200000_u64};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_rpt.initialize(mut_tls, mut_page_pool));
                    bsl::ut_required_step(
                        mut_rpt.map<l1e_t>(mut_tls, mut_page_pool, {}, {}, {}, {}, mut_sys));
                    auto const ents{mut_rpt.entries<l0e_t>(mut_tls, mut_page_pool, virt)};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(nullptr == ents.l3e);
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        mut_rpt.release(mut_tls, mut_page_pool);
                    };
                };
            };
        };

        bsl::ut_scenario{"entries map 2m adjacent (2m), never mapped 2m"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                root_page_table_t mut_rpt{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                bsl::dontcare_t mut_sys{};
                constexpr auto virt{0x200000_u64};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_rpt.initialize(mut_tls, mut_page_pool));
                    bsl::ut_required_step(
                        mut_rpt.map<l1e_t>(mut_tls, mut_page_pool, {}, {}, {}, {}, mut_sys));
                    auto const ents{mut_rpt.entries<l1e_t>(mut_tls, mut_page_pool, virt)};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(nullptr == ents.l3e);
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        mut_rpt.release(mut_tls, mut_page_pool);
                    };
                };
            };
        };

        bsl::ut_scenario{"entries map 2m adjacent (1g), never mapped 4k"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                root_page_table_t mut_rpt{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                bsl::dontcare_t mut_sys{};
                constexpr auto virt{0x40000000_u64};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_rpt.initialize(mut_tls, mut_page_pool));
                    bsl::ut_required_step(
                        mut_rpt.map<l1e_t>(mut_tls, mut_page_pool, {}, {}, {}, {}, mut_sys));
                    auto const ents{mut_rpt.entries<l0e_t>(mut_tls, mut_page_pool, virt)};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(nullptr == ents.l3e);
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        mut_rpt.release(mut_tls, mut_page_pool);
                    };
                };
            };
        };

        bsl::ut_scenario{"entries map 2m adjacent (1g), never mapped 2m"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                root_page_table_t mut_rpt{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                bsl::dontcare_t mut_sys{};
                constexpr auto virt{0x40000000_u64};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_rpt.initialize(mut_tls, mut_page_pool));
                    bsl::ut_required_step(
                        mut_rpt.map<l1e_t>(mut_tls, mut_page_pool, {}, {}, {}, {}, mut_sys));
                    auto const ents{mut_rpt.entries<l1e_t>(mut_tls, mut_page_pool, virt)};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(nullptr == ents.l3e);
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        mut_rpt.release(mut_tls, mut_page_pool);
                    };
                };
            };
        };

        bsl::ut_scenario{"entries map 2m adjacent (1g), never mapped 1g"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                root_page_table_t mut_rpt{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                bsl::dontcare_t mut_sys{};
                constexpr auto virt{0x40000000_u64};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_rpt.initialize(mut_tls, mut_page_pool));
                    bsl::ut_required_step(
                        mut_rpt.map<l1e_t>(mut_tls, mut_page_pool, {}, {}, {}, {}, mut_sys));
                    auto const ents{mut_rpt.entries<l2e_t>(mut_tls, mut_page_pool, virt)};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(nullptr == ents.l3e);
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        mut_rpt.release(mut_tls, mut_page_pool);
                    };
                };
            };
        };

        bsl::ut_scenario{"entries map 1g adjacent (2m), never mapped 4k"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                root_page_table_t mut_rpt{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                bsl::dontcare_t mut_sys{};
                constexpr auto virt{0x200000_u64};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_rpt.initialize(mut_tls, mut_page_pool));
                    bsl::ut_required_step(
                        mut_rpt.map<l2e_t>(mut_tls, mut_page_pool, {}, {}, {}, {}, mut_sys));
                    auto const ents{mut_rpt.entries<l0e_t>(mut_tls, mut_page_pool, virt)};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(nullptr == ents.l3e);
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        mut_rpt.release(mut_tls, mut_page_pool);
                    };
                };
            };
        };

        bsl::ut_scenario{"entries map 1g adjacent (2m), never mapped 2m"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                root_page_table_t mut_rpt{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                bsl::dontcare_t mut_sys{};
                constexpr auto virt{0x200000_u64};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_rpt.initialize(mut_tls, mut_page_pool));
                    bsl::ut_required_step(
                        mut_rpt.map<l2e_t>(mut_tls, mut_page_pool, {}, {}, {}, {}, mut_sys));
                    auto const ents{mut_rpt.entries<l1e_t>(mut_tls, mut_page_pool, virt)};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(nullptr == ents.l3e);
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        mut_rpt.release(mut_tls, mut_page_pool);
                    };
                };
            };
        };

        bsl::ut_scenario{"entries map 1g adjacent (1g), never mapped 4k"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                root_page_table_t mut_rpt{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                bsl::dontcare_t mut_sys{};
                constexpr auto virt{0x40000000_u64};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_rpt.initialize(mut_tls, mut_page_pool));
                    bsl::ut_required_step(
                        mut_rpt.map<l2e_t>(mut_tls, mut_page_pool, {}, {}, {}, {}, mut_sys));
                    auto const ents{mut_rpt.entries<l0e_t>(mut_tls, mut_page_pool, virt)};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(nullptr == ents.l3e);
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        mut_rpt.release(mut_tls, mut_page_pool);
                    };
                };
            };
        };

        bsl::ut_scenario{"entries map 1g adjacent (1g), never mapped 2m"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                root_page_table_t mut_rpt{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                bsl::dontcare_t mut_sys{};
                constexpr auto virt{0x40000000_u64};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_rpt.initialize(mut_tls, mut_page_pool));
                    bsl::ut_required_step(
                        mut_rpt.map<l2e_t>(mut_tls, mut_page_pool, {}, {}, {}, {}, mut_sys));
                    auto const ents{mut_rpt.entries<l1e_t>(mut_tls, mut_page_pool, virt)};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(nullptr == ents.l3e);
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        mut_rpt.release(mut_tls, mut_page_pool);
                    };
                };
            };
        };

        bsl::ut_scenario{"entries map 1g adjacent (1g), never mapped 1g"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                root_page_table_t mut_rpt{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                bsl::dontcare_t mut_sys{};
                constexpr auto virt{0x40000000_u64};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_rpt.initialize(mut_tls, mut_page_pool));
                    bsl::ut_required_step(
                        mut_rpt.map<l2e_t>(mut_tls, mut_page_pool, {}, {}, {}, {}, mut_sys));
                    auto const ents{mut_rpt.entries<l2e_t>(mut_tls, mut_page_pool, virt)};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(nullptr == ents.l3e);
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        mut_rpt.release(mut_tls, mut_page_pool);
                    };
                };
            };
        };

        bsl::ut_scenario{"entries 4k reserved l3e"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                root_page_table_t mut_rpt{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                bsl::dontcare_t mut_sys{};
                helpers::l3t_t l3t{};
                constexpr auto phys{0x000FFFFF00000000_u64};
                bsl::ut_when{} = [&]() noexcept {
                    mut_page_pool.set_allocate<helpers::l3t_t>(&l3t, phys);
                    bsl::ut_required_step(mut_rpt.initialize(mut_tls, mut_page_pool));
                    bsl::ut_required_step(
                        mut_rpt.map<l0e_t>(mut_tls, mut_page_pool, {}, {}, {}, {}, mut_sys));
                    l3t.entries.front().alias = bsl::safe_u64::magic_1().get();
                    auto const ents{mut_rpt.entries<l0e_t>(mut_tls, mut_page_pool, {})};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(nullptr == ents.l3e);
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        l3t.entries.front().alias = {};
                        mut_rpt.release(mut_tls, mut_page_pool);
                    };
                };
            };
        };

        bsl::ut_scenario{"entries 2m reserved l3e"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                root_page_table_t mut_rpt{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                bsl::dontcare_t mut_sys{};
                helpers::l3t_t l3t{};
                constexpr auto phys{0x000FFFFF00000000_u64};
                bsl::ut_when{} = [&]() noexcept {
                    mut_page_pool.set_allocate<helpers::l3t_t>(&l3t, phys);
                    bsl::ut_required_step(mut_rpt.initialize(mut_tls, mut_page_pool));
                    bsl::ut_required_step(
                        mut_rpt.map<l1e_t>(mut_tls, mut_page_pool, {}, {}, {}, {}, mut_sys));
                    l3t.entries.front().alias = bsl::safe_u64::magic_1().get();
                    auto const ents{mut_rpt.entries<l1e_t>(mut_tls, mut_page_pool, {})};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(nullptr == ents.l3e);
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        l3t.entries.front().alias = {};
                        mut_rpt.release(mut_tls, mut_page_pool);
                    };
                };
            };
        };

        bsl::ut_scenario{"entries 1g reserved l3e"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                root_page_table_t mut_rpt{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                bsl::dontcare_t mut_sys{};
                helpers::l3t_t l3t{};
                constexpr auto phys{0x000FFFFF00000000_u64};
                bsl::ut_when{} = [&]() noexcept {
                    mut_page_pool.set_allocate<helpers::l3t_t>(&l3t, phys);
                    bsl::ut_required_step(mut_rpt.initialize(mut_tls, mut_page_pool));
                    bsl::ut_required_step(
                        mut_rpt.map<l2e_t>(mut_tls, mut_page_pool, {}, {}, {}, {}, mut_sys));
                    l3t.entries.front().alias = bsl::safe_u64::magic_1().get();
                    auto const ents{mut_rpt.entries<l2e_t>(mut_tls, mut_page_pool, {})};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(nullptr == ents.l3e);
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        l3t.entries.front().alias = {};
                        mut_rpt.release(mut_tls, mut_page_pool);
                    };
                };
            };
        };

        bsl::ut_scenario{"entries 4k reserved l2e"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                root_page_table_t mut_rpt{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                bsl::dontcare_t mut_sys{};
                helpers::l2t_t l2t{};
                constexpr auto phys{0x000FFFFF00000000_u64};
                bsl::ut_when{} = [&]() noexcept {
                    mut_page_pool.set_allocate<helpers::l2t_t>(&l2t, phys);
                    bsl::ut_required_step(mut_rpt.initialize(mut_tls, mut_page_pool));
                    bsl::ut_required_step(
                        mut_rpt.map<l0e_t>(mut_tls, mut_page_pool, {}, {}, {}, {}, mut_sys));
                    l2t.entries.front().alias = bsl::safe_u64::magic_1().get();
                    auto const ents{mut_rpt.entries<l0e_t>(mut_tls, mut_page_pool, {})};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(nullptr == ents.l3e);
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        l2t.entries.front().alias = {};
                        mut_rpt.release(mut_tls, mut_page_pool);
                    };
                };
            };
        };

        bsl::ut_scenario{"entries 2m reserved l2e"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                root_page_table_t mut_rpt{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                bsl::dontcare_t mut_sys{};
                helpers::l2t_t l2t{};
                constexpr auto phys{0x000FFFFF00000000_u64};
                bsl::ut_when{} = [&]() noexcept {
                    mut_page_pool.set_allocate<helpers::l2t_t>(&l2t, phys);
                    bsl::ut_required_step(mut_rpt.initialize(mut_tls, mut_page_pool));
                    bsl::ut_required_step(
                        mut_rpt.map<l1e_t>(mut_tls, mut_page_pool, {}, {}, {}, {}, mut_sys));
                    l2t.entries.front().alias = bsl::safe_u64::magic_1().get();
                    auto const ents{mut_rpt.entries<l1e_t>(mut_tls, mut_page_pool, {})};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(nullptr == ents.l3e);
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        l2t.entries.front().alias = {};
                        mut_rpt.release(mut_tls, mut_page_pool);
                    };
                };
            };
        };

        bsl::ut_scenario{"entries 1g reserved l2e"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                root_page_table_t mut_rpt{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                bsl::dontcare_t mut_sys{};
                helpers::l2t_t l2t{};
                constexpr auto phys{0x000FFFFF00000000_u64};
                bsl::ut_when{} = [&]() noexcept {
                    mut_page_pool.set_allocate<helpers::l2t_t>(&l2t, phys);
                    bsl::ut_required_step(mut_rpt.initialize(mut_tls, mut_page_pool));
                    bsl::ut_required_step(
                        mut_rpt.map<l2e_t>(mut_tls, mut_page_pool, {}, {}, {}, {}, mut_sys));
                    l2t.entries.front().alias = bsl::safe_u64::magic_1().get();
                    auto const ents{mut_rpt.entries<l2e_t>(mut_tls, mut_page_pool, {})};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(nullptr == ents.l3e);
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        l2t.entries.front().alias = {};
                        mut_rpt.release(mut_tls, mut_page_pool);
                    };
                };
            };
        };

        bsl::ut_scenario{"entries 4k reserved l1e"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                root_page_table_t mut_rpt{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                bsl::dontcare_t mut_sys{};
                helpers::l1t_t l1t{};
                constexpr auto phys{0x000FFFFF00000000_u64};
                bsl::ut_when{} = [&]() noexcept {
                    mut_page_pool.set_allocate<helpers::l1t_t>(&l1t, phys);
                    bsl::ut_required_step(mut_rpt.initialize(mut_tls, mut_page_pool));
                    bsl::ut_required_step(
                        mut_rpt.map<l0e_t>(mut_tls, mut_page_pool, {}, {}, {}, {}, mut_sys));
                    l1t.entries.front().alias = bsl::safe_u64::magic_1().get();
                    auto const ents{mut_rpt.entries<l0e_t>(mut_tls, mut_page_pool, {})};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(nullptr == ents.l3e);
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        l1t.entries.front().alias = {};
                        mut_rpt.release(mut_tls, mut_page_pool);
                    };
                };
            };
        };

        bsl::ut_scenario{"entries 2m reserved l1e"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                root_page_table_t mut_rpt{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                bsl::dontcare_t mut_sys{};
                helpers::l1t_t l1t{};
                constexpr auto phys{0x000FFFFF00000000_u64};
                bsl::ut_when{} = [&]() noexcept {
                    mut_page_pool.set_allocate<helpers::l1t_t>(&l1t, phys);
                    bsl::ut_required_step(mut_rpt.initialize(mut_tls, mut_page_pool));
                    bsl::ut_required_step(
                        mut_rpt.map<l1e_t>(mut_tls, mut_page_pool, {}, {}, {}, {}, mut_sys));
                    l1t.entries.front().alias = bsl::safe_u64::magic_1().get();
                    auto const ents{mut_rpt.entries<l1e_t>(mut_tls, mut_page_pool, {})};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(nullptr == ents.l3e);
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        l1t.entries.front().alias = {};
                        mut_rpt.release(mut_tls, mut_page_pool);
                    };
                };
            };
        };

        bsl::ut_scenario{"entries 4k reserved l0e"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                root_page_table_t mut_rpt{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                bsl::dontcare_t mut_sys{};
                helpers::l0t_t l0t{};
                constexpr auto phys{0x000FFFFF00000000_u64};
                bsl::ut_when{} = [&]() noexcept {
                    mut_page_pool.set_allocate<helpers::l0t_t>(&l0t, phys);
                    bsl::ut_required_step(mut_rpt.initialize(mut_tls, mut_page_pool));
                    bsl::ut_required_step(
                        mut_rpt.map<l0e_t>(mut_tls, mut_page_pool, {}, {}, {}, {}, mut_sys));
                    l0t.entries.front().alias = bsl::safe_u64::magic_1().get();
                    auto const ents{mut_rpt.entries<l0e_t>(mut_tls, mut_page_pool, {})};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(nullptr == ents.l3e);
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        l0t.entries.front().alias = {};
                        mut_rpt.release(mut_tls, mut_page_pool);
                    };
                };
            };
        };

        bsl::ut_scenario{"entries 4k unknown l3e"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                root_page_table_t mut_rpt{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                bsl::dontcare_t mut_sys{};
                helpers::l3t_t l3t{};
                constexpr auto phys{0x000FFFFF00000000_u64};
                bsl::ut_when{} = [&]() noexcept {
                    mut_page_pool.set_allocate<helpers::l3t_t>(&l3t, phys);
                    bsl::ut_required_step(mut_rpt.initialize(mut_tls, mut_page_pool));
                    bsl::ut_required_step(
                        mut_rpt.map<l0e_t>(mut_tls, mut_page_pool, {}, {}, {}, {}, mut_sys));
                    l3t.entries.front().u = bsl::safe_u64::magic_1().get();
                    auto const ents{mut_rpt.entries<l0e_t>(mut_tls, mut_page_pool, {})};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(nullptr == ents.l3e);
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        l3t.entries.front().u = {};
                        mut_rpt.release(mut_tls, mut_page_pool);
                    };
                };
            };
        };

        bsl::ut_scenario{"entries 2m unknown l3e"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                root_page_table_t mut_rpt{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                bsl::dontcare_t mut_sys{};
                helpers::l3t_t l3t{};
                constexpr auto phys{0x000FFFFF00000000_u64};
                bsl::ut_when{} = [&]() noexcept {
                    mut_page_pool.set_allocate<helpers::l3t_t>(&l3t, phys);
                    bsl::ut_required_step(mut_rpt.initialize(mut_tls, mut_page_pool));
                    bsl::ut_required_step(
                        mut_rpt.map<l1e_t>(mut_tls, mut_page_pool, {}, {}, {}, {}, mut_sys));
                    l3t.entries.front().u = bsl::safe_u64::magic_1().get();
                    auto const ents{mut_rpt.entries<l1e_t>(mut_tls, mut_page_pool, {})};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(nullptr == ents.l3e);
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        l3t.entries.front().u = {};
                        mut_rpt.release(mut_tls, mut_page_pool);
                    };
                };
            };
        };

        bsl::ut_scenario{"entries 1g unknown l3e"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                root_page_table_t mut_rpt{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                bsl::dontcare_t mut_sys{};
                helpers::l3t_t l3t{};
                constexpr auto phys{0x000FFFFF00000000_u64};
                bsl::ut_when{} = [&]() noexcept {
                    mut_page_pool.set_allocate<helpers::l3t_t>(&l3t, phys);
                    bsl::ut_required_step(mut_rpt.initialize(mut_tls, mut_page_pool));
                    bsl::ut_required_step(
                        mut_rpt.map<l2e_t>(mut_tls, mut_page_pool, {}, {}, {}, {}, mut_sys));
                    l3t.entries.front().u = bsl::safe_u64::magic_1().get();
                    auto const ents{mut_rpt.entries<l2e_t>(mut_tls, mut_page_pool, {})};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(nullptr == ents.l3e);
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        l3t.entries.front().u = {};
                        mut_rpt.release(mut_tls, mut_page_pool);
                    };
                };
            };
        };

        bsl::ut_scenario{"entries 4k unknown l2e"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                root_page_table_t mut_rpt{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                bsl::dontcare_t mut_sys{};
                helpers::l2t_t l2t{};
                constexpr auto phys{0x000FFFFF00000000_u64};
                bsl::ut_when{} = [&]() noexcept {
                    mut_page_pool.set_allocate<helpers::l2t_t>(&l2t, phys);
                    bsl::ut_required_step(mut_rpt.initialize(mut_tls, mut_page_pool));
                    bsl::ut_required_step(
                        mut_rpt.map<l0e_t>(mut_tls, mut_page_pool, {}, {}, {}, {}, mut_sys));
                    l2t.entries.front().u = bsl::safe_u64::magic_1().get();
                    auto const ents{mut_rpt.entries<l0e_t>(mut_tls, mut_page_pool, {})};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(nullptr == ents.l3e);
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        l2t.entries.front().u = {};
                        mut_rpt.release(mut_tls, mut_page_pool);
                    };
                };
            };
        };

        bsl::ut_scenario{"entries 2m unknown l2e"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                root_page_table_t mut_rpt{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                bsl::dontcare_t mut_sys{};
                helpers::l2t_t l2t{};
                constexpr auto phys{0x000FFFFF00000000_u64};
                bsl::ut_when{} = [&]() noexcept {
                    mut_page_pool.set_allocate<helpers::l2t_t>(&l2t, phys);
                    bsl::ut_required_step(mut_rpt.initialize(mut_tls, mut_page_pool));
                    bsl::ut_required_step(
                        mut_rpt.map<l1e_t>(mut_tls, mut_page_pool, {}, {}, {}, {}, mut_sys));
                    l2t.entries.front().u = bsl::safe_u64::magic_1().get();
                    auto const ents{mut_rpt.entries<l1e_t>(mut_tls, mut_page_pool, {})};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(nullptr == ents.l3e);
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        l2t.entries.front().u = {};
                        mut_rpt.release(mut_tls, mut_page_pool);
                    };
                };
            };
        };

        bsl::ut_scenario{"entries 1g unknown l2e"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                root_page_table_t mut_rpt{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                bsl::dontcare_t mut_sys{};
                helpers::l2t_t l2t{};
                constexpr auto phys{0x000FFFFF00000000_u64};
                bsl::ut_when{} = [&]() noexcept {
                    mut_page_pool.set_allocate<helpers::l2t_t>(&l2t, phys);
                    bsl::ut_required_step(mut_rpt.initialize(mut_tls, mut_page_pool));
                    bsl::ut_required_step(
                        mut_rpt.map<l2e_t>(mut_tls, mut_page_pool, {}, {}, {}, {}, mut_sys));
                    l2t.entries.front().u = bsl::safe_u64::magic_1().get();
                    auto const ents{mut_rpt.entries<l2e_t>(mut_tls, mut_page_pool, {})};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(nullptr == ents.l3e);
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        l2t.entries.front().u = {};
                        mut_rpt.release(mut_tls, mut_page_pool);
                    };
                };
            };
        };

        bsl::ut_scenario{"entries 4k unknown l1e"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                root_page_table_t mut_rpt{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                bsl::dontcare_t mut_sys{};
                helpers::l1t_t l1t{};
                constexpr auto phys{0x000FFFFF00000000_u64};
                bsl::ut_when{} = [&]() noexcept {
                    mut_page_pool.set_allocate<helpers::l1t_t>(&l1t, phys);
                    bsl::ut_required_step(mut_rpt.initialize(mut_tls, mut_page_pool));
                    bsl::ut_required_step(
                        mut_rpt.map<l0e_t>(mut_tls, mut_page_pool, {}, {}, {}, {}, mut_sys));
                    l1t.entries.front().u = bsl::safe_u64::magic_1().get();
                    auto const ents{mut_rpt.entries<l0e_t>(mut_tls, mut_page_pool, {})};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(nullptr == ents.l3e);
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        l1t.entries.front().u = {};
                        mut_rpt.release(mut_tls, mut_page_pool);
                    };
                };
            };
        };

        bsl::ut_scenario{"entries 2m unknown l1e"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                root_page_table_t mut_rpt{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                bsl::dontcare_t mut_sys{};
                helpers::l1t_t l1t{};
                constexpr auto phys{0x000FFFFF00000000_u64};
                bsl::ut_when{} = [&]() noexcept {
                    mut_page_pool.set_allocate<helpers::l1t_t>(&l1t, phys);
                    bsl::ut_required_step(mut_rpt.initialize(mut_tls, mut_page_pool));
                    bsl::ut_required_step(
                        mut_rpt.map<l1e_t>(mut_tls, mut_page_pool, {}, {}, {}, {}, mut_sys));
                    l1t.entries.front().u = bsl::safe_u64::magic_1().get();
                    auto const ents{mut_rpt.entries<l1e_t>(mut_tls, mut_page_pool, {})};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(nullptr == ents.l3e);
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        l1t.entries.front().u = {};
                        mut_rpt.release(mut_tls, mut_page_pool);
                    };
                };
            };
        };

        bsl::ut_scenario{"entries 4k unknown l0e"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                root_page_table_t mut_rpt{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                bsl::dontcare_t mut_sys{};
                helpers::l0t_t l0t{};
                constexpr auto phys{0x000FFFFF00000000_u64};
                bsl::ut_when{} = [&]() noexcept {
                    mut_page_pool.set_allocate<helpers::l0t_t>(&l0t, phys);
                    bsl::ut_required_step(mut_rpt.initialize(mut_tls, mut_page_pool));
                    bsl::ut_required_step(
                        mut_rpt.map<l0e_t>(mut_tls, mut_page_pool, {}, {}, {}, {}, mut_sys));
                    l0t.entries.front().u = bsl::safe_u64::magic_1().get();
                    auto const ents{mut_rpt.entries<l0e_t>(mut_tls, mut_page_pool, {})};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(nullptr == ents.l3e);
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        l0t.entries.front().u = {};
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
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_cleanup{} = [&]() noexcept {
                        mut_rpt.release(mut_tls, mut_page_pool);
                    };
                };
            };
        };

        bsl::ut_scenario{"release 4k without explicit unmap l0e"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                root_page_table_t mut_rpt{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                bsl::dontcare_t mut_sys{};
                helpers::l3t_t l3t{};
                helpers::l2t_t l2t{};
                helpers::l1t_t l1t{};
                helpers::l0t_t l0t{};
                constexpr auto phys3{0x000FFFFF00003000_u64};
                constexpr auto phys2{0x000FFFFF00002000_u64};
                constexpr auto phys1{0x000FFFFF00001000_u64};
                constexpr auto phys0{0x000FFFFF00000000_u64};
                bsl::ut_when{} = [&]() noexcept {
                    mut_page_pool.set_allocate<helpers::l3t_t>(&l3t, phys3);
                    mut_page_pool.set_allocate<helpers::l2t_t>(&l2t, phys2);
                    mut_page_pool.set_allocate<helpers::l1t_t>(&l1t, phys1);
                    mut_page_pool.set_allocate<helpers::l0t_t>(&l0t, phys0);
                    bsl::ut_required_step(mut_rpt.initialize(mut_tls, mut_page_pool));
                    bsl::ut_required_step(
                        mut_rpt.map<l0e_t>(mut_tls, mut_page_pool, {}, {}, {}, {}, mut_sys));
                    l0t.entries.front().explicit_unmap = bsl::safe_u64::magic_1().get();
                    bsl::ut_then{} = [&]() noexcept {
                        mut_rpt.release(mut_tls, mut_page_pool);
                    };
                };
            };
        };

        bsl::ut_scenario{"release 4k without explicit unmap l1e"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                root_page_table_t mut_rpt{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                bsl::dontcare_t mut_sys{};
                helpers::l3t_t l3t{};
                helpers::l2t_t l2t{};
                helpers::l1t_t l1t{};
                helpers::l0t_t l0t{};
                constexpr auto phys3{0x000FFFFF00003000_u64};
                constexpr auto phys2{0x000FFFFF00002000_u64};
                constexpr auto phys1{0x000FFFFF00001000_u64};
                constexpr auto phys0{0x000FFFFF00000000_u64};
                bsl::ut_when{} = [&]() noexcept {
                    mut_page_pool.set_allocate<helpers::l3t_t>(&l3t, phys3);
                    mut_page_pool.set_allocate<helpers::l2t_t>(&l2t, phys2);
                    mut_page_pool.set_allocate<helpers::l1t_t>(&l1t, phys1);
                    mut_page_pool.set_allocate<helpers::l0t_t>(&l0t, phys0);
                    bsl::ut_required_step(mut_rpt.initialize(mut_tls, mut_page_pool));
                    bsl::ut_required_step(
                        mut_rpt.map<l0e_t>(mut_tls, mut_page_pool, {}, {}, {}, {}, mut_sys));
                    l1t.entries.front().explicit_unmap = bsl::safe_u64::magic_1().get();
                    bsl::ut_then{} = [&]() noexcept {
                        mut_rpt.release(mut_tls, mut_page_pool);
                    };
                };
            };
        };

        bsl::ut_scenario{"release 4k without explicit unmap l2e"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                root_page_table_t mut_rpt{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                bsl::dontcare_t mut_sys{};
                helpers::l3t_t l3t{};
                helpers::l2t_t l2t{};
                helpers::l1t_t l1t{};
                helpers::l0t_t l0t{};
                constexpr auto phys3{0x000FFFFF00003000_u64};
                constexpr auto phys2{0x000FFFFF00002000_u64};
                constexpr auto phys1{0x000FFFFF00001000_u64};
                constexpr auto phys0{0x000FFFFF00000000_u64};
                bsl::ut_when{} = [&]() noexcept {
                    mut_page_pool.set_allocate<helpers::l3t_t>(&l3t, phys3);
                    mut_page_pool.set_allocate<helpers::l2t_t>(&l2t, phys2);
                    mut_page_pool.set_allocate<helpers::l1t_t>(&l1t, phys1);
                    mut_page_pool.set_allocate<helpers::l0t_t>(&l0t, phys0);
                    bsl::ut_required_step(mut_rpt.initialize(mut_tls, mut_page_pool));
                    bsl::ut_required_step(
                        mut_rpt.map<l0e_t>(mut_tls, mut_page_pool, {}, {}, {}, {}, mut_sys));
                    l2t.entries.front().explicit_unmap = bsl::safe_u64::magic_1().get();
                    bsl::ut_then{} = [&]() noexcept {
                        mut_rpt.release(mut_tls, mut_page_pool);
                    };
                };
            };
        };

        bsl::ut_scenario{"release 4k without explicit unmap l3e"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                root_page_table_t mut_rpt{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                bsl::dontcare_t mut_sys{};
                helpers::l3t_t l3t{};
                helpers::l2t_t l2t{};
                helpers::l1t_t l1t{};
                helpers::l0t_t l0t{};
                constexpr auto phys3{0x000FFFFF00003000_u64};
                constexpr auto phys2{0x000FFFFF00002000_u64};
                constexpr auto phys1{0x000FFFFF00001000_u64};
                constexpr auto phys0{0x000FFFFF00000000_u64};
                bsl::ut_when{} = [&]() noexcept {
                    mut_page_pool.set_allocate<helpers::l3t_t>(&l3t, phys3);
                    mut_page_pool.set_allocate<helpers::l2t_t>(&l2t, phys2);
                    mut_page_pool.set_allocate<helpers::l1t_t>(&l1t, phys1);
                    mut_page_pool.set_allocate<helpers::l0t_t>(&l0t, phys0);
                    bsl::ut_required_step(mut_rpt.initialize(mut_tls, mut_page_pool));
                    bsl::ut_required_step(
                        mut_rpt.map<l0e_t>(mut_tls, mut_page_pool, {}, {}, {}, {}, mut_sys));
                    l3t.entries.front().explicit_unmap = bsl::safe_u64::magic_1().get();
                    bsl::ut_then{} = [&]() noexcept {
                        mut_rpt.release(mut_tls, mut_page_pool);
                    };
                };
            };
        };

        bsl::ut_scenario{"release 2m without explicit unmap l0e"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                root_page_table_t mut_rpt{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                bsl::dontcare_t mut_sys{};
                helpers::l3t_t l3t{};
                helpers::l2t_t l2t{};
                helpers::l1t_t l1t{};
                helpers::l0t_t l0t{};
                constexpr auto phys3{0x000FFFFF00003000_u64};
                constexpr auto phys2{0x000FFFFF00002000_u64};
                constexpr auto phys1{0x000FFFFF00001000_u64};
                constexpr auto phys0{0x000FFFFF00000000_u64};
                bsl::ut_when{} = [&]() noexcept {
                    mut_page_pool.set_allocate<helpers::l3t_t>(&l3t, phys3);
                    mut_page_pool.set_allocate<helpers::l2t_t>(&l2t, phys2);
                    mut_page_pool.set_allocate<helpers::l1t_t>(&l1t, phys1);
                    mut_page_pool.set_allocate<helpers::l0t_t>(&l0t, phys0);
                    bsl::ut_required_step(mut_rpt.initialize(mut_tls, mut_page_pool));
                    bsl::ut_required_step(
                        mut_rpt.map<l1e_t>(mut_tls, mut_page_pool, {}, {}, {}, {}, mut_sys));
                    l0t.entries.front().explicit_unmap = bsl::safe_u64::magic_1().get();
                    bsl::ut_then{} = [&]() noexcept {
                        mut_rpt.release(mut_tls, mut_page_pool);
                    };
                };
            };
        };

        bsl::ut_scenario{"release 2m without explicit unmap l1e"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                root_page_table_t mut_rpt{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                bsl::dontcare_t mut_sys{};
                helpers::l3t_t l3t{};
                helpers::l2t_t l2t{};
                helpers::l1t_t l1t{};
                helpers::l0t_t l0t{};
                constexpr auto phys3{0x000FFFFF00003000_u64};
                constexpr auto phys2{0x000FFFFF00002000_u64};
                constexpr auto phys1{0x000FFFFF00001000_u64};
                constexpr auto phys0{0x000FFFFF00000000_u64};
                bsl::ut_when{} = [&]() noexcept {
                    mut_page_pool.set_allocate<helpers::l3t_t>(&l3t, phys3);
                    mut_page_pool.set_allocate<helpers::l2t_t>(&l2t, phys2);
                    mut_page_pool.set_allocate<helpers::l1t_t>(&l1t, phys1);
                    mut_page_pool.set_allocate<helpers::l0t_t>(&l0t, phys0);
                    bsl::ut_required_step(mut_rpt.initialize(mut_tls, mut_page_pool));
                    bsl::ut_required_step(
                        mut_rpt.map<l1e_t>(mut_tls, mut_page_pool, {}, {}, {}, {}, mut_sys));
                    l1t.entries.front().explicit_unmap = bsl::safe_u64::magic_1().get();
                    bsl::ut_then{} = [&]() noexcept {
                        mut_rpt.release(mut_tls, mut_page_pool);
                    };
                };
            };
        };

        bsl::ut_scenario{"release 2m without explicit unmap l2e"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                root_page_table_t mut_rpt{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                bsl::dontcare_t mut_sys{};
                helpers::l3t_t l3t{};
                helpers::l2t_t l2t{};
                helpers::l1t_t l1t{};
                helpers::l0t_t l0t{};
                constexpr auto phys3{0x000FFFFF00003000_u64};
                constexpr auto phys2{0x000FFFFF00002000_u64};
                constexpr auto phys1{0x000FFFFF00001000_u64};
                constexpr auto phys0{0x000FFFFF00000000_u64};
                bsl::ut_when{} = [&]() noexcept {
                    mut_page_pool.set_allocate<helpers::l3t_t>(&l3t, phys3);
                    mut_page_pool.set_allocate<helpers::l2t_t>(&l2t, phys2);
                    mut_page_pool.set_allocate<helpers::l1t_t>(&l1t, phys1);
                    mut_page_pool.set_allocate<helpers::l0t_t>(&l0t, phys0);
                    bsl::ut_required_step(mut_rpt.initialize(mut_tls, mut_page_pool));
                    bsl::ut_required_step(
                        mut_rpt.map<l1e_t>(mut_tls, mut_page_pool, {}, {}, {}, {}, mut_sys));
                    l2t.entries.front().explicit_unmap = bsl::safe_u64::magic_1().get();
                    bsl::ut_then{} = [&]() noexcept {
                        mut_rpt.release(mut_tls, mut_page_pool);
                    };
                };
            };
        };

        bsl::ut_scenario{"release 2m without explicit unmap l3e"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                root_page_table_t mut_rpt{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                bsl::dontcare_t mut_sys{};
                helpers::l3t_t l3t{};
                helpers::l2t_t l2t{};
                helpers::l1t_t l1t{};
                helpers::l0t_t l0t{};
                constexpr auto phys3{0x000FFFFF00003000_u64};
                constexpr auto phys2{0x000FFFFF00002000_u64};
                constexpr auto phys1{0x000FFFFF00001000_u64};
                constexpr auto phys0{0x000FFFFF00000000_u64};
                bsl::ut_when{} = [&]() noexcept {
                    mut_page_pool.set_allocate<helpers::l3t_t>(&l3t, phys3);
                    mut_page_pool.set_allocate<helpers::l2t_t>(&l2t, phys2);
                    mut_page_pool.set_allocate<helpers::l1t_t>(&l1t, phys1);
                    mut_page_pool.set_allocate<helpers::l0t_t>(&l0t, phys0);
                    bsl::ut_required_step(mut_rpt.initialize(mut_tls, mut_page_pool));
                    bsl::ut_required_step(
                        mut_rpt.map<l1e_t>(mut_tls, mut_page_pool, {}, {}, {}, {}, mut_sys));
                    l3t.entries.front().explicit_unmap = bsl::safe_u64::magic_1().get();
                    bsl::ut_then{} = [&]() noexcept {
                        mut_rpt.release(mut_tls, mut_page_pool);
                    };
                };
            };
        };

        bsl::ut_scenario{"release 1g without explicit unmap l0e"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                root_page_table_t mut_rpt{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                bsl::dontcare_t mut_sys{};
                helpers::l3t_t l3t{};
                helpers::l2t_t l2t{};
                helpers::l1t_t l1t{};
                helpers::l0t_t l0t{};
                constexpr auto phys3{0x000FFFFF00003000_u64};
                constexpr auto phys2{0x000FFFFF00002000_u64};
                constexpr auto phys1{0x000FFFFF00001000_u64};
                constexpr auto phys0{0x000FFFFF00000000_u64};
                bsl::ut_when{} = [&]() noexcept {
                    mut_page_pool.set_allocate<helpers::l3t_t>(&l3t, phys3);
                    mut_page_pool.set_allocate<helpers::l2t_t>(&l2t, phys2);
                    mut_page_pool.set_allocate<helpers::l1t_t>(&l1t, phys1);
                    mut_page_pool.set_allocate<helpers::l0t_t>(&l0t, phys0);
                    bsl::ut_required_step(mut_rpt.initialize(mut_tls, mut_page_pool));
                    bsl::ut_required_step(
                        mut_rpt.map<l2e_t>(mut_tls, mut_page_pool, {}, {}, {}, {}, mut_sys));
                    l0t.entries.front().explicit_unmap = bsl::safe_u64::magic_1().get();
                    bsl::ut_then{} = [&]() noexcept {
                        mut_rpt.release(mut_tls, mut_page_pool);
                    };
                };
            };
        };

        bsl::ut_scenario{"release 1g without explicit unmap l1e"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                root_page_table_t mut_rpt{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                bsl::dontcare_t mut_sys{};
                helpers::l3t_t l3t{};
                helpers::l2t_t l2t{};
                helpers::l1t_t l1t{};
                helpers::l0t_t l0t{};
                constexpr auto phys3{0x000FFFFF00003000_u64};
                constexpr auto phys2{0x000FFFFF00002000_u64};
                constexpr auto phys1{0x000FFFFF00001000_u64};
                constexpr auto phys0{0x000FFFFF00000000_u64};
                bsl::ut_when{} = [&]() noexcept {
                    mut_page_pool.set_allocate<helpers::l3t_t>(&l3t, phys3);
                    mut_page_pool.set_allocate<helpers::l2t_t>(&l2t, phys2);
                    mut_page_pool.set_allocate<helpers::l1t_t>(&l1t, phys1);
                    mut_page_pool.set_allocate<helpers::l0t_t>(&l0t, phys0);
                    bsl::ut_required_step(mut_rpt.initialize(mut_tls, mut_page_pool));
                    bsl::ut_required_step(
                        mut_rpt.map<l2e_t>(mut_tls, mut_page_pool, {}, {}, {}, {}, mut_sys));
                    l1t.entries.front().explicit_unmap = bsl::safe_u64::magic_1().get();
                    bsl::ut_then{} = [&]() noexcept {
                        mut_rpt.release(mut_tls, mut_page_pool);
                    };
                };
            };
        };

        bsl::ut_scenario{"release 1g without explicit unmap l2e"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                root_page_table_t mut_rpt{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                bsl::dontcare_t mut_sys{};
                helpers::l3t_t l3t{};
                helpers::l2t_t l2t{};
                helpers::l1t_t l1t{};
                helpers::l0t_t l0t{};
                constexpr auto phys3{0x000FFFFF00003000_u64};
                constexpr auto phys2{0x000FFFFF00002000_u64};
                constexpr auto phys1{0x000FFFFF00001000_u64};
                constexpr auto phys0{0x000FFFFF00000000_u64};
                bsl::ut_when{} = [&]() noexcept {
                    mut_page_pool.set_allocate<helpers::l3t_t>(&l3t, phys3);
                    mut_page_pool.set_allocate<helpers::l2t_t>(&l2t, phys2);
                    mut_page_pool.set_allocate<helpers::l1t_t>(&l1t, phys1);
                    mut_page_pool.set_allocate<helpers::l0t_t>(&l0t, phys0);
                    bsl::ut_required_step(mut_rpt.initialize(mut_tls, mut_page_pool));
                    bsl::ut_required_step(
                        mut_rpt.map<l2e_t>(mut_tls, mut_page_pool, {}, {}, {}, {}, mut_sys));
                    l2t.entries.front().explicit_unmap = bsl::safe_u64::magic_1().get();
                    bsl::ut_then{} = [&]() noexcept {
                        mut_rpt.release(mut_tls, mut_page_pool);
                    };
                };
            };
        };

        bsl::ut_scenario{"release 1g without explicit unmap l3e"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                root_page_table_t mut_rpt{};
                tls_t mut_tls{};
                page_pool_t mut_page_pool{};
                bsl::dontcare_t mut_sys{};
                helpers::l3t_t l3t{};
                helpers::l2t_t l2t{};
                helpers::l1t_t l1t{};
                helpers::l0t_t l0t{};
                constexpr auto phys3{0x000FFFFF00003000_u64};
                constexpr auto phys2{0x000FFFFF00002000_u64};
                constexpr auto phys1{0x000FFFFF00001000_u64};
                constexpr auto phys0{0x000FFFFF00000000_u64};
                bsl::ut_when{} = [&]() noexcept {
                    mut_page_pool.set_allocate<helpers::l3t_t>(&l3t, phys3);
                    mut_page_pool.set_allocate<helpers::l2t_t>(&l2t, phys2);
                    mut_page_pool.set_allocate<helpers::l1t_t>(&l1t, phys1);
                    mut_page_pool.set_allocate<helpers::l0t_t>(&l0t, phys0);
                    bsl::ut_required_step(mut_rpt.initialize(mut_tls, mut_page_pool));
                    bsl::ut_required_step(
                        mut_rpt.map<l2e_t>(mut_tls, mut_page_pool, {}, {}, {}, {}, mut_sys));
                    l3t.entries.front().explicit_unmap = bsl::safe_u64::magic_1().get();
                    bsl::ut_then{} = [&]() noexcept {
                        mut_rpt.release(mut_tls, mut_page_pool);
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

    static_assert(lib::tests() == bsl::ut_success());
    return lib::tests();
}
