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

#include "../../../mocks/basic_page_pool_t.hpp"
#include "../../../src/basic_root_page_table_t.hpp"
#include "l0e_t.hpp"
#include "l1e_t.hpp"
#include "l2e_t.hpp"
#include "l3e_t.hpp"

#include <intrinsic_t.hpp>
#include <tls_t.hpp>

#include <bsl/errc_type.hpp>
#include <bsl/safe_integral.hpp>
#include <bsl/ut.hpp>

namespace lib
{
    /// @brief defines the page_pool_t used by the microkernel
    using page_pool_t = lib::basic_page_pool_t<tls_t>;

    /// @brief defines the root_page_table_t used by the microkernel
    using root_page_table_t =
        lib::basic_root_page_table_t<tls_t, page_pool_t, intrinsic_t, l3e_t, l2e_t, l1e_t, l0e_t>;

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
        bsl::ut_scenario{"initialize allocate fails"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                root_page_table_t mut_rpt{};
                page_pool_t mut_page_pool{};
                tls_t mut_tls{};
                bsl::ut_when{} = [&]() noexcept {
                    mut_page_pool.set_oneshot<helpers::l3t_t>(nullptr, {});
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(!mut_rpt.initialize(mut_tls, mut_page_pool));
                    };
                };
            };
        };

        bsl::ut_scenario{"initialize success"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                root_page_table_t mut_rpt{};
                page_pool_t mut_page_pool{};
                tls_t mut_tls{};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(mut_rpt.initialize(mut_tls, mut_page_pool));
                    bsl::ut_cleanup{} = [&]() noexcept {
                        mut_rpt.release(mut_tls, mut_page_pool);
                    };
                };
            };
        };

        bsl::ut_scenario{"release without initialize"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                root_page_table_t mut_rpt{};
                page_pool_t mut_page_pool{};
                tls_t mut_tls{};
                bsl::ut_then{} = [&]() noexcept {
                    mut_rpt.release(mut_tls, mut_page_pool);
                };
            };
        };

        bsl::ut_scenario{"release success"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                root_page_table_t mut_rpt{};
                page_pool_t mut_page_pool{};
                tls_t mut_tls{};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(mut_rpt.initialize(mut_tls, mut_page_pool));
                    bsl::ut_cleanup{} = [&]() noexcept {
                        mut_rpt.release(mut_tls, mut_page_pool);
                    };
                };
            };
        };

        bsl::ut_scenario{"is_initialized"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                root_page_table_t mut_rpt{};
                page_pool_t mut_page_pool{};
                tls_t mut_tls{};
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

        bsl::ut_scenario{"activate"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                root_page_table_t mut_rpt{};
                page_pool_t mut_page_pool{};
                tls_t mut_tls{};
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

        // bsl::ut_scenario{"map_page uninitialized fails"} = []() noexcept {
        //     bsl::ut_given{} = []() noexcept {
        //         root_page_table_t mut_rpt{};
        //         page_pool_t mut_page_pool{};
        //         tls_t mut_tls{};
        //         constexpr auto virt{0x1000_umx};
        //         constexpr auto phys{0x1000_umx};
        //         constexpr auto flgs{MAP_PAGE_READ | MAP_PAGE_WRITE};
        //         constexpr auto atrl{MAP_PAGE_NO_AUTO_RELEASE};
        //         bsl::ut_then{} = [&]() noexcept {
        //             bsl::ut_check(
        //                 !mut_rpt.map_page(mut_tls, mut_page_pool, virt, phys, flgs, atrl));
        //         };
        //     };
        // };

        // bsl::ut_scenario{"map_page invalid virt (0)"} = []() noexcept {
        //     bsl::ut_given{} = []() noexcept {
        //         root_page_table_t mut_rpt{};
        //         page_pool_t mut_page_pool{};
        //         tls_t mut_tls{};
        //         constexpr auto virt{0_umx};
        //         constexpr auto phys{0x1000_umx};
        //         constexpr auto flgs{MAP_PAGE_READ | MAP_PAGE_WRITE};
        //         constexpr auto atrl{MAP_PAGE_NO_AUTO_RELEASE};
        //         bsl::ut_when{} = [&]() noexcept {
        //             bsl::ut_required_step(mut_rpt.initialize(mut_tls, mut_page_pool));
        //             bsl::ut_then{} = [&]() noexcept {
        //                 bsl::ut_check(
        //                     !mut_rpt.map_page(mut_tls, mut_page_pool, virt, phys, flgs, atrl));
        //                 bsl::ut_cleanup{} = [&]() noexcept {
        //                     mut_rpt.release(mut_tls, mut_page_pool);
        //                 };
        //             };
        //         };
        //     };
        // };

        // bsl::ut_scenario{"map_page invalid virt (failure)"} = []() noexcept {
        //     bsl::ut_given{} = []() noexcept {
        //         root_page_table_t mut_rpt{};
        //         page_pool_t mut_page_pool{};
        //         tls_t mut_tls{};
        //         constexpr auto virt{bsl::safe_umx::failure()};
        //         constexpr auto phys{0x1000_umx};
        //         constexpr auto flgs{MAP_PAGE_READ | MAP_PAGE_WRITE};
        //         constexpr auto atrl{MAP_PAGE_NO_AUTO_RELEASE};
        //         bsl::ut_when{} = [&]() noexcept {
        //             bsl::ut_required_step(mut_rpt.initialize(mut_tls, mut_page_pool));
        //             bsl::ut_then{} = [&]() noexcept {
        //                 bsl::ut_check(
        //                     !mut_rpt.map_page(mut_tls, mut_page_pool, virt, phys, flgs, atrl));
        //                 bsl::ut_cleanup{} = [&]() noexcept {
        //                     mut_rpt.release(mut_tls, mut_page_pool);
        //                 };
        //             };
        //         };
        //     };
        // };

        // bsl::ut_scenario{"map_page invalid virt (page alignment)"} = []() noexcept {
        //     bsl::ut_given{} = []() noexcept {
        //         root_page_table_t mut_rpt{};
        //         page_pool_t mut_page_pool{};
        //         tls_t mut_tls{};
        //         constexpr auto virt{42_umx};
        //         constexpr auto phys{0x1000_umx};
        //         constexpr auto flgs{MAP_PAGE_READ | MAP_PAGE_WRITE};
        //         constexpr auto atrl{MAP_PAGE_NO_AUTO_RELEASE};
        //         bsl::ut_when{} = [&]() noexcept {
        //             bsl::ut_required_step(mut_rpt.initialize(mut_tls, mut_page_pool));
        //             bsl::ut_then{} = [&]() noexcept {
        //                 bsl::ut_check(
        //                     !mut_rpt.map_page(mut_tls, mut_page_pool, virt, phys, flgs, atrl));
        //                 bsl::ut_cleanup{} = [&]() noexcept {
        //                     mut_rpt.release(mut_tls, mut_page_pool);
        //                 };
        //             };
        //         };
        //     };
        // };

        // bsl::ut_scenario{"map_page invalid phys (0)"} = []() noexcept {
        //     bsl::ut_given{} = []() noexcept {
        //         root_page_table_t mut_rpt{};
        //         page_pool_t mut_page_pool{};
        //         tls_t mut_tls{};
        //         constexpr auto virt{0x1000_umx};
        //         constexpr auto phys{0_umx};
        //         constexpr auto flgs{MAP_PAGE_READ | MAP_PAGE_WRITE};
        //         constexpr auto atrl{MAP_PAGE_NO_AUTO_RELEASE};
        //         bsl::ut_when{} = [&]() noexcept {
        //             bsl::ut_required_step(mut_rpt.initialize(mut_tls, mut_page_pool));
        //             bsl::ut_then{} = [&]() noexcept {
        //                 bsl::ut_check(
        //                     !mut_rpt.map_page(mut_tls, mut_page_pool, virt, phys, flgs, atrl));
        //                 bsl::ut_cleanup{} = [&]() noexcept {
        //                     mut_rpt.release(mut_tls, mut_page_pool);
        //                 };
        //             };
        //         };
        //     };
        // };

        // bsl::ut_scenario{"map_page invalid phys (failure)"} = []() noexcept {
        //     bsl::ut_given{} = []() noexcept {
        //         root_page_table_t mut_rpt{};
        //         page_pool_t mut_page_pool{};
        //         tls_t mut_tls{};
        //         constexpr auto virt{0x1000_umx};
        //         constexpr auto phys{bsl::safe_umx::failure()};
        //         constexpr auto flgs{MAP_PAGE_READ | MAP_PAGE_WRITE};
        //         constexpr auto atrl{MAP_PAGE_NO_AUTO_RELEASE};
        //         bsl::ut_when{} = [&]() noexcept {
        //             bsl::ut_required_step(mut_rpt.initialize(mut_tls, mut_page_pool));
        //             bsl::ut_then{} = [&]() noexcept {
        //                 bsl::ut_check(
        //                     !mut_rpt.map_page(mut_tls, mut_page_pool, virt, phys, flgs, atrl));
        //                 bsl::ut_cleanup{} = [&]() noexcept {
        //                     mut_rpt.release(mut_tls, mut_page_pool);
        //                 };
        //             };
        //         };
        //     };
        // };

        // bsl::ut_scenario{"map_page invalid phys (page alignment)"} = []() noexcept {
        //     bsl::ut_given{} = []() noexcept {
        //         root_page_table_t mut_rpt{};
        //         page_pool_t mut_page_pool{};
        //         tls_t mut_tls{};
        //         constexpr auto virt{0x1000_umx};
        //         constexpr auto phys{42_umx};
        //         constexpr auto flgs{MAP_PAGE_READ | MAP_PAGE_WRITE};
        //         constexpr auto atrl{MAP_PAGE_NO_AUTO_RELEASE};
        //         bsl::ut_when{} = [&]() noexcept {
        //             bsl::ut_required_step(mut_rpt.initialize(mut_tls, mut_page_pool));
        //             bsl::ut_then{} = [&]() noexcept {
        //                 bsl::ut_check(
        //                     !mut_rpt.map_page(mut_tls, mut_page_pool, virt, phys, flgs, atrl));
        //                 bsl::ut_cleanup{} = [&]() noexcept {
        //                     mut_rpt.release(mut_tls, mut_page_pool);
        //                 };
        //             };
        //         };
        //     };
        // };

        // bsl::ut_scenario{"map_page invalid flags (0)"} = []() noexcept {
        //     bsl::ut_given{} = []() noexcept {
        //         root_page_table_t mut_rpt{};
        //         page_pool_t mut_page_pool{};
        //         tls_t mut_tls{};
        //         constexpr auto virt{0x1000_umx};
        //         constexpr auto phys{0x1000_umx};
        //         constexpr auto flgs{0_umx};
        //         constexpr auto atrl{MAP_PAGE_NO_AUTO_RELEASE};
        //         bsl::ut_when{} = [&]() noexcept {
        //             bsl::ut_required_step(mut_rpt.initialize(mut_tls, mut_page_pool));
        //             bsl::ut_then{} = [&]() noexcept {
        //                 bsl::ut_check(
        //                     !mut_rpt.map_page(mut_tls, mut_page_pool, virt, phys, flgs, atrl));
        //                 bsl::ut_cleanup{} = [&]() noexcept {
        //                     mut_rpt.release(mut_tls, mut_page_pool);
        //                 };
        //             };
        //         };
        //     };
        // };

        // bsl::ut_scenario{"map_page invalid flags (failure)"} = []() noexcept {
        //     bsl::ut_given{} = []() noexcept {
        //         root_page_table_t mut_rpt{};
        //         page_pool_t mut_page_pool{};
        //         tls_t mut_tls{};
        //         constexpr auto virt{0x1000_umx};
        //         constexpr auto phys{0x1000_umx};
        //         constexpr auto flgs{bsl::safe_umx::failure()};
        //         constexpr auto atrl{MAP_PAGE_NO_AUTO_RELEASE};
        //         bsl::ut_when{} = [&]() noexcept {
        //             bsl::ut_required_step(mut_rpt.initialize(mut_tls, mut_page_pool));
        //             bsl::ut_then{} = [&]() noexcept {
        //                 bsl::ut_check(
        //                     !mut_rpt.map_page(mut_tls, mut_page_pool, virt, phys, flgs, atrl));
        //                 bsl::ut_cleanup{} = [&]() noexcept {
        //                     mut_rpt.release(mut_tls, mut_page_pool);
        //                 };
        //             };
        //         };
        //     };
        // };

        // bsl::ut_scenario{"map_page invalid flags (w/e)"} = []() noexcept {
        //     bsl::ut_given{} = []() noexcept {
        //         root_page_table_t mut_rpt{};
        //         page_pool_t mut_page_pool{};
        //         tls_t mut_tls{};
        //         constexpr auto virt{0x1000_umx};
        //         constexpr auto phys{0x1000_umx};
        //         constexpr auto flgs{MAP_PAGE_WRITE | MAP_PAGE_EXECUTE};
        //         constexpr auto atrl{MAP_PAGE_NO_AUTO_RELEASE};
        //         bsl::ut_when{} = [&]() noexcept {
        //             bsl::ut_required_step(mut_rpt.initialize(mut_tls, mut_page_pool));
        //             bsl::ut_then{} = [&]() noexcept {
        //                 bsl::ut_check(
        //                     !mut_rpt.map_page(mut_tls, mut_page_pool, virt, phys, flgs, atrl));
        //                 bsl::ut_cleanup{} = [&]() noexcept {
        //                     mut_rpt.release(mut_tls, mut_page_pool);
        //                 };
        //             };
        //         };
        //     };
        // };

        // bsl::ut_scenario{"map_page invalid auto_release (failure)"} = []() noexcept {
        //     bsl::ut_given{} = []() noexcept {
        //         root_page_table_t mut_rpt{};
        //         page_pool_t mut_page_pool{};
        //         tls_t mut_tls{};
        //         constexpr auto virt{0x1000_umx};
        //         constexpr auto phys{0x1000_umx};
        //         constexpr auto flgs{MAP_PAGE_READ | MAP_PAGE_WRITE};
        //         constexpr auto atrl{bsl::safe_umx::failure()};
        //         bsl::ut_when{} = [&]() noexcept {
        //             bsl::ut_required_step(mut_rpt.initialize(mut_tls, mut_page_pool));
        //             bsl::ut_then{} = [&]() noexcept {
        //                 bsl::ut_check(
        //                     !mut_rpt.map_page(mut_tls, mut_page_pool, virt, phys, flgs, atrl));
        //                 bsl::ut_cleanup{} = [&]() noexcept {
        //                     mut_rpt.release(mut_tls, mut_page_pool);
        //                 };
        //             };
        //         };
        //     };
        // };

        // bsl::ut_scenario{"map_page invalid auto_release (out of range)"} = []() noexcept {
        //     bsl::ut_given{} = []() noexcept {
        //         root_page_table_t mut_rpt{};
        //         page_pool_t mut_page_pool{};
        //         tls_t mut_tls{};
        //         constexpr auto virt{0x1000_umx};
        //         constexpr auto phys{0x1000_umx};
        //         constexpr auto flgs{MAP_PAGE_READ | MAP_PAGE_WRITE};
        //         constexpr auto atrl{9_umx};
        //         bsl::ut_when{} = [&]() noexcept {
        //             bsl::ut_required_step(mut_rpt.initialize(mut_tls, mut_page_pool));
        //             bsl::ut_then{} = [&]() noexcept {
        //                 bsl::ut_check(
        //                     !mut_rpt.map_page(mut_tls, mut_page_pool, virt, phys, flgs, atrl));
        //                 bsl::ut_cleanup{} = [&]() noexcept {
        //                     mut_rpt.release(mut_tls, mut_page_pool);
        //                 };
        //             };
        //         };
        //     };
        // };

        // bsl::ut_scenario{"map_page twice fails"} = []() noexcept {
        //     bsl::ut_given{} = []() noexcept {
        //         root_page_table_t mut_rpt{};
        //         page_pool_t mut_page_pool{};
        //         tls_t mut_tls{};
        //         constexpr auto virt{0x1000_umx};
        //         constexpr auto phys{0x1000_umx};
        //         constexpr auto flgs{MAP_PAGE_READ | MAP_PAGE_WRITE};
        //         constexpr auto atrl{MAP_PAGE_NO_AUTO_RELEASE};
        //         bsl::ut_when{} = [&]() noexcept {
        //             bsl::ut_required_step(mut_rpt.initialize(mut_tls, mut_page_pool));
        //             bsl::ut_required_step(
        //                 mut_rpt.map_page(mut_tls, mut_page_pool, virt, phys, flgs, atrl));
        //             bsl::ut_then{} = [&]() noexcept {
        //                 bsl::ut_check(
        //                     !mut_rpt.map_page(mut_tls, mut_page_pool, virt, phys, flgs, atrl));
        //                 bsl::ut_cleanup{} = [&]() noexcept {
        //                     mut_rpt.release(mut_tls, mut_page_pool);
        //                 };
        //             };
        //         };
        //     };
        // };

        // bsl::ut_scenario{"map_page add_pdpt allocation fails"} = []() noexcept {
        //     bsl::ut_given{} = []() noexcept {
        //         root_page_table_t mut_rpt{};
        //         page_pool_t mut_page_pool{};
        //         tls_t mut_tls{};
        //         constexpr auto virt{0x1000_umx};
        //         constexpr auto phys{0x1000_umx};
        //         constexpr auto flgs{MAP_PAGE_READ | MAP_PAGE_WRITE};
        //         constexpr auto atrl{MAP_PAGE_NO_AUTO_RELEASE};
        //         bsl::ut_when{} = [&]() noexcept {
        //             bsl::ut_required_step(mut_rpt.initialize(mut_tls, mut_page_pool));
        //             mut_page_pool.set_allocate<pdpt_t>(ALLOCATE_TAG_PDPTS, nullptr, {});
        //             bsl::ut_then{} = [&]() noexcept {
        //                 bsl::ut_check(
        //                     !mut_rpt.map_page(mut_tls, mut_page_pool, virt, phys, flgs, atrl));
        //                 bsl::ut_cleanup{} = [&]() noexcept {
        //                     mut_rpt.release(mut_tls, mut_page_pool);
        //                 };
        //             };
        //         };
        //     };
        // };

        // bsl::ut_scenario{"map_page add_pdpt virt to phys fails"} = []() noexcept {
        //     bsl::ut_given{} = []() noexcept {
        //         root_page_table_t mut_rpt{};
        //         page_pool_t mut_page_pool{};
        //         tls_t mut_tls{};
        //         pdpt_t mut_pdpt{};
        //         constexpr auto virt{0x1000_umx};
        //         constexpr auto phys{0x1000_umx};
        //         constexpr auto flgs{MAP_PAGE_READ | MAP_PAGE_WRITE};
        //         constexpr auto atrl{MAP_PAGE_NO_AUTO_RELEASE};
        //         bsl::ut_when{} = [&]() noexcept {
        //             bsl::ut_required_step(mut_rpt.initialize(mut_tls, mut_page_pool));
        //             mut_page_pool.set_allocate<pdpt_t>(ALLOCATE_TAG_PDPTS, &mut_pdpt, phys);
        //             mut_page_pool.set_virt_to_phys(&mut_pdpt, bsl::safe_umx::failure());
        //             bsl::ut_then{} = [&]() noexcept {
        //                 bsl::ut_check(
        //                     !mut_rpt.map_page(mut_tls, mut_page_pool, virt, phys, flgs, atrl));
        //                 bsl::ut_cleanup{} = [&]() noexcept {
        //                     mut_rpt.release(mut_tls, mut_page_pool);
        //                 };
        //             };
        //         };
        //     };
        // };

        // bsl::ut_scenario{"map_page add_pdt allocation fails"} = []() noexcept {
        //     bsl::ut_given{} = []() noexcept {
        //         root_page_table_t mut_rpt{};
        //         page_pool_t mut_page_pool{};
        //         tls_t mut_tls{};
        //         constexpr auto virt{0x1000_umx};
        //         constexpr auto phys{0x1000_umx};
        //         constexpr auto flgs{MAP_PAGE_READ | MAP_PAGE_WRITE};
        //         constexpr auto atrl{MAP_PAGE_NO_AUTO_RELEASE};
        //         bsl::ut_when{} = [&]() noexcept {
        //             bsl::ut_required_step(mut_rpt.initialize(mut_tls, mut_page_pool));
        //             mut_page_pool.set_allocate<pdt_t>(ALLOCATE_TAG_PDTS, nullptr, {});
        //             bsl::ut_then{} = [&]() noexcept {
        //                 bsl::ut_check(
        //                     !mut_rpt.map_page(mut_tls, mut_page_pool, virt, phys, flgs, atrl));
        //                 bsl::ut_cleanup{} = [&]() noexcept {
        //                     mut_rpt.release(mut_tls, mut_page_pool);
        //                 };
        //             };
        //         };
        //     };
        // };

        // bsl::ut_scenario{"map_page add_pdt virt to phys fails"} = []() noexcept {
        //     bsl::ut_given{} = []() noexcept {
        //         root_page_table_t mut_rpt{};
        //         page_pool_t mut_page_pool{};
        //         tls_t mut_tls{};
        //         pdt_t mut_pdt{};
        //         constexpr auto virt{0x1000_umx};
        //         constexpr auto phys{0x1000_umx};
        //         constexpr auto flgs{MAP_PAGE_READ | MAP_PAGE_WRITE};
        //         constexpr auto atrl{MAP_PAGE_NO_AUTO_RELEASE};
        //         bsl::ut_when{} = [&]() noexcept {
        //             bsl::ut_required_step(mut_rpt.initialize(mut_tls, mut_page_pool));
        //             mut_page_pool.set_allocate<pdt_t>(ALLOCATE_TAG_PDTS, &mut_pdt, phys);
        //             mut_page_pool.set_virt_to_phys(&mut_pdt, bsl::safe_umx::failure());
        //             bsl::ut_then{} = [&]() noexcept {
        //                 bsl::ut_check(
        //                     !mut_rpt.map_page(mut_tls, mut_page_pool, virt, phys, flgs, atrl));
        //                 bsl::ut_cleanup{} = [&]() noexcept {
        //                     mut_rpt.release(mut_tls, mut_page_pool);
        //                 };
        //             };
        //         };
        //     };
        // };

        // bsl::ut_scenario{"map_page add_pt allocation fails"} = []() noexcept {
        //     bsl::ut_given{} = []() noexcept {
        //         root_page_table_t mut_rpt{};
        //         page_pool_t mut_page_pool{};
        //         tls_t mut_tls{};
        //         constexpr auto virt{0x1000_umx};
        //         constexpr auto phys{0x1000_umx};
        //         constexpr auto flgs{MAP_PAGE_READ | MAP_PAGE_WRITE};
        //         constexpr auto atrl{MAP_PAGE_NO_AUTO_RELEASE};
        //         bsl::ut_when{} = [&]() noexcept {
        //             bsl::ut_required_step(mut_rpt.initialize(mut_tls, mut_page_pool));
        //             mut_page_pool.set_allocate<pt_t>(ALLOCATE_TAG_PTS, nullptr, {});
        //             bsl::ut_then{} = [&]() noexcept {
        //                 bsl::ut_check(
        //                     !mut_rpt.map_page(mut_tls, mut_page_pool, virt, phys, flgs, atrl));
        //                 bsl::ut_cleanup{} = [&]() noexcept {
        //                     mut_rpt.release(mut_tls, mut_page_pool);
        //                 };
        //             };
        //         };
        //     };
        // };

        // bsl::ut_scenario{"map_page add_pt virt to phys fails"} = []() noexcept {
        //     bsl::ut_given{} = []() noexcept {
        //         root_page_table_t mut_rpt{};
        //         page_pool_t mut_page_pool{};
        //         tls_t mut_tls{};
        //         pt_t mut_pt{};
        //         constexpr auto virt{0x1000_umx};
        //         constexpr auto phys{0x1000_umx};
        //         constexpr auto flgs{MAP_PAGE_READ | MAP_PAGE_WRITE};
        //         constexpr auto atrl{MAP_PAGE_NO_AUTO_RELEASE};
        //         bsl::ut_when{} = [&]() noexcept {
        //             bsl::ut_required_step(mut_rpt.initialize(mut_tls, mut_page_pool));
        //             mut_page_pool.set_allocate<pt_t>(ALLOCATE_TAG_PTS, &mut_pt, phys);
        //             mut_page_pool.set_virt_to_phys(&mut_pt, bsl::safe_umx::failure());
        //             bsl::ut_then{} = [&]() noexcept {
        //                 bsl::ut_check(
        //                     !mut_rpt.map_page(mut_tls, mut_page_pool, virt, phys, flgs, atrl));
        //                 bsl::ut_cleanup{} = [&]() noexcept {
        //                     mut_rpt.release(mut_tls, mut_page_pool);
        //                 };
        //             };
        //         };
        //     };
        // };

        // bsl::ut_scenario{"map_page map into kernel memory fails"} = []() noexcept {
        //     bsl::ut_given{} = []() noexcept {
        //         root_page_table_t mut_rpt{};
        //         page_pool_t mut_page_pool{};
        //         tls_t mut_tls{};
        //         pml4t_t mut_pml4t{};
        //         constexpr auto pml4t_phys{0x200000_umx};
        //         constexpr auto virt{0x1000_umx};
        //         constexpr auto phys{0x1000_umx};
        //         constexpr auto flgs{MAP_PAGE_READ | MAP_PAGE_WRITE};
        //         constexpr auto atrl{MAP_PAGE_NO_AUTO_RELEASE};
        //         constexpr auto enable{1_umx};
        //         constexpr auto disable{0_umx};
        //         bsl::ut_when{} = [&]() noexcept {
        //             mut_page_pool.set_allocate<pml4t_t>(
        //                 ALLOCATE_TAG_PML4TS, &mut_pml4t, pml4t_phys);
        //             mut_pml4t.entries.front().p = enable.get();
        //             mut_pml4t.entries.front().us = disable.get();
        //             bsl::ut_required_step(mut_rpt.initialize(mut_tls, mut_page_pool));
        //             bsl::ut_then{} = [&]() noexcept {
        //                 bsl::ut_check(
        //                     !mut_rpt.map_page(mut_tls, mut_page_pool, virt, phys, flgs, atrl));
        //                 bsl::ut_cleanup{} = [&]() noexcept {
        //                     mut_rpt.release(mut_tls, mut_page_pool);
        //                 };
        //             };
        //         };
        //     };
        // };

        // bsl::ut_scenario{"map_page read/write success"} = []() noexcept {
        //     bsl::ut_given{} = []() noexcept {
        //         root_page_table_t mut_rpt{};
        //         page_pool_t mut_page_pool{};
        //         tls_t mut_tls{};
        //         constexpr auto virt{0x1000_umx};
        //         constexpr auto phys{0x1000_umx};
        //         constexpr auto flgs{MAP_PAGE_READ | MAP_PAGE_WRITE};
        //         constexpr auto atrl{MAP_PAGE_NO_AUTO_RELEASE};
        //         bsl::ut_when{} = [&]() noexcept {
        //             bsl::ut_required_step(mut_rpt.initialize(mut_tls, mut_page_pool));
        //             bsl::ut_then{} = [&]() noexcept {
        //                 bsl::ut_check(
        //                     mut_rpt.map_page(mut_tls, mut_page_pool, virt, phys, flgs, atrl));
        //                 bsl::ut_cleanup{} = [&]() noexcept {
        //                     mut_rpt.release(mut_tls, mut_page_pool);
        //                 };
        //             };
        //         };
        //     };
        // };

        // bsl::ut_scenario{"map_page read/execute success"} = []() noexcept {
        //     bsl::ut_given{} = []() noexcept {
        //         root_page_table_t mut_rpt{};
        //         page_pool_t mut_page_pool{};
        //         tls_t mut_tls{};
        //         constexpr auto virt{0x1000_umx};
        //         constexpr auto phys{0x1000_umx};
        //         constexpr auto flgs{MAP_PAGE_READ | MAP_PAGE_EXECUTE};
        //         constexpr auto atrl{MAP_PAGE_NO_AUTO_RELEASE};
        //         bsl::ut_when{} = [&]() noexcept {
        //             bsl::ut_required_step(mut_rpt.initialize(mut_tls, mut_page_pool));
        //             bsl::ut_then{} = [&]() noexcept {
        //                 bsl::ut_check(
        //                     mut_rpt.map_page(mut_tls, mut_page_pool, virt, phys, flgs, atrl));
        //                 bsl::ut_cleanup{} = [&]() noexcept {
        //                     mut_rpt.release(mut_tls, mut_page_pool);
        //                 };
        //             };
        //         };
        //     };
        // };

        // bsl::ut_scenario{"map_page multiple virtual address"} = []() noexcept {
        //     bsl::ut_given{} = []() noexcept {
        //         root_page_table_t mut_rpt{};
        //         page_pool_t mut_page_pool{};
        //         tls_t mut_tls{};
        //         constexpr auto virt1{0x1000_umx};
        //         constexpr auto virt2{0x2000_umx};
        //         constexpr auto virt3{0x201000_umx};
        //         constexpr auto virt4{0x202000_umx};
        //         constexpr auto virt5{0x40001000_umx};
        //         constexpr auto virt6{0x40002000_umx};
        //         constexpr auto virt7{0x8000001000_umx};
        //         constexpr auto virt8{0x8000002000_umx};
        //         constexpr auto phys{0x1000_umx};
        //         constexpr auto flgs{MAP_PAGE_READ | MAP_PAGE_WRITE};
        //         constexpr auto atrl{MAP_PAGE_NO_AUTO_RELEASE};
        //         bsl::ut_when{} = [&]() noexcept {
        //             bsl::ut_required_step(mut_rpt.initialize(mut_tls, mut_page_pool));
        //             bsl::ut_then{} = [&]() noexcept {
        //                 bsl::ut_check(
        //                     mut_rpt.map_page(mut_tls, mut_page_pool, virt1, phys, flgs, atrl));
        //                 bsl::ut_check(
        //                     mut_rpt.map_page(mut_tls, mut_page_pool, virt2, phys, flgs, atrl));
        //                 bsl::ut_check(
        //                     mut_rpt.map_page(mut_tls, mut_page_pool, virt3, phys, flgs, atrl));
        //                 bsl::ut_check(
        //                     mut_rpt.map_page(mut_tls, mut_page_pool, virt4, phys, flgs, atrl));
        //                 bsl::ut_check(
        //                     mut_rpt.map_page(mut_tls, mut_page_pool, virt5, phys, flgs, atrl));
        //                 bsl::ut_check(
        //                     mut_rpt.map_page(mut_tls, mut_page_pool, virt6, phys, flgs, atrl));
        //                 bsl::ut_check(
        //                     mut_rpt.map_page(mut_tls, mut_page_pool, virt7, phys, flgs, atrl));
        //                 bsl::ut_check(
        //                     mut_rpt.map_page(mut_tls, mut_page_pool, virt8, phys, flgs, atrl));
        //                 bsl::ut_cleanup{} = [&]() noexcept {
        //                     mut_rpt.release(mut_tls, mut_page_pool);
        //                 };
        //             };
        //         };
        //     };
        // };

        // bsl::ut_scenario{"map_page_unaligned"} = []() noexcept {
        //     bsl::ut_given{} = []() noexcept {
        //         root_page_table_t mut_rpt{};
        //         page_pool_t mut_page_pool{};
        //         tls_t mut_tls{};
        //         constexpr auto virt{0x1042_umx};
        //         constexpr auto phys{0x1000_umx};
        //         constexpr auto flgs{MAP_PAGE_READ | MAP_PAGE_WRITE};
        //         constexpr auto atrl{MAP_PAGE_NO_AUTO_RELEASE};
        //         bsl::ut_when{} = [&]() noexcept {
        //             bsl::ut_required_step(mut_rpt.initialize(mut_tls, mut_page_pool));
        //             bsl::ut_then{} = [&]() noexcept {
        //                 bsl::ut_check(mut_rpt.map_page_unaligned(
        //                     mut_tls, mut_page_pool, virt, phys, flgs, atrl));
        //                 bsl::ut_cleanup{} = [&]() noexcept {
        //                     mut_rpt.release(mut_tls, mut_page_pool);
        //                 };
        //             };
        //         };
        //     };
        // };

        // bsl::ut_scenario{"allocate_page_rw without initialize fails"} = []() noexcept {
        //     bsl::ut_given{} = []() noexcept {
        //         root_page_table_t mut_rpt{};
        //         page_pool_t mut_page_pool{};
        //         tls_t mut_tls{};
        //         constexpr auto virt{0x1000_umx};
        //         constexpr auto atrl{MAP_PAGE_AUTO_RELEASE_STACK};
        //         bsl::ut_then{} = [&]() noexcept {
        //             bsl::ut_check(
        //                 nullptr ==
        //                 mut_rpt.allocate_page_rw<page_t>(mut_tls, mut_page_pool, virt, atrl));
        //             bsl::ut_check(
        //                 nullptr ==
        //                 mut_rpt.allocate_page_rw<ext_tcb_t>(mut_tls, mut_page_pool, virt, atrl));
        //         };
        //     };
        // };

        // bsl::ut_scenario{"allocate_page_rw twice fails (stack)"} = []() noexcept {
        //     bsl::ut_given{} = []() noexcept {
        //         root_page_table_t mut_rpt{};
        //         page_pool_t mut_page_pool{};
        //         tls_t mut_tls{};
        //         constexpr auto virt{0x1000_umx};
        //         constexpr auto atrl{MAP_PAGE_AUTO_RELEASE_STACK};
        //         bsl::ut_when{} = [&]() noexcept {
        //             bsl::ut_required_step(mut_rpt.initialize(mut_tls, mut_page_pool));
        //             bsl::ut_required_step(
        //                 nullptr !=
        //                 mut_rpt.allocate_page_rw<page_t>(mut_tls, mut_page_pool, virt, atrl));
        //             bsl::ut_then{} = [&]() noexcept {
        //                 bsl::ut_check(
        //                     nullptr ==
        //                     mut_rpt.allocate_page_rw<page_t>(mut_tls, mut_page_pool, virt, atrl));
        //                 bsl::ut_cleanup{} = [&]() noexcept {
        //                     mut_rpt.release(mut_tls, mut_page_pool);
        //                 };
        //             };
        //         };
        //     };
        // };

        // bsl::ut_scenario{"allocate_page_rw twice fails (tls)"} = []() noexcept {
        //     bsl::ut_given{} = []() noexcept {
        //         root_page_table_t mut_rpt{};
        //         page_pool_t mut_page_pool{};
        //         tls_t mut_tls{};
        //         constexpr auto virt{0x1000_umx};
        //         constexpr auto atrl{MAP_PAGE_AUTO_RELEASE_TLS};
        //         bsl::ut_when{} = [&]() noexcept {
        //             bsl::ut_required_step(mut_rpt.initialize(mut_tls, mut_page_pool));
        //             bsl::ut_required_step(
        //                 nullptr !=
        //                 mut_rpt.allocate_page_rw<page_t>(mut_tls, mut_page_pool, virt, atrl));
        //             bsl::ut_then{} = [&]() noexcept {
        //                 bsl::ut_check(
        //                     nullptr ==
        //                     mut_rpt.allocate_page_rw<page_t>(mut_tls, mut_page_pool, virt, atrl));
        //                 bsl::ut_cleanup{} = [&]() noexcept {
        //                     mut_rpt.release(mut_tls, mut_page_pool);
        //                 };
        //             };
        //         };
        //     };
        // };

        // bsl::ut_scenario{"allocate_page_rw twice fails (tcb)"} = []() noexcept {
        //     bsl::ut_given{} = []() noexcept {
        //         root_page_table_t mut_rpt{};
        //         page_pool_t mut_page_pool{};
        //         tls_t mut_tls{};
        //         constexpr auto virt{0x1000_umx};
        //         constexpr auto atrl{MAP_PAGE_AUTO_RELEASE_TCB};
        //         bsl::ut_when{} = [&]() noexcept {
        //             bsl::ut_required_step(mut_rpt.initialize(mut_tls, mut_page_pool));
        //             bsl::ut_required_step(
        //                 nullptr !=
        //                 mut_rpt.allocate_page_rw<ext_tcb_t>(mut_tls, mut_page_pool, virt, atrl));
        //             bsl::ut_then{} = [&]() noexcept {
        //                 bsl::ut_check(
        //                     nullptr == mut_rpt.allocate_page_rw<ext_tcb_t>(
        //                                    mut_tls, mut_page_pool, virt, atrl));
        //                 bsl::ut_cleanup{} = [&]() noexcept {
        //                     mut_rpt.release(mut_tls, mut_page_pool);
        //                 };
        //             };
        //         };
        //     };
        // };

        // bsl::ut_scenario{"allocate_page_rw twice fails (elf)"} = []() noexcept {
        //     bsl::ut_given{} = []() noexcept {
        //         root_page_table_t mut_rpt{};
        //         page_pool_t mut_page_pool{};
        //         tls_t mut_tls{};
        //         constexpr auto virt{0x1000_umx};
        //         constexpr auto atrl{MAP_PAGE_AUTO_RELEASE_ELF};
        //         bsl::ut_when{} = [&]() noexcept {
        //             bsl::ut_required_step(mut_rpt.initialize(mut_tls, mut_page_pool));
        //             bsl::ut_required_step(
        //                 nullptr !=
        //                 mut_rpt.allocate_page_rw<page_t>(mut_tls, mut_page_pool, virt, atrl));
        //             bsl::ut_then{} = [&]() noexcept {
        //                 bsl::ut_check(
        //                     nullptr ==
        //                     mut_rpt.allocate_page_rw<page_t>(mut_tls, mut_page_pool, virt, atrl));
        //                 bsl::ut_cleanup{} = [&]() noexcept {
        //                     mut_rpt.release(mut_tls, mut_page_pool);
        //                 };
        //             };
        //         };
        //     };
        // };

        // bsl::ut_scenario{"allocate_page_rw invalid virt (0"} = []() noexcept {
        //     bsl::ut_given{} = []() noexcept {
        //         root_page_table_t mut_rpt{};
        //         page_pool_t mut_page_pool{};
        //         tls_t mut_tls{};
        //         constexpr auto virt{0_umx};
        //         constexpr auto atrl{MAP_PAGE_AUTO_RELEASE_STACK};
        //         bsl::ut_when{} = [&]() noexcept {
        //             bsl::ut_required_step(mut_rpt.initialize(mut_tls, mut_page_pool));
        //             bsl::ut_then{} = [&]() noexcept {
        //                 bsl::ut_check(
        //                     nullptr ==
        //                     mut_rpt.allocate_page_rw<page_t>(mut_tls, mut_page_pool, virt, atrl));
        //                 bsl::ut_check(
        //                     nullptr == mut_rpt.allocate_page_rw<ext_tcb_t>(
        //                                    mut_tls, mut_page_pool, virt, atrl));
        //                 bsl::ut_cleanup{} = [&]() noexcept {
        //                     mut_rpt.release(mut_tls, mut_page_pool);
        //                 };
        //             };
        //         };
        //     };
        // };

        // bsl::ut_scenario{"allocate_page_rw invalid virt (failure)"} = []() noexcept {
        //     bsl::ut_given{} = []() noexcept {
        //         root_page_table_t mut_rpt{};
        //         page_pool_t mut_page_pool{};
        //         tls_t mut_tls{};
        //         constexpr auto virt{bsl::safe_umx::failure()};
        //         constexpr auto atrl{MAP_PAGE_AUTO_RELEASE_STACK};
        //         bsl::ut_when{} = [&]() noexcept {
        //             bsl::ut_required_step(mut_rpt.initialize(mut_tls, mut_page_pool));
        //             bsl::ut_then{} = [&]() noexcept {
        //                 bsl::ut_check(
        //                     nullptr ==
        //                     mut_rpt.allocate_page_rw<page_t>(mut_tls, mut_page_pool, virt, atrl));
        //                 bsl::ut_check(
        //                     nullptr == mut_rpt.allocate_page_rw<ext_tcb_t>(
        //                                    mut_tls, mut_page_pool, virt, atrl));
        //                 bsl::ut_cleanup{} = [&]() noexcept {
        //                     mut_rpt.release(mut_tls, mut_page_pool);
        //                 };
        //             };
        //         };
        //     };
        // };

        // bsl::ut_scenario{"allocate_page_rw invalid virt (page alignment)"} = []() noexcept {
        //     bsl::ut_given{} = []() noexcept {
        //         root_page_table_t mut_rpt{};
        //         page_pool_t mut_page_pool{};
        //         tls_t mut_tls{};
        //         constexpr auto virt{42_umx};
        //         constexpr auto atrl{MAP_PAGE_AUTO_RELEASE_STACK};
        //         bsl::ut_when{} = [&]() noexcept {
        //             bsl::ut_required_step(mut_rpt.initialize(mut_tls, mut_page_pool));
        //             bsl::ut_then{} = [&]() noexcept {
        //                 bsl::ut_check(
        //                     nullptr ==
        //                     mut_rpt.allocate_page_rw<page_t>(mut_tls, mut_page_pool, virt, atrl));
        //                 bsl::ut_check(
        //                     nullptr == mut_rpt.allocate_page_rw<ext_tcb_t>(
        //                                    mut_tls, mut_page_pool, virt, atrl));
        //                 bsl::ut_cleanup{} = [&]() noexcept {
        //                     mut_rpt.release(mut_tls, mut_page_pool);
        //                 };
        //             };
        //         };
        //     };
        // };

        // bsl::ut_scenario{"allocate_page_rw invalid auto_release (0)"} = []() noexcept {
        //     bsl::ut_given{} = []() noexcept {
        //         root_page_table_t mut_rpt{};
        //         page_pool_t mut_page_pool{};
        //         tls_t mut_tls{};
        //         constexpr auto virt{0x1000_umx};
        //         constexpr auto atrl{0_umx};
        //         bsl::ut_when{} = [&]() noexcept {
        //             bsl::ut_required_step(mut_rpt.initialize(mut_tls, mut_page_pool));
        //             bsl::ut_then{} = [&]() noexcept {
        //                 bsl::ut_check(
        //                     nullptr ==
        //                     mut_rpt.allocate_page_rw<page_t>(mut_tls, mut_page_pool, virt, atrl));
        //                 bsl::ut_check(
        //                     nullptr == mut_rpt.allocate_page_rw<ext_tcb_t>(
        //                                    mut_tls, mut_page_pool, virt, atrl));
        //                 bsl::ut_cleanup{} = [&]() noexcept {
        //                     mut_rpt.release(mut_tls, mut_page_pool);
        //                 };
        //             };
        //         };
        //     };
        // };

        // bsl::ut_scenario{"allocate_page_rw invalid auto_release (failure)"} = []() noexcept {
        //     bsl::ut_given{} = []() noexcept {
        //         root_page_table_t mut_rpt{};
        //         page_pool_t mut_page_pool{};
        //         tls_t mut_tls{};
        //         constexpr auto virt{0x1000_umx};
        //         constexpr auto atrl{bsl::safe_umx::failure()};
        //         bsl::ut_when{} = [&]() noexcept {
        //             bsl::ut_required_step(mut_rpt.initialize(mut_tls, mut_page_pool));
        //             bsl::ut_then{} = [&]() noexcept {
        //                 bsl::ut_check(
        //                     nullptr ==
        //                     mut_rpt.allocate_page_rw<page_t>(mut_tls, mut_page_pool, virt, atrl));
        //                 bsl::ut_check(
        //                     nullptr == mut_rpt.allocate_page_rw<ext_tcb_t>(
        //                                    mut_tls, mut_page_pool, virt, atrl));
        //                 bsl::ut_cleanup{} = [&]() noexcept {
        //                     mut_rpt.release(mut_tls, mut_page_pool);
        //                 };
        //             };
        //         };
        //     };
        // };

        // bsl::ut_scenario{"allocate_page_rw virt to phys fails (page_t)"} = []() noexcept {
        //     bsl::ut_given{} = []() noexcept {
        //         root_page_table_t mut_rpt{};
        //         page_pool_t mut_page_pool{};
        //         tls_t mut_tls{};
        //         page_t mut_page{};
        //         constexpr auto virt{0x1000_umx};
        //         constexpr auto atrl{MAP_PAGE_AUTO_RELEASE_STACK};
        //         bsl::ut_when{} = [&]() noexcept {
        //             bsl::ut_required_step(mut_rpt.initialize(mut_tls, mut_page_pool));
        //             mut_page_pool.set_allocate<page_t>(ALLOCATE_TAG_EXT_STACK, &mut_page, {});
        //             mut_page_pool.set_virt_to_phys(&mut_page, bsl::safe_umx::failure());
        //             bsl::ut_then{} = [&]() noexcept {
        //                 bsl::ut_check(
        //                     nullptr ==
        //                     mut_rpt.allocate_page_rw<page_t>(mut_tls, mut_page_pool, virt, atrl));
        //                 bsl::ut_cleanup{} = [&]() noexcept {
        //                     mut_rpt.release(mut_tls, mut_page_pool);
        //                 };
        //             };
        //         };
        //     };
        // };

        // bsl::ut_scenario{"allocate_page_rw virt to phys fails (ext_tcb_t)"} = []() noexcept {
        //     bsl::ut_given{} = []() noexcept {
        //         root_page_table_t mut_rpt{};
        //         page_pool_t mut_page_pool{};
        //         tls_t mut_tls{};
        //         ext_tcb_t mut_page{};
        //         constexpr auto virt{0x1000_umx};
        //         constexpr auto atrl{MAP_PAGE_AUTO_RELEASE_TCB};
        //         bsl::ut_when{} = [&]() noexcept {
        //             bsl::ut_required_step(mut_rpt.initialize(mut_tls, mut_page_pool));
        //             mut_page_pool.set_allocate<ext_tcb_t>(ALLOCATE_TAG_EXT_TCB, &mut_page, {});
        //             mut_page_pool.set_virt_to_phys(&mut_page, bsl::safe_umx::failure());
        //             bsl::ut_then{} = [&]() noexcept {
        //                 bsl::ut_check(
        //                     nullptr == mut_rpt.allocate_page_rw<ext_tcb_t>(
        //                                    mut_tls, mut_page_pool, virt, atrl));
        //                 bsl::ut_cleanup{} = [&]() noexcept {
        //                     mut_rpt.release(mut_tls, mut_page_pool);
        //                 };
        //             };
        //         };
        //     };
        // };

        // bsl::ut_scenario{"allocate_page_rw MAP_PAGE_AUTO_RELEASE_STACK"} = []() noexcept {
        //     bsl::ut_given{} = []() noexcept {
        //         root_page_table_t mut_rpt{};
        //         page_pool_t mut_page_pool{};
        //         tls_t mut_tls{};
        //         constexpr auto virt{0x1000_umx};
        //         constexpr auto atrl{MAP_PAGE_AUTO_RELEASE_STACK};
        //         bsl::ut_when{} = [&]() noexcept {
        //             bsl::ut_required_step(mut_rpt.initialize(mut_tls, mut_page_pool));
        //             bsl::ut_then{} = [&]() noexcept {
        //                 bsl::ut_check(
        //                     nullptr !=
        //                     mut_rpt.allocate_page_rw<page_t>(mut_tls, mut_page_pool, virt, atrl));
        //                 bsl::ut_cleanup{} = [&]() noexcept {
        //                     mut_rpt.release(mut_tls, mut_page_pool);
        //                 };
        //             };
        //         };
        //     };
        // };

        // bsl::ut_scenario{"allocate_page_rw MAP_PAGE_AUTO_RELEASE_TLS"} = []() noexcept {
        //     bsl::ut_given{} = []() noexcept {
        //         root_page_table_t mut_rpt{};
        //         page_pool_t mut_page_pool{};
        //         tls_t mut_tls{};
        //         constexpr auto virt{0x1000_umx};
        //         constexpr auto atrl{MAP_PAGE_AUTO_RELEASE_TLS};
        //         bsl::ut_when{} = [&]() noexcept {
        //             bsl::ut_required_step(mut_rpt.initialize(mut_tls, mut_page_pool));
        //             bsl::ut_then{} = [&]() noexcept {
        //                 bsl::ut_check(
        //                     nullptr !=
        //                     mut_rpt.allocate_page_rw<page_t>(mut_tls, mut_page_pool, virt, atrl));
        //                 bsl::ut_cleanup{} = [&]() noexcept {
        //                     mut_rpt.release(mut_tls, mut_page_pool);
        //                 };
        //             };
        //         };
        //     };
        // };

        // bsl::ut_scenario{"allocate_page_rw MAP_PAGE_AUTO_RELEASE_TCB"} = []() noexcept {
        //     bsl::ut_given{} = []() noexcept {
        //         root_page_table_t mut_rpt{};
        //         page_pool_t mut_page_pool{};
        //         tls_t mut_tls{};
        //         constexpr auto virt{0x1000_umx};
        //         constexpr auto atrl{MAP_PAGE_AUTO_RELEASE_TCB};
        //         bsl::ut_when{} = [&]() noexcept {
        //             bsl::ut_required_step(mut_rpt.initialize(mut_tls, mut_page_pool));
        //             bsl::ut_then{} = [&]() noexcept {
        //                 bsl::ut_check(
        //                     nullptr != mut_rpt.allocate_page_rw<ext_tcb_t>(
        //                                    mut_tls, mut_page_pool, virt, atrl));
        //                 bsl::ut_cleanup{} = [&]() noexcept {
        //                     mut_rpt.release(mut_tls, mut_page_pool);
        //                 };
        //             };
        //         };
        //     };
        // };

        // bsl::ut_scenario{"allocate_page_rw MAP_PAGE_AUTO_RELEASE_ELF"} = []() noexcept {
        //     bsl::ut_given{} = []() noexcept {
        //         root_page_table_t mut_rpt{};
        //         page_pool_t mut_page_pool{};
        //         tls_t mut_tls{};
        //         constexpr auto virt{0x1000_umx};
        //         constexpr auto atrl{MAP_PAGE_AUTO_RELEASE_ELF};
        //         bsl::ut_when{} = [&]() noexcept {
        //             bsl::ut_required_step(mut_rpt.initialize(mut_tls, mut_page_pool));
        //             bsl::ut_then{} = [&]() noexcept {
        //                 bsl::ut_check(
        //                     nullptr !=
        //                     mut_rpt.allocate_page_rw<page_t>(mut_tls, mut_page_pool, virt, atrl));
        //                 bsl::ut_cleanup{} = [&]() noexcept {
        //                     mut_rpt.release(mut_tls, mut_page_pool);
        //                 };
        //             };
        //         };
        //     };
        // };

        // bsl::ut_scenario{"allocate_page_rx without initialize fails"} = []() noexcept {
        //     bsl::ut_given{} = []() noexcept {
        //         root_page_table_t mut_rpt{};
        //         page_pool_t mut_page_pool{};
        //         tls_t mut_tls{};
        //         constexpr auto virt{0x1000_umx};
        //         constexpr auto atrl{MAP_PAGE_AUTO_RELEASE_STACK};
        //         bsl::ut_then{} = [&]() noexcept {
        //             bsl::ut_check(
        //                 nullptr ==
        //                 mut_rpt.allocate_page_rx<page_t>(mut_tls, mut_page_pool, virt, atrl));
        //             bsl::ut_check(
        //                 nullptr ==
        //                 mut_rpt.allocate_page_rx<ext_tcb_t>(mut_tls, mut_page_pool, virt, atrl));
        //         };
        //     };
        // };

        // bsl::ut_scenario{"allocate_page_rx twice fails (stack)"} = []() noexcept {
        //     bsl::ut_given{} = []() noexcept {
        //         root_page_table_t mut_rpt{};
        //         page_pool_t mut_page_pool{};
        //         tls_t mut_tls{};
        //         constexpr auto virt{0x1000_umx};
        //         constexpr auto atrl{MAP_PAGE_AUTO_RELEASE_STACK};
        //         bsl::ut_when{} = [&]() noexcept {
        //             bsl::ut_required_step(mut_rpt.initialize(mut_tls, mut_page_pool));
        //             bsl::ut_required_step(
        //                 nullptr !=
        //                 mut_rpt.allocate_page_rx<page_t>(mut_tls, mut_page_pool, virt, atrl));
        //             bsl::ut_then{} = [&]() noexcept {
        //                 bsl::ut_check(
        //                     nullptr ==
        //                     mut_rpt.allocate_page_rx<page_t>(mut_tls, mut_page_pool, virt, atrl));
        //                 bsl::ut_cleanup{} = [&]() noexcept {
        //                     mut_rpt.release(mut_tls, mut_page_pool);
        //                 };
        //             };
        //         };
        //     };
        // };

        // bsl::ut_scenario{"allocate_page_rx twice fails (tls)"} = []() noexcept {
        //     bsl::ut_given{} = []() noexcept {
        //         root_page_table_t mut_rpt{};
        //         page_pool_t mut_page_pool{};
        //         tls_t mut_tls{};
        //         constexpr auto virt{0x1000_umx};
        //         constexpr auto atrl{MAP_PAGE_AUTO_RELEASE_TLS};
        //         bsl::ut_when{} = [&]() noexcept {
        //             bsl::ut_required_step(mut_rpt.initialize(mut_tls, mut_page_pool));
        //             bsl::ut_required_step(
        //                 nullptr !=
        //                 mut_rpt.allocate_page_rx<page_t>(mut_tls, mut_page_pool, virt, atrl));
        //             bsl::ut_then{} = [&]() noexcept {
        //                 bsl::ut_check(
        //                     nullptr ==
        //                     mut_rpt.allocate_page_rx<page_t>(mut_tls, mut_page_pool, virt, atrl));
        //                 bsl::ut_cleanup{} = [&]() noexcept {
        //                     mut_rpt.release(mut_tls, mut_page_pool);
        //                 };
        //             };
        //         };
        //     };
        // };

        // bsl::ut_scenario{"allocate_page_rx twice fails (tcb)"} = []() noexcept {
        //     bsl::ut_given{} = []() noexcept {
        //         root_page_table_t mut_rpt{};
        //         page_pool_t mut_page_pool{};
        //         tls_t mut_tls{};
        //         constexpr auto virt{0x1000_umx};
        //         constexpr auto atrl{MAP_PAGE_AUTO_RELEASE_TCB};
        //         bsl::ut_when{} = [&]() noexcept {
        //             bsl::ut_required_step(mut_rpt.initialize(mut_tls, mut_page_pool));
        //             bsl::ut_required_step(
        //                 nullptr !=
        //                 mut_rpt.allocate_page_rx<ext_tcb_t>(mut_tls, mut_page_pool, virt, atrl));
        //             bsl::ut_then{} = [&]() noexcept {
        //                 bsl::ut_check(
        //                     nullptr == mut_rpt.allocate_page_rx<ext_tcb_t>(
        //                                    mut_tls, mut_page_pool, virt, atrl));
        //                 bsl::ut_cleanup{} = [&]() noexcept {
        //                     mut_rpt.release(mut_tls, mut_page_pool);
        //                 };
        //             };
        //         };
        //     };
        // };

        // bsl::ut_scenario{"allocate_page_rx twice fails (elf)"} = []() noexcept {
        //     bsl::ut_given{} = []() noexcept {
        //         root_page_table_t mut_rpt{};
        //         page_pool_t mut_page_pool{};
        //         tls_t mut_tls{};
        //         constexpr auto virt{0x1000_umx};
        //         constexpr auto atrl{MAP_PAGE_AUTO_RELEASE_ELF};
        //         bsl::ut_when{} = [&]() noexcept {
        //             bsl::ut_required_step(mut_rpt.initialize(mut_tls, mut_page_pool));
        //             bsl::ut_required_step(
        //                 nullptr !=
        //                 mut_rpt.allocate_page_rx<page_t>(mut_tls, mut_page_pool, virt, atrl));
        //             bsl::ut_then{} = [&]() noexcept {
        //                 bsl::ut_check(
        //                     nullptr ==
        //                     mut_rpt.allocate_page_rx<page_t>(mut_tls, mut_page_pool, virt, atrl));
        //                 bsl::ut_cleanup{} = [&]() noexcept {
        //                     mut_rpt.release(mut_tls, mut_page_pool);
        //                 };
        //             };
        //         };
        //     };
        // };

        // bsl::ut_scenario{"allocate_page_rx invalid virt (0"} = []() noexcept {
        //     bsl::ut_given{} = []() noexcept {
        //         root_page_table_t mut_rpt{};
        //         page_pool_t mut_page_pool{};
        //         tls_t mut_tls{};
        //         constexpr auto virt{0_umx};
        //         constexpr auto atrl{MAP_PAGE_AUTO_RELEASE_STACK};
        //         bsl::ut_when{} = [&]() noexcept {
        //             bsl::ut_required_step(mut_rpt.initialize(mut_tls, mut_page_pool));
        //             bsl::ut_then{} = [&]() noexcept {
        //                 bsl::ut_check(
        //                     nullptr ==
        //                     mut_rpt.allocate_page_rx<page_t>(mut_tls, mut_page_pool, virt, atrl));
        //                 bsl::ut_check(
        //                     nullptr == mut_rpt.allocate_page_rx<ext_tcb_t>(
        //                                    mut_tls, mut_page_pool, virt, atrl));
        //                 bsl::ut_cleanup{} = [&]() noexcept {
        //                     mut_rpt.release(mut_tls, mut_page_pool);
        //                 };
        //             };
        //         };
        //     };
        // };

        // bsl::ut_scenario{"allocate_page_rx invalid virt (failure)"} = []() noexcept {
        //     bsl::ut_given{} = []() noexcept {
        //         root_page_table_t mut_rpt{};
        //         page_pool_t mut_page_pool{};
        //         tls_t mut_tls{};
        //         constexpr auto virt{bsl::safe_umx::failure()};
        //         constexpr auto atrl{MAP_PAGE_AUTO_RELEASE_STACK};
        //         bsl::ut_when{} = [&]() noexcept {
        //             bsl::ut_required_step(mut_rpt.initialize(mut_tls, mut_page_pool));
        //             bsl::ut_then{} = [&]() noexcept {
        //                 bsl::ut_check(
        //                     nullptr ==
        //                     mut_rpt.allocate_page_rx<page_t>(mut_tls, mut_page_pool, virt, atrl));
        //                 bsl::ut_check(
        //                     nullptr == mut_rpt.allocate_page_rx<ext_tcb_t>(
        //                                    mut_tls, mut_page_pool, virt, atrl));
        //                 bsl::ut_cleanup{} = [&]() noexcept {
        //                     mut_rpt.release(mut_tls, mut_page_pool);
        //                 };
        //             };
        //         };
        //     };
        // };

        // bsl::ut_scenario{"allocate_page_rx invalid virt (page alignment)"} = []() noexcept {
        //     bsl::ut_given{} = []() noexcept {
        //         root_page_table_t mut_rpt{};
        //         page_pool_t mut_page_pool{};
        //         tls_t mut_tls{};
        //         constexpr auto virt{42_umx};
        //         constexpr auto atrl{MAP_PAGE_AUTO_RELEASE_STACK};
        //         bsl::ut_when{} = [&]() noexcept {
        //             bsl::ut_required_step(mut_rpt.initialize(mut_tls, mut_page_pool));
        //             bsl::ut_then{} = [&]() noexcept {
        //                 bsl::ut_check(
        //                     nullptr ==
        //                     mut_rpt.allocate_page_rx<page_t>(mut_tls, mut_page_pool, virt, atrl));
        //                 bsl::ut_check(
        //                     nullptr == mut_rpt.allocate_page_rx<ext_tcb_t>(
        //                                    mut_tls, mut_page_pool, virt, atrl));
        //                 bsl::ut_cleanup{} = [&]() noexcept {
        //                     mut_rpt.release(mut_tls, mut_page_pool);
        //                 };
        //             };
        //         };
        //     };
        // };

        // bsl::ut_scenario{"allocate_page_rx invalid auto_release (0)"} = []() noexcept {
        //     bsl::ut_given{} = []() noexcept {
        //         root_page_table_t mut_rpt{};
        //         page_pool_t mut_page_pool{};
        //         tls_t mut_tls{};
        //         constexpr auto virt{0x1000_umx};
        //         constexpr auto atrl{0_umx};
        //         bsl::ut_when{} = [&]() noexcept {
        //             bsl::ut_required_step(mut_rpt.initialize(mut_tls, mut_page_pool));
        //             bsl::ut_then{} = [&]() noexcept {
        //                 bsl::ut_check(
        //                     nullptr ==
        //                     mut_rpt.allocate_page_rx<page_t>(mut_tls, mut_page_pool, virt, atrl));
        //                 bsl::ut_check(
        //                     nullptr == mut_rpt.allocate_page_rx<ext_tcb_t>(
        //                                    mut_tls, mut_page_pool, virt, atrl));
        //                 bsl::ut_cleanup{} = [&]() noexcept {
        //                     mut_rpt.release(mut_tls, mut_page_pool);
        //                 };
        //             };
        //         };
        //     };
        // };

        // bsl::ut_scenario{"allocate_page_rx invalid auto_release (failure)"} = []() noexcept {
        //     bsl::ut_given{} = []() noexcept {
        //         root_page_table_t mut_rpt{};
        //         page_pool_t mut_page_pool{};
        //         tls_t mut_tls{};
        //         constexpr auto virt{0x1000_umx};
        //         constexpr auto atrl{bsl::safe_umx::failure()};
        //         bsl::ut_when{} = [&]() noexcept {
        //             bsl::ut_required_step(mut_rpt.initialize(mut_tls, mut_page_pool));
        //             bsl::ut_then{} = [&]() noexcept {
        //                 bsl::ut_check(
        //                     nullptr ==
        //                     mut_rpt.allocate_page_rx<page_t>(mut_tls, mut_page_pool, virt, atrl));
        //                 bsl::ut_check(
        //                     nullptr == mut_rpt.allocate_page_rx<ext_tcb_t>(
        //                                    mut_tls, mut_page_pool, virt, atrl));
        //                 bsl::ut_cleanup{} = [&]() noexcept {
        //                     mut_rpt.release(mut_tls, mut_page_pool);
        //                 };
        //             };
        //         };
        //     };
        // };

        // bsl::ut_scenario{"allocate_page_rx virt to phys fails (page_t)"} = []() noexcept {
        //     bsl::ut_given{} = []() noexcept {
        //         root_page_table_t mut_rpt{};
        //         page_pool_t mut_page_pool{};
        //         tls_t mut_tls{};
        //         page_t mut_page{};
        //         constexpr auto virt{0x1000_umx};
        //         constexpr auto atrl{MAP_PAGE_AUTO_RELEASE_STACK};
        //         bsl::ut_when{} = [&]() noexcept {
        //             bsl::ut_required_step(mut_rpt.initialize(mut_tls, mut_page_pool));
        //             mut_page_pool.set_allocate<page_t>(ALLOCATE_TAG_EXT_STACK, &mut_page, {});
        //             mut_page_pool.set_virt_to_phys(&mut_page, bsl::safe_umx::failure());
        //             bsl::ut_then{} = [&]() noexcept {
        //                 bsl::ut_check(
        //                     nullptr ==
        //                     mut_rpt.allocate_page_rx<page_t>(mut_tls, mut_page_pool, virt, atrl));
        //                 bsl::ut_cleanup{} = [&]() noexcept {
        //                     mut_rpt.release(mut_tls, mut_page_pool);
        //                 };
        //             };
        //         };
        //     };
        // };

        // bsl::ut_scenario{"allocate_page_rx virt to phys fails (ext_tcb_t)"} = []() noexcept {
        //     bsl::ut_given{} = []() noexcept {
        //         root_page_table_t mut_rpt{};
        //         page_pool_t mut_page_pool{};
        //         tls_t mut_tls{};
        //         ext_tcb_t mut_page{};
        //         constexpr auto virt{0x1000_umx};
        //         constexpr auto atrl{MAP_PAGE_AUTO_RELEASE_TCB};
        //         bsl::ut_when{} = [&]() noexcept {
        //             bsl::ut_required_step(mut_rpt.initialize(mut_tls, mut_page_pool));
        //             mut_page_pool.set_allocate<ext_tcb_t>(ALLOCATE_TAG_EXT_TCB, &mut_page, {});
        //             mut_page_pool.set_virt_to_phys(&mut_page, bsl::safe_umx::failure());
        //             bsl::ut_then{} = [&]() noexcept {
        //                 bsl::ut_check(
        //                     nullptr == mut_rpt.allocate_page_rx<ext_tcb_t>(
        //                                    mut_tls, mut_page_pool, virt, atrl));
        //                 bsl::ut_cleanup{} = [&]() noexcept {
        //                     mut_rpt.release(mut_tls, mut_page_pool);
        //                 };
        //             };
        //         };
        //     };
        // };

        // bsl::ut_scenario{"allocate_page_rx MAP_PAGE_AUTO_RELEASE_STACK"} = []() noexcept {
        //     bsl::ut_given{} = []() noexcept {
        //         root_page_table_t mut_rpt{};
        //         page_pool_t mut_page_pool{};
        //         tls_t mut_tls{};
        //         constexpr auto virt{0x1000_umx};
        //         constexpr auto atrl{MAP_PAGE_AUTO_RELEASE_STACK};
        //         bsl::ut_when{} = [&]() noexcept {
        //             bsl::ut_required_step(mut_rpt.initialize(mut_tls, mut_page_pool));
        //             bsl::ut_then{} = [&]() noexcept {
        //                 bsl::ut_check(
        //                     nullptr !=
        //                     mut_rpt.allocate_page_rx<page_t>(mut_tls, mut_page_pool, virt, atrl));
        //                 bsl::ut_cleanup{} = [&]() noexcept {
        //                     mut_rpt.release(mut_tls, mut_page_pool);
        //                 };
        //             };
        //         };
        //     };
        // };

        // bsl::ut_scenario{"allocate_page_rx MAP_PAGE_AUTO_RELEASE_TLS"} = []() noexcept {
        //     bsl::ut_given{} = []() noexcept {
        //         root_page_table_t mut_rpt{};
        //         page_pool_t mut_page_pool{};
        //         tls_t mut_tls{};
        //         constexpr auto virt{0x1000_umx};
        //         constexpr auto atrl{MAP_PAGE_AUTO_RELEASE_TLS};
        //         bsl::ut_when{} = [&]() noexcept {
        //             bsl::ut_required_step(mut_rpt.initialize(mut_tls, mut_page_pool));
        //             bsl::ut_then{} = [&]() noexcept {
        //                 bsl::ut_check(
        //                     nullptr !=
        //                     mut_rpt.allocate_page_rx<page_t>(mut_tls, mut_page_pool, virt, atrl));
        //                 bsl::ut_cleanup{} = [&]() noexcept {
        //                     mut_rpt.release(mut_tls, mut_page_pool);
        //                 };
        //             };
        //         };
        //     };
        // };

        // bsl::ut_scenario{"allocate_page_rx MAP_PAGE_AUTO_RELEASE_TCB"} = []() noexcept {
        //     bsl::ut_given{} = []() noexcept {
        //         root_page_table_t mut_rpt{};
        //         page_pool_t mut_page_pool{};
        //         tls_t mut_tls{};
        //         constexpr auto virt{0x1000_umx};
        //         constexpr auto atrl{MAP_PAGE_AUTO_RELEASE_TCB};
        //         bsl::ut_when{} = [&]() noexcept {
        //             bsl::ut_required_step(mut_rpt.initialize(mut_tls, mut_page_pool));
        //             bsl::ut_then{} = [&]() noexcept {
        //                 bsl::ut_check(
        //                     nullptr != mut_rpt.allocate_page_rx<ext_tcb_t>(
        //                                    mut_tls, mut_page_pool, virt, atrl));
        //                 bsl::ut_cleanup{} = [&]() noexcept {
        //                     mut_rpt.release(mut_tls, mut_page_pool);
        //                 };
        //             };
        //         };
        //     };
        // };

        // bsl::ut_scenario{"allocate_page_rx MAP_PAGE_AUTO_RELEASE_ELF"} = []() noexcept {
        //     bsl::ut_given{} = []() noexcept {
        //         root_page_table_t mut_rpt{};
        //         page_pool_t mut_page_pool{};
        //         tls_t mut_tls{};
        //         constexpr auto virt{0x1000_umx};
        //         constexpr auto atrl{MAP_PAGE_AUTO_RELEASE_ELF};
        //         bsl::ut_when{} = [&]() noexcept {
        //             bsl::ut_required_step(mut_rpt.initialize(mut_tls, mut_page_pool));
        //             bsl::ut_then{} = [&]() noexcept {
        //                 bsl::ut_check(
        //                     nullptr !=
        //                     mut_rpt.allocate_page_rx<page_t>(mut_tls, mut_page_pool, virt, atrl));
        //                 bsl::ut_cleanup{} = [&]() noexcept {
        //                     mut_rpt.release(mut_tls, mut_page_pool);
        //                 };
        //             };
        //         };
        //     };
        // };

        // bsl::ut_scenario{"add_tables without initialize rpt1"} = []() noexcept {
        //     bsl::ut_given{} = []() noexcept {
        //         root_page_table_t mut_rpt1{};
        //         root_page_table_t mut_rpt2{};
        //         page_pool_t mut_page_pool{};
        //         tls_t mut_tls{};
        //         bsl::ut_when{} = [&]() noexcept {
        //             bsl::ut_required_step(mut_rpt2.initialize(mut_tls, mut_page_pool));
        //             bsl::ut_then{} = [&]() noexcept {
        //                 bsl::ut_check(!mut_rpt2.add_tables(mut_tls, mut_rpt1));
        //                 bsl::ut_cleanup{} = [&]() noexcept {
        //                     mut_rpt2.release(mut_tls, mut_page_pool);
        //                 };
        //             };
        //         };
        //     };
        // };

        // bsl::ut_scenario{"add_tables without initialize rpt2"} = []() noexcept {
        //     bsl::ut_given{} = []() noexcept {
        //         root_page_table_t mut_rpt1{};
        //         root_page_table_t mut_rpt2{};
        //         page_pool_t mut_page_pool{};
        //         tls_t mut_tls{};
        //         constexpr auto virt1{0x1000_umx};
        //         constexpr auto atrl{MAP_PAGE_AUTO_RELEASE_STACK};
        //         bsl::ut_when{} = [&]() noexcept {
        //             bsl::ut_required_step(mut_rpt1.initialize(mut_tls, mut_page_pool));
        //             bsl::ut_required_step(
        //                 nullptr !=
        //                 mut_rpt1.allocate_page_rw<page_t>(mut_tls, mut_page_pool, virt1, atrl));
        //             bsl::ut_then{} = [&]() noexcept {
        //                 bsl::ut_check(!mut_rpt2.add_tables(mut_tls, mut_rpt1));
        //                 bsl::ut_cleanup{} = [&]() noexcept {
        //                     mut_rpt1.release(mut_tls, mut_page_pool);
        //                 };
        //             };
        //         };
        //     };
        // };

        // bsl::ut_scenario{"add_tables"} = []() noexcept {
        //     bsl::ut_given{} = []() noexcept {
        //         root_page_table_t mut_rpt1{};
        //         root_page_table_t mut_rpt2{};
        //         page_pool_t mut_page_pool{};
        //         tls_t mut_tls{};
        //         constexpr auto virt1{0x1000_umx};
        //         constexpr auto virt2{0x2000_umx};
        //         constexpr auto atrl{MAP_PAGE_AUTO_RELEASE_STACK};
        //         bsl::ut_when{} = [&]() noexcept {
        //             bsl::ut_required_step(mut_rpt1.initialize(mut_tls, mut_page_pool));
        //             bsl::ut_required_step(mut_rpt2.initialize(mut_tls, mut_page_pool));
        //             bsl::ut_required_step(
        //                 nullptr !=
        //                 mut_rpt1.allocate_page_rw<page_t>(mut_tls, mut_page_pool, virt1, atrl));
        //             bsl::ut_then{} = [&]() noexcept {
        //                 bsl::ut_check(mut_rpt2.add_tables(mut_tls, mut_rpt1));
        //                 bsl::ut_check(
        //                     nullptr !=
        //                     mut_rpt2.allocate_page_rw<page_t>(mut_tls, mut_page_pool, virt2, atrl));
        //                 bsl::ut_cleanup{} = [&]() noexcept {
        //                     mut_rpt1.release(mut_tls, mut_page_pool);
        //                     mut_rpt2.release(mut_tls, mut_page_pool);
        //                 };
        //             };
        //         };
        //     };
        // };

        // bsl::ut_scenario{"dump without initialize"} = []() noexcept {
        //     bsl::ut_given{} = []() noexcept {
        //         root_page_table_t const rpt{};
        //         page_pool_t const page_pool{};
        //         bsl::ut_then{} = [&]() noexcept {
        //             rpt.dump(page_pool);
        //         };
        //     };
        // };

        // bsl::ut_scenario{"dump"} = []() noexcept {
        //     bsl::ut_given{} = []() noexcept {
        //         root_page_table_t mut_rpt{};
        //         page_pool_t mut_page_pool{};
        //         tls_t mut_tls{};
        //         page_t *pmut_mut_page0{};
        //         page_t *pmut_mut_page1{};
        //         page_t *pmut_mut_page2{};
        //         page_t *pmut_mut_page3{};
        //         page_t *pmut_mut_page4{};
        //         ext_tcb_t *pmut_mut_page5{};
        //         page_t *pmut_mut_page6{};
        //         pml4t_t mut_pml4t{};
        //         constexpr auto pml4t_phys{0x200000_umx};
        //         constexpr auto virt0{0x1000_umx};
        //         constexpr auto virt1{0x2000_umx};
        //         constexpr auto virt2{0x3000_umx};
        //         constexpr auto virt3{0x4000_umx};
        //         constexpr auto virt4{0x5000_umx};
        //         constexpr auto virt5{0x6000_umx};
        //         constexpr auto virt6{0x7000_umx};
        //         bsl::safe_umx mut_phys0{};
        //         bsl::safe_umx mut_phys1{};
        //         bsl::safe_umx mut_phys2{};
        //         bsl::safe_umx mut_phys3{};
        //         bsl::safe_umx mut_phys4{};
        //         bsl::safe_umx mut_phys5{};
        //         bsl::safe_umx mut_phys6{};
        //         constexpr auto flgs0{MAP_PAGE_READ | MAP_PAGE_WRITE};
        //         constexpr auto flgs1{MAP_PAGE_READ | MAP_PAGE_WRITE};
        //         constexpr auto flgs2{MAP_PAGE_READ | MAP_PAGE_WRITE};
        //         constexpr auto flgs3{MAP_PAGE_READ | MAP_PAGE_WRITE};
        //         constexpr auto flgs4{MAP_PAGE_READ | MAP_PAGE_WRITE};
        //         constexpr auto flgs5{MAP_PAGE_READ | MAP_PAGE_WRITE};
        //         constexpr auto flgs6{MAP_PAGE_READ | MAP_PAGE_EXECUTE};
        //         constexpr auto atrl0{MAP_PAGE_NO_AUTO_RELEASE};
        //         constexpr auto atrl1{MAP_PAGE_AUTO_RELEASE_ALLOC_PAGE};
        //         constexpr auto atrl2{MAP_PAGE_AUTO_RELEASE_ALLOC_HEAP};
        //         constexpr auto atrl3{MAP_PAGE_AUTO_RELEASE_STACK};
        //         constexpr auto atrl4{MAP_PAGE_AUTO_RELEASE_TLS};
        //         constexpr auto atrl5{MAP_PAGE_AUTO_RELEASE_TCB};
        //         constexpr auto atrl6{MAP_PAGE_AUTO_RELEASE_ELF};
        //         constexpr auto enable{1_umx};
        //         constexpr auto disable{0_umx};
        //         constexpr auto pml4te_index0{510_umx};
        //         constexpr auto pml4te_index1{511_umx};
        //         bsl::ut_when{} = [&]() noexcept {
        //             pmut_mut_page0 =
        //                 mut_page_pool.allocate<page_t>(mut_tls, ALLOCATE_TAG_BF_MEM_OP_ALLOC_PAGE);
        //             pmut_mut_page1 =
        //                 mut_page_pool.allocate<page_t>(mut_tls, ALLOCATE_TAG_BF_MEM_OP_ALLOC_PAGE);
        //             pmut_mut_page2 =
        //                 mut_page_pool.allocate<page_t>(mut_tls, ALLOCATE_TAG_BF_MEM_OP_ALLOC_HEAP);
        //             pmut_mut_page3 =
        //                 mut_page_pool.allocate<page_t>(mut_tls, ALLOCATE_TAG_EXT_STACK);
        //             pmut_mut_page4 = mut_page_pool.allocate<page_t>(mut_tls, ALLOCATE_TAG_EXT_TLS);
        //             pmut_mut_page5 =
        //                 mut_page_pool.allocate<ext_tcb_t>(mut_tls, ALLOCATE_TAG_EXT_TCB);
        //             pmut_mut_page6 = mut_page_pool.allocate<page_t>(mut_tls, ALLOCATE_TAG_EXT_ELF);
        //             mut_phys0 = mut_page_pool.virt_to_phys(pmut_mut_page0);
        //             mut_phys1 = mut_page_pool.virt_to_phys(pmut_mut_page1);
        //             mut_phys2 = mut_page_pool.virt_to_phys(pmut_mut_page2);
        //             mut_phys3 = mut_page_pool.virt_to_phys(pmut_mut_page3);
        //             mut_phys4 = mut_page_pool.virt_to_phys(pmut_mut_page4);
        //             mut_phys5 = mut_page_pool.virt_to_phys(pmut_mut_page5);
        //             mut_phys6 = mut_page_pool.virt_to_phys(pmut_mut_page6);
        //             mut_page_pool.set_allocate<pml4t_t>(
        //                 ALLOCATE_TAG_PML4TS, &mut_pml4t, pml4t_phys);
        //             mut_pml4t.entries.at_if(pml4te_index0)->p = enable.get();
        //             mut_pml4t.entries.at_if(pml4te_index0)->us = disable.get();
        //             mut_pml4t.entries.at_if(pml4te_index0)->alias = disable.get();
        //             mut_pml4t.entries.at_if(pml4te_index1)->p = enable.get();
        //             mut_pml4t.entries.at_if(pml4te_index1)->us = disable.get();
        //             mut_pml4t.entries.at_if(pml4te_index1)->alias = enable.get();
        //             bsl::ut_required_step(mut_rpt.initialize(mut_tls, mut_page_pool));
        //             bsl::ut_required_step(
        //                 mut_rpt.map_page(mut_tls, mut_page_pool, virt0, mut_phys0, flgs0, atrl0));
        //             bsl::ut_required_step(
        //                 mut_rpt.map_page(mut_tls, mut_page_pool, virt1, mut_phys1, flgs1, atrl1));
        //             bsl::ut_required_step(
        //                 mut_rpt.map_page(mut_tls, mut_page_pool, virt2, mut_phys2, flgs2, atrl2));
        //             bsl::ut_required_step(
        //                 mut_rpt.map_page(mut_tls, mut_page_pool, virt3, mut_phys3, flgs3, atrl3));
        //             bsl::ut_required_step(
        //                 mut_rpt.map_page(mut_tls, mut_page_pool, virt4, mut_phys4, flgs4, atrl4));
        //             bsl::ut_required_step(
        //                 mut_rpt.map_page(mut_tls, mut_page_pool, virt5, mut_phys5, flgs5, atrl5));
        //             bsl::ut_required_step(
        //                 mut_rpt.map_page(mut_tls, mut_page_pool, virt6, mut_phys6, flgs6, atrl6));
        //             bsl::ut_then{} = [&]() noexcept {
        //                 mut_rpt.dump(mut_page_pool);
        //                 bsl::ut_cleanup{} = [&]() noexcept {
        //                     mut_rpt.release(mut_tls, mut_page_pool);
        //                     mut_page_pool.deallocate(
        //                         mut_tls, pmut_mut_page0, ALLOCATE_TAG_BF_MEM_OP_ALLOC_PAGE);
        //                 };
        //             };
        //         };
        //     };
        // };

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
