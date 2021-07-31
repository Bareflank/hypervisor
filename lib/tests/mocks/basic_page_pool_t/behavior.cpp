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

// clang-format off

#include "basic_page_pool_helpers.hpp"
#include "../../../mocks/basic_page_pool_t.hpp"

// clang-format on

#include <tls_t.hpp>

#include <bsl/array.hpp>
#include <bsl/ut.hpp>

namespace lib
{
    /// @brief reduce the verbosity of the tests.
    using pg_t = basic_page_4k_t;
    /// @brief reduce the verbosity of the tests.
    using nd_t = basic_page_pool_node_t;

    /// <!-- description -->
    ///   @brief Sets up the mut_pool. Note that this similar to how the loader
    ///     would set up the pool, but not the same. The loader's pages will
    ///     be spare in their layout the virtual addresses of each page are
    ///     based on their physical address as they are in the direct map.
    ///     This spare nature of the pages is not a requirement of the page
    ///     mut_pool. All the basic_page_pool_t<tls_t, bool> cares about is that it is given a linked
    ///     list of pages. How those pages are layed out in memory does not
    ///     matter, so in the case of the unit test, we use a simple array.
    ///
    /// <!-- inputs/outputs -->
    ///   @param mut_pool the pool to initialize
    ///
    constexpr void
    initialize_pool(bsl::span<basic_page_pool_node_t> &mut_pool) noexcept
    {
        auto const size{(mut_pool.size() - bsl::safe_umx::magic_1()).checked()};
        for (bsl::safe_idx mut_i{}; mut_i < size; ++mut_i) {
            mut_pool.at_if(mut_i)->next = mut_pool.at_if(mut_i + bsl::safe_idx::magic_1());
        }

        mut_pool.back_if()->next = nullptr;
    }

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
        bsl::ut_scenario{"allocate/deallocate"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                basic_page_pool_t<tls_t> mut_page_pool{};
                tls_t mut_tls{};
                bsl::ut_when{} = [&]() noexcept {
                    auto *const pmut_nd0{mut_page_pool.allocate<nd_t>(mut_tls)};
                    auto *const pmut_nd1{mut_page_pool.allocate<nd_t>(mut_tls)};
                    auto *const pmut_nd2{mut_page_pool.allocate<nd_t>(mut_tls)};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(pmut_nd0 != nullptr);
                        bsl::ut_check(pmut_nd1 != nullptr);
                        bsl::ut_check(pmut_nd2 != nullptr);
                        bsl::ut_cleanup{} = [&]() noexcept {
                            mut_page_pool.deallocate(mut_tls, pmut_nd0);
                            mut_page_pool.deallocate(mut_tls, pmut_nd1);
                            mut_page_pool.deallocate(mut_tls, pmut_nd2);
                        };
                    };
                };
            };
        };

        bsl::ut_scenario{"allocate/deallocate oneshot"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                basic_page_pool_t<tls_t> mut_page_pool{};
                tls_t mut_tls{};
                pg_t mut_virt_backing{};
                pg_t *const pmut_virt{&mut_virt_backing};
                constexpr bsl::safe_umx phys{HYPERVISOR_PAGE_SIZE};
                bsl::ut_when{} = [&]() noexcept {
                    mut_page_pool.set_oneshot(pmut_virt, phys);
                    auto const *const pg{mut_page_pool.allocate<pg_t>(mut_tls)};
                    auto const *const nd{mut_page_pool.allocate<nd_t>(mut_tls)};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(pg == pmut_virt);
                        bsl::ut_check(mut_page_pool.virt_to_phys(pmut_virt) == phys);
                        bsl::ut_check(mut_page_pool.phys_to_virt<pg_t>(phys) == pmut_virt);
                        bsl::ut_check(nd != nullptr);
                        bsl::ut_cleanup{} = [&]() noexcept {
                            mut_page_pool.deallocate(mut_tls, nd);
                            mut_page_pool.deallocate(mut_tls, pg);
                        };
                    };
                };
            };
        };

        bsl::ut_scenario{"size"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                basic_page_pool_t<tls_t> mut_page_pool{};
                tls_t mut_tls{};
                auto const expected_size{(3_umx * HYPERVISOR_PAGE_SIZE).checked()};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_page_pool.size().is_zero());
                    };

                    auto *const pmut_nd0{mut_page_pool.allocate<nd_t>(mut_tls)};
                    auto *const pmut_nd1{mut_page_pool.allocate<nd_t>(mut_tls)};
                    auto *const pmut_nd2{mut_page_pool.allocate<nd_t>(mut_tls)};

                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_page_pool.size() == expected_size);
                    };

                    bsl::ut_cleanup{} = [&]() noexcept {
                        mut_page_pool.deallocate(mut_tls, pmut_nd0);
                        mut_page_pool.deallocate(mut_tls, pmut_nd1);
                        mut_page_pool.deallocate(mut_tls, pmut_nd2);
                    };
                };
            };
        };

        bsl::ut_scenario{"allocated"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                basic_page_pool_t<tls_t> mut_page_pool{};
                tls_t mut_tls{};
                auto const expected0{(0_umx * HYPERVISOR_PAGE_SIZE).checked()};
                auto const expected1{(1_umx * HYPERVISOR_PAGE_SIZE).checked()};
                auto const expected2{(2_umx * HYPERVISOR_PAGE_SIZE).checked()};
                auto const expected3{(3_umx * HYPERVISOR_PAGE_SIZE).checked()};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_page_pool.allocated(mut_tls) == expected0);
                    };

                    auto *const pmut_nd0{mut_page_pool.allocate<nd_t>(mut_tls)};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_page_pool.allocated(mut_tls) == expected1);
                    };

                    auto *const pmut_nd1{mut_page_pool.allocate<nd_t>(mut_tls)};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_page_pool.allocated(mut_tls) == expected2);
                    };

                    auto *const pmut_nd2{mut_page_pool.allocate<nd_t>(mut_tls)};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_page_pool.allocated(mut_tls) == expected3);
                    };

                    bsl::ut_cleanup{} = [&]() noexcept {
                        mut_page_pool.deallocate(mut_tls, pmut_nd0);
                        mut_page_pool.deallocate(mut_tls, pmut_nd1);
                        mut_page_pool.deallocate(mut_tls, pmut_nd2);
                    };
                };
            };
        };

        bsl::ut_scenario{"remaining"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                basic_page_pool_t<tls_t> mut_page_pool{};
                tls_t mut_tls{};
                auto const expected{(0_umx * HYPERVISOR_PAGE_SIZE).checked()};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_page_pool.remaining(mut_tls) == expected);
                    };

                    auto *const pmut_nd0{mut_page_pool.allocate<nd_t>(mut_tls)};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_page_pool.remaining(mut_tls) == expected);
                    };

                    auto *const pmut_nd1{mut_page_pool.allocate<nd_t>(mut_tls)};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_page_pool.remaining(mut_tls) == expected);
                    };

                    auto *const pmut_nd2{mut_page_pool.allocate<nd_t>(mut_tls)};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_page_pool.remaining(mut_tls) == expected);
                    };

                    bsl::ut_cleanup{} = [&]() noexcept {
                        mut_page_pool.deallocate(mut_tls, pmut_nd0);
                        mut_page_pool.deallocate(mut_tls, pmut_nd1);
                        mut_page_pool.deallocate(mut_tls, pmut_nd2);
                    };
                };
            };
        };

        bsl::ut_scenario{"virt_to_phys/phys_to_virt"} = []() noexcept {
            bsl::ut_given{"nd_t"} = []() noexcept {
                basic_page_pool_t<tls_t> mut_page_pool{};
                tls_t mut_tls{};
                bsl::ut_when{} = [&]() noexcept {
                    auto const *const virt{mut_page_pool.allocate<nd_t>(mut_tls)};
                    auto const phys{mut_page_pool.virt_to_phys(virt)};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_page_pool.phys_to_virt<nd_t>(phys) == virt);
                    };

                    bsl::ut_cleanup{} = [&]() noexcept {
                        mut_page_pool.deallocate(mut_tls, virt);
                    };
                };
            };

            bsl::ut_given{"pg_t"} = []() noexcept {
                basic_page_pool_t<tls_t> mut_page_pool{};
                tls_t mut_tls{};
                bsl::ut_when{} = [&]() noexcept {
                    auto const *const virt{mut_page_pool.allocate<pg_t>(mut_tls)};
                    auto const phys{mut_page_pool.virt_to_phys(virt)};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_page_pool.phys_to_virt<pg_t>(phys) == virt);
                    };

                    bsl::ut_cleanup{} = [&]() noexcept {
                        mut_page_pool.deallocate<pg_t>(mut_tls, virt);
                    };
                };
            };
        };

        bsl::ut_scenario{"dump"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                basic_page_pool_t<tls_t> mut_page_pool{};
                tls_t mut_tls{};
                bsl::ut_then{} = [&]() noexcept {
                    mut_page_pool.dump(mut_tls);
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
