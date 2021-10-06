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

#include "../../../src/huge_pool_t.hpp"

#include <basic_page_4k_t.hpp>
#include <page_4k_t.hpp>

#include <bsl/array.hpp>
#include <bsl/convert.hpp>
#include <bsl/discard.hpp>
#include <bsl/safe_idx.hpp>
#include <bsl/safe_integral.hpp>
#include <bsl/span.hpp>
#include <bsl/ut.hpp>

namespace mk
{
    /// @brief used by most of the tests
    constexpr auto POOL_SIZE{4_umx};
    /// @brief only used by the dump test as this is too large for the stack
    constexpr auto LARGE_POOL_SIZE{5000_umx};

    /// @brief used for dump to prevent the unit test from running out of stack
    bsl::array<page_4k_t, LARGE_POOL_SIZE.get()> g_mut_pool{};

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
                huge_pool_t mut_huge_pool{};
                bsl::array<page_4k_t, POOL_SIZE.get()> mut_pool{};
                bsl::span mut_view{mut_pool};
                bsl::ut_then{} = [&]() noexcept {
                    mut_huge_pool.initialize(mut_view);
                };
            };
        };

        bsl::ut_scenario{"allocate until full"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                huge_pool_t mut_huge_pool{};
                bsl::array<page_4k_t, POOL_SIZE.get()> mut_pool{};
                bsl::span mut_view{mut_pool};
                constexpr auto size{2_umx};
                bsl::ut_when{} = [&]() noexcept {
                    mut_huge_pool.initialize(mut_view);
                    auto const alloc1{mut_huge_pool.allocate({}, size)};
                    auto const alloc2{mut_huge_pool.allocate({}, size)};
                    auto const alloc3{mut_huge_pool.allocate({}, size)};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(alloc1.is_valid());
                        bsl::ut_check(alloc2.is_valid());
                        bsl::ut_check(alloc3.is_invalid());
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        mut_huge_pool.deallocate({}, alloc1);
                        mut_huge_pool.deallocate({}, alloc2);
                        mut_huge_pool.deallocate({}, alloc3);
                    };
                };
            };
        };

        bsl::ut_scenario{"size"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                huge_pool_t mut_huge_pool{};
                bsl::array<page_4k_t, POOL_SIZE.get()> mut_pool{};
                bsl::span mut_view{mut_pool};
                auto const expected_size{(mut_pool.size() * HYPERVISOR_PAGE_SIZE).checked()};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_huge_pool.size().is_zero());
                    };

                    mut_huge_pool.initialize(mut_view);
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_huge_pool.size() == expected_size);
                    };
                };
            };
        };

        bsl::ut_scenario{"allocated"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                huge_pool_t mut_huge_pool{};
                bsl::array<page_4k_t, POOL_SIZE.get()> mut_pool{};
                bsl::span mut_view{mut_pool};
                constexpr auto size{2_umx};
                auto const expected0{(0_umx * HYPERVISOR_PAGE_SIZE).checked()};
                auto const expected1{(2_umx * HYPERVISOR_PAGE_SIZE).checked()};
                auto const expected2{(4_umx * HYPERVISOR_PAGE_SIZE).checked()};
                bsl::ut_when{} = [&]() noexcept {
                    mut_huge_pool.initialize(mut_view);
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_huge_pool.allocated({}) == expected0);
                    };

                    bsl::discard(mut_huge_pool.allocate({}, size));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_huge_pool.allocated({}) == expected1);
                    };

                    bsl::discard(mut_huge_pool.allocate({}, size));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_huge_pool.allocated({}) == expected2);
                    };
                };
            };
        };

        bsl::ut_scenario{"remaining"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                huge_pool_t mut_huge_pool{};
                bsl::array<page_4k_t, POOL_SIZE.get()> mut_pool{};
                bsl::span mut_view{mut_pool};
                constexpr auto size{2_umx};
                auto const expected0{(4_umx * HYPERVISOR_PAGE_SIZE).checked()};
                auto const expected1{(2_umx * HYPERVISOR_PAGE_SIZE).checked()};
                auto const expected2{(0_umx * HYPERVISOR_PAGE_SIZE).checked()};
                bsl::ut_when{} = [&]() noexcept {
                    mut_huge_pool.initialize(mut_view);
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_huge_pool.remaining({}) == expected0);
                    };

                    bsl::discard(mut_huge_pool.allocate({}, size));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_huge_pool.remaining({}) == expected1);
                    };

                    bsl::discard(mut_huge_pool.allocate({}, size));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_huge_pool.remaining({}) == expected2);
                    };
                };
            };
        };

        bsl::ut_scenario{"virt_to_phys"} = [&]() noexcept {
            bsl::ut_given_at_runtime{} = [&]() noexcept {
                huge_pool_t const huge_pool{};
                constexpr auto min_addr{HYPERVISOR_MK_DIRECT_MAP_ADDR};
                bsl::safe_umx const virt{(min_addr + HYPERVISOR_PAGE_SIZE).checked()};
                bsl::safe_umx const phys{(virt - min_addr).checked()};
                // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
                auto const *const addr{reinterpret_cast<page_4k_t const *>(virt.get())};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(huge_pool.virt_to_phys<page_4k_t>(addr) == phys);
                };
            };
        };

        bsl::ut_scenario{"phys_to_virt"} = [&]() noexcept {
            bsl::ut_given_at_runtime{} = [&]() noexcept {
                huge_pool_t const huge_pool{};
                constexpr auto min_addr{HYPERVISOR_MK_DIRECT_MAP_ADDR};
                bsl::safe_umx const virt{(min_addr + HYPERVISOR_PAGE_SIZE).checked()};
                bsl::safe_umx const phys{(virt - min_addr).checked()};
                // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
                auto const *const addr{reinterpret_cast<page_4k_t const *>(virt.get())};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(huge_pool.phys_to_virt<page_4k_t>(phys) == addr);
                };
            };
        };

        bsl::ut_scenario{"dump"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                huge_pool_t mut_huge_pool{};
                bsl::array<page_4k_t, POOL_SIZE.get()> mut_pool{};
                bsl::span mut_view{mut_pool};
                constexpr auto size{2_umx};
                bsl::ut_when{} = [&]() noexcept {
                    mut_huge_pool.initialize(mut_view);
                    bsl::discard(mut_huge_pool.allocate({}, size));
                    bsl::ut_then{} = [&]() noexcept {
                        mut_huge_pool.dump({});
                    };
                };
            };

            bsl::ut_given_at_runtime{} = [&]() noexcept {
                huge_pool_t mut_huge_pool{};
                bsl::span mut_view{g_mut_pool};
                constexpr auto size{2_umx};
                bsl::ut_when{} = [&]() noexcept {
                    mut_huge_pool.initialize(mut_view);
                    for (bsl::safe_idx mut_i{}; mut_i < 2048_umx; ++mut_i) {
                        bsl::discard(mut_huge_pool.allocate({}, size));
                    }
                    bsl::ut_then{} = [&]() noexcept {
                        mut_huge_pool.dump({});
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
