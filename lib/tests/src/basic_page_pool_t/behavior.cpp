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

#include "../../../src/basic_page_pool_t.hpp"

#include <tls_t.hpp>

#include <bsl/array.hpp>
#include <bsl/convert.hpp>
#include <bsl/discard.hpp>
#include <bsl/safe_idx.hpp>
#include <bsl/safe_integral.hpp>
#include <bsl/span.hpp>
#include <bsl/ut.hpp>

namespace lib
{
    /// @brief used by most of the tests
    constexpr auto POOL_SIZE{3_umx};
    /// @brief only used by the dump test as this is too large for the stack
    constexpr auto LARGE_POOL_SIZE{2048_umx};

    /// @brief used for dump to prevent the unit test from running out of stack
    bsl::array<basic_page_pool_node_t, LARGE_POOL_SIZE.get()> g_mut_pool{};

    /// @brief reduce the verbosity of the tests.
    using nd_t = basic_page_pool_node_t;

    /// <!-- description -->
    ///   @brief Sets up the mut_pool. Note that this similar to how the loader
    ///     would set up the pool, but not the same. The loader's pages will
    ///     be spare in their layout the virtual addresses of each page are
    ///     based on their physical address as they are in the direct map.
    ///     This spare nature of the pages is not a requirement of the page
    ///     mut_pool. All the pool_t cares about is that it is given a linked
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
        using pool_t = basic_page_pool_t<
            tls_t,
            bool,
            HYPERVISOR_MK_DIRECT_MAP_ADDR.get(),
            HYPERVISOR_MK_DIRECT_MAP_SIZE.get()>;

        bsl::ut_scenario{"allocate empty"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                pool_t mut_page_pool{};
                bsl::span<basic_page_pool_node_t> mut_view{};
                tls_t mut_tls{};
                bool mut_return_nullptr{true};
                bsl::ut_when{} = [&]() noexcept {
                    mut_page_pool.initialize(mut_view);
                    bsl::ut_then{} = [&]() noexcept {
                        auto const *const nd{
                            mut_page_pool.allocate<nd_t>(mut_tls, mut_return_nullptr)};
                        bsl::ut_check(nd == nullptr);
                    };
                };
            };
        };

        bsl::ut_scenario{"allocate until empty"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                pool_t mut_page_pool{};
                bsl::array<basic_page_pool_node_t, POOL_SIZE.get()> mut_pool{};
                bsl::span mut_view{mut_pool};
                tls_t mut_tls{};
                bool mut_return_nullptr{true};
                bsl::ut_when{} = [&]() noexcept {
                    initialize_pool(mut_view);
                    mut_page_pool.initialize(mut_view);
                    auto *const pmut_nd0{mut_page_pool.allocate<nd_t>(mut_tls, mut_return_nullptr)};
                    auto *const pmut_nd1{mut_page_pool.allocate<nd_t>(mut_tls, mut_return_nullptr)};
                    auto *const pmut_nd2{mut_page_pool.allocate<nd_t>(mut_tls, mut_return_nullptr)};
                    bsl::ut_required_step(pmut_nd0 == mut_pool.at_if(0_idx));
                    bsl::ut_required_step(pmut_nd1 == mut_pool.at_if(1_idx));
                    bsl::ut_required_step(pmut_nd2 == mut_pool.at_if(2_idx));
                    bsl::ut_then{} = [&]() noexcept {
                        auto *const pmut_nd3{
                            mut_page_pool.allocate<nd_t>(mut_tls, mut_return_nullptr)};
                        bsl::ut_check(pmut_nd3 == nullptr);
                    };
                };
            };
        };

        bsl::ut_scenario{"allocate until empty, then alloc more"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                pool_t mut_page_pool{};
                bsl::array<basic_page_pool_node_t, POOL_SIZE.get()> mut_pool{};
                bsl::span mut_view{mut_pool};
                tls_t mut_tls{};
                bool mut_return_nd{false};
                bsl::ut_when{} = [&]() noexcept {
                    initialize_pool(mut_view);
                    mut_page_pool.initialize(mut_view);
                    auto *const pmut_nd0{mut_page_pool.allocate<nd_t>(mut_tls, mut_return_nd)};
                    auto *const pmut_nd1{mut_page_pool.allocate<nd_t>(mut_tls, mut_return_nd)};
                    auto *const pmut_nd2{mut_page_pool.allocate<nd_t>(mut_tls, mut_return_nd)};
                    bsl::ut_required_step(pmut_nd0 == mut_pool.at_if(0_idx));
                    bsl::ut_required_step(pmut_nd1 == mut_pool.at_if(1_idx));
                    bsl::ut_required_step(pmut_nd2 == mut_pool.at_if(2_idx));
                    bsl::ut_then{} = [&]() noexcept {
                        auto *const pmut_nd3{mut_page_pool.allocate<nd_t>(mut_tls, mut_return_nd)};
                        bsl::ut_check(pmut_nd3 != nullptr);
                        bsl::ut_cleanup{} = [&]() noexcept {
                            // NOLINTNEXTLINE(cppcoreguidelines-owning-memory)
                            delete pmut_nd3;    // GRCOV_EXCLUDE_BR
                        };
                    };
                };
            };
        };

        bsl::ut_scenario{"deallocate"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                pool_t mut_page_pool{};
                bsl::array<basic_page_pool_node_t, POOL_SIZE.get()> mut_pool{};
                bsl::span mut_view{mut_pool};
                tls_t mut_tls{};
                bool mut_return_nullptr{true};
                bsl::ut_when{} = [&]() noexcept {
                    initialize_pool(mut_view);
                    mut_page_pool.initialize(mut_view);
                    auto *const pmut_nd0{mut_page_pool.allocate<nd_t>(mut_tls, mut_return_nullptr)};
                    auto *const pmut_nd1{mut_page_pool.allocate<nd_t>(mut_tls, mut_return_nullptr)};
                    auto *const pmut_nd2{mut_page_pool.allocate<nd_t>(mut_tls, mut_return_nullptr)};
                    bsl::ut_required_step(pmut_nd0 == mut_pool.at_if(0_idx));
                    bsl::ut_required_step(pmut_nd1 == mut_pool.at_if(1_idx));
                    bsl::ut_required_step(pmut_nd2 == mut_pool.at_if(2_idx));
                    bsl::ut_then{} = [&]() noexcept {
                        mut_page_pool.deallocate<nd_t>(mut_tls, pmut_nd0);
                        mut_page_pool.deallocate<nd_t>(mut_tls, pmut_nd1);
                        mut_page_pool.deallocate<nd_t>(mut_tls, pmut_nd2);
                    };
                };
            };
        };

        bsl::ut_scenario{"size"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                pool_t mut_page_pool{};
                bsl::array<basic_page_pool_node_t, POOL_SIZE.get()> mut_pool{};
                bsl::span mut_view{mut_pool};
                auto const expected_size{(mut_pool.size() * HYPERVISOR_PAGE_SIZE).checked()};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_page_pool.size().is_zero());
                    };

                    initialize_pool(mut_view);
                    mut_page_pool.initialize(mut_view);
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_page_pool.size() == expected_size);
                    };
                };
            };
        };

        bsl::ut_scenario{"allocated"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                pool_t mut_page_pool{};
                bsl::array<basic_page_pool_node_t, POOL_SIZE.get()> mut_pool{};
                bsl::span mut_view{mut_pool};
                tls_t mut_tls{};
                bool mut_return_nullptr{true};
                auto const expected0{(0_umx * HYPERVISOR_PAGE_SIZE).checked()};
                auto const expected1{(1_umx * HYPERVISOR_PAGE_SIZE).checked()};
                auto const expected2{(2_umx * HYPERVISOR_PAGE_SIZE).checked()};
                auto const expected3{(3_umx * HYPERVISOR_PAGE_SIZE).checked()};
                bsl::ut_when{} = [&]() noexcept {
                    initialize_pool(mut_view);
                    mut_page_pool.initialize(mut_view);
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_page_pool.allocated(mut_tls) == expected0);
                    };

                    bsl::discard(mut_page_pool.allocate<nd_t>(mut_tls, mut_return_nullptr));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_page_pool.allocated(mut_tls) == expected1);
                    };

                    bsl::discard(mut_page_pool.allocate<nd_t>(mut_tls, mut_return_nullptr));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_page_pool.allocated(mut_tls) == expected2);
                    };

                    bsl::discard(mut_page_pool.allocate<nd_t>(mut_tls, mut_return_nullptr));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_page_pool.allocated(mut_tls) == expected3);
                    };
                };
            };
        };

        bsl::ut_scenario{"remaining"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                pool_t mut_page_pool{};
                bsl::array<basic_page_pool_node_t, POOL_SIZE.get()> mut_pool{};
                bsl::span mut_view{mut_pool};
                tls_t mut_tls{};
                bool mut_return_nullptr{true};
                auto const expected0{(3_umx * HYPERVISOR_PAGE_SIZE).checked()};
                auto const expected1{(2_umx * HYPERVISOR_PAGE_SIZE).checked()};
                auto const expected2{(1_umx * HYPERVISOR_PAGE_SIZE).checked()};
                auto const expected3{(0_umx * HYPERVISOR_PAGE_SIZE).checked()};
                bsl::ut_when{} = [&]() noexcept {
                    initialize_pool(mut_view);
                    mut_page_pool.initialize(mut_view);
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_page_pool.remaining(mut_tls) == expected0);
                    };

                    bsl::discard(mut_page_pool.allocate<nd_t>(mut_tls, mut_return_nullptr));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_page_pool.remaining(mut_tls) == expected1);
                    };

                    bsl::discard(mut_page_pool.allocate<nd_t>(mut_tls, mut_return_nullptr));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_page_pool.remaining(mut_tls) == expected2);
                    };

                    bsl::discard(mut_page_pool.allocate<nd_t>(mut_tls, mut_return_nullptr));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_page_pool.remaining(mut_tls) == expected3);
                    };
                };
            };
        };

        bsl::ut_scenario{"virt_to_phys"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                pool_t const page_pool{};
                constexpr auto min_addr{HYPERVISOR_MK_DIRECT_MAP_ADDR};
                bsl::safe_umx const virt{(min_addr + HYPERVISOR_PAGE_SIZE).checked()};
                bsl::safe_umx const phys{(virt - min_addr).checked()};
                // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
                nd_t const *const addr{reinterpret_cast<nd_t const *>(virt.get())};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(page_pool.virt_to_phys<nd_t>(addr) == phys);
                };
            };
        };

        bsl::ut_scenario{"phys_to_virt"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                pool_t const page_pool{};
                constexpr auto min_addr{HYPERVISOR_MK_DIRECT_MAP_ADDR};
                bsl::safe_umx const virt{(min_addr + HYPERVISOR_PAGE_SIZE).checked()};
                bsl::safe_umx const phys{(virt - min_addr).checked()};
                // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
                nd_t const *const addr{reinterpret_cast<nd_t const *>(virt.get())};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(page_pool.phys_to_virt<nd_t>(phys) == addr);
                };
            };
        };

        bsl::ut_scenario{"dump"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                pool_t mut_page_pool{};
                bsl::array<basic_page_pool_node_t, POOL_SIZE.get()> mut_pool{};
                bsl::span mut_view{mut_pool};
                tls_t mut_tls{};
                bool mut_return_nullptr{true};
                bsl::ut_when{} = [&]() noexcept {
                    initialize_pool(mut_view);
                    mut_page_pool.initialize(mut_view);
                    bsl::discard(mut_page_pool.allocate<nd_t>(mut_tls, mut_return_nullptr));
                    bsl::discard(mut_page_pool.allocate<nd_t>(mut_tls, mut_return_nullptr));
                    bsl::discard(mut_page_pool.allocate<nd_t>(mut_tls, mut_return_nullptr));
                    bsl::ut_then{} = [&]() noexcept {
                        mut_page_pool.dump(mut_tls);
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                pool_t mut_page_pool{};
                bsl::span mut_view{g_mut_pool};
                tls_t mut_tls{};
                bool mut_return_nullptr{true};
                bsl::ut_when{} = [&]() noexcept {
                    initialize_pool(mut_view);
                    mut_page_pool.initialize(mut_view);
                    for (bsl::safe_idx mut_i{}; mut_i < 1048_umx; ++mut_i) {
                        bsl::discard(mut_page_pool.allocate<nd_t>(mut_tls, mut_return_nullptr));
                    }
                    bsl::ut_then{} = [&]() noexcept {
                        mut_page_pool.dump(mut_tls);
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
