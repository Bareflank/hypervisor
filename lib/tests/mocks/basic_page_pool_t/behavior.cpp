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

#include <basic_page_4k_t.hpp>
#include <basic_page_pool_node_t.hpp>
#include <ext_tcb_t.hpp>
#include <tls_t.hpp>
#include <vmcb_t.hpp>
#include <vmcs_t.hpp>

#include <bsl/convert.hpp>
#include <bsl/discard.hpp>
#include <bsl/safe_idx.hpp>
#include <bsl/safe_integral.hpp>
#include <bsl/span.hpp>
#include <bsl/ut.hpp>

namespace lib
{
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
    ///   @tparam T the type to allocate/deallocate
    ///   @return Always returns bsl::exit_success.
    ///
    template<typename T>
    [[nodiscard]] constexpr auto
    tests() noexcept -> bsl::exit_code
    {
        bsl::ut_scenario{"allocate/deallocate"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                basic_page_pool_t<tls_t> mut_page_pool{};
                bsl::ut_when{} = [&]() noexcept {
                    helpers::page_pool_storage_t mut_store{};
                    auto *const pmut_ptr0{mut_page_pool.allocate<T>({})};
                    auto *const pmut_ptr1{mut_page_pool.allocate<T>({})};
                    helpers::set_page_pool_storage<T>(mut_store, mut_page_pool.allocate<T>({}), {});
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(pmut_ptr0 != nullptr);
                        bsl::ut_check(pmut_ptr1 != nullptr);
                        bsl::ut_cleanup{} = [&]() noexcept {
                            mut_page_pool.deallocate({}, pmut_ptr0);
                            mut_page_pool.deallocate({}, pmut_ptr1);
                            helpers::clr_page_pool_storage(mut_page_pool, mut_store);
                        };
                    };
                };
            };
        };

        bsl::ut_scenario{"allocate/deallocate set_allocate"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                basic_page_pool_t<tls_t> mut_page_pool{};
                T mut_virt_backing{};
                T *const pmut_virt{&mut_virt_backing};
                constexpr bsl::safe_umx phys{HYPERVISOR_PAGE_SIZE};
                bsl::ut_when{} = [&]() noexcept {
                    mut_page_pool.set_allocate(pmut_virt, phys);
                    auto const *const ptr{mut_page_pool.allocate<T>({})};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(ptr == pmut_virt);
                        bsl::ut_check(mut_page_pool.virt_to_phys(pmut_virt) == phys);
                        bsl::ut_check(mut_page_pool.phys_to_virt<T>(phys) == pmut_virt);
                        bsl::ut_cleanup{} = [&]() noexcept {
                            mut_page_pool.deallocate({}, ptr);
                        };
                    };
                };

                bsl::ut_when{} = [&]() noexcept {
                    mut_page_pool.set_allocate(pmut_virt, phys);
                    auto *const pmut_ptr{mut_page_pool.allocate<T>({})};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(pmut_ptr == pmut_virt);
                        bsl::ut_check(mut_page_pool.virt_to_phys(pmut_virt) == phys);
                        bsl::ut_check(mut_page_pool.phys_to_virt<T>(phys) == pmut_virt);
                        bsl::ut_cleanup{} = [&]() noexcept {
                            mut_page_pool.deallocate({}, pmut_ptr);
                        };
                    };
                };
            };
        };

        bsl::ut_scenario{"allocate/deallocate set_max"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                basic_page_pool_t<tls_t> mut_page_pool{};
                bsl::ut_when{} = [&]() noexcept {
                    mut_page_pool.set_max(bsl::safe_umx::magic_2());
                    auto *const pmut_ptr0{mut_page_pool.allocate<T>({})};
                    auto *const pmut_ptr1{mut_page_pool.allocate<T>({})};
                    auto *const pmut_ptr2{mut_page_pool.allocate<T>({})};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(pmut_ptr0 != nullptr);
                        bsl::ut_check(pmut_ptr1 != nullptr);
                        bsl::ut_check(pmut_ptr2 == nullptr);
                        bsl::ut_cleanup{} = [&]() noexcept {
                            mut_page_pool.deallocate({}, pmut_ptr0);
                            mut_page_pool.deallocate({}, pmut_ptr1);
                        };
                    };
                };
            };
        };

        bsl::ut_scenario{"size"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                basic_page_pool_t<tls_t> mut_page_pool{};
                auto const expected_size{(3_umx * HYPERVISOR_PAGE_SIZE).checked()};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_page_pool.size().is_zero());
                    };

                    auto *const pmut_ptr0{mut_page_pool.allocate<T>({})};
                    auto *const pmut_ptr1{mut_page_pool.allocate<T>({})};
                    auto *const pmut_ptr2{mut_page_pool.allocate<T>({})};

                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_page_pool.size() == expected_size);
                    };

                    bsl::ut_cleanup{} = [&]() noexcept {
                        mut_page_pool.deallocate({}, pmut_ptr0);
                        mut_page_pool.deallocate({}, pmut_ptr1);
                        mut_page_pool.deallocate({}, pmut_ptr2);
                    };
                };
            };
        };

        bsl::ut_scenario{"allocated"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                basic_page_pool_t<tls_t> mut_page_pool{};
                auto const expected0{(0_umx * HYPERVISOR_PAGE_SIZE).checked()};
                auto const expected1{(1_umx * HYPERVISOR_PAGE_SIZE).checked()};
                auto const expected2{(2_umx * HYPERVISOR_PAGE_SIZE).checked()};
                auto const expected3{(3_umx * HYPERVISOR_PAGE_SIZE).checked()};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_page_pool.allocated({}) == expected0);
                    };

                    auto *const pmut_ptr0{mut_page_pool.allocate<T>({})};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_page_pool.allocated({}) == expected1);
                    };

                    auto *const pmut_ptr1{mut_page_pool.allocate<T>({})};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_page_pool.allocated({}) == expected2);
                    };

                    auto *const pmut_ptr2{mut_page_pool.allocate<T>({})};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_page_pool.allocated({}) == expected3);
                    };

                    bsl::ut_cleanup{} = [&]() noexcept {
                        mut_page_pool.deallocate({}, pmut_ptr0);
                        mut_page_pool.deallocate({}, pmut_ptr1);
                        mut_page_pool.deallocate({}, pmut_ptr2);
                    };
                };
            };
        };

        bsl::ut_scenario{"remaining"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                basic_page_pool_t<tls_t> mut_page_pool{};
                auto const expected{(0_umx * HYPERVISOR_PAGE_SIZE).checked()};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_page_pool.remaining({}) == expected);
                    };

                    auto *const pmut_ptr0{mut_page_pool.allocate<T>({})};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_page_pool.remaining({}) == expected);
                    };

                    auto *const pmut_ptr1{mut_page_pool.allocate<T>({})};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_page_pool.remaining({}) == expected);
                    };

                    auto *const pmut_ptr2{mut_page_pool.allocate<T>({})};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_page_pool.remaining({}) == expected);
                    };

                    bsl::ut_cleanup{} = [&]() noexcept {
                        mut_page_pool.deallocate({}, pmut_ptr0);
                        mut_page_pool.deallocate({}, pmut_ptr1);
                        mut_page_pool.deallocate({}, pmut_ptr2);
                    };
                };
            };
        };

        bsl::ut_scenario{"virt_to_phys/phys_to_virt"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                basic_page_pool_t<tls_t> mut_page_pool{};
                bsl::ut_when{} = [&]() noexcept {
                    auto const *const virt{mut_page_pool.allocate<T>({})};
                    auto const phys{mut_page_pool.virt_to_phys(virt)};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_page_pool.phys_to_virt<T>(phys) == virt);
                    };

                    bsl::ut_cleanup{} = [&]() noexcept {
                        mut_page_pool.deallocate({}, virt);
                    };
                };
            };
        };

        bsl::ut_scenario{"dump"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                basic_page_pool_t<tls_t> mut_page_pool{};
                bsl::ut_then{} = [&]() noexcept {
                    mut_page_pool.dump({});
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

    static_assert(lib::tests<helpers::l3t_t>() == bsl::ut_success());
    static_assert(lib::tests<helpers::l2t_t>() == bsl::ut_success());
    static_assert(lib::tests<helpers::l1t_t>() == bsl::ut_success());
    static_assert(lib::tests<helpers::l0t_t>() == bsl::ut_success());
    static_assert(lib::tests<lib::basic_page_4k_t>() == bsl::ut_success());
    static_assert(lib::tests<lib::basic_page_pool_node_t>() == bsl::ut_success());
    static_assert(lib::tests<mk::ext_tcb_t>() == bsl::ut_success());
    static_assert(lib::tests<mk::vmcb_t>() == bsl::ut_success());
    static_assert(lib::tests<mk::vmcs_t>() == bsl::ut_success());

    bsl::discard(lib::tests<helpers::l3t_t>());
    bsl::discard(lib::tests<helpers::l2t_t>());
    bsl::discard(lib::tests<helpers::l1t_t>());
    bsl::discard(lib::tests<helpers::l0t_t>());
    bsl::discard(lib::tests<lib::basic_page_4k_t>());
    bsl::discard(lib::tests<lib::basic_page_pool_node_t>());
    bsl::discard(lib::tests<mk::ext_tcb_t>());
    bsl::discard(lib::tests<mk::vmcb_t>());
    bsl::discard(lib::tests<mk::vmcs_t>());

    return bsl::ut_success();
}
