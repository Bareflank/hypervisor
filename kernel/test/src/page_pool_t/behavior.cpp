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

#include "../../../src/page_pool_t.hpp"

#include <bsl/array.hpp>
#include <bsl/ut.hpp>

/// NOTE:
/// - The page pool is unit tested using constexpr. How this works is really
///   simple. There are two different points of view to pay attention to here:
///   - The unit test for the page pool (this file)
///   - The unit test for something else that uses the page pool
/// - This unit test is responsible for unit testing the page pool itself, and
///   it has to do this as a constexpr. This ensures that we do not invoke
///   undefined behavior. This is really important as the allocator is not only
///   managing memory in a way that could lead to really bad things if not
///   handled correctly, it is also responsible for defining the lifetime of
///   an allocated object, and the constexpr nature of this unit test ensures
///   that this lifetime is handled properly. This unit test however cannot
///   test the allocation of anything other than nodes. Meaning, the allocator
///   allocates page_pool_node_t nodes, and deallocates them. The
///   runtime logic allocates things like page tables and uint8 buffers for
///   random memory used by an extension. In a constexpr however, you cannot
///   change the type of memory. So for example, the page pool is managing a
///   linked list of pages, with each page in the list being a node. The page
///   pool cannot change a node from a node to a page table. This is not
///   allowed from a constexpr. That is not because it invokes UB, it is just
///   a rule that we must overcome. Interestingly though, we are not interested
///   in allocating page tables from this unit test. Instead, we are interested
///   in testing the logic itself, as well as things like object lifetime.
///   So, we only allocate nodes. This prevents a node from being changed to
///   something other than a node, which makes the unit test compile.
/// - The other point of view is from code that uses the page mut_pool. That code
///   will use a mocked version of the page mut_pool. So when that code calls
///   allocate from the page pool, it will allocate memory using new and then
///   deallocate memory using delete. These operators are allowed from a
///   constexpr, and they properly construct as required. Therefor, that mocked
///   version of the page pool can also be used in a constexpr, which means
///   that UB cannot occur there are well, including forgetting to deallocate
///   or deallocating using the wrong memory or wrong types.
/// - Using this approach, all of the code can be unit tested as a constexpr,
///   even with a custom allocator.
/// - Finally virt to phys translations. It would be possible to implement
///   these in a way that is also constexpr friendly as well.
///   - To convert a virtual address to a physical address, you would simply
///     use a null bsl::uint8 pointer. You can then use the address of the
///     direct map as the index into this array and grab it's address, and
///     perform pointer arithmetic to calculate the pointer version of the
///     physical address as follows:
///
///     @code
///     T *base{};
///     auto *const addr{&base[(HYPERVISOR_MK_PAGE_POOL_ADDR / HYPERVISOR_PAGE_SIZE).get()]};
///     auto *const phys{virt - addr};
///     for (bsl::safe_uintmax i{}; i < bsl::safe_uintmax::max(); ++i) {
///         if (&base[i.get()] == phys) {
///             return i;
///         }
///     }
///
///     return bsl::safe_uintmax::failure();
///     @endcode
///
///     This example works because we never actually dereference the nullptr,
///     we are simply using it to perform pointer arithmetic. We need the loop
///     because we have no way of converting the calculated pointer to an
///     integral, so we loop until we find it. Even with some optimizations
///     this would be slow. It would work because we are not using any casts
///     to perform the translation, but it would be slow.
///   - To convert a physical address to a virtual addres, we can simply do
///     the same thing but in reverse, only this time the loop is not needed
///     as we can simply return the address of base at the calculated index.
///
///   Although it is possible to make these constexpr friendly, there are a
///   couple of reasons why this would be a bad idea:
///   - Well, its slow, which is pretty obvious
///   - The translation is simple arithmetic. There is nothing UB to worry
///     about here. We are simply returning a calculation. If there is no
///     need to worry about UB, there is no need to worry about constexpr
///     here. The only UB to worry about is an overflow.
///   - It's not clear what would happen with the above arithmetic here if
///     an overflow were to occur. During the unit test, this type of overflow
///     would likely be detected, but at runtime, it wouldn't be and the
///     result would likely be UB. Using a cast, we can ensure that the pointer
///     becomes a safe integral, which means that any overflow, either at
///     compile time or runtime would be detected.
///   - The above code is no more compliant with AUTOSAR than the use of the
///     cast is. The above code performs pointer arithmetic which is also not
///     allowed. It is constexpr friendly, but that is not a requirement for
///     AUTOSAR, so no matter what, we would need an exception for this
///     operation.
///   - The only code that would need to be runtime only is in this unit test.
///     Any code that uses a mocked version of the page pool can use a map
///     of the allocated pointers to generate a physical address that can
///     then be used by the code in a constexpr, so at the end of the day,
///     yes it can be done, but no it should not be.
///

namespace mk
{
    /// @brief used by most of the tests
    constexpr auto POOL_SIZE{3_umax};
    /// @brief used by the fill tag buffer test
    constexpr auto TAG_POOL_SIZE{11_umax};
    /// @brief only used by the dump test as this is too large for the stack
    constexpr auto LARGE_POOL_SIZE{2048_umax};

    /// @brief used for dump to prevent the unit test from running out of stack
    bsl::array<page_pool_node_t, LARGE_POOL_SIZE.get()> g_mut_pool{};

    /// @brief reduce the verbosity of the tests.
    using nd_t = page_pool_node_t;

    /// <!-- description -->
    ///   @brief Sets up the mut_pool. Note that this similar to how the loader
    ///     would set up the pool, but not the same. The loader's pages will
    ///     be spare in their layout the virtual addresses of each page are
    ///     based on their physical address as they are in the direct map.
    ///     This spare nature of the pages is not a requirement of the page
    ///     mut_pool. All the page pool cares about is that it is given a linked
    ///     list of pages. How those pages are layed out in memory does not
    ///     matter, so in the case of the unit test, we use a simple array.
    ///
    /// <!-- inputs/outputs -->
    ///   @param mut_pool the pool to initialize
    ///
    constexpr void
    initialize_pool(bsl::span<page_pool_node_t> &mut_pool) noexcept
    {
        constexpr auto one{1_umax};
        for (bsl::safe_uintmax mut_i{}; mut_i < mut_pool.size() - one; ++mut_i) {
            mut_pool.at_if(mut_i)->next = mut_pool.at_if(mut_i + one);
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
        bsl::ut_scenario{"allocate invalid tag"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                page_pool_t mut_page_pool{};
                bsl::array<page_pool_node_t, POOL_SIZE.get()> mut_pool{};
                bsl::span mut_view{mut_pool};
                tls_t mut_tls{};
                bsl::ut_when{} = [&]() noexcept {
                    initialize_pool(mut_view);
                    mut_page_pool.initialize(mut_view);
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_page_pool.allocate<nd_t>(mut_tls, "") == nullptr);
                    };
                };
            };
        };

        bsl::ut_scenario{"allocate empty"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                page_pool_t mut_page_pool{};
                bsl::span<page_pool_node_t> mut_view{};
                tls_t mut_tls{};
                bsl::ut_when{} = [&]() noexcept {
                    mut_page_pool.initialize(mut_view);
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_page_pool.allocate<nd_t>(mut_tls, "*") == nullptr);
                    };
                };
            };
        };

        bsl::ut_scenario{"allocate until empty"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                page_pool_t mut_page_pool{};
                bsl::array<page_pool_node_t, POOL_SIZE.get()> mut_pool{};
                bsl::span mut_view{mut_pool};
                tls_t mut_tls{};
                bsl::ut_when{} = [&]() noexcept {
                    initialize_pool(mut_view);
                    mut_page_pool.initialize(mut_view);
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            mut_page_pool.allocate<nd_t>(mut_tls, "*") == mut_pool.at_if(0_umax));
                        bsl::ut_check(
                            mut_page_pool.allocate<nd_t>(mut_tls, "*") == mut_pool.at_if(1_umax));
                        bsl::ut_check(
                            mut_page_pool.allocate<nd_t>(mut_tls, "*") == mut_pool.at_if(2_umax));
                        bsl::ut_check(mut_page_pool.allocate<nd_t>(mut_tls, "*") == nullptr);
                    };
                };
            };
        };

        bsl::ut_scenario{"allocate until tags are full"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                page_pool_t mut_page_pool{};
                bsl::array<page_pool_node_t, TAG_POOL_SIZE.get()> mut_pool{};
                bsl::span mut_view{mut_pool};
                tls_t mut_tls{};
                bsl::ut_when{} = [&]() noexcept {
                    initialize_pool(mut_view);
                    mut_page_pool.initialize(mut_view);
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            mut_page_pool.allocate<nd_t>(mut_tls, "0") == mut_pool.at_if(0_umax));
                        bsl::ut_check(
                            mut_page_pool.allocate<nd_t>(mut_tls, "1") == mut_pool.at_if(1_umax));
                        bsl::ut_check(
                            mut_page_pool.allocate<nd_t>(mut_tls, "2") == mut_pool.at_if(2_umax));
                        bsl::ut_check(
                            mut_page_pool.allocate<nd_t>(mut_tls, "3") == mut_pool.at_if(3_umax));
                        bsl::ut_check(
                            mut_page_pool.allocate<nd_t>(mut_tls, "4") == mut_pool.at_if(4_umax));
                        bsl::ut_check(
                            mut_page_pool.allocate<nd_t>(mut_tls, "5") == mut_pool.at_if(5_umax));
                        bsl::ut_check(
                            mut_page_pool.allocate<nd_t>(mut_tls, "6") == mut_pool.at_if(6_umax));
                        bsl::ut_check(
                            mut_page_pool.allocate<nd_t>(mut_tls, "7") == mut_pool.at_if(7_umax));
                        bsl::ut_check(
                            mut_page_pool.allocate<nd_t>(mut_tls, "8") == mut_pool.at_if(8_umax));
                        bsl::ut_check(
                            mut_page_pool.allocate<nd_t>(mut_tls, "9") == mut_pool.at_if(9_umax));
                        bsl::ut_check(mut_page_pool.allocate<nd_t>(mut_tls, "42") == nullptr);
                    };
                };
            };
        };

        bsl::ut_scenario{"deallocate nullptr"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                page_pool_t mut_page_pool{};
                bsl::array<page_pool_node_t, POOL_SIZE.get()> mut_pool{};
                bsl::span mut_view{mut_pool};
                tls_t mut_tls{};
                nd_t *pmut_mut_node0{};
                bsl::ut_when{} = [&]() noexcept {
                    initialize_pool(mut_view);
                    mut_page_pool.initialize(mut_view);
                    pmut_mut_node0 = mut_page_pool.allocate<nd_t>(mut_tls, "*");
                    bsl::ut_required_step(
                        mut_page_pool.allocated(mut_tls, "*") == HYPERVISOR_PAGE_SIZE);
                    bsl::ut_then{} = [&]() noexcept {
                        mut_page_pool.deallocate<nd_t>(mut_tls, nullptr, "*");
                        bsl::ut_check(
                            mut_page_pool.allocated(mut_tls, "*") == HYPERVISOR_PAGE_SIZE);
                    };
                };
            };
        };

        bsl::ut_scenario{"deallocate invalid tag"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                page_pool_t mut_page_pool{};
                bsl::array<page_pool_node_t, POOL_SIZE.get()> mut_pool{};
                bsl::span mut_view{mut_pool};
                tls_t mut_tls{};
                nd_t *pmut_mut_node0{};
                bsl::ut_when{} = [&]() noexcept {
                    initialize_pool(mut_view);
                    mut_page_pool.initialize(mut_view);
                    pmut_mut_node0 = mut_page_pool.allocate<nd_t>(mut_tls, "*");
                    bsl::ut_required_step(
                        mut_page_pool.allocated(mut_tls, "*") == HYPERVISOR_PAGE_SIZE);
                    bsl::ut_then{} = [&]() noexcept {
                        mut_page_pool.deallocate<nd_t>(mut_tls, pmut_mut_node0, "42");
                        bsl::ut_check(
                            mut_page_pool.allocated(mut_tls, "*") == HYPERVISOR_PAGE_SIZE);
                    };
                };
            };
        };

        bsl::ut_scenario{"deallocate"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                page_pool_t mut_page_pool{};
                bsl::array<page_pool_node_t, POOL_SIZE.get()> mut_pool{};
                bsl::span mut_view{mut_pool};
                tls_t mut_tls{};
                nd_t *pmut_mut_node0{};
                bsl::ut_when{} = [&]() noexcept {
                    initialize_pool(mut_view);
                    mut_page_pool.initialize(mut_view);
                    pmut_mut_node0 = mut_page_pool.allocate<nd_t>(mut_tls, "*");
                    bsl::ut_required_step(
                        mut_page_pool.allocated(mut_tls, "*") == HYPERVISOR_PAGE_SIZE);
                    bsl::ut_then{} = [&]() noexcept {
                        mut_page_pool.deallocate<nd_t>(mut_tls, pmut_mut_node0, "*");
                        bsl::ut_check(mut_page_pool.allocated(mut_tls, "*").is_zero());
                    };
                };
            };
        };

        bsl::ut_scenario{"deallocate from empty"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                page_pool_t mut_page_pool{};
                bsl::array<page_pool_node_t, POOL_SIZE.get()> mut_pool{};
                bsl::span mut_view{mut_pool};
                tls_t mut_tls{};
                nd_t *pmut_mut_node0{};
                nd_t *pmut_mut_node1{};
                nd_t *pmut_mut_node2{};
                bsl::ut_when{} = [&]() noexcept {
                    initialize_pool(mut_view);
                    mut_page_pool.initialize(mut_view);
                    pmut_mut_node0 = mut_page_pool.allocate<nd_t>(mut_tls, "*");
                    pmut_mut_node1 = mut_page_pool.allocate<nd_t>(mut_tls, "*");
                    pmut_mut_node2 = mut_page_pool.allocate<nd_t>(mut_tls, "*");
                    bsl::ut_required_step(mut_page_pool.allocate<nd_t>(mut_tls, "*") == nullptr);
                    bsl::ut_then{} = [&]() noexcept {
                        mut_page_pool.deallocate<nd_t>(mut_tls, pmut_mut_node2, "*");
                        mut_page_pool.deallocate<nd_t>(mut_tls, pmut_mut_node1, "*");
                        mut_page_pool.deallocate<nd_t>(mut_tls, pmut_mut_node0, "*");
                        bsl::ut_check(mut_page_pool.allocated(mut_tls, "*").is_zero());
                    };
                };
            };
        };

        bsl::ut_scenario{"deallocate from empty in reverse order"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                page_pool_t mut_page_pool{};
                bsl::array<page_pool_node_t, POOL_SIZE.get()> mut_pool{};
                bsl::span mut_view{mut_pool};
                tls_t mut_tls{};
                nd_t *pmut_mut_node0{};
                nd_t *pmut_mut_node1{};
                nd_t *pmut_mut_node2{};
                bsl::ut_when{} = [&]() noexcept {
                    initialize_pool(mut_view);
                    mut_page_pool.initialize(mut_view);
                    pmut_mut_node0 = mut_page_pool.allocate<nd_t>(mut_tls, "*");
                    pmut_mut_node1 = mut_page_pool.allocate<nd_t>(mut_tls, "*");
                    pmut_mut_node2 = mut_page_pool.allocate<nd_t>(mut_tls, "*");
                    bsl::ut_required_step(mut_page_pool.allocate<nd_t>(mut_tls, "*") == nullptr);
                    bsl::ut_then{} = [&]() noexcept {
                        mut_page_pool.deallocate<nd_t>(mut_tls, pmut_mut_node0, "*");
                        mut_page_pool.deallocate<nd_t>(mut_tls, pmut_mut_node1, "*");
                        mut_page_pool.deallocate<nd_t>(mut_tls, pmut_mut_node2, "*");
                        bsl::ut_check(mut_page_pool.allocated(mut_tls, "*").is_zero());
                    };
                };
            };
        };

        bsl::ut_scenario{"allocated"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                page_pool_t mut_page_pool{};
                bsl::array<page_pool_node_t, POOL_SIZE.get()> mut_pool{};
                bsl::span mut_view{mut_pool};
                tls_t mut_tls{};
                constexpr auto expected1{HYPERVISOR_PAGE_SIZE * 1_umax};
                constexpr auto expected2{HYPERVISOR_PAGE_SIZE * 2_umax};
                constexpr auto expected3{HYPERVISOR_PAGE_SIZE * 3_umax};
                bsl::ut_when{} = [&]() noexcept {
                    initialize_pool(mut_view);
                    mut_page_pool.initialize(mut_view);
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(!mut_page_pool.allocated(mut_tls, ""));
                        bsl::ut_check(!mut_page_pool.allocated(mut_tls, "*"));
                        bsl::ut_check(
                            mut_page_pool.allocate<nd_t>(mut_tls, "*") == mut_pool.at_if(0_umax));
                        bsl::ut_check(mut_page_pool.allocated(mut_tls, "*") == expected1);
                        bsl::ut_check(
                            mut_page_pool.allocate<nd_t>(mut_tls, "*") == mut_pool.at_if(1_umax));
                        bsl::ut_check(mut_page_pool.allocated(mut_tls, "*") == expected2);
                        bsl::ut_check(
                            mut_page_pool.allocate<nd_t>(mut_tls, "*") == mut_pool.at_if(2_umax));
                        bsl::ut_check(mut_page_pool.allocated(mut_tls, "*") == expected3);
                        bsl::ut_check(!mut_page_pool.allocated(mut_tls, "42"));
                    };
                };
            };
        };

        bsl::ut_scenario{"virt_to_phys"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                page_pool_t const page_pool{};
                nd_t mut_node{};
                // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
                bsl::safe_uintmax const virt{reinterpret_cast<bsl::uintmax>(&mut_node)};
                bsl::safe_uintmax const phys{virt - HYPERVISOR_MK_PAGE_POOL_ADDR};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!page_pool.virt_to_phys<nd_t>(nullptr));
                    bsl::ut_check(page_pool.virt_to_phys<nd_t>(&mut_node) == phys);
                };
            };
        };

        bsl::ut_scenario{"phys_to_virt"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                page_pool_t const page_pool{};
                nd_t mut_node{};
                constexpr auto bad_phys{0xFFFFFFFFFFFFFFFF_umax};
                // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
                bsl::safe_uintmax const virt{reinterpret_cast<bsl::uintmax>(&mut_node)};
                bsl::safe_uintmax const phys{virt - HYPERVISOR_MK_PAGE_POOL_ADDR};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(nullptr == page_pool.phys_to_virt<nd_t>(bad_phys));
                    bsl::ut_check(page_pool.phys_to_virt<nd_t>(phys) == &mut_node);
                };
            };
        };

        bsl::ut_scenario{"dump"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                page_pool_t mut_page_pool{};
                bsl::array<page_pool_node_t, POOL_SIZE.get()> mut_pool{};
                bsl::span mut_view{mut_pool};
                tls_t mut_tls{};
                bsl::ut_when{} = [&]() noexcept {
                    initialize_pool(mut_view);
                    mut_page_pool.initialize(mut_view);
                    bsl::ut_required_step(mut_page_pool.allocate<nd_t>(mut_tls, "*") != nullptr);
                    bsl::ut_required_step(mut_page_pool.allocate<nd_t>(mut_tls, "*") != nullptr);
                    bsl::ut_required_step(mut_page_pool.allocate<nd_t>(mut_tls, "*") != nullptr);
                    bsl::ut_then{} = [&]() noexcept {
                        mut_page_pool.dump();
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                page_pool_t mut_page_pool{};
                bsl::span mut_view{g_mut_pool};
                tls_t mut_tls{};
                bsl::ut_when{} = [&]() noexcept {
                    initialize_pool(mut_view);
                    mut_page_pool.initialize(mut_view);
                    for (bsl::safe_uintmax mut_i{}; mut_i < 1024_umax; ++mut_i) {
                        bsl::ut_required_step(
                            mut_page_pool.allocate<nd_t>(mut_tls, "memory hog") != nullptr);
                    }
                    bsl::ut_required_step(mut_page_pool.allocate<nd_t>(mut_tls, "*") != nullptr);
                    bsl::ut_then{} = [&]() noexcept {
                        mut_page_pool.dump();
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
