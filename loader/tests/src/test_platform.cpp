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

#include "../../include/platform.h"

#include <helpers.hpp>
#include <types.h>

#include <bsl/convert.hpp>
#include <bsl/discard.hpp>
#include <bsl/safe_integral.hpp>
#include <bsl/ut.hpp>

namespace loader
{
    /// <!-- description -->
    ///   @brief Test function to execute
    ///
    /// <!-- inputs/outputs -->
    ///   @param cpu the core this function is run on (faked)
    ///   @return LOADER_SUCCESS
    ///
    extern "C" [[nodiscard]] auto
    test_func(bsl::uint32 const cpu) noexcept -> int64_t
    {
        bsl::discard(cpu);
        return LOADER_SUCCESS;
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
        helpers::init();

        bsl::ut_scenario{"platform_alloc success"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                bsl::ut_when{} = [&]() noexcept {
                    auto const *const ptr{platform_alloc(HYPERVISOR_PAGE_SIZE)};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(nullptr != ptr);
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        platform_free(ptr, HYPERVISOR_PAGE_SIZE);
                    };
                };
            };
        };

        bsl::ut_scenario{"platform_alloc non-aligned success"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                constexpr auto size{0x2042_umx};
                bsl::ut_when{} = [&]() noexcept {
                    auto const *const ptr{platform_alloc(size.get())};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(nullptr != ptr);
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        platform_free(ptr, HYPERVISOR_PAGE_SIZE);
                    };
                };
            };
        };

        bsl::ut_scenario{"platform_alloc fails"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                bsl::ut_when{} = [&]() noexcept {
                    helpers::g_mut_platform_alloc = 1;
                    auto const *const ptr{platform_alloc(HYPERVISOR_PAGE_SIZE)};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(nullptr == ptr);
                    };
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::ut_when{} = [&]() noexcept {
                    helpers::g_mut_platform_alloc = 2;
                    auto const *const ptr1{platform_alloc(HYPERVISOR_PAGE_SIZE)};
                    auto const *const ptr2{platform_alloc(HYPERVISOR_PAGE_SIZE)};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(nullptr != ptr1);
                        bsl::ut_check(nullptr == ptr2);
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        platform_free(ptr1, HYPERVISOR_PAGE_SIZE);
                    };
                };
            };
        };

        bsl::ut_scenario{"platform_alloc_contiguous success"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                bsl::ut_when{} = [&]() noexcept {
                    auto const *const ptr{platform_alloc_contiguous(HYPERVISOR_PAGE_SIZE)};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(nullptr != ptr);
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        platform_free_contiguous(ptr, HYPERVISOR_PAGE_SIZE);
                    };
                };
            };
        };

        bsl::ut_scenario{"platform_alloc_contiguous non-aligned success"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                constexpr auto size{0x2042_umx};
                bsl::ut_when{} = [&]() noexcept {
                    auto const *const ptr{platform_alloc_contiguous(size.get())};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(nullptr != ptr);
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        platform_free_contiguous(ptr, HYPERVISOR_PAGE_SIZE);
                    };
                };
            };
        };

        bsl::ut_scenario{"platform_alloc_contiguous fails"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                bsl::ut_when{} = [&]() noexcept {
                    helpers::g_mut_platform_alloc_contiguous = 1;
                    auto const *const ptr{platform_alloc_contiguous(HYPERVISOR_PAGE_SIZE)};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(nullptr == ptr);
                    };
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::ut_when{} = [&]() noexcept {
                    helpers::g_mut_platform_alloc_contiguous = 2;
                    auto const *const ptr1{platform_alloc_contiguous(HYPERVISOR_PAGE_SIZE)};
                    auto const *const ptr2{platform_alloc_contiguous(HYPERVISOR_PAGE_SIZE)};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(nullptr != ptr1);
                        bsl::ut_check(nullptr == ptr2);
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        platform_free_contiguous(ptr1, HYPERVISOR_PAGE_SIZE);
                    };
                };
            };
        };

        bsl::ut_scenario{"platform_virt_to_phys success"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                bool const var{};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::safe_u64 const phys{platform_virt_to_phys(&var)};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(bsl::safe_u64::magic_0() != phys);
                    };
                };
            };
        };

        bsl::ut_scenario{"platform_virt_to_phys fails"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                bool const var{};
                bsl::ut_when{} = [&]() noexcept {
                    helpers::g_mut_platform_virt_to_phys = 1;
                    bsl::safe_u64 const phys{platform_virt_to_phys(&var)};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(bsl::safe_u64::magic_0() == phys);
                    };
                };
            };
        };

        bsl::ut_scenario{"platform_memset"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                bool mut_dst{true};
                bsl::ut_when{} = [&]() noexcept {
                    platform_memset(&mut_dst, {}, sizeof(bool));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(!mut_dst);
                    };
                };
            };
        };

        bsl::ut_scenario{"platform_memcpy"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                bool mut_dst{};
                bool const src{true};
                bsl::ut_when{} = [&]() noexcept {
                    platform_memcpy(&mut_dst, &src, sizeof(bool));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_dst);
                    };
                };
            };
        };

        bsl::ut_scenario{"platform_copy_from_user success"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                bool mut_dst{};
                bool const src{true};
                bsl::ut_then{} = [&]() noexcept {
                    helpers::ut_check(platform_copy_from_user(&mut_dst, &src, sizeof(bool)));
                    bsl::ut_check(mut_dst);
                };
            };
        };

        bsl::ut_scenario{"platform_copy_from_user fails"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                bool mut_dst{};
                bool const src{true};
                bsl::ut_when{} = [&]() noexcept {
                    helpers::g_mut_platform_copy_from_user = 1;
                    bsl::ut_then{} = [&]() noexcept {
                        helpers::ut_fails(platform_copy_from_user(&mut_dst, &src, sizeof(bool)));
                        bsl::ut_check(!mut_dst);
                    };
                };
            };
        };

        bsl::ut_scenario{"platform_copy_to_user success"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                bool mut_dst{};
                bool const src{true};
                bsl::ut_then{} = [&]() noexcept {
                    helpers::ut_check(platform_copy_to_user(&mut_dst, &src, sizeof(bool)));
                    bsl::ut_check(mut_dst);
                };
            };
        };

        bsl::ut_scenario{"platform_copy_to_user fails"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                bool mut_dst{};
                bool const src{true};
                bsl::ut_when{} = [&]() noexcept {
                    helpers::g_mut_platform_copy_to_user = 1;
                    bsl::ut_then{} = [&]() noexcept {
                        helpers::ut_fails(platform_copy_to_user(&mut_dst, &src, sizeof(bool)));
                        bsl::ut_check(!mut_dst);
                    };
                };
            };
        };

        bsl::ut_scenario{"platform_num_online_cpus"} = [&]() noexcept {
            bsl::ut_then{} = [&]() noexcept {
                bsl::ut_check(bsl::safe_u32::magic_1() == platform_num_online_cpus());
            };
        };

        bsl::ut_scenario{"platform_current_cpu"} = [&]() noexcept {
            bsl::ut_then{} = [&]() noexcept {
                bsl::ut_check(bsl::safe_u32::magic_0() == platform_current_cpu());
            };
        };

        bsl::ut_scenario{"platform_on_each_cpu"} = [&]() noexcept {
            bsl::ut_then{} = [&]() noexcept {
                helpers::ut_check(platform_on_each_cpu(&test_func, {}));
            };
        };

        bsl::ut_scenario{"platform_arch_init"} = [&]() noexcept {
            bsl::ut_then{} = [&]() noexcept {
                helpers::ut_check(platform_arch_init());
            };
        };

        return helpers::fini();
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
    platform_expects(1);
    platform_ensures(1);

    platform_dump_vmm();
    platform_mark_gdt_writable();
    platform_mark_gdt_readonly();

    helpers::esr_default();
    helpers::esr_df();
    helpers::esr_gpf();
    helpers::esr_nmi();
    helpers::esr_pf();

    bsl::enable_color();
    return loader::tests();
}
