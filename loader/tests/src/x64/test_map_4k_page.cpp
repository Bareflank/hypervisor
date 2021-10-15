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

#include "../../../include/alloc_mk_root_page_table.h"
#include "../../../include/free_mk_root_page_table.h"
#include "../../../include/map_4k_page.h"

#include <bfelf/bfelf_elf64_phdr_t.h>
#include <helpers.hpp>
#include <root_page_table_t.h>

#include <bsl/convert.hpp>
#include <bsl/safe_integral.hpp>
#include <bsl/ut.hpp>

namespace loader
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
    [[nodiscard]] constexpr auto
    tests() noexcept -> bsl::exit_code
    {
        helpers::init_x64();
        constexpr auto func{&map_4k_page};

        bsl::ut_scenario{"success"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                root_page_table_t *pmut_mut_rpt{};
                constexpr auto virt{0x1000_u64};
                constexpr auto phys{0x1000_u64};
                constexpr auto flags{0x0_u32};
                bsl::ut_when{} = [&]() noexcept {
                    helpers::ut_check(alloc_mk_root_page_table(&pmut_mut_rpt));
                    bsl::ut_then{} = [&]() noexcept {
                        helpers::ut_check(func(virt.get(), phys.get(), flags.get(), pmut_mut_rpt));
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        free_mk_root_page_table(&pmut_mut_rpt);
                        helpers::reset_x64();
                    };
                };
            };
        };

        bsl::ut_scenario{"nullptr virt"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                root_page_table_t *pmut_mut_rpt{};
                constexpr auto virt{0x0_u64};
                constexpr auto phys{0x1000_u64};
                constexpr auto flags{0x0_u32};
                bsl::ut_when{} = [&]() noexcept {
                    helpers::ut_check(alloc_mk_root_page_table(&pmut_mut_rpt));
                    bsl::ut_then{} = [&]() noexcept {
                        helpers::ut_fails(func(virt.get(), phys.get(), flags.get(), pmut_mut_rpt));
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        free_mk_root_page_table(&pmut_mut_rpt);
                        helpers::reset_x64();
                    };
                };
            };
        };

        bsl::ut_scenario{"nullptr phys"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                root_page_table_t *pmut_mut_rpt{};
                constexpr auto virt{0x1000_u64};
                constexpr auto phys{0x1000_u64};
                constexpr auto flags{0x0_u32};
                bsl::ut_when{} = [&]() noexcept {
                    helpers::ut_check(alloc_mk_root_page_table(&pmut_mut_rpt));
                    bsl::ut_then{} = [&]() noexcept {
                        helpers::ut_check(func(virt.get(), phys.get(), flags.get(), pmut_mut_rpt));
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        free_mk_root_page_table(&pmut_mut_rpt);
                        helpers::reset_x64();
                    };
                };
            };
        };

        bsl::ut_scenario{"nullptr phys platform_virt_to_phys fails"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                root_page_table_t *pmut_mut_rpt{};
                constexpr auto virt{0x1000_u64};
                constexpr auto phys{0x0_u64};
                constexpr auto flags{0x0_u32};
                bsl::ut_when{} = [&]() noexcept {
                    helpers::ut_check(alloc_mk_root_page_table(&pmut_mut_rpt));
                    helpers::g_mut_platform_virt_to_phys = 1;
                    bsl::ut_then{} = [&]() noexcept {
                        helpers::ut_fails(func(virt.get(), phys.get(), flags.get(), pmut_mut_rpt));
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        free_mk_root_page_table(&pmut_mut_rpt);
                        helpers::reset_x64();
                    };
                };
            };
        };

        bsl::ut_scenario{"unaligned virt"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                root_page_table_t *pmut_mut_rpt{};
                constexpr auto virt{0x1042_u64};
                constexpr auto phys{0x1000_u64};
                constexpr auto flags{0x0_u32};
                bsl::ut_when{} = [&]() noexcept {
                    helpers::ut_check(alloc_mk_root_page_table(&pmut_mut_rpt));
                    bsl::ut_then{} = [&]() noexcept {
                        helpers::ut_fails(func(virt.get(), phys.get(), flags.get(), pmut_mut_rpt));
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        free_mk_root_page_table(&pmut_mut_rpt);
                        helpers::reset_x64();
                    };
                };
            };
        };

        bsl::ut_scenario{"unaligned phys"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                root_page_table_t *pmut_mut_rpt{};
                constexpr auto virt{0x1000_u64};
                constexpr auto phys{0x1042_u64};
                constexpr auto flags{0x0_u32};
                bsl::ut_when{} = [&]() noexcept {
                    helpers::ut_check(alloc_mk_root_page_table(&pmut_mut_rpt));
                    bsl::ut_then{} = [&]() noexcept {
                        helpers::ut_fails(func(virt.get(), phys.get(), flags.get(), pmut_mut_rpt));
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        free_mk_root_page_table(&pmut_mut_rpt);
                        helpers::reset_x64();
                    };
                };
            };
        };

        bsl::ut_scenario{"map more than once with the same virts"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                root_page_table_t *pmut_mut_rpt{};
                constexpr auto virt1{0x1000_u64};
                constexpr auto virt2{0x1000_u64};
                constexpr auto phys{0x1000_u64};
                constexpr auto flags{0x0_u32};
                bsl::ut_when{} = [&]() noexcept {
                    helpers::ut_check(alloc_mk_root_page_table(&pmut_mut_rpt));
                    bsl::ut_then{} = [&]() noexcept {
                        helpers::ut_check(func(virt1.get(), phys.get(), flags.get(), pmut_mut_rpt));
                        helpers::ut_fails(func(virt2.get(), phys.get(), flags.get(), pmut_mut_rpt));
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        free_mk_root_page_table(&pmut_mut_rpt);
                        helpers::reset_x64();
                    };
                };
            };
        };

        bsl::ut_scenario{"map more than once with different virts"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                root_page_table_t *pmut_mut_rpt{};
                constexpr auto virt1{0x1000_u64};
                constexpr auto virt2{0x2000_u64};
                constexpr auto phys{0x1000_u64};
                constexpr auto flags{0x0_u32};
                bsl::ut_when{} = [&]() noexcept {
                    helpers::ut_check(alloc_mk_root_page_table(&pmut_mut_rpt));
                    bsl::ut_then{} = [&]() noexcept {
                        helpers::ut_check(func(virt1.get(), phys.get(), flags.get(), pmut_mut_rpt));
                        helpers::ut_check(func(virt2.get(), phys.get(), flags.get(), pmut_mut_rpt));
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        free_mk_root_page_table(&pmut_mut_rpt);
                        helpers::reset_x64();
                    };
                };
            };
        };

        bsl::ut_scenario{"map rw"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                root_page_table_t *pmut_mut_rpt{};
                constexpr auto virt{0x1000_u64};
                constexpr auto phys{0x1000_u64};
                constexpr auto flags{0x0_u32 | bfelf_pf_w};
                bsl::ut_when{} = [&]() noexcept {
                    helpers::ut_check(alloc_mk_root_page_table(&pmut_mut_rpt));
                    bsl::ut_then{} = [&]() noexcept {
                        helpers::ut_check(func(virt.get(), phys.get(), flags.get(), pmut_mut_rpt));
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        free_mk_root_page_table(&pmut_mut_rpt);
                        helpers::reset_x64();
                    };
                };
            };
        };

        bsl::ut_scenario{"map re"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                root_page_table_t *pmut_mut_rpt{};
                constexpr auto virt{0x1000_u64};
                constexpr auto phys{0x1000_u64};
                constexpr auto flags{0x0_u32 | bfelf_pf_x};
                bsl::ut_when{} = [&]() noexcept {
                    helpers::ut_check(alloc_mk_root_page_table(&pmut_mut_rpt));
                    bsl::ut_then{} = [&]() noexcept {
                        helpers::ut_check(func(virt.get(), phys.get(), flags.get(), pmut_mut_rpt));
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        free_mk_root_page_table(&pmut_mut_rpt);
                        helpers::reset_x64();
                    };
                };
            };
        };

        bsl::ut_scenario{"add_pdpt fails"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                root_page_table_t *pmut_mut_rpt{};
                constexpr auto virt{0x8000000000_u64};
                constexpr auto phys{0x1000_u64};
                constexpr auto flags{0x0_u32};
                bsl::ut_when{} = [&]() noexcept {
                    helpers::ut_check(alloc_mk_root_page_table(&pmut_mut_rpt));
                    helpers::g_mut_platform_alloc = 1;
                    bsl::ut_then{} = [&]() noexcept {
                        helpers::ut_fails(func(virt.get(), phys.get(), flags.get(), pmut_mut_rpt));
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        free_mk_root_page_table(&pmut_mut_rpt);
                        helpers::reset_x64();
                    };
                };
            };
        };

        bsl::ut_scenario{"add_pdt fails"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                root_page_table_t *pmut_mut_rpt{};
                constexpr auto virt{0x40000000_u64};
                constexpr auto phys{0x1000_u64};
                constexpr auto flags{0x0_u32};
                bsl::ut_when{} = [&]() noexcept {
                    helpers::ut_check(alloc_mk_root_page_table(&pmut_mut_rpt));
                    helpers::g_mut_platform_alloc = 1;
                    bsl::ut_then{} = [&]() noexcept {
                        helpers::ut_fails(func(virt.get(), phys.get(), flags.get(), pmut_mut_rpt));
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        free_mk_root_page_table(&pmut_mut_rpt);
                        helpers::reset_x64();
                    };
                };
            };
        };

        bsl::ut_scenario{"add_pt fails"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                root_page_table_t *pmut_mut_rpt{};
                constexpr auto virt{0x200000_u64};
                constexpr auto phys{0x1000_u64};
                constexpr auto flags{0x0_u32};
                bsl::ut_when{} = [&]() noexcept {
                    helpers::ut_check(alloc_mk_root_page_table(&pmut_mut_rpt));
                    helpers::g_mut_platform_alloc = 1;
                    bsl::ut_then{} = [&]() noexcept {
                        helpers::ut_fails(func(virt.get(), phys.get(), flags.get(), pmut_mut_rpt));
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        free_mk_root_page_table(&pmut_mut_rpt);
                        helpers::reset_x64();
                    };
                };
            };
        };

        bsl::ut_scenario{"force to allocate all tables"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                root_page_table_t *pmut_mut_rpt{};
                constexpr auto virt{0x8000000000_u64};
                constexpr auto phys{0x1000_u64};
                constexpr auto flags{0x0_u32};
                bsl::ut_when{} = [&]() noexcept {
                    helpers::ut_check(alloc_mk_root_page_table(&pmut_mut_rpt));
                    bsl::ut_then{} = [&]() noexcept {
                        helpers::ut_check(func(virt.get(), phys.get(), flags.get(), pmut_mut_rpt));
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        free_mk_root_page_table(&pmut_mut_rpt);
                        helpers::reset_x64();
                    };
                };
            };
        };

        bsl::ut_scenario{"failed to allocate pt only"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                root_page_table_t *pmut_mut_rpt{};
                constexpr auto virt{0x8000000000_u64};
                constexpr auto phys{0x1000_u64};
                constexpr auto flags{0x0_u32};
                bsl::ut_when{} = [&]() noexcept {
                    helpers::ut_check(alloc_mk_root_page_table(&pmut_mut_rpt));
                    helpers::g_mut_platform_alloc = 3;
                    bsl::ut_then{} = [&]() noexcept {
                        helpers::ut_fails(func(virt.get(), phys.get(), flags.get(), pmut_mut_rpt));
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        free_mk_root_page_table(&pmut_mut_rpt);
                        helpers::reset_x64();
                    };
                };
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
    bsl::enable_color();
    return loader::tests();
}
