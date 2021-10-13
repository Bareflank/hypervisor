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

#define DO_NOT_INCLUDE_ALIASES

#include "../../../include/alloc_and_copy_mk_code_aliases.h"
#include "../../../include/alloc_mk_root_page_table.h"
#include "../../../include/free_mk_code_aliases.h"
#include "../../../include/free_mk_root_page_table.h"
#include "../../../include/map_mk_code_aliases.h"

#include <code_aliases_t.h>
#include <constants.h>
#include <helpers.hpp>
#include <platform.h>
#include <root_page_table_t.h>

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
        constexpr auto func{&map_mk_code_aliases};

        bsl::ut_scenario{"success"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                root_page_table_t *pmut_mut_rpt{};
                code_aliases_t mut_a{};
                bsl::ut_when{} = [&]() noexcept {
                    helpers::ut_check(alloc_mk_root_page_table(&pmut_mut_rpt));
                    helpers::ut_check(alloc_and_copy_mk_code_aliases(&mut_a));
                    bsl::ut_then{} = [&]() noexcept {
                        helpers::ut_check(func(&mut_a, pmut_mut_rpt));
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        free_mk_code_aliases(&mut_a);
                        free_mk_root_page_table(&pmut_mut_rpt);
                        helpers::reset_x64();
                    };
                };
            };
        };

        bsl::ut_scenario{"platform_virt_to_phys demote fails"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                root_page_table_t *pmut_mut_rpt{};
                code_aliases_t mut_a{};
                bsl::ut_when{} = [&]() noexcept {
                    helpers::ut_check(alloc_mk_root_page_table(&pmut_mut_rpt));
                    helpers::ut_check(alloc_and_copy_mk_code_aliases(&mut_a));
                    platform_free(mut_a.demote, sizeof(HYPERVISOR_PAGE_SIZE));
                    mut_a.demote = {};
                    bsl::ut_then{} = [&]() noexcept {
                        helpers::ut_fails(func(&mut_a, pmut_mut_rpt));
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        free_mk_code_aliases(&mut_a);
                        free_mk_root_page_table(&pmut_mut_rpt);
                        helpers::reset_x64();
                    };
                };
            };
        };

        bsl::ut_scenario{"map_4k_page_rx demote fails"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                root_page_table_t *pmut_mut_rpt{};
                code_aliases_t mut_a{};
                bsl::ut_when{} = [&]() noexcept {
                    helpers::ut_check(alloc_mk_root_page_table(&pmut_mut_rpt));
                    helpers::ut_check(alloc_and_copy_mk_code_aliases(&mut_a));
                    platform_free(mut_a.demote, sizeof(HYPERVISOR_PAGE_SIZE));
                    mut_a.demote = reinterpret_cast<void *>(42);
                    bsl::ut_then{} = [&]() noexcept {
                        helpers::ut_fails(func(&mut_a, pmut_mut_rpt));
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        mut_a.demote = {};
                        free_mk_code_aliases(&mut_a);
                        free_mk_root_page_table(&pmut_mut_rpt);
                        helpers::reset_x64();
                    };
                };
            };
        };

        bsl::ut_scenario{"platform_virt_to_phys promote fails"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                root_page_table_t *pmut_mut_rpt{};
                code_aliases_t mut_a{};
                bsl::ut_when{} = [&]() noexcept {
                    helpers::ut_check(alloc_mk_root_page_table(&pmut_mut_rpt));
                    helpers::ut_check(alloc_and_copy_mk_code_aliases(&mut_a));
                    platform_free(mut_a.promote, sizeof(HYPERVISOR_PAGE_SIZE));
                    mut_a.promote = {};
                    bsl::ut_then{} = [&]() noexcept {
                        helpers::ut_fails(func(&mut_a, pmut_mut_rpt));
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        free_mk_code_aliases(&mut_a);
                        free_mk_root_page_table(&pmut_mut_rpt);
                        helpers::reset_x64();
                    };
                };
            };
        };

        bsl::ut_scenario{"map_4k_page_rx promote fails"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                root_page_table_t *pmut_mut_rpt{};
                code_aliases_t mut_a{};
                bsl::ut_when{} = [&]() noexcept {
                    helpers::ut_check(alloc_mk_root_page_table(&pmut_mut_rpt));
                    helpers::ut_check(alloc_and_copy_mk_code_aliases(&mut_a));
                    platform_free(mut_a.promote, sizeof(HYPERVISOR_PAGE_SIZE));
                    mut_a.promote = reinterpret_cast<void *>(42);
                    bsl::ut_then{} = [&]() noexcept {
                        helpers::ut_fails(func(&mut_a, pmut_mut_rpt));
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        mut_a.promote = {};
                        free_mk_code_aliases(&mut_a);
                        free_mk_root_page_table(&pmut_mut_rpt);
                        helpers::reset_x64();
                    };
                };
            };
        };

        bsl::ut_scenario{"platform_virt_to_phys esr_default fails"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                root_page_table_t *pmut_mut_rpt{};
                code_aliases_t mut_a{};
                bsl::ut_when{} = [&]() noexcept {
                    helpers::ut_check(alloc_mk_root_page_table(&pmut_mut_rpt));
                    helpers::ut_check(alloc_and_copy_mk_code_aliases(&mut_a));
                    platform_free(mut_a.esr_default, sizeof(HYPERVISOR_PAGE_SIZE));
                    mut_a.esr_default = {};
                    bsl::ut_then{} = [&]() noexcept {
                        helpers::ut_fails(func(&mut_a, pmut_mut_rpt));
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        free_mk_code_aliases(&mut_a);
                        free_mk_root_page_table(&pmut_mut_rpt);
                        helpers::reset_x64();
                    };
                };
            };
        };

        bsl::ut_scenario{"map_4k_page_rx esr_default fails"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                root_page_table_t *pmut_mut_rpt{};
                code_aliases_t mut_a{};
                bsl::ut_when{} = [&]() noexcept {
                    helpers::ut_check(alloc_mk_root_page_table(&pmut_mut_rpt));
                    helpers::ut_check(alloc_and_copy_mk_code_aliases(&mut_a));
                    platform_free(mut_a.esr_default, sizeof(HYPERVISOR_PAGE_SIZE));
                    mut_a.esr_default = reinterpret_cast<void *>(42);
                    bsl::ut_then{} = [&]() noexcept {
                        helpers::ut_fails(func(&mut_a, pmut_mut_rpt));
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        mut_a.esr_default = {};
                        free_mk_code_aliases(&mut_a);
                        free_mk_root_page_table(&pmut_mut_rpt);
                        helpers::reset_x64();
                    };
                };
            };
        };

        bsl::ut_scenario{"platform_virt_to_phys esr_df fails"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                root_page_table_t *pmut_mut_rpt{};
                code_aliases_t mut_a{};
                bsl::ut_when{} = [&]() noexcept {
                    helpers::ut_check(alloc_mk_root_page_table(&pmut_mut_rpt));
                    helpers::ut_check(alloc_and_copy_mk_code_aliases(&mut_a));
                    platform_free(mut_a.esr_df, sizeof(HYPERVISOR_PAGE_SIZE));
                    mut_a.esr_df = {};
                    bsl::ut_then{} = [&]() noexcept {
                        helpers::ut_fails(func(&mut_a, pmut_mut_rpt));
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        free_mk_code_aliases(&mut_a);
                        free_mk_root_page_table(&pmut_mut_rpt);
                        helpers::reset_x64();
                    };
                };
            };
        };

        bsl::ut_scenario{"map_4k_page_rx esr_df fails"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                root_page_table_t *pmut_mut_rpt{};
                code_aliases_t mut_a{};
                bsl::ut_when{} = [&]() noexcept {
                    helpers::ut_check(alloc_mk_root_page_table(&pmut_mut_rpt));
                    helpers::ut_check(alloc_and_copy_mk_code_aliases(&mut_a));
                    platform_free(mut_a.esr_df, sizeof(HYPERVISOR_PAGE_SIZE));
                    mut_a.esr_df = reinterpret_cast<void *>(42);
                    bsl::ut_then{} = [&]() noexcept {
                        helpers::ut_fails(func(&mut_a, pmut_mut_rpt));
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        mut_a.esr_df = {};
                        free_mk_code_aliases(&mut_a);
                        free_mk_root_page_table(&pmut_mut_rpt);
                        helpers::reset_x64();
                    };
                };
            };
        };
        bsl::ut_scenario{"platform_virt_to_phys esr_gpf fails"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                root_page_table_t *pmut_mut_rpt{};
                code_aliases_t mut_a{};
                bsl::ut_when{} = [&]() noexcept {
                    helpers::ut_check(alloc_mk_root_page_table(&pmut_mut_rpt));
                    helpers::ut_check(alloc_and_copy_mk_code_aliases(&mut_a));
                    platform_free(mut_a.esr_gpf, sizeof(HYPERVISOR_PAGE_SIZE));
                    mut_a.esr_gpf = {};
                    bsl::ut_then{} = [&]() noexcept {
                        helpers::ut_fails(func(&mut_a, pmut_mut_rpt));
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        free_mk_code_aliases(&mut_a);
                        free_mk_root_page_table(&pmut_mut_rpt);
                        helpers::reset_x64();
                    };
                };
            };
        };

        bsl::ut_scenario{"map_4k_page_rx esr_gpf fails"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                root_page_table_t *pmut_mut_rpt{};
                code_aliases_t mut_a{};
                bsl::ut_when{} = [&]() noexcept {
                    helpers::ut_check(alloc_mk_root_page_table(&pmut_mut_rpt));
                    helpers::ut_check(alloc_and_copy_mk_code_aliases(&mut_a));
                    platform_free(mut_a.esr_gpf, sizeof(HYPERVISOR_PAGE_SIZE));
                    mut_a.esr_gpf = reinterpret_cast<void *>(42);
                    bsl::ut_then{} = [&]() noexcept {
                        helpers::ut_fails(func(&mut_a, pmut_mut_rpt));
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        mut_a.esr_gpf = {};
                        free_mk_code_aliases(&mut_a);
                        free_mk_root_page_table(&pmut_mut_rpt);
                        helpers::reset_x64();
                    };
                };
            };
        };

        bsl::ut_scenario{"platform_virt_to_phys esr_nmi fails"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                root_page_table_t *pmut_mut_rpt{};
                code_aliases_t mut_a{};
                bsl::ut_when{} = [&]() noexcept {
                    helpers::ut_check(alloc_mk_root_page_table(&pmut_mut_rpt));
                    helpers::ut_check(alloc_and_copy_mk_code_aliases(&mut_a));
                    platform_free(mut_a.esr_nmi, sizeof(HYPERVISOR_PAGE_SIZE));
                    mut_a.esr_nmi = {};
                    bsl::ut_then{} = [&]() noexcept {
                        helpers::ut_fails(func(&mut_a, pmut_mut_rpt));
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        free_mk_code_aliases(&mut_a);
                        free_mk_root_page_table(&pmut_mut_rpt);
                        helpers::reset_x64();
                    };
                };
            };
        };

        bsl::ut_scenario{"map_4k_page_rx esr_nmi fails"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                root_page_table_t *pmut_mut_rpt{};
                code_aliases_t mut_a{};
                bsl::ut_when{} = [&]() noexcept {
                    helpers::ut_check(alloc_mk_root_page_table(&pmut_mut_rpt));
                    helpers::ut_check(alloc_and_copy_mk_code_aliases(&mut_a));
                    platform_free(mut_a.esr_nmi, sizeof(HYPERVISOR_PAGE_SIZE));
                    mut_a.esr_nmi = reinterpret_cast<void *>(42);
                    bsl::ut_then{} = [&]() noexcept {
                        helpers::ut_fails(func(&mut_a, pmut_mut_rpt));
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        mut_a.esr_nmi = {};
                        free_mk_code_aliases(&mut_a);
                        free_mk_root_page_table(&pmut_mut_rpt);
                        helpers::reset_x64();
                    };
                };
            };
        };

        bsl::ut_scenario{"platform_virt_to_phys esr_pf fails"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                root_page_table_t *pmut_mut_rpt{};
                code_aliases_t mut_a{};
                bsl::ut_when{} = [&]() noexcept {
                    helpers::ut_check(alloc_mk_root_page_table(&pmut_mut_rpt));
                    helpers::ut_check(alloc_and_copy_mk_code_aliases(&mut_a));
                    platform_free(mut_a.esr_pf, sizeof(HYPERVISOR_PAGE_SIZE));
                    mut_a.esr_pf = {};
                    bsl::ut_then{} = [&]() noexcept {
                        helpers::ut_fails(func(&mut_a, pmut_mut_rpt));
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        free_mk_code_aliases(&mut_a);
                        free_mk_root_page_table(&pmut_mut_rpt);
                        helpers::reset_x64();
                    };
                };
            };
        };

        bsl::ut_scenario{"map_4k_page_rx esr_pf fails"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                root_page_table_t *pmut_mut_rpt{};
                code_aliases_t mut_a{};
                bsl::ut_when{} = [&]() noexcept {
                    helpers::ut_check(alloc_mk_root_page_table(&pmut_mut_rpt));
                    helpers::ut_check(alloc_and_copy_mk_code_aliases(&mut_a));
                    platform_free(mut_a.esr_pf, sizeof(HYPERVISOR_PAGE_SIZE));
                    mut_a.esr_pf = reinterpret_cast<void *>(42);
                    bsl::ut_then{} = [&]() noexcept {
                        helpers::ut_fails(func(&mut_a, pmut_mut_rpt));
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        mut_a.esr_pf = {};
                        free_mk_code_aliases(&mut_a);
                        free_mk_root_page_table(&pmut_mut_rpt);
                        helpers::reset_x64();
                    };
                };
            };
        };

        bsl::ut_scenario{"platform_virt_to_phys serial_write_c fails"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                root_page_table_t *pmut_mut_rpt{};
                code_aliases_t mut_a{};
                bsl::ut_when{} = [&]() noexcept {
                    helpers::ut_check(alloc_mk_root_page_table(&pmut_mut_rpt));
                    helpers::ut_check(alloc_and_copy_mk_code_aliases(&mut_a));
                    platform_free(mut_a.serial_write_c, sizeof(HYPERVISOR_PAGE_SIZE));
                    mut_a.serial_write_c = {};
                    bsl::ut_then{} = [&]() noexcept {
                        helpers::ut_fails(func(&mut_a, pmut_mut_rpt));
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        free_mk_code_aliases(&mut_a);
                        free_mk_root_page_table(&pmut_mut_rpt);
                        helpers::reset_x64();
                    };
                };
            };
        };

        bsl::ut_scenario{"map_4k_page_rx serial_write_c fails"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                root_page_table_t *pmut_mut_rpt{};
                code_aliases_t mut_a{};
                bsl::ut_when{} = [&]() noexcept {
                    helpers::ut_check(alloc_mk_root_page_table(&pmut_mut_rpt));
                    helpers::ut_check(alloc_and_copy_mk_code_aliases(&mut_a));
                    platform_free(mut_a.serial_write_c, sizeof(HYPERVISOR_PAGE_SIZE));
                    mut_a.serial_write_c = reinterpret_cast<void *>(42);
                    bsl::ut_then{} = [&]() noexcept {
                        helpers::ut_fails(func(&mut_a, pmut_mut_rpt));
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        mut_a.serial_write_c = {};
                        free_mk_code_aliases(&mut_a);
                        free_mk_root_page_table(&pmut_mut_rpt);
                        helpers::reset_x64();
                    };
                };
            };
        };

        bsl::ut_scenario{"platform_virt_to_phys serial_write_hex fails"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                root_page_table_t *pmut_mut_rpt{};
                code_aliases_t mut_a{};
                bsl::ut_when{} = [&]() noexcept {
                    helpers::ut_check(alloc_mk_root_page_table(&pmut_mut_rpt));
                    helpers::ut_check(alloc_and_copy_mk_code_aliases(&mut_a));
                    platform_free(mut_a.serial_write_hex, sizeof(HYPERVISOR_PAGE_SIZE));
                    mut_a.serial_write_hex = {};
                    bsl::ut_then{} = [&]() noexcept {
                        helpers::ut_fails(func(&mut_a, pmut_mut_rpt));
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        free_mk_code_aliases(&mut_a);
                        free_mk_root_page_table(&pmut_mut_rpt);
                        helpers::reset_x64();
                    };
                };
            };
        };

        bsl::ut_scenario{"map_4k_page_rx serial_write_hex fails"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                root_page_table_t *pmut_mut_rpt{};
                code_aliases_t mut_a{};
                bsl::ut_when{} = [&]() noexcept {
                    helpers::ut_check(alloc_mk_root_page_table(&pmut_mut_rpt));
                    helpers::ut_check(alloc_and_copy_mk_code_aliases(&mut_a));
                    platform_free(mut_a.serial_write_hex, sizeof(HYPERVISOR_PAGE_SIZE));
                    mut_a.serial_write_hex = reinterpret_cast<void *>(42);
                    bsl::ut_then{} = [&]() noexcept {
                        helpers::ut_fails(func(&mut_a, pmut_mut_rpt));
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        mut_a.serial_write_hex = {};
                        free_mk_code_aliases(&mut_a);
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
