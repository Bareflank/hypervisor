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

#include "../../../include/alloc_and_copy_mk_state.h"
#include "../../../include/alloc_mk_root_page_table.h"
#include "../../../include/free_mk_root_page_table.h"
#include "../../../include/free_mk_state.h"
#include "../../../include/map_mk_state.h"

#include <bfelf/bfelf_elf64_ehdr_t.h>
#include <constants.h>
#include <elf_file_t.h>
#include <global_descriptor_table_register_t.h>
#include <helpers.hpp>
#include <interrupt_descriptor_table_register_t.h>
#include <platform.h>
#include <root_page_table_t.h>
#include <span_t.h>
#include <state_save_t.h>

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
        constexpr auto func{&map_mk_state};

        bsl::ut_scenario{"success"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                root_page_table_t *pmut_mut_rpt{};
                elf_file_t mut_mk_elf_file{};
                span_t const mk_stack{};
                bsl::safe_u64 const mk_stack_virt{};
                state_save_t *pmut_mut_state{};
                bfelf_elf64_ehdr_t const ehdr{};
                bsl::ut_when{} = [&]() noexcept {
                    mut_mk_elf_file.addr = &ehdr;
                    helpers::ut_check(alloc_mk_root_page_table(&pmut_mut_rpt));
                    helpers::ut_check(alloc_and_copy_mk_state(
                        pmut_mut_rpt,
                        &mut_mk_elf_file,
                        &mk_stack,
                        mk_stack_virt.get(),
                        &pmut_mut_state));
                    bsl::ut_then{} = [&]() noexcept {
                        helpers::ut_check(func(pmut_mut_state, pmut_mut_rpt));
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        free_mk_state(&pmut_mut_state);
                        free_mk_root_page_table(&pmut_mut_rpt);
                        helpers::reset_x64();
                    };
                };
            };
        };

        bsl::ut_scenario{"map_4k_page_rw state fails"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                root_page_table_t *pmut_mut_rpt{};
                elf_file_t mut_mk_elf_file{};
                span_t const mk_stack{};
                bsl::safe_u64 const mk_stack_virt{};
                state_save_t *pmut_mut_state{};
                bfelf_elf64_ehdr_t const ehdr{};
                bsl::ut_when{} = [&]() noexcept {
                    mut_mk_elf_file.addr = &ehdr;
                    helpers::ut_check(alloc_mk_root_page_table(&pmut_mut_rpt));
                    helpers::ut_check(alloc_and_copy_mk_state(
                        pmut_mut_rpt,
                        &mut_mk_elf_file,
                        &mk_stack,
                        mk_stack_virt.get(),
                        &pmut_mut_state));
                    helpers::g_mut_platform_virt_to_phys = 1;
                    bsl::ut_then{} = [&]() noexcept {
                        helpers::ut_fails(func(pmut_mut_state, pmut_mut_rpt));
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        free_mk_state(&pmut_mut_state);
                        free_mk_root_page_table(&pmut_mut_rpt);
                        helpers::reset_x64();
                    };
                };
            };
        };

        bsl::ut_scenario{"map_4k_page_rw tss fails"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                root_page_table_t *pmut_mut_rpt{};
                elf_file_t mut_mk_elf_file{};
                span_t const mk_stack{};
                bsl::safe_u64 const mk_stack_virt{};
                state_save_t *pmut_mut_state{};
                bfelf_elf64_ehdr_t const ehdr{};
                bsl::ut_when{} = [&]() noexcept {
                    mut_mk_elf_file.addr = &ehdr;
                    helpers::ut_check(alloc_mk_root_page_table(&pmut_mut_rpt));
                    helpers::ut_check(alloc_and_copy_mk_state(
                        pmut_mut_rpt,
                        &mut_mk_elf_file,
                        &mk_stack,
                        mk_stack_virt.get(),
                        &pmut_mut_state));
                    platform_free(pmut_mut_state->tss, sizeof(HYPERVISOR_PAGE_SIZE));
                    pmut_mut_state->tss = {};
                    bsl::ut_then{} = [&]() noexcept {
                        helpers::ut_fails(func(pmut_mut_state, pmut_mut_rpt));
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        free_mk_state(&pmut_mut_state);
                        free_mk_root_page_table(&pmut_mut_rpt);
                        helpers::reset_x64();
                    };
                };
            };
        };

        bsl::ut_scenario{"map_4k_page_rw ist fails"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                root_page_table_t *pmut_mut_rpt{};
                elf_file_t mut_mk_elf_file{};
                span_t const mk_stack{};
                bsl::safe_u64 const mk_stack_virt{};
                state_save_t *pmut_mut_state{};
                bfelf_elf64_ehdr_t const ehdr{};
                bsl::ut_when{} = [&]() noexcept {
                    mut_mk_elf_file.addr = &ehdr;
                    helpers::ut_check(alloc_mk_root_page_table(&pmut_mut_rpt));
                    helpers::ut_check(alloc_and_copy_mk_state(
                        pmut_mut_rpt,
                        &mut_mk_elf_file,
                        &mk_stack,
                        mk_stack_virt.get(),
                        &pmut_mut_state));
                    platform_free(pmut_mut_state->ist, sizeof(HYPERVISOR_PAGE_SIZE));
                    pmut_mut_state->ist = {};
                    bsl::ut_then{} = [&]() noexcept {
                        helpers::ut_fails(func(pmut_mut_state, pmut_mut_rpt));
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        free_mk_state(&pmut_mut_state);
                        free_mk_root_page_table(&pmut_mut_rpt);
                        helpers::reset_x64();
                    };
                };
            };
        };

        bsl::ut_scenario{"map_4k_page_rw gdtr fails"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                root_page_table_t *pmut_mut_rpt{};
                elf_file_t mut_mk_elf_file{};
                span_t const mk_stack{};
                bsl::safe_u64 const mk_stack_virt{};
                state_save_t *pmut_mut_state{};
                bfelf_elf64_ehdr_t const ehdr{};
                bsl::ut_when{} = [&]() noexcept {
                    mut_mk_elf_file.addr = &ehdr;
                    helpers::ut_check(alloc_mk_root_page_table(&pmut_mut_rpt));
                    helpers::ut_check(alloc_and_copy_mk_state(
                        pmut_mut_rpt,
                        &mut_mk_elf_file,
                        &mk_stack,
                        mk_stack_virt.get(),
                        &pmut_mut_state));
                    platform_free(pmut_mut_state->gdtr.base, sizeof(HYPERVISOR_PAGE_SIZE));
                    pmut_mut_state->gdtr.base = {};
                    bsl::ut_then{} = [&]() noexcept {
                        helpers::ut_fails(func(pmut_mut_state, pmut_mut_rpt));
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        free_mk_state(&pmut_mut_state);
                        free_mk_root_page_table(&pmut_mut_rpt);
                        helpers::reset_x64();
                    };
                };
            };
        };

        bsl::ut_scenario{"map_4k_page_rw idtr fails"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                root_page_table_t *pmut_mut_rpt{};
                elf_file_t mut_mk_elf_file{};
                span_t const mk_stack{};
                bsl::safe_u64 const mk_stack_virt{};
                state_save_t *pmut_mut_state{};
                bfelf_elf64_ehdr_t const ehdr{};
                bsl::ut_when{} = [&]() noexcept {
                    mut_mk_elf_file.addr = &ehdr;
                    helpers::ut_check(alloc_mk_root_page_table(&pmut_mut_rpt));
                    helpers::ut_check(alloc_and_copy_mk_state(
                        pmut_mut_rpt,
                        &mut_mk_elf_file,
                        &mk_stack,
                        mk_stack_virt.get(),
                        &pmut_mut_state));
                    platform_free(pmut_mut_state->idtr.base, sizeof(HYPERVISOR_PAGE_SIZE));
                    pmut_mut_state->idtr.base = {};
                    bsl::ut_then{} = [&]() noexcept {
                        helpers::ut_fails(func(pmut_mut_state, pmut_mut_rpt));
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        free_mk_state(&pmut_mut_state);
                        free_mk_root_page_table(&pmut_mut_rpt);
                        helpers::reset_x64();
                    };
                };
            };
        };

        bsl::ut_scenario{"map_4k_page_rw state hve_page"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                root_page_table_t *pmut_mut_rpt{};
                elf_file_t mut_mk_elf_file{};
                span_t const mk_stack{};
                bsl::safe_u64 const mk_stack_virt{};
                state_save_t *pmut_mut_state{};
                bfelf_elf64_ehdr_t const ehdr{};
                bsl::ut_when{} = [&]() noexcept {
                    mut_mk_elf_file.addr = &ehdr;
                    helpers::ut_check(alloc_mk_root_page_table(&pmut_mut_rpt));
                    helpers::ut_check(alloc_and_copy_mk_state(
                        pmut_mut_rpt,
                        &mut_mk_elf_file,
                        &mk_stack,
                        mk_stack_virt.get(),
                        &pmut_mut_state));
                    platform_free(pmut_mut_state->hve_page, sizeof(HYPERVISOR_PAGE_SIZE));
                    pmut_mut_state->hve_page = {};
                    bsl::ut_then{} = [&]() noexcept {
                        helpers::ut_fails(func(pmut_mut_state, pmut_mut_rpt));
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        free_mk_state(&pmut_mut_state);
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
