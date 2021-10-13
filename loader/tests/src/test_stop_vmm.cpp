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

#include "../../include/g_mut_vmm_status.h"
#include "../../include/loader_fini.h"
#include "../../include/loader_init.h"
#include "../../include/start_vmm.h"
#include "../../include/stop_vmm.h"

#include <helpers.hpp>
#include <span_t.h>
#include <start_vmm_args_t.h>
#include <stop_vmm_args_t.h>

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
        helpers::init();
        constexpr auto func{&stop_vmm};

        bsl::ut_scenario{"success"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                stop_vmm_args_t mut_stop_args{};
                start_vmm_args_t mut_start_args{};
                helpers::file_t mut_mk_elf_file{};
                helpers::file_t mut_ext_elf_files{};
                bsl::ut_when{} = [&]() noexcept {
                    helpers::init_file(mut_mk_elf_file);
                    helpers::init_file(mut_ext_elf_files);
                    mut_stop_args.ver = bsl::safe_u64::magic_1().get();
                    mut_start_args.ver = bsl::safe_u64::magic_1().get();
                    mut_start_args.num_pages_in_page_pool = bsl::safe_u32::magic_1().get();
                    mut_start_args.mk_elf_file.addr = helpers::to_u8_ptr(&mut_mk_elf_file);
                    mut_start_args.mk_elf_file.size = sizeof(mut_mk_elf_file);
                    mut_start_args.ext_elf_files[0].addr = helpers::to_u8_ptr(&mut_ext_elf_files);
                    mut_start_args.ext_elf_files[0].size = sizeof(mut_ext_elf_files);
                    helpers::ut_check(loader_init());
                    helpers::ut_check(start_vmm(&mut_start_args));
                    bsl::ut_then{} = [&]() noexcept {
                        helpers::ut_check(func(&mut_stop_args));
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        helpers::ut_check(loader_fini());
                        helpers::reset();
                    };
                };
            };
        };

        bsl::ut_scenario{"stop twice"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                stop_vmm_args_t mut_stop_args{};
                start_vmm_args_t mut_start_args{};
                helpers::file_t mut_mk_elf_file{};
                helpers::file_t mut_ext_elf_files{};
                bsl::ut_when{} = [&]() noexcept {
                    helpers::init_file(mut_mk_elf_file);
                    helpers::init_file(mut_ext_elf_files);
                    mut_stop_args.ver = bsl::safe_u64::magic_1().get();
                    mut_start_args.ver = bsl::safe_u64::magic_1().get();
                    mut_start_args.num_pages_in_page_pool = bsl::safe_u32::magic_1().get();
                    mut_start_args.mk_elf_file.addr = helpers::to_u8_ptr(&mut_mk_elf_file);
                    mut_start_args.mk_elf_file.size = sizeof(mut_mk_elf_file);
                    mut_start_args.ext_elf_files[0].addr = helpers::to_u8_ptr(&mut_ext_elf_files);
                    mut_start_args.ext_elf_files[0].size = sizeof(mut_ext_elf_files);
                    helpers::ut_check(loader_init());
                    helpers::ut_check(start_vmm(&mut_start_args));
                    bsl::ut_then{} = [&]() noexcept {
                        helpers::ut_check(func(&mut_stop_args));
                        helpers::ut_check(func(&mut_stop_args));
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        helpers::ut_check(loader_fini());
                        helpers::reset();
                    };
                };
            };
        };

        bsl::ut_scenario{"corrupt vmm fails"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                stop_vmm_args_t mut_stop_args{};
                start_vmm_args_t mut_start_args{};
                helpers::file_t mut_mk_elf_file{};
                helpers::file_t mut_ext_elf_files{};
                bsl::ut_when{} = [&]() noexcept {
                    helpers::init_file(mut_mk_elf_file);
                    helpers::init_file(mut_ext_elf_files);
                    mut_stop_args.ver = bsl::safe_u64::magic_1().get();
                    mut_start_args.ver = bsl::safe_u64::magic_1().get();
                    mut_start_args.num_pages_in_page_pool = bsl::safe_u32::magic_1().get();
                    mut_start_args.mk_elf_file.addr = helpers::to_u8_ptr(&mut_mk_elf_file);
                    mut_start_args.mk_elf_file.size = sizeof(mut_mk_elf_file);
                    mut_start_args.ext_elf_files[0].addr = helpers::to_u8_ptr(&mut_ext_elf_files);
                    mut_start_args.ext_elf_files[0].size = sizeof(mut_ext_elf_files);
                    helpers::ut_check(loader_init());
                    helpers::ut_check(start_vmm(&mut_start_args));
                    g_mut_vmm_status = VMM_STATUS_CORRUPT;
                    bsl::ut_then{} = [&]() noexcept {
                        helpers::ut_check(func(&mut_stop_args));
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        g_mut_vmm_status = VMM_STATUS_RUNNING;
                        helpers::ut_check(loader_fini());
                        helpers::reset();
                    };
                };
            };
        };

        bsl::ut_scenario{"platform_on_each_cpu fails"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                stop_vmm_args_t mut_stop_args{};
                start_vmm_args_t mut_start_args{};
                helpers::file_t mut_mk_elf_file{};
                helpers::file_t mut_ext_elf_files{};
                bsl::ut_when{} = [&]() noexcept {
                    helpers::init_file(mut_mk_elf_file);
                    helpers::init_file(mut_ext_elf_files);
                    mut_stop_args.ver = bsl::safe_u64::magic_1().get();
                    mut_start_args.ver = bsl::safe_u64::magic_1().get();
                    mut_start_args.num_pages_in_page_pool = bsl::safe_u32::magic_1().get();
                    mut_start_args.mk_elf_file.addr = helpers::to_u8_ptr(&mut_mk_elf_file);
                    mut_start_args.mk_elf_file.size = sizeof(mut_mk_elf_file);
                    mut_start_args.ext_elf_files[0].addr = helpers::to_u8_ptr(&mut_ext_elf_files);
                    mut_start_args.ext_elf_files[0].size = sizeof(mut_ext_elf_files);
                    helpers::ut_check(loader_init());
                    helpers::ut_check(start_vmm(&mut_start_args));
                    helpers::g_mut_send_command_stop = 1;
                    bsl::ut_then{} = [&]() noexcept {
                        helpers::ut_check(func(&mut_stop_args));
                        bsl::ut_check(VMM_STATUS_CORRUPT == g_mut_vmm_status);
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        g_mut_vmm_status = VMM_STATUS_RUNNING;
                        helpers::ut_check(loader_fini());
                        helpers::reset();
                    };
                };
            };
        };

        bsl::ut_scenario{"invalid version"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                stop_vmm_args_t mut_args{};
                bsl::ut_then{} = [&]() noexcept {
                    helpers::ut_fails(func(&mut_args));
                };
                bsl::ut_cleanup{} = [&]() noexcept {
                    helpers::reset();
                };
            };
        };

        bsl::ut_scenario{"nullptr args"} = [&]() noexcept {
            bsl::ut_then{} = [&]() noexcept {
                helpers::ut_fails(func({}));
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
