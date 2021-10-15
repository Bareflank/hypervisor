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

#include "../../include/loader_fini.h"
#include "../../include/loader_init.h"
#include "../../include/start_vmm.h"
#include "../../include/start_vmm_per_cpu.h"
#include "../../include/stop_vmm_per_cpu.h"

#include <helpers.hpp>
#include <span_t.h>
#include <start_vmm_args_t.h>

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
        constexpr auto func{&start_vmm_per_cpu};

        bsl::ut_scenario{"success"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                start_vmm_args_t mut_args{};
                helpers::file_t mut_mk_elf_file{};
                helpers::file_t mut_ext_elf_files{};
                bsl::ut_when{} = [&]() noexcept {
                    helpers::init_file(mut_mk_elf_file);
                    helpers::init_file(mut_ext_elf_files);
                    mut_args.ver = bsl::safe_u64::magic_1().get();
                    mut_args.num_pages_in_page_pool = bsl::safe_u32::magic_1().get();
                    mut_args.mk_elf_file.addr = helpers::to_u8_ptr(&mut_mk_elf_file);
                    mut_args.mk_elf_file.size = sizeof(mut_mk_elf_file);
                    mut_args.ext_elf_files[0].addr = helpers::to_u8_ptr(&mut_ext_elf_files);
                    mut_args.ext_elf_files[0].size = sizeof(mut_ext_elf_files);
                    helpers::ut_check(loader_init());
                    helpers::ut_check(start_vmm(&mut_args));
                    bsl::ut_then{} = [&]() noexcept {
                        helpers::ut_check(func(1U));
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        helpers::ut_check(stop_vmm_per_cpu(1U));
                        helpers::ut_check(loader_fini());
                        helpers::reset();
                    };
                };
            };
        };

        bsl::ut_scenario{"invalid cpu"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                start_vmm_args_t mut_args{};
                helpers::file_t mut_mk_elf_file{};
                helpers::file_t mut_ext_elf_files{};
                bsl::ut_when{} = [&]() noexcept {
                    helpers::init_file(mut_mk_elf_file);
                    helpers::init_file(mut_ext_elf_files);
                    mut_args.ver = bsl::safe_u64::magic_1().get();
                    mut_args.num_pages_in_page_pool = bsl::safe_u32::magic_1().get();
                    mut_args.mk_elf_file.addr = helpers::to_u8_ptr(&mut_mk_elf_file);
                    mut_args.mk_elf_file.size = sizeof(mut_mk_elf_file);
                    mut_args.ext_elf_files[0].addr = helpers::to_u8_ptr(&mut_ext_elf_files);
                    mut_args.ext_elf_files[0].size = sizeof(mut_ext_elf_files);
                    helpers::ut_check(loader_init());
                    helpers::ut_check(start_vmm(&mut_args));
                    bsl::ut_then{} = [&]() noexcept {
                        helpers::ut_fails(func(42U));
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        helpers::ut_check(loader_fini());
                        helpers::reset();
                    };
                };
            };
        };

        bsl::ut_scenario{"cpu already running"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                start_vmm_args_t mut_args{};
                helpers::file_t mut_mk_elf_file{};
                helpers::file_t mut_ext_elf_files{};
                bsl::ut_when{} = [&]() noexcept {
                    helpers::init_file(mut_mk_elf_file);
                    helpers::init_file(mut_ext_elf_files);
                    mut_args.ver = bsl::safe_u64::magic_1().get();
                    mut_args.num_pages_in_page_pool = bsl::safe_u32::magic_1().get();
                    mut_args.mk_elf_file.addr = helpers::to_u8_ptr(&mut_mk_elf_file);
                    mut_args.mk_elf_file.size = sizeof(mut_mk_elf_file);
                    mut_args.ext_elf_files[0].addr = helpers::to_u8_ptr(&mut_ext_elf_files);
                    mut_args.ext_elf_files[0].size = sizeof(mut_ext_elf_files);
                    helpers::ut_check(loader_init());
                    helpers::ut_check(start_vmm(&mut_args));
                    bsl::ut_then{} = [&]() noexcept {
                        helpers::ut_fails(func({}));
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        helpers::ut_check(loader_fini());
                        helpers::reset();
                    };
                };
            };
        };

        bsl::ut_scenario{"check_cpu_configuration fails"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                start_vmm_args_t mut_args{};
                helpers::file_t mut_mk_elf_file{};
                helpers::file_t mut_ext_elf_files{};
                bsl::ut_when{} = [&]() noexcept {
                    helpers::init_file(mut_mk_elf_file);
                    helpers::init_file(mut_ext_elf_files);
                    mut_args.ver = bsl::safe_u64::magic_1().get();
                    mut_args.num_pages_in_page_pool = bsl::safe_u32::magic_1().get();
                    mut_args.mk_elf_file.addr = helpers::to_u8_ptr(&mut_mk_elf_file);
                    mut_args.mk_elf_file.size = sizeof(mut_mk_elf_file);
                    mut_args.ext_elf_files[0].addr = helpers::to_u8_ptr(&mut_ext_elf_files);
                    mut_args.ext_elf_files[0].size = sizeof(mut_ext_elf_files);
                    helpers::ut_check(loader_init());
                    helpers::ut_check(start_vmm(&mut_args));
                    helpers::g_mut_check_cpu_configuration = 1;
                    bsl::ut_then{} = [&]() noexcept {
                        helpers::ut_fails(func(1U));
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        helpers::ut_check(loader_fini());
                        helpers::reset();
                    };
                };
            };
        };

        bsl::ut_scenario{"alloc_mk_stack fails"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                start_vmm_args_t mut_args{};
                helpers::file_t mut_mk_elf_file{};
                helpers::file_t mut_ext_elf_files{};
                bsl::ut_when{} = [&]() noexcept {
                    helpers::init_file(mut_mk_elf_file);
                    helpers::init_file(mut_ext_elf_files);
                    mut_args.ver = bsl::safe_u64::magic_1().get();
                    mut_args.num_pages_in_page_pool = bsl::safe_u32::magic_1().get();
                    mut_args.mk_elf_file.addr = helpers::to_u8_ptr(&mut_mk_elf_file);
                    mut_args.mk_elf_file.size = sizeof(mut_mk_elf_file);
                    mut_args.ext_elf_files[0].addr = helpers::to_u8_ptr(&mut_ext_elf_files);
                    mut_args.ext_elf_files[0].size = sizeof(mut_ext_elf_files);
                    helpers::ut_check(loader_init());
                    helpers::ut_check(start_vmm(&mut_args));
                    helpers::g_mut_platform_alloc = 1;
                    bsl::ut_then{} = [&]() noexcept {
                        helpers::ut_fails(func(1U));
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        helpers::ut_check(loader_fini());
                        helpers::reset();
                    };
                };
            };
        };

        bsl::ut_scenario{"alloc_and_copy_mk_state fails"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                start_vmm_args_t mut_args{};
                helpers::file_t mut_mk_elf_file{};
                helpers::file_t mut_ext_elf_files{};
                bsl::ut_when{} = [&]() noexcept {
                    helpers::init_file(mut_mk_elf_file);
                    helpers::init_file(mut_ext_elf_files);
                    mut_args.ver = bsl::safe_u64::magic_1().get();
                    mut_args.num_pages_in_page_pool = bsl::safe_u32::magic_1().get();
                    mut_args.mk_elf_file.addr = helpers::to_u8_ptr(&mut_mk_elf_file);
                    mut_args.mk_elf_file.size = sizeof(mut_mk_elf_file);
                    mut_args.ext_elf_files[0].addr = helpers::to_u8_ptr(&mut_ext_elf_files);
                    mut_args.ext_elf_files[0].size = sizeof(mut_ext_elf_files);
                    helpers::ut_check(loader_init());
                    helpers::ut_check(start_vmm(&mut_args));
                    helpers::g_mut_platform_alloc = 2;
                    bsl::ut_then{} = [&]() noexcept {
                        helpers::ut_fails(func(1U));
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        helpers::ut_check(loader_fini());
                        helpers::reset();
                    };
                };
            };
        };

        bsl::ut_scenario{"alloc_and_copy_root_vp_state fails"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                start_vmm_args_t mut_args{};
                helpers::file_t mut_mk_elf_file{};
                helpers::file_t mut_ext_elf_files{};
                bsl::ut_when{} = [&]() noexcept {
                    helpers::init_file(mut_mk_elf_file);
                    helpers::init_file(mut_ext_elf_files);
                    mut_args.ver = bsl::safe_u64::magic_1().get();
                    mut_args.num_pages_in_page_pool = bsl::safe_u32::magic_1().get();
                    mut_args.mk_elf_file.addr = helpers::to_u8_ptr(&mut_mk_elf_file);
                    mut_args.mk_elf_file.size = sizeof(mut_mk_elf_file);
                    mut_args.ext_elf_files[0].addr = helpers::to_u8_ptr(&mut_ext_elf_files);
                    mut_args.ext_elf_files[0].size = sizeof(mut_ext_elf_files);
                    helpers::ut_check(loader_init());
                    helpers::ut_check(start_vmm(&mut_args));
                    helpers::g_mut_platform_alloc = 3;
                    bsl::ut_then{} = [&]() noexcept {
                        helpers::ut_fails(func(1U));
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        helpers::ut_check(loader_fini());
                        helpers::reset();
                    };
                };
            };
        };

        bsl::ut_scenario{"alloc_mk_args fails"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                start_vmm_args_t mut_args{};
                helpers::file_t mut_mk_elf_file{};
                helpers::file_t mut_ext_elf_files{};
                bsl::ut_when{} = [&]() noexcept {
                    helpers::init_file(mut_mk_elf_file);
                    helpers::init_file(mut_ext_elf_files);
                    mut_args.ver = bsl::safe_u64::magic_1().get();
                    mut_args.num_pages_in_page_pool = bsl::safe_u32::magic_1().get();
                    mut_args.mk_elf_file.addr = helpers::to_u8_ptr(&mut_mk_elf_file);
                    mut_args.mk_elf_file.size = sizeof(mut_mk_elf_file);
                    mut_args.ext_elf_files[0].addr = helpers::to_u8_ptr(&mut_ext_elf_files);
                    mut_args.ext_elf_files[0].size = sizeof(mut_ext_elf_files);
                    helpers::ut_check(loader_init());
                    helpers::ut_check(start_vmm(&mut_args));
                    helpers::g_mut_platform_alloc = 4;
                    bsl::ut_then{} = [&]() noexcept {
                        helpers::ut_fails(func(1U));
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        helpers::ut_check(loader_fini());
                        helpers::reset();
                    };
                };
            };
        };

        bsl::ut_scenario{"map_mk_stack fails"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                start_vmm_args_t mut_args{};
                helpers::file_t mut_mk_elf_file{};
                helpers::file_t mut_ext_elf_files{};
                bsl::ut_when{} = [&]() noexcept {
                    helpers::init_file(mut_mk_elf_file);
                    helpers::init_file(mut_ext_elf_files);
                    mut_args.ver = bsl::safe_u64::magic_1().get();
                    mut_args.num_pages_in_page_pool = bsl::safe_u32::magic_1().get();
                    mut_args.mk_elf_file.addr = helpers::to_u8_ptr(&mut_mk_elf_file);
                    mut_args.mk_elf_file.size = sizeof(mut_mk_elf_file);
                    mut_args.ext_elf_files[0].addr = helpers::to_u8_ptr(&mut_ext_elf_files);
                    mut_args.ext_elf_files[0].size = sizeof(mut_ext_elf_files);
                    helpers::ut_check(loader_init());
                    helpers::ut_check(start_vmm(&mut_args));
                    helpers::g_mut_map_4k_page = 1;
                    bsl::ut_then{} = [&]() noexcept {
                        helpers::ut_fails(func(1U));
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        helpers::ut_check(loader_fini());
                        helpers::reset();
                    };
                };
            };
        };

        bsl::ut_scenario{"map_mk_state fails"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                start_vmm_args_t mut_args{};
                helpers::file_t mut_mk_elf_file{};
                helpers::file_t mut_ext_elf_files{};
                bsl::ut_when{} = [&]() noexcept {
                    helpers::init_file(mut_mk_elf_file);
                    helpers::init_file(mut_ext_elf_files);
                    mut_args.ver = bsl::safe_u64::magic_1().get();
                    mut_args.num_pages_in_page_pool = bsl::safe_u32::magic_1().get();
                    mut_args.mk_elf_file.addr = helpers::to_u8_ptr(&mut_mk_elf_file);
                    mut_args.mk_elf_file.size = sizeof(mut_mk_elf_file);
                    mut_args.ext_elf_files[0].addr = helpers::to_u8_ptr(&mut_ext_elf_files);
                    mut_args.ext_elf_files[0].size = sizeof(mut_ext_elf_files);
                    helpers::ut_check(loader_init());
                    helpers::ut_check(start_vmm(&mut_args));
                    helpers::g_mut_map_4k_page = 2;
                    bsl::ut_then{} = [&]() noexcept {
                        helpers::ut_fails(func(1U));
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        helpers::ut_check(loader_fini());
                        helpers::reset();
                    };
                };
            };
        };

        bsl::ut_scenario{"map_root_vp_state fails"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                start_vmm_args_t mut_args{};
                helpers::file_t mut_mk_elf_file{};
                helpers::file_t mut_ext_elf_files{};
                bsl::ut_when{} = [&]() noexcept {
                    helpers::init_file(mut_mk_elf_file);
                    helpers::init_file(mut_ext_elf_files);
                    mut_args.ver = bsl::safe_u64::magic_1().get();
                    mut_args.num_pages_in_page_pool = bsl::safe_u32::magic_1().get();
                    mut_args.mk_elf_file.addr = helpers::to_u8_ptr(&mut_mk_elf_file);
                    mut_args.mk_elf_file.size = sizeof(mut_mk_elf_file);
                    mut_args.ext_elf_files[0].addr = helpers::to_u8_ptr(&mut_ext_elf_files);
                    mut_args.ext_elf_files[0].size = sizeof(mut_ext_elf_files);
                    helpers::ut_check(loader_init());
                    helpers::ut_check(start_vmm(&mut_args));
                    helpers::g_mut_map_4k_page = 3;
                    bsl::ut_then{} = [&]() noexcept {
                        helpers::ut_fails(func(1U));
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        helpers::ut_check(loader_fini());
                        helpers::reset();
                    };
                };
            };
        };

        bsl::ut_scenario{"map_mk_args fails"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                start_vmm_args_t mut_args{};
                helpers::file_t mut_mk_elf_file{};
                helpers::file_t mut_ext_elf_files{};
                bsl::ut_when{} = [&]() noexcept {
                    helpers::init_file(mut_mk_elf_file);
                    helpers::init_file(mut_ext_elf_files);
                    mut_args.ver = bsl::safe_u64::magic_1().get();
                    mut_args.num_pages_in_page_pool = bsl::safe_u32::magic_1().get();
                    mut_args.mk_elf_file.addr = helpers::to_u8_ptr(&mut_mk_elf_file);
                    mut_args.mk_elf_file.size = sizeof(mut_mk_elf_file);
                    mut_args.ext_elf_files[0].addr = helpers::to_u8_ptr(&mut_ext_elf_files);
                    mut_args.ext_elf_files[0].size = sizeof(mut_ext_elf_files);
                    helpers::ut_check(loader_init());
                    helpers::ut_check(start_vmm(&mut_args));
                    helpers::g_mut_map_4k_page = 4;
                    bsl::ut_then{} = [&]() noexcept {
                        helpers::ut_fails(func(1U));
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        helpers::ut_check(loader_fini());
                        helpers::reset();
                    };
                };
            };
        };

        bsl::ut_scenario{"get_mk_page_pool_addr fails"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                start_vmm_args_t mut_args{};
                helpers::file_t mut_mk_elf_file{};
                helpers::file_t mut_ext_elf_files{};
                bsl::ut_when{} = [&]() noexcept {
                    helpers::init_file(mut_mk_elf_file);
                    helpers::init_file(mut_ext_elf_files);
                    mut_args.ver = bsl::safe_u64::magic_1().get();
                    mut_args.num_pages_in_page_pool = bsl::safe_u32::magic_1().get();
                    mut_args.mk_elf_file.addr = helpers::to_u8_ptr(&mut_mk_elf_file);
                    mut_args.mk_elf_file.size = sizeof(mut_mk_elf_file);
                    mut_args.ext_elf_files[0].addr = helpers::to_u8_ptr(&mut_ext_elf_files);
                    mut_args.ext_elf_files[0].size = sizeof(mut_ext_elf_files);
                    helpers::ut_check(loader_init());
                    helpers::ut_check(start_vmm(&mut_args));
                    helpers::g_mut_platform_virt_to_phys = 3;
                    bsl::ut_then{} = [&]() noexcept {
                        helpers::ut_fails(func(1U));
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        helpers::ut_check(loader_fini());
                        helpers::reset();
                    };
                };
            };
        };

        bsl::ut_scenario{"get_mk_huge_pool_addr fails"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                start_vmm_args_t mut_args{};
                helpers::file_t mut_mk_elf_file{};
                helpers::file_t mut_ext_elf_files{};
                bsl::ut_when{} = [&]() noexcept {
                    helpers::init_file(mut_mk_elf_file);
                    helpers::init_file(mut_ext_elf_files);
                    mut_args.ver = bsl::safe_u64::magic_1().get();
                    mut_args.num_pages_in_page_pool = bsl::safe_u32::magic_1().get();
                    mut_args.mk_elf_file.addr = helpers::to_u8_ptr(&mut_mk_elf_file);
                    mut_args.mk_elf_file.size = sizeof(mut_mk_elf_file);
                    mut_args.ext_elf_files[0].addr = helpers::to_u8_ptr(&mut_ext_elf_files);
                    mut_args.ext_elf_files[0].size = sizeof(mut_ext_elf_files);
                    helpers::ut_check(loader_init());
                    helpers::ut_check(start_vmm(&mut_args));
                    helpers::g_mut_platform_virt_to_phys = 4;
                    bsl::ut_then{} = [&]() noexcept {
                        helpers::ut_fails(func(1U));
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        helpers::ut_check(loader_fini());
                        helpers::reset();
                    };
                };
            };
        };

        bsl::ut_scenario{"demote fails"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                start_vmm_args_t mut_args{};
                helpers::file_t mut_mk_elf_file{};
                helpers::file_t mut_ext_elf_files{};
                bsl::ut_when{} = [&]() noexcept {
                    helpers::init_file(mut_mk_elf_file);
                    helpers::init_file(mut_ext_elf_files);
                    mut_args.ver = bsl::safe_u64::magic_1().get();
                    mut_args.num_pages_in_page_pool = bsl::safe_u32::magic_1().get();
                    mut_args.mk_elf_file.addr = helpers::to_u8_ptr(&mut_mk_elf_file);
                    mut_args.mk_elf_file.size = sizeof(mut_mk_elf_file);
                    mut_args.ext_elf_files[0].addr = helpers::to_u8_ptr(&mut_ext_elf_files);
                    mut_args.ext_elf_files[0].size = sizeof(mut_ext_elf_files);
                    helpers::ut_check(loader_init());
                    helpers::ut_check(start_vmm(&mut_args));
                    helpers::g_mut_demote = 1;
                    bsl::ut_then{} = [&]() noexcept {
                        helpers::ut_fails(func(1U));
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        helpers::ut_check(loader_fini());
                        helpers::reset();
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
