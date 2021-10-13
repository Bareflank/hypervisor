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

#include "../../include/alloc_and_copy_ext_elf_files_from_user.h"
#include "../../include/free_ext_elf_files.h"

#include <bfelf/bfelf_elf64_ehdr_t.h>
#include <constants.h>
#include <elf_file_t.h>
#include <helpers.hpp>
#include <span_t.h>

#include <bsl/array.hpp>
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
        constexpr auto func{&alloc_and_copy_ext_elf_files_from_user};

        bsl::ut_scenario{"success"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                bfelf_elf64_ehdr_t mut_file{};
                bsl::array<span_t, HYPERVISOR_MAX_EXTENSIONS> mut_ext_elf_files_from_user{};
                bsl::array<elf_file_t, HYPERVISOR_MAX_EXTENSIONS> mut_copied_ext_elf_files{};
                bsl::ut_when{} = [&]() noexcept {
                    mut_ext_elf_files_from_user.front().addr = helpers::to_u8_ptr(&mut_file);
                    mut_ext_elf_files_from_user.front().size = sizeof(bfelf_elf64_ehdr_t);
                    mut_file.e_phnum = bsl::safe_u16::magic_1().get();
                    mut_file.e_shnum = bsl::safe_u16::magic_1().get();
                    bsl::ut_then{} = [&]() noexcept {
                        helpers::ut_check(func(
                            mut_ext_elf_files_from_user.data(), mut_copied_ext_elf_files.data()));
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        free_ext_elf_files(mut_copied_ext_elf_files.data());
                        helpers::reset();
                    };
                };
            };
        };

        bsl::ut_scenario{"free without alloc"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                bsl::array<elf_file_t, HYPERVISOR_MAX_EXTENSIONS> mut_copied_ext_elf_files{};
                bsl::ut_then{} = [&]() noexcept {
                    free_ext_elf_files(mut_copied_ext_elf_files.data());
                };
                bsl::ut_cleanup{} = [&]() noexcept {
                    helpers::reset();
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
