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

#include "../../include/map_mk_elf_segments.h"

#include <constants.h>
#include <elf_segment_t.h>
#include <helpers.hpp>
#include <root_page_table_t.h>

#include <bsl/array.hpp>
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
        helpers::init();
        constexpr auto func{&map_mk_elf_segments};

        bsl::ut_scenario{"success"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                bsl::array<elf_segment_t, HYPERVISOR_MAX_SEGMENTS> mut_segments{};
                root_page_table_t mut_rpt{};
                constexpr auto buf_size{0x2042_umx};
                bsl::array<bsl::uint8, buf_size.get()> mut_buf{};
                bsl::ut_when{} = [&]() noexcept {
                    mut_segments.front().addr = mut_buf.data();
                    mut_segments.front().size = mut_buf.size().get();
                    bsl::ut_then{} = [&]() noexcept {
                        helpers::ut_check(func(mut_segments.data(), &mut_rpt));
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        helpers::reset();
                    };
                };
            };
        };

        bsl::ut_scenario{"platform_virt_to_phys fails"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                bsl::array<elf_segment_t, HYPERVISOR_MAX_SEGMENTS> mut_segments{};
                root_page_table_t mut_rpt{};
                constexpr auto buf_size{0x2042_umx};
                bsl::array<bsl::uint8, buf_size.get()> mut_buf{};
                bsl::ut_when{} = [&]() noexcept {
                    mut_segments.front().addr = mut_buf.data();
                    mut_segments.front().size = mut_buf.size().get();
                    helpers::g_mut_platform_virt_to_phys = 1;
                    bsl::ut_then{} = [&]() noexcept {
                        helpers::ut_fails(func(mut_segments.data(), &mut_rpt));
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        helpers::reset();
                    };
                };
            };
        };

        bsl::ut_scenario{"map_4k_page fails"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                bsl::array<elf_segment_t, HYPERVISOR_MAX_SEGMENTS> mut_segments{};
                root_page_table_t mut_rpt{};
                constexpr auto buf_size{0x2042_umx};
                bsl::array<bsl::uint8, buf_size.get()> mut_buf{};
                bsl::ut_when{} = [&]() noexcept {
                    mut_segments.front().addr = mut_buf.data();
                    mut_segments.front().size = mut_buf.size().get();
                    helpers::g_mut_map_4k_page = 1;
                    bsl::ut_then{} = [&]() noexcept {
                        helpers::ut_fails(func(mut_segments.data(), &mut_rpt));
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
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
