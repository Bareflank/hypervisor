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

#include "../../../include/x64/get_gdt_descriptor_attrib.h"

#include <global_descriptor_table_register_t.h>
#include <helpers.hpp>

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
        helpers::init_x64();
        constexpr auto func{&get_gdt_descriptor_attrib};

        bsl::ut_scenario{"descriptor 0"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                global_descriptor_table_register_t const gdtr{};
                constexpr auto selector{0x0_u16};
                bsl::safe_u16 mut_attrib{};
                bsl::ut_then{} = [&]() noexcept {
                    func(&gdtr, selector.get(), mut_attrib.data());
                };
                bsl::ut_cleanup{} = [&]() noexcept {
                    helpers::reset_x64();
                };
            };
        };

        bsl::ut_scenario{"descriptor 1"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                global_descriptor_table_register_t mut_gdtr{};
                constexpr auto selector{0x8_u16};
                constexpr auto num_descriptors{512_umx};
                constexpr auto limit{(num_descriptors - bsl::safe_umx::magic_1()).checked()};
                bsl::array<bsl::uint64, num_descriptors.get()> mut_descriptors{};
                bsl::safe_u16 mut_attrib{};
                bsl::ut_when{} = [&]() noexcept {
                    mut_gdtr.base = mut_descriptors.data();
                    mut_gdtr.limit = bsl::to_u16(limit).get();
                    bsl::ut_then{} = [&]() noexcept {
                        func(&mut_gdtr, selector.get(), mut_attrib.data());
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
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
