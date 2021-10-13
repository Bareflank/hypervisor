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

#include "../../../include/x64/alloc_pt.h"
#include "../../../include/x64/free_pdt.h"

#include <helpers.hpp>
#include <pdt_t.h>
#include <pdte_t.h>

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
        constexpr auto func{&alloc_pt};

        bsl::ut_scenario{"success"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                pdt_t mut_pdt{};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(nullptr != func(&mut_pdt, {}));
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        free_pdt(&mut_pdt);
                        helpers::reset_x64();
                    };
                };
            };
        };

        bsl::ut_scenario{"already present"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                pdt_t mut_pdt{};
                bsl::ut_when{} = [&]() noexcept {
                    mut_pdt.entires[0].p = bsl::safe_u64::magic_1().get();
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(nullptr == func(&mut_pdt, {}));
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        helpers::reset_x64();
                    };
                };
            };
        };

        bsl::ut_scenario{"platform_alloc fails"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                pdt_t mut_pdt{};
                bsl::ut_when{} = [&]() noexcept {
                    helpers::g_mut_platform_alloc = 1;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(nullptr == func(&mut_pdt, {}));
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        helpers::reset_x64();
                    };
                };
            };
        };

        bsl::ut_scenario{"platform_virt_to_phys fails"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                pdt_t mut_pdt{};
                bsl::ut_when{} = [&]() noexcept {
                    helpers::g_mut_platform_virt_to_phys = 1;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(nullptr == func(&mut_pdt, {}));
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
