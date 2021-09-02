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

#include "../../../MOCK/vmexit_t.hpp"

#include <bsl/ut.hpp>

namespace example
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
        bsl::ut_scenario{"initialize fails"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                vmexit_t mut_vmexit{};
                bsl::ut_when{} = [&]() noexcept {
                    mut_vmexit.set_initialize(bsl::errc_failure);
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(!mut_vmexit.initialize({}, {}, {}, {}, {}, {}));
                    };
                };
            };
        };

        bsl::ut_scenario{"initialize success"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                vmexit_t mut_vmexit{};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(mut_vmexit.initialize({}, {}, {}, {}, {}, {}));
                };
            };
        };

        bsl::ut_scenario{"release executes"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                vmexit_t mut_vmexit{};
                bsl::ut_then{} = [&]() noexcept {
                    mut_vmexit.release({}, {}, {}, {}, {}, {});
                };
            };
        };

        bsl::ut_scenario{"dispatch fails"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                vmexit_t mut_vmexit{};
                bsl::ut_when{} = [&]() noexcept {
                    mut_vmexit.set_dispatch(bsl::errc_failure);
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(!mut_vmexit.dispatch({}, {}, {}, {}, {}, {}, {}, {}));
                    };
                };
            };
        };

        bsl::ut_scenario{"dispatch success"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                vmexit_t mut_vmexit{};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(mut_vmexit.dispatch({}, {}, {}, {}, {}, {}, {}, {}));
                };
            };
        };

        return bsl::ut_success();
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

    static_assert(example::tests() == bsl::ut_success());
    return example::tests();
}
