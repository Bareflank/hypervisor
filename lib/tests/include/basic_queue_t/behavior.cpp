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

#include "../../../include/basic_queue_t.hpp"

#include <bsl/convert.hpp>
#include <bsl/errc_type.hpp>
#include <bsl/safe_idx.hpp>
#include <bsl/safe_integral.hpp>
#include <bsl/ut.hpp>

namespace microv
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
        constexpr auto queue_size{3_umx};

        bsl::ut_scenario{"initial state"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                lib::basic_queue_t<bool, queue_size.get()> mut_queue{};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_queue.empty());
                        bsl::ut_check(mut_queue.size() == queue_size);
                    };
                };
            };
        };

        bsl::ut_scenario{"push until full"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                lib::basic_queue_t<bool, queue_size.get()> mut_queue{};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_queue.push(true));
                    bsl::ut_required_step(mut_queue.push(true));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(!mut_queue.push(true));
                        bsl::ut_check(!mut_queue.empty());
                    };
                };
            };
        };

        bsl::ut_scenario{"pop until empty"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                lib::basic_queue_t<bool, queue_size.get()> mut_queue{};
                bool mut_val{};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_queue.push(true));
                    bsl::ut_required_step(mut_queue.push(true));
                    bsl::ut_then{} = [&]() noexcept {
                        mut_val = {};
                        bsl::ut_check(mut_queue.pop(mut_val));
                        bsl::ut_check(!mut_queue.empty());
                        bsl::ut_check(mut_val);

                        mut_val = {};
                        bsl::ut_check(mut_queue.pop(mut_val));
                        bsl::ut_check(mut_queue.empty());
                        bsl::ut_check(mut_val);

                        mut_val = {};
                        bsl::ut_check(!mut_queue.pop(mut_val));
                        bsl::ut_check(mut_queue.empty());
                        bsl::ut_check(!mut_val);
                    };
                };
            };
        };

        bsl::ut_scenario{"push/pop in a loop"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                lib::basic_queue_t<bool, queue_size.get()> mut_queue{};
                bool mut_val{};
                bsl::ut_when{} = [&]() noexcept {
                    for (bsl::safe_idx mut_i{}; mut_i < bsl::to_umx(0x1000); ++mut_i) {
                        bsl::ut_required_step(mut_queue.push(true));
                        bsl::ut_required_step(mut_queue.pop(mut_val));
                    }
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_queue.empty());
                    };
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

    static_assert(microv::tests() == bsl::ut_success());
    return microv::tests();
}
