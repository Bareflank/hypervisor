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
#include <bsl/safe_integral.hpp>
#include <bsl/ut.hpp>

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
    constexpr auto queue_size{3_umx};

    bsl::ut_scenario{"verify noexcept"} = [&]() noexcept {
        bsl::ut_given{} = [&]() noexcept {
            bool mut_val{};
            lib::basic_queue_t<bool, queue_size.get()> mut_queue{};
            lib::basic_queue_t<bool, queue_size.get()> const queue{};
            bsl::ut_then{} = [&]() noexcept {
                static_assert(noexcept(lib::basic_queue_t<bool, queue_size.get()>{}));

                static_assert(noexcept(mut_queue.push({})));
                static_assert(noexcept(mut_queue.pop(mut_val)));
                static_assert(noexcept(mut_queue.empty()));
                static_assert(noexcept(mut_queue.full()));
                static_assert(noexcept(mut_queue.size()));

                static_assert(noexcept(queue.empty()));
                static_assert(noexcept(queue.full()));
                static_assert(noexcept(queue.size()));
            };
        };
    };

    return bsl::ut_success();
}
