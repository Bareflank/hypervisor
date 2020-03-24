/// @copyright
/// Copyright (C) 2019 Assured Information Security, Inc.
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

#include <bsl/ut.hpp>
#include <bsl/span.hpp>
#include <bsl/is_pod.hpp>

namespace bsl
{
    /// <!-- description -->
    ///   @brief Provides the example's main function
    ///
    /// <!-- contracts -->
    ///   @pre none
    ///   @post none
    ///
    /// <!-- inputs/outputs -->
    ///   @param args the arguments passed to the application
    ///   @return exit_success on success, exit_failure otherwise
    ///
    bsl::exit_code
    entry(bsl::arguments const &args) noexcept
    {
        bsl::discard(args);
        static_assert(is_pod<span<bsl::int32>>::value);

        bsl::ut_scenario{"at"} = []() {
            bsl::ut_given{} = []() {
                bsl::span<bsl::int32> test{};
                bsl::ut_then{} = [&test]() {
                    bsl::ut_check(test.empty());
                    bsl::ut_check(test.front() == nullptr);
                    bsl::ut_check(test.back() == nullptr);
                };
            };
        };

        bsl::ut_scenario{"at"} = []() {
            bsl::ut_given{} = []() {
                bsl::int32 arr[1]{};
                bsl::int32 *ptr = arr;
                bsl::span<bsl::int32> test1{ptr, 42};
                bsl::span<bsl::int32> const test2{ptr, 42};
                bsl::ut_then{} = [&test1, &test2]() {
                    if (auto const elem = test1.at(0U)) {
                        *elem = 42;
                    }
                    if (auto const elem = test2.at(0U)) {
                        bsl::ut_check(*elem == 42);
                    }
                };
            };
        };

        bsl::ut_scenario{"at"} = []() {
            bsl::ut_given{} = []() {
                bsl::int32 arr[42]{};
                bsl::span test1{arr};
                bsl::span const test2{arr};
                bsl::ut_then{} = [&test1, &test2]() {
                    if (auto const elem = test1.at(0U)) {
                        *elem = 42;
                    }
                    if (auto const elem = test2.at(0U)) {
                        bsl::ut_check(*elem == 42);
                    }
                };
            };
        };

        return bsl::ut_success();
    }
}
