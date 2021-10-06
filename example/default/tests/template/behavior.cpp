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

// #include "../../src/<name>.hpp"

#include <bsl/convert.hpp>
#include <bsl/safe_integral.hpp>
#include <bsl/ut.hpp>

namespace example
{
    /// <!-- description -->
    ///   @brief Simple function for testing non-constexpr functions.
    ///
    /// <!-- inputs/outputs -->
    ///   @param val a value to test
    ///   @return Returns true if val is correct
    ///
    [[nodiscard]] auto
    runtime_only_function_that_knows_all(bsl::safe_umx const &val) noexcept -> bool
    {
        constexpr auto the_answer_to_everything{42_umx};
        return val == the_answer_to_everything;
    }

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
        /// NOTE:
        /// - The tests() function is executed both at compile-time and at
        ///   runtime. This is done using the following at the bottom of this
        ///   file.
        ///
        ///   static_assert(example::tests() == bsl::ut_success());
        ///   return example::tests();
        ///
        /// - Anything executed in a static_assert is executed at compile-time
        ///   while the other call is your typical runtime call.
        ///

        /// NOTE:
        /// - BSL unit tests use behavioral driven unit testing.
        ///   https://en.wikipedia.org/wiki/Behavior-driven_development
        ///
        /// - All of these calls are syntactic sugar, meaning they do
        ///   absolutely nothing, except to ensure you are setting up your
        ///   tests using behavioral driven methods. The actual work is
        ///   performed by the following:
        ///   - bsl::ut_check() - used inside bsl::ut_then, and is used to
        ///     verify the results of your unit test
        ///   - bsl::ut_required_step() - used inside of bsl::ut_when, and
        ///     is used to verify that your unit test's set up is correct.
        ///

        bsl::ut_scenario{"this is what I am testing"} = [&]() noexcept {
            bsl::ut_given{"given the following"} = [&]() noexcept {
                /// add variables here
                bsl::ut_when{"when we do the following"} = [&]() noexcept {
                    /// add function calls here
                    bsl::ut_then{"we expect the following"} = [&]() noexcept {
                        /// add results checking here
                    };
                };
            };
        };

        /// NOTE:
        /// - There are a couple of different ways to do this. Once way
        ///   is to group tests under the same scenario as follows:
        ///

        bsl::ut_scenario{"verify +="} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                constexpr auto data1{42_umx};
                bsl::safe_umx mut_data2{};
                bsl::ut_when{} = [&]() noexcept {
                    mut_data2 += data1;
                    bsl::ut_then{"adds correctly"} = [&]() noexcept {
                        bsl::ut_check(mut_data2.checked() == data1);
                    };
                };
            };

            bsl::ut_given_at_runtime{} = [&]() noexcept {
                constexpr auto data1{42_umx};
                auto mut_data2{bsl::safe_umx::failure()};
                bsl::ut_when{} = [&]() noexcept {
                    mut_data2 += data1;
                    bsl::ut_then{"preserves the error flag"} = [&]() noexcept {
                        bsl::ut_check(mut_data2.is_invalid());
                    };
                };
            };
        };

        /// NOTE:
        /// - Another way is to have one scenario for each test as follows.
        ///   Which way you choose if up to you, there likely isn't a right
        ///   way here. One advantage with this approach is each description
        ///   is a bit more helpful in determining what you are actually
        ///   changing as sometimes, the changes between each test can be
        ///   really hard to see, especially when each test is big and you
        ///   are only changing one thing (or even a single character)
        ///

        bsl::ut_scenario{"verify += adds correctly"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                constexpr auto data1{42_umx};
                bsl::safe_umx mut_data2{};
                bsl::ut_when{} = [&]() noexcept {
                    mut_data2 += data1;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_data2.checked() == data1);
                    };
                };
            };
        };

        bsl::ut_scenario{"verify += preserves the error flag"} = [&]() noexcept {
            bsl::ut_given_at_runtime{} = [&]() noexcept {
                constexpr auto data1{42_umx};
                auto mut_data2{bsl::safe_umx::failure()};
                bsl::ut_when{} = [&]() noexcept {
                    mut_data2 += data1;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_data2.is_invalid());
                    };
                };
            };
        };

        /// NOTE:
        /// - If you have to unit test something that does not support
        ///   constexpr, you can use this pattern. This should be avoided
        ///   whenever possible. These tests will only be verified at
        ///   runtime as they are excluded from compile-time verification.
        /// - Also not how bsl::ut_when was removed. This is because there
        ///   was no additional action to take.
        ///

        bsl::ut_scenario{"test something at runtime only"} = [&]() noexcept {
            bsl::ut_given_at_runtime{} = [&]() noexcept {
                constexpr auto val{42_umx};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(runtime_only_function_that_knows_all(val));
                };
            };

            bsl::ut_given_at_runtime{} = [&]() noexcept {
                constexpr auto val{23_umx};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!runtime_only_function_that_knows_all(val));
                };
            };
        };

        /// NOTE:
        /// - There are also times when you need to set up a test and ensure
        ///   that specific steps in the test's set up succeed. Otherwise, the
        ///   test itself might not be valid, could cause a crach, etc. When
        ///   this is needed, you can use the bsl::ut_required_step() function.
        /// - This function is identical to bsl::ut_check(). It just has a
        ///   different name and is intended to be used in the bsl::ut_when()
        ///   block, and has a different name just to help with readability.
        ///

        bsl::ut_scenario{"verify += preserves the error flag"} = [&]() noexcept {
            bsl::ut_given_at_runtime{} = [&]() noexcept {
                constexpr auto data1{42_umx};
                auto mut_data2{bsl::safe_umx::failure()};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(mut_data2.is_invalid());
                    mut_data2 += data1;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_data2.is_invalid());
                    };
                };
            };
        };

        /// NOTE:
        /// - Finally, some tests will use the same variables, but check
        ///   different conditions. When you do this, we don't want to have
        ///   to manually reset a specific variable for each test. If the
        ///   type is copyable, we can use the following pattern, otherwise
        ///   you should create a new variable for each test to ensure you
        ///   have a clean slate as we did in the tests above.
        /// - Note that the key difference here is that we are not passing
        ///   by reference but instead by value which performs a copy, but
        ///   when we do this, we need to add the mutable keyword.
        ///

        bsl::ut_scenario{"verify two different conditions"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                constexpr auto data1{42_umx};
                bsl::safe_umx mut_data2{};
                bsl::ut_when{} = [&, mut_data2]() mutable noexcept {
                    mut_data2 += data1;
                    bsl::ut_then{} = [&, mut_data2]() noexcept {
                        bsl::ut_check(mut_data2.checked() == data1);
                    };
                };

                bsl::ut_when{} = [&, mut_data2]() mutable noexcept {
                    mut_data2 += (data1 * data1);
                    bsl::ut_then{} = [&, mut_data2]() noexcept {
                        bsl::ut_check(mut_data2.checked() == (data1 * data1).checked());
                    };
                };
            };
        };

        /// NOTE:
        /// - The following provides a basic block that you can cut/paste
        ///   for each test as needed. Don't forget that you have the following
        ///   make targets when you compile with CODECOV as the build target,
        ///   which will help you check for coverage.
        ///   - make codecov-grcov (puts the results in ${CMAKE_SOURCE_DIR}/grcov)
        ///   - make codecov-genhtml (Linux only, puts the results in ${CMAKE_SOURCE_DIR}/genhtml)
        ///   - make codecov-upload (uploads coverage reports to Codecov if you set your token)
        ///
        /// - Good luck!!!
        ///

        bsl::ut_scenario{"description"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_required_step(true);
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(true);
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

    static_assert(example::tests() == bsl::ut_success());
    return example::tests();
}
