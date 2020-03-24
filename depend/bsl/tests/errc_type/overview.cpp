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

#include <bsl/errc_type.hpp>
#include <bsl/ut.hpp>

/// <!-- description -->
///   @brief Main function for this unit test. If a call to ut_check() fails
///     the application will fast fail. If all calls to ut_check() pass, this
///     function will successfully return with bsl::exit_success.
///
/// <!-- contracts -->
///   @pre none
///   @post none
///
/// <!-- inputs/outputs -->
///   @return Always returns bsl::exit_success.
///
bsl::exit_code
main() noexcept
{
    using namespace bsl;

    bsl::ut_scenario{"constructor / get"} = []() {
        bsl::ut_given{} = []() {
            bsl::errc_type errc{42};
            bsl::ut_then{} = [&errc]() {
                bsl::ut_check(errc.get() == 42);
            };
        };
    };

    bsl::ut_scenario{"success"} = []() {
        bsl::ut_check(errc_success.success());
        bsl::ut_check(!errc_failure.success());
        bsl::ut_check(!errc_precondition.success());
        bsl::ut_check(!errc_postcondition.success());
        bsl::ut_check(!errc_assetion.success());
        bsl::ut_check(!errc_invalid_argument.success());
        bsl::ut_check(!errc_index_out_of_bounds.success());
        bsl::ut_check(!errc_bad_function.success());
        bsl::ut_check(!errc_unsigned_wrap.success());
        bsl::ut_check(!errc_narrow_overflow.success());
        bsl::ut_check(!errc_signed_overflow.success());
        bsl::ut_check(!errc_divide_by_zero.success());
        bsl::ut_check(!errc_nullptr_dereference.success());
    };

    bsl::ut_scenario{"failure"} = []() {
        bsl::ut_check(!errc_success.failure());
        bsl::ut_check(errc_failure.failure());
        bsl::ut_check(errc_precondition.failure());
        bsl::ut_check(errc_postcondition.failure());
        bsl::ut_check(errc_assetion.failure());
        bsl::ut_check(errc_invalid_argument.failure());
        bsl::ut_check(errc_index_out_of_bounds.failure());
        bsl::ut_check(errc_bad_function.failure());
        bsl::ut_check(errc_unsigned_wrap.failure());
        bsl::ut_check(errc_narrow_overflow.failure());
        bsl::ut_check(errc_signed_overflow.failure());
        bsl::ut_check(errc_divide_by_zero.failure());
        bsl::ut_check(errc_nullptr_dereference.failure());
    };

    bsl::ut_scenario{"is_checked"} = []() {
        bsl::ut_check(!errc_success.is_checked());
        bsl::ut_check(!errc_failure.is_checked());
        bsl::ut_check(!errc_precondition.is_checked());
        bsl::ut_check(!errc_postcondition.is_checked());
        bsl::ut_check(!errc_assetion.is_checked());
        bsl::ut_check(!errc_invalid_argument.is_checked());
        bsl::ut_check(!errc_index_out_of_bounds.is_checked());
        bsl::ut_check(!errc_bad_function.is_checked());
        bsl::ut_check(!errc_unsigned_wrap.is_checked());
        bsl::ut_check(!errc_narrow_overflow.is_checked());
        bsl::ut_check(!errc_signed_overflow.is_checked());
        bsl::ut_check(!errc_divide_by_zero.is_checked());
        bsl::ut_check(!errc_nullptr_dereference.is_checked());
    };

    bsl::ut_scenario{"is_unchecked"} = []() {
        bsl::ut_check(!errc_success.is_unchecked());
        bsl::ut_check(errc_failure.is_unchecked());
        bsl::ut_check(errc_precondition.is_unchecked());
        bsl::ut_check(errc_postcondition.is_unchecked());
        bsl::ut_check(errc_assetion.is_unchecked());
        bsl::ut_check(errc_invalid_argument.is_unchecked());
        bsl::ut_check(errc_index_out_of_bounds.is_unchecked());
        bsl::ut_check(errc_bad_function.is_unchecked());
        bsl::ut_check(errc_unsigned_wrap.is_unchecked());
        bsl::ut_check(errc_narrow_overflow.is_unchecked());
        bsl::ut_check(errc_signed_overflow.is_unchecked());
        bsl::ut_check(errc_divide_by_zero.is_unchecked());
        bsl::ut_check(errc_nullptr_dereference.is_unchecked());
    };

    bsl::ut_scenario{"message"} = []() {
        bsl::ut_check(errc_success.message() != nullptr);
        bsl::ut_check(errc_failure.message() != nullptr);
        bsl::ut_check(errc_precondition.message() != nullptr);
        bsl::ut_check(errc_postcondition.message() != nullptr);
        bsl::ut_check(errc_assetion.message() != nullptr);
        bsl::ut_check(errc_invalid_argument.message() != nullptr);
        bsl::ut_check(errc_index_out_of_bounds.message() != nullptr);
        bsl::ut_check(errc_bad_function.message() != nullptr);
        bsl::ut_check(errc_unsigned_wrap.message() != nullptr);
        bsl::ut_check(errc_narrow_overflow.message() != nullptr);
        bsl::ut_check(errc_signed_overflow.message() != nullptr);
        bsl::ut_check(errc_divide_by_zero.message() != nullptr);
        bsl::ut_check(errc_nullptr_dereference.message() != nullptr);
    };

    bsl::ut_scenario{"message with user defined"} = []() {
        bsl::ut_given{} = []() {
            bsl::errc_type errc{42};
            bsl::ut_then{} = [&errc]() {
                bsl::ut_check(errc.message() == nullptr);
            };
        };
    };

    bsl::ut_scenario{"equals"} = []() {
        bsl::ut_given{} = []() {
            bsl::errc_type errc1{42};
            bsl::errc_type errc2{42};
            bsl::ut_then{} = [&errc1, &errc2]() {
                bsl::ut_check(errc1 == errc2);
            };
        };
    };

    bsl::ut_scenario{"not equals"} = []() {
        bsl::ut_given{} = []() {
            bsl::errc_type errc1{23};
            bsl::errc_type errc2{42};
            bsl::ut_then{} = [&errc1, &errc2]() {
                bsl::ut_check(errc1 != errc2);
            };
        };
    };

    return bsl::ut_success();
}
