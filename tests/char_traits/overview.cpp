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

#include <bsl/char_traits.hpp>
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
    using traits = char_traits<char_type>;

    bsl::ut_scenario{"assign"} = []() {
        bsl::ut_given{} = []() {
            char_type a{23};
            char_type b{42};
            bsl::ut_when{} = [&a, &b]() {
                traits::assign(a, b);
                bsl::ut_then{} = [&a, &b]() {
                    bsl::ut_check(a == 42);
                    bsl::ut_check(b == 42);
                };
            };
        };

        bsl::ut_given{} = []() {
            char_type a{23};
            char_type b{42};
            bsl::ut_when{} = [&a, &b]() {
                traits::assign(&a, 1, b);
                bsl::ut_then{} = [&a, &b]() {
                    bsl::ut_check(a == 42);
                    bsl::ut_check(b == 42);
                };
            };
        };
    };

    bsl::ut_scenario{"eq"} = []() {
        bsl::ut_given{} = []() {
            char_type a{42};
            char_type b{42};
            bsl::ut_then{} = [&a, &b]() {
                bsl::ut_check(traits::eq(a, b));
            };
        };
    };

    bsl::ut_scenario{"lt"} = []() {
        bsl::ut_given{} = []() {
            char_type a{23};
            char_type b{42};
            bsl::ut_then{} = [&a, &b]() {
                bsl::ut_check(traits::lt(a, b));
            };
        };
    };

    bsl::ut_scenario{"move"} = []() {
        bsl::ut_given{} = []() {
            char_type a{23};
            char_type b{42};
            bsl::ut_when{} = [&a, &b]() {
                traits::move(&a, &b, 1);
                bsl::ut_then{} = [&a, &b]() {
                    bsl::ut_check(a == 42);
                    bsl::ut_check(b == 42);
                };
            };
        };
    };

    bsl::ut_scenario{"copy"} = []() {
        bsl::ut_given{} = []() {
            char_type a{23};
            char_type b{42};
            bsl::ut_when{} = [&a, &b]() {
                traits::copy(&a, &b, 1);
                bsl::ut_then{} = [&a, &b]() {
                    bsl::ut_check(a == 42);
                    bsl::ut_check(b == 42);
                };
            };
        };
    };

    bsl::ut_scenario{"compare"} = []() {
        bsl::ut_check(traits::compare(nullptr, "42", 2) == 0);
        bsl::ut_check(traits::compare("42", nullptr, 2) == 0);
        bsl::ut_check(traits::compare("42", "42", 3) == 0);
        bsl::ut_check(traits::compare("42", "42", 2) == 0);
        bsl::ut_check(traits::compare("42", "42", 1) == 0);
        bsl::ut_check(traits::compare("42", "42", 0) == 0);
        bsl::ut_check(traits::compare("42", "23", 2) != 0);
        bsl::ut_check(traits::compare("23", "42", 2) != 0);
        bsl::ut_check(traits::compare("4", "42", 2) != 0);
        bsl::ut_check(traits::compare("42", "4", 2) != 0);
        bsl::ut_check(traits::compare("", "42", 2) != 0);
        bsl::ut_check(traits::compare("42", "", 2) != 0);
    };

    bsl::ut_scenario{"length"} = []() {
        bsl::ut_check(traits::length(nullptr) == 0);
        bsl::ut_check(traits::length("") == 0);
        bsl::ut_check(traits::length("42") == 2);
        bsl::ut_check(traits::length("4\0 2") == 1);
    };

    bsl::ut_scenario{"find"} = []() {
        bsl::ut_given{} = []() {
            char_type test[] = "Hello World";                               // NOLINT
            bsl::ut_then{} = [&test]() {                                    // NOLINT
                bsl::ut_check(traits::find(nullptr, 5, 'l') == nullptr);    // NOLINT
                bsl::ut_check(traits::find(test, 5, 'l') == test + 2);      // NOLINT
                bsl::ut_check(traits::find(test, 1, 'l') == nullptr);       // NOLINT
                bsl::ut_check(traits::find(test, 2, 'l') == nullptr);       // NOLINT
                bsl::ut_check(traits::find(test, 3, 'l') == test + 2);      // NOLINT
                bsl::ut_check(traits::find(test, 255, 'l') == test + 2);    // NOLINT
                bsl::ut_check(traits::find(test, 5, 'z') == nullptr);       // NOLINT
            };
        };
    };

    bsl::ut_scenario{"to_char_type"} = []() {
        bsl::ut_check(traits::to_char_type(42) == 42);
        bsl::ut_check(
            traits::to_char_type(numeric_limits<bsl::intmax>::max()) !=
            numeric_limits<bsl::intmax>::max());
    };

    bsl::ut_scenario{"to_int_type"} = []() {
        bsl::ut_check(traits::to_char_type(42) == 42);
    };

    bsl::ut_scenario{"eq_int_type"} = []() {
        bsl::ut_check(traits::eq_int_type(42, 42));
        bsl::ut_check(traits::eq_int_type(traits::eof(), traits::eof()));
        bsl::ut_check(!traits::eq_int_type(42, traits::eof()));
        bsl::ut_check(!traits::eq_int_type(traits::eof(), 42));
    };

    bsl::ut_scenario{"eof"} = []() {
        bsl::ut_check(traits::eof() == -1);
    };

    bsl::ut_scenario{"not_eof"} = []() {
        bsl::ut_check(traits::not_eof(42) == 42);
        bsl::ut_check(traits::not_eof(0) == 0);
        bsl::ut_check(traits::not_eof(traits::eof()) == 0);
    };

    return bsl::ut_success();
}
