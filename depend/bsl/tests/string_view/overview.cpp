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

#include <bsl/string_view.hpp>
#include <bsl/cstr_type.hpp>
#include <bsl/is_base_of.hpp>
#include <bsl/is_pod.hpp>
#include <bsl/max.hpp>
#include <bsl/ut.hpp>

namespace
{
    constexpr bsl::cstr_type msg{"Hello World"};
    constexpr bsl::uintmax msg_length{bsl::char_traits<bsl::char_type>::length(msg)};
}

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

    bsl::ut_scenario{"requirements"} = []() {
        static_assert(is_pod<string_view>::value);
        static_assert(is_base_of<details::view<char_type const>, string_view>::value);
    };

    bsl::ut_scenario{"default constructor"} = []() {
        static_assert(string_view{}.empty());
    };

    bsl::ut_scenario{"pointer to string and size constructor"} = []() {
        static_assert(string_view{msg, msg_length}.data() == msg);
        static_assert(string_view{msg, msg_length}.size() == msg_length);
        static_assert(string_view{nullptr, msg_length}.data() == nullptr);    // NOLINT
        static_assert(string_view{nullptr, msg_length}.size() == 0);          // NOLINT
        static_assert(string_view{msg, 0}.data() == nullptr);                 // NOLINT
        static_assert(string_view{msg, 0}.size() == 0);                       // NOLINT
        static_assert(string_view{nullptr, 0}.data() == nullptr);             // NOLINT
        static_assert(string_view{nullptr, 0}.size() == 0);                   // NOLINT
    };

    bsl::ut_scenario{"pointer to string constructor"} = []() {
        static_assert(string_view{msg}.data() == msg);
        static_assert(string_view{msg}.size() == msg_length);
        static_assert(string_view{nullptr}.data() == nullptr);    // NOLINT
        static_assert(string_view{nullptr}.size() == 0);          // NOLINT
    };

    bsl::ut_scenario{"length"} = []() {
        static_assert(string_view{}.length() == 0);
        static_assert(string_view{msg, msg_length}.length() == msg_length);
        static_assert(string_view{msg}.length() == msg_length);
        static_assert(string_view{msg, 5}.length() == 5);
        static_assert(string_view{msg, 0}.length() == 0);
    };

    bsl::ut_scenario{"remove_prefix"} = []() {
        static_assert(string_view{}.remove_prefix(0).empty());
        static_assert(string_view{}.remove_prefix(6).empty());
        static_assert(string_view{msg}.remove_prefix(0).compare(msg) == 0);
        static_assert(string_view{msg}.remove_prefix(6).compare("World") == 0);
        static_assert(string_view{msg}.remove_prefix(msg_length).empty());
        static_assert(string_view{msg}.remove_prefix(bsl::npos).empty());
    };

    bsl::ut_scenario{"remove_suffix"} = []() {
        static_assert(string_view{}.remove_suffix(0).empty());
        static_assert(string_view{}.remove_suffix(6).empty());
        static_assert(string_view{msg}.remove_suffix(0).compare(msg) == 0);
        static_assert(string_view{msg}.remove_suffix(6).compare("Hello") == 0);
        static_assert(string_view{msg}.remove_suffix(msg_length).empty());
        static_assert(string_view{msg}.remove_suffix(bsl::npos).empty());
    };

    bsl::ut_scenario{"copy"} = []() {
        bsl::ut_then{} = []() {
            ut_check(string_view{}.copy(nullptr, 0) == 0);
            ut_check(string_view{}.copy(nullptr, msg_length) == 0);
        };

        bsl::ut_given{} = []() {
            char_type buf[256];                                                      // NOLINT
            bsl::ut_then{} = [&buf]() {                                              // NOLINT
                ut_check(string_view{msg}.copy(buf, 0, bsl::npos) == 0);             // NOLINT
                ut_check(string_view{msg}.copy(buf, msg_length, bsl::npos) == 0);    // NOLINT
            };
        };

        bsl::ut_given{} = []() {
            char_type buf[256];                                        // NOLINT
            bsl::ut_then{} = [&buf]() {                                // NOLINT
                ut_check(string_view{}.copy(buf, 0) == 0);             // NOLINT
                ut_check(string_view{}.copy(buf, msg_length) == 0);    // NOLINT
            };
        };

        bsl::ut_given{} = []() {
            char_type buf[256];                                           // NOLINT
            bsl::ut_then{} = [&buf]() {                                   // NOLINT
                ut_check(string_view{}.copy(buf, 0, 6) == 0);             // NOLINT
                ut_check(string_view{}.copy(buf, msg_length, 6) == 0);    // NOLINT
            };
        };

        bsl::ut_given{} = []() {
            char_type buf[256];                                                   // NOLINT
            bsl::ut_then{} = [&buf]() {                                           // NOLINT
                ut_check(string_view{msg}.copy(buf, 0) == 0);                     // NOLINT
                ut_check(string_view{msg}.copy(buf, bsl::npos) == msg_length);    // NOLINT
                ut_check(
                    string_view{msg}.compare(0, msg_length, buf, msg_length) == 0);    // NOLINT
            };
        };

        bsl::ut_given{} = []() {
            char_type buf[256];                                                            // NOLINT
            bsl::ut_then{} = [&buf]() {                                                    // NOLINT
                ut_check(string_view{msg}.copy(buf, 0, 6) == 0);                           // NOLINT
                ut_check(string_view{msg}.copy(buf, bsl::npos, 6) == 5);                   // NOLINT
                ut_check(string_view{msg}.compare(6, bsl::npos, buf, msg_length) == 0);    // NOLINT
            };
        };
    };

    bsl::ut_scenario{"substr"} = []() {
        static_assert(string_view{}.substr().empty());
        static_assert(string_view{msg}.substr() == msg);
        static_assert(string_view{}.substr(0).empty());
        static_assert(string_view{}.substr(0, 0).empty());
        static_assert(string_view{}.substr(0, bsl::npos).empty());
        static_assert(string_view{}.substr(msg_length, bsl::npos).empty());
        static_assert(string_view{msg}.substr(0) == msg);
        static_assert(string_view{msg}.substr(6) == "World");
        static_assert(string_view{msg}.substr(msg_length).empty());
        static_assert(string_view{msg}.substr(0, msg_length) == msg);
        static_assert(string_view{msg}.substr(6, msg_length) == "World");
        static_assert(string_view{msg}.substr(msg_length, msg_length).empty());
    };

    // clang-format off

    bsl::ut_scenario{"compare"} = []() {
        static_assert(string_view{}.compare(string_view{}) == 0);
        static_assert(string_view{}.compare(string_view{msg}) == 0);
        static_assert(string_view{msg}.compare(string_view{}) == 0);

        static_assert(string_view{msg}.compare(string_view{}) == 0);
        static_assert(string_view{msg}.compare(string_view{msg}) == 0);
        static_assert(string_view{msg}.compare(string_view{"invalid"}) != 0);

        static_assert(string_view{msg}.compare(0, 0, string_view{}) == 0);
        static_assert(string_view{msg}.compare(0, 0, string_view{msg}) == 0);
        static_assert(string_view{msg}.compare(0, 0, string_view{"invalid"}) == 0);
        static_assert(string_view{msg}.compare(6, 5, string_view{}) == 0);
        static_assert(string_view{msg}.compare(6, 5, string_view{"World"}) == 0);
        static_assert(string_view{msg}.compare(6, 5, string_view{"invalid"}) != 0);
        static_assert(string_view{msg}.compare(6, bsl::npos, string_view{}) == 0);
        static_assert(string_view{msg}.compare(6, bsl::npos, string_view{"World"}) == 0);
        static_assert(string_view{msg}.compare(6, bsl::npos, string_view{"invalid"}) != 0);
        static_assert(string_view{msg}.compare(bsl::npos, bsl::npos, string_view{}) == 0);
        static_assert(string_view{msg}.compare(bsl::npos, bsl::npos, string_view{"World"}) == 0);
        static_assert(string_view{msg}.compare(bsl::npos, bsl::npos, string_view{"invalid"}) == 0);

        static_assert(string_view{msg}.compare(0, 0, string_view{}, 0, 0) == 0);
        static_assert(string_view{msg}.compare(0, 0, string_view{msg}, 0, 0) == 0);
        static_assert(string_view{msg}.compare(0, 0, string_view{"invalid"}, 0, 0) == 0);
        static_assert(string_view{msg}.compare(6, 5, string_view{}, 0, 0) == 0);
        static_assert(string_view{msg}.compare(6, 5, string_view{msg}, 0, 0) == 0);
        static_assert(string_view{msg}.compare(6, 5, string_view{"invalid"}, 0, 0) == 0);
        static_assert(string_view{msg}.compare(6, bsl::npos, string_view{}, 0, 0) == 0);
        static_assert(string_view{msg}.compare(6, bsl::npos, string_view{msg}, 0, 0) == 0);
        static_assert(string_view{msg}.compare(6, bsl::npos, string_view{"invalid"}, 0, 0) == 0);
        static_assert(string_view{msg}.compare(bsl::npos, bsl::npos, string_view{}, 0, 0) == 0);
        static_assert(string_view{msg}.compare(bsl::npos, bsl::npos, string_view{msg}, 0, 0) == 0);
        static_assert(string_view{msg}.compare(bsl::npos, bsl::npos, string_view{"invalid"}, 0, 0) == 0);
        static_assert(string_view{msg}.compare(0, 0, string_view{}, 6, 5) == 0);
        static_assert(string_view{msg}.compare(0, 0, string_view{msg}, 6, 5) == 0);
        static_assert(string_view{msg}.compare(0, 0, string_view{"invalid"}, 6, 5) == 0);
        static_assert(string_view{msg}.compare(6, 5, string_view{}, 6, 5) == 0);
        static_assert(string_view{msg}.compare(6, 5, string_view{msg}, 6, 5) == 0);
        static_assert(string_view{msg}.compare(6, 5, string_view{"invalid"}, 6, 5) != 0);
        static_assert(string_view{msg}.compare(6, bsl::npos, string_view{}, 6, 5) == 0);
        static_assert(string_view{msg}.compare(6, bsl::npos, string_view{msg}, 6, 5) == 0);
        static_assert(string_view{msg}.compare(6, bsl::npos, string_view{"invalid"}, 6, 5) != 0);
        static_assert(string_view{msg}.compare(bsl::npos, bsl::npos, string_view{}, 6, 5) == 0);
        static_assert(string_view{msg}.compare(bsl::npos, bsl::npos, string_view{msg}, 6, 5) == 0);
        static_assert(string_view{msg}.compare(bsl::npos, bsl::npos, string_view{"invalid"}, 6, 5) == 0);
        static_assert(string_view{msg}.compare(0, 0, string_view{}, 6, bsl::npos) == 0);
        static_assert(string_view{msg}.compare(0, 0, string_view{msg}, 6, bsl::npos) == 0);
        static_assert(string_view{msg}.compare(0, 0, string_view{"invalid"}, 6, bsl::npos) == 0);
        static_assert(string_view{msg}.compare(6, 5, string_view{}, 6, bsl::npos) == 0);
        static_assert(string_view{msg}.compare(6, 5, string_view{msg}, 6, bsl::npos) == 0);
        static_assert(string_view{msg}.compare(6, 5, string_view{"invalid"}, 6, bsl::npos) != 0);
        static_assert(string_view{msg}.compare(6, bsl::npos, string_view{}, 6, bsl::npos) == 0);
        static_assert(string_view{msg}.compare(6, bsl::npos, string_view{msg}, 6, bsl::npos) == 0);
        static_assert(string_view{msg}.compare(6, bsl::npos, string_view{"invalid"}, 6, bsl::npos) != 0);
        static_assert(string_view{msg}.compare(bsl::npos, bsl::npos, string_view{}, 6, bsl::npos) == 0);
        static_assert(string_view{msg}.compare(bsl::npos, bsl::npos, string_view{msg}, 6, bsl::npos) == 0);
        static_assert(string_view{msg}.compare(bsl::npos, bsl::npos, string_view{"invalid"}, 6, bsl::npos) == 0);
        static_assert(string_view{msg}.compare(0, 0, string_view{}, bsl::npos, bsl::npos) == 0);
        static_assert(string_view{msg}.compare(0, 0, string_view{msg}, bsl::npos, bsl::npos) == 0);
        static_assert(string_view{msg}.compare(0, 0, string_view{"invalid"}, bsl::npos, bsl::npos) == 0);
        static_assert(string_view{msg}.compare(6, 5, string_view{}, bsl::npos, bsl::npos) == 0);
        static_assert(string_view{msg}.compare(6, 5, string_view{msg}, bsl::npos, bsl::npos) == 0);
        static_assert(string_view{msg}.compare(6, 5, string_view{"invalid"}, bsl::npos, bsl::npos) == 0);
        static_assert(string_view{msg}.compare(6, bsl::npos, string_view{}, bsl::npos, bsl::npos) == 0);
        static_assert(string_view{msg}.compare(6, bsl::npos, string_view{msg}, bsl::npos, bsl::npos) == 0);
        static_assert(string_view{msg}.compare(6, bsl::npos, string_view{"invalid"}, bsl::npos, bsl::npos) == 0);
        static_assert(string_view{msg}.compare(bsl::npos, bsl::npos, string_view{}, bsl::npos, bsl::npos) == 0);
        static_assert(string_view{msg}.compare(bsl::npos, bsl::npos, string_view{msg}, bsl::npos, bsl::npos) == 0);
        static_assert(string_view{msg}.compare(bsl::npos, bsl::npos, string_view{"invalid"}, bsl::npos, bsl::npos) == 0);

        static_assert(string_view{msg}.compare("") == 0);
        static_assert(string_view{msg}.compare(msg) == 0);
        static_assert(string_view{msg}.compare("invalid") != 0);

        static_assert(string_view{msg}.compare(0, 0, "") == 0);
        static_assert(string_view{msg}.compare(0, 0, msg) == 0);
        static_assert(string_view{msg}.compare(0, 0, "invalid") == 0);
        static_assert(string_view{msg}.compare(6, 5, "") == 0);
        static_assert(string_view{msg}.compare(6, 5, "World") == 0);
        static_assert(string_view{msg}.compare(6, 5, "invalid") != 0);
        static_assert(string_view{msg}.compare(6, bsl::npos, "") == 0);
        static_assert(string_view{msg}.compare(6, bsl::npos, "World") == 0);
        static_assert(string_view{msg}.compare(6, bsl::npos, "invalid") != 0);
        static_assert(string_view{msg}.compare(bsl::npos, bsl::npos, "") == 0);
        static_assert(string_view{msg}.compare(bsl::npos, bsl::npos, "World") == 0);
        static_assert(string_view{msg}.compare(bsl::npos, bsl::npos, "invalid") == 0);

        static_assert(string_view{msg}.compare(0, 0, "", 0) == 0);
        static_assert(string_view{msg}.compare(0, 0, msg, 0) == 0);
        static_assert(string_view{msg}.compare(0, 0, "invalid", 0) == 0);
        static_assert(string_view{msg}.compare(6, 5, "", 0) == 0);
        static_assert(string_view{msg}.compare(6, 5, "World", 0) == 0);
        static_assert(string_view{msg}.compare(6, 5, "invalid", 0) == 0);
        static_assert(string_view{msg}.compare(6, bsl::npos, "", 0) == 0);
        static_assert(string_view{msg}.compare(6, bsl::npos, "World", 0) == 0);
        static_assert(string_view{msg}.compare(6, bsl::npos, "invalid", 0) == 0);
        static_assert(string_view{msg}.compare(bsl::npos, bsl::npos, "", 0) == 0);
        static_assert(string_view{msg}.compare(bsl::npos, bsl::npos, "World", 0) == 0);
        static_assert(string_view{msg}.compare(bsl::npos, bsl::npos, "invalid", 0) == 0);
        static_assert(string_view{msg}.compare(0, 0, "", 0) == 0);
        static_assert(string_view{msg}.compare(0, 0, msg, msg_length) == 0);
        static_assert(string_view{msg}.compare(0, 0, "invalid", 7) == 0);
        static_assert(string_view{msg}.compare(6, 5, "", 0) == 0);
        static_assert(string_view{msg}.compare(6, 5, "World", 5) == 0);
        static_assert(string_view{msg}.compare(6, 5, "invalid", 7) != 0);
        static_assert(string_view{msg}.compare(6, bsl::npos, "", 0) == 0);
        static_assert(string_view{msg}.compare(6, bsl::npos, "World", 5) == 0);
        static_assert(string_view{msg}.compare(6, bsl::npos, "invalid", 7) != 0);
        static_assert(string_view{msg}.compare(bsl::npos, bsl::npos, "", 0) == 0);
        static_assert(string_view{msg}.compare(bsl::npos, bsl::npos, "World", 5) == 0);
        static_assert(string_view{msg}.compare(bsl::npos, bsl::npos, "invalid", 7) == 0);
    };

    // clang-format on

    bsl::ut_scenario{"starts_with"} = []() {
        static_assert(string_view{}.starts_with(""));
        static_assert(!string_view{}.starts_with(msg));
        static_assert(string_view{msg}.starts_with(""));
        static_assert(string_view{msg}.starts_with(msg));
        static_assert(string_view{msg}.starts_with("Hello"));
        static_assert(!string_view{msg}.starts_with("World"));
        static_assert(!string_view{}.starts_with('H'));
        static_assert(string_view{msg}.starts_with('H'));
        static_assert(!string_view{msg}.starts_with('d'));
    };

    bsl::ut_scenario{"ends_with"} = []() {
        static_assert(string_view{}.ends_with(""));
        static_assert(!string_view{}.ends_with(msg));
        static_assert(string_view{msg}.ends_with(""));
        static_assert(string_view{msg}.ends_with(msg));
        static_assert(string_view{msg}.ends_with("World"));
        static_assert(!string_view{msg}.ends_with("Hello"));
        static_assert(!string_view{}.ends_with('d'));
        static_assert(string_view{msg}.ends_with('d'));
        static_assert(!string_view{msg}.ends_with('H'));
    };

    bsl::ut_scenario{"equals"} = []() {
        static_assert(string_view{} == string_view{});          // NOLINT
        static_assert(string_view{} == "");                     // NOLINT
        static_assert("" == string_view{});                     // NOLINT
        static_assert(string_view{msg} == string_view{msg});    // NOLINT
        static_assert(string_view{msg} == msg);                 // NOLINT
        static_assert(msg == string_view{msg});                 // NOLINT
    };

    bsl::ut_scenario{"not equals"} = []() {
        static_assert(string_view{} != string_view{msg});               // NOLINT
        static_assert(string_view{msg} != string_view{});               // NOLINT
        static_assert(string_view{msg} != "");                          // NOLINT
        static_assert(msg != string_view{});                            // NOLINT
        static_assert(string_view{} != msg);                            // NOLINT
        static_assert("" != string_view{msg});                          // NOLINT
        static_assert(string_view{"Hello"} != string_view{"World"});    // NOLINT
        static_assert(string_view{"Hello"} != "World");                 // NOLINT
        static_assert("World" != string_view{"Hello"});                 // NOLINT
    };

    return bsl::ut_success();
}
