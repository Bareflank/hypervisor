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

#include <bsl/color.hpp>
#include <bsl/ut.hpp>

namespace
{
    /// <!-- description -->
    ///   @brief String comparison function
    ///
    /// <!-- contracts -->
    ///   @pre none
    ///   @post none
    ///
    /// <!-- inputs/outputs -->
    ///   @param lhs the left hand side of the comparison
    ///   @param rhs the right hand side of the comparison
    ///   @return Returns true if the strings are equal, false otherwise
    ///
    [[nodiscard]] constexpr bool
    check(bsl::cstr_type const lhs, bsl::cstr_type const rhs) noexcept
    {
        bsl::uintmax i{};
        for (; lhs[i] != '\0' && rhs[i] != '\0'; ++i) {
            if (lhs[i] != rhs[i]) {
                return false;
            }
        }

        return lhs[i] == rhs[i];
    }
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

    static_assert(check(reset_color, "\033[0m"));

    static_assert(check(black, "\033[0;90m"));
    static_assert(check(red, "\033[0;91m"));
    static_assert(check(green, "\033[0;92m"));
    static_assert(check(yellow, "\033[0;93m"));
    static_assert(check(blue, "\033[0;94m"));
    static_assert(check(magenta, "\033[0;95m"));
    static_assert(check(cyan, "\033[0;96m"));
    static_assert(check(white, "\033[0;97m"));

    static_assert(check(bold_black, "\033[1;90m"));
    static_assert(check(bold_red, "\033[1;91m"));
    static_assert(check(bold_green, "\033[1;92m"));
    static_assert(check(bold_yellow, "\033[1;93m"));
    static_assert(check(bold_blue, "\033[1;94m"));
    static_assert(check(bold_magenta, "\033[1;95m"));
    static_assert(check(bold_cyan, "\033[1;96m"));
    static_assert(check(bold_white, "\033[1;97m"));

    return bsl::ut_success();
}
