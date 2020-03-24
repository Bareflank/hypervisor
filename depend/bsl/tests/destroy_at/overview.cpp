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

#include <bsl/destroy_at.hpp>
#include <bsl/ut.hpp>

namespace
{
    /// @brief set to true when our custom class's destructor is called
    bool g_called{false};

    /// @class myclass
    ///
    /// <!-- description -->
    ///   @brief Defines a class with a destructor that sets g_called when
    ///     it is called to test that destroy_at works as expected
    ///
    class myclass final    // NOLINT
    {
    public:
        /// <!-- description -->
        ///   @brief When called, sets g_called to true
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        ~myclass() noexcept
        {
            g_called = true;
        }
    };
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

    bsl::ut_scenario{"detroy_at"} = []() {
        bsl::ut_given{} = []() {
            myclass c;
            bsl::ut_when{} = [&c]() {
                bsl::destroy_at(&c);
                bsl::ut_then{} = []() {
                    bsl::ut_check(g_called);
                };
            };
        };
    };

    return bsl::ut_success();
}
