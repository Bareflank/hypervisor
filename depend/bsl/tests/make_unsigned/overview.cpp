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

#include <bsl/is_same.hpp>
#include <bsl/make_unsigned.hpp>
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

    static_assert(is_same<make_unsigned_t<bsl::int8>, bsl::uint8>::value);
    static_assert(is_same<make_unsigned_t<bsl::int8 const>, bsl::uint8 const>::value);
    static_assert(is_same<make_unsigned_t<bsl::int16>, bsl::uint16>::value);
    static_assert(is_same<make_unsigned_t<bsl::int16 const>, bsl::uint16 const>::value);
    static_assert(is_same<make_unsigned_t<bsl::int32>, bsl::uint32>::value);
    static_assert(is_same<make_unsigned_t<bsl::int32 const>, bsl::uint32 const>::value);
    static_assert(is_same<make_unsigned_t<bsl::int64>, bsl::uint64>::value);
    static_assert(is_same<make_unsigned_t<bsl::int64 const>, bsl::uint64 const>::value);

    return bsl::ut_success();
}
