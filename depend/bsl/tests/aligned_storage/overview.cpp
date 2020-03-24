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

#include <bsl/aligned_storage.hpp>
#include <bsl/alignment_of.hpp>

#include <bsl/ut.hpp>

namespace
{
    template<typename T, bsl::uintmax align>
    constexpr void
    test_aligned_storage() noexcept
    {
        using namespace bsl;

        static_assert(alignment_of<aligned_storage_t<sizeof(T), align>>::value == align);
        static_assert(sizeof(aligned_storage_t<sizeof(T), align>) >= sizeof(T));
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

    test_aligned_storage<bsl::int8, 64>();
    test_aligned_storage<bsl::int16, 64>();
    test_aligned_storage<bsl::int32, 64>();
    test_aligned_storage<bsl::int64, 64>();

    test_aligned_storage<bsl::uint8, 64>();
    test_aligned_storage<bsl::uint16, 64>();
    test_aligned_storage<bsl::uint32, 64>();
    test_aligned_storage<bsl::uint64, 64>();

    test_aligned_storage<bsl::uint8[BSL_PAGE_SIZE], BSL_PAGE_SIZE>();    // NOLINT

    return ut_success();
}
