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

#include <bsl/byte.hpp>
#include <bsl/is_same.hpp>
#include <bsl/is_pod.hpp>

#include <bsl/ut.hpp>

namespace
{
    constexpr bool
    test_lshift_assign(bsl::uint8 c, bsl::uint8 shift) noexcept
    {
        bsl::byte lhs{c};
        lhs <<= shift;
        bsl::byte const rhs{static_cast<bsl::uint8>(c << shift)};

        return lhs == rhs;
    }

    constexpr bool
    test_rshift_assign(bsl::uint8 c, bsl::uint8 shift) noexcept
    {
        bsl::byte lhs{c};
        lhs >>= shift;
        bsl::byte const rhs{static_cast<bsl::uint8>(c >> shift)};

        return lhs == rhs;
    }

    constexpr bool
    test_lshift(bsl::uint8 c, bsl::uint8 shift) noexcept
    {
        bsl::byte const lhs{c};
        return (lhs << shift) == bsl::byte{static_cast<bsl::uint8>(c << shift)};
    }

    constexpr bool
    test_rshift(bsl::uint8 c, bsl::uint8 shift) noexcept
    {
        bsl::byte const lhs{c};
        return (lhs >> shift) == bsl::byte{static_cast<bsl::uint8>(c >> shift)};
    }

    constexpr bool
    test_or_assign(bsl::uint8 lhs, bsl::uint8 rhs) noexcept
    {
        bsl::byte b{lhs};
        b |= bsl::byte{rhs};

        return b == bsl::byte{static_cast<bsl::uint8>(lhs | rhs)};
    }

    constexpr bool
    test_and_assign(bsl::uint8 lhs, bsl::uint8 rhs) noexcept
    {
        bsl::byte b{lhs};
        b &= bsl::byte{rhs};

        return b == bsl::byte{static_cast<bsl::uint8>(lhs & rhs)};
    }

    constexpr bool
    test_xor_assign(bsl::uint8 lhs, bsl::uint8 rhs) noexcept
    {
        bsl::byte b{lhs};
        b ^= bsl::byte{rhs};

        return b == bsl::byte{static_cast<bsl::uint8>(lhs ^ rhs)};
    }

    constexpr bool
    test_or(bsl::uint8 lhs, bsl::uint8 rhs) noexcept
    {
        return (bsl::byte{lhs} | bsl::byte{rhs}) == bsl::byte{static_cast<bsl::uint8>(lhs | rhs)};
    }

    constexpr bool
    test_and(bsl::uint8 lhs, bsl::uint8 rhs) noexcept
    {
        return (bsl::byte{lhs} & bsl::byte{rhs}) == bsl::byte{static_cast<bsl::uint8>(lhs & rhs)};
    }

    constexpr bool
    test_xor(bsl::uint8 lhs, bsl::uint8 rhs) noexcept
    {
        return (bsl::byte{lhs} ^ bsl::byte{rhs}) == bsl::byte{static_cast<bsl::uint8>(lhs ^ rhs)};
    }

    constexpr bool
    test_complement(bsl::uint8 c) noexcept
    {
        return (~bsl::byte{c}) == bsl::byte{static_cast<bsl::uint8>(~c)};
    }

    constexpr bool
    test_to_integer(bsl::uint8 c) noexcept
    {
        return bsl::byte{c}.to_integer() == c;
    }

    constexpr bool
    test_not_equal(bsl::uint8 c1, bsl::uint8 c2) noexcept
    {
        return bsl::byte{c1} != bsl::byte(c2);
    }

    bsl::byte b;
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
    static_assert(is_pod<bsl::byte>::value);

    bsl::ut_scenario{"default construction"} = []() {
        bsl::ut_given{} = []() {
            bsl::ut_when{} = []() {
                b = bsl::byte{static_cast<bsl::uint8>(42)};
                bsl::ut_then{} = []() {
                    bsl::ut_check(b.to_integer<bsl::int32>() == 42);
                };
            };
        };
    };

    static_assert(test_lshift_assign(0, 1U));
    static_assert(test_lshift_assign(255, 1U));
    static_assert(test_lshift_assign(4, 1U));
    static_assert(test_lshift_assign(8, 1U));
    static_assert(test_lshift_assign(15, 1U));
    static_assert(test_lshift_assign(16, 1U));
    static_assert(test_lshift_assign(23, 1U));
    static_assert(test_lshift_assign(42, 1U));

    static_assert(test_rshift_assign(0, 1U));
    static_assert(test_rshift_assign(255, 1U));
    static_assert(test_rshift_assign(4, 1U));
    static_assert(test_rshift_assign(8, 1U));
    static_assert(test_rshift_assign(15, 1U));
    static_assert(test_rshift_assign(16, 1U));
    static_assert(test_rshift_assign(23, 1U));
    static_assert(test_rshift_assign(42, 1U));

    static_assert(test_lshift(0, 1U));
    static_assert(test_lshift(255, 1U));
    static_assert(test_lshift(4, 1U));
    static_assert(test_lshift(8, 1U));
    static_assert(test_lshift(15, 1U));
    static_assert(test_lshift(16, 1U));
    static_assert(test_lshift(23, 1U));
    static_assert(test_lshift(42, 1U));

    static_assert(test_rshift(0, 1U));
    static_assert(test_rshift(255, 1U));
    static_assert(test_rshift(4, 1U));
    static_assert(test_rshift(8, 1U));
    static_assert(test_rshift(15, 1U));
    static_assert(test_rshift(16, 1U));
    static_assert(test_rshift(23, 1U));
    static_assert(test_rshift(42, 1U));

    static_assert(test_or_assign(0, 1U));
    static_assert(test_or_assign(255, 1U));
    static_assert(test_or_assign(4, 1U));
    static_assert(test_or_assign(8, 1U));
    static_assert(test_or_assign(15, 1U));
    static_assert(test_or_assign(16, 1U));
    static_assert(test_or_assign(23, 1U));
    static_assert(test_or_assign(42, 1U));

    static_assert(test_and_assign(0, 1U));
    static_assert(test_and_assign(255, 1U));
    static_assert(test_and_assign(4, 1U));
    static_assert(test_and_assign(8, 1U));
    static_assert(test_and_assign(15, 1U));
    static_assert(test_and_assign(16, 1U));
    static_assert(test_and_assign(23, 1U));
    static_assert(test_and_assign(42, 1U));

    static_assert(test_xor_assign(0, 1U));
    static_assert(test_xor_assign(255, 1U));
    static_assert(test_xor_assign(4, 1U));
    static_assert(test_xor_assign(8, 1U));
    static_assert(test_xor_assign(15, 1U));
    static_assert(test_xor_assign(16, 1U));
    static_assert(test_xor_assign(23, 1U));
    static_assert(test_xor_assign(42, 1U));

    static_assert(test_or(0, 1U));
    static_assert(test_or(255, 1U));
    static_assert(test_or(4, 1U));
    static_assert(test_or(8, 1U));
    static_assert(test_or(15, 1U));
    static_assert(test_or(16, 1U));
    static_assert(test_or(23, 1U));
    static_assert(test_or(42, 1U));

    static_assert(test_and(0, 1U));
    static_assert(test_and(255, 1U));
    static_assert(test_and(4, 1U));
    static_assert(test_and(8, 1U));
    static_assert(test_and(15, 1U));
    static_assert(test_and(16, 1U));
    static_assert(test_and(23, 1U));
    static_assert(test_and(42, 1U));

    static_assert(test_xor(0, 1U));
    static_assert(test_xor(255, 1U));
    static_assert(test_xor(4, 1U));
    static_assert(test_xor(8, 1U));
    static_assert(test_xor(15, 1U));
    static_assert(test_xor(16, 1U));
    static_assert(test_xor(23, 1U));
    static_assert(test_xor(42, 1U));

    static_assert(test_complement(0));
    static_assert(test_complement(255));
    static_assert(test_complement(4));
    static_assert(test_complement(8));
    static_assert(test_complement(15));
    static_assert(test_complement(16));
    static_assert(test_complement(23));
    static_assert(test_complement(42));

    static_assert(test_to_integer(0));
    static_assert(test_to_integer(255));
    static_assert(test_to_integer(4));
    static_assert(test_to_integer(8));
    static_assert(test_to_integer(15));
    static_assert(test_to_integer(16));
    static_assert(test_to_integer(23));
    static_assert(test_to_integer(42));

    static_assert(test_not_equal(0, 1U));
    static_assert(test_not_equal(255, 1U));
    static_assert(test_not_equal(4, 1U));
    static_assert(test_not_equal(8, 1U));
    static_assert(test_not_equal(15, 1U));
    static_assert(test_not_equal(16, 1U));
    static_assert(test_not_equal(23, 1U));
    static_assert(test_not_equal(42, 1U));

    return bsl::ut_success();
}
