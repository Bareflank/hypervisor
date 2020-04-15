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
///
/// @file byte.hpp
///

#ifndef BSL_BYTE_HPP
#define BSL_BYTE_HPP

#include "cstdint.hpp"
#include "move.hpp"

#include "enable_if.hpp"
#include "is_integral.hpp"
#include "is_same.hpp"
#include "is_unsigned.hpp"

namespace bsl
{
    /// @class bsl::byte
    ///
    /// <!-- description -->
    ///   @brief std::byte is a distinct type that implements the concept of
    ///     byte as specified in the C++ language definition. Shift operations
    ///     all require unsigned integer types, instead of any integer type.
    ///   @include example_byte_overview.hpp
    ///
    class byte final
    {
    public:
        /// @brief alias for: T
        using value_type = bsl::uint8;

        /// <!-- description -->
        ///   @brief Default constructor. This ensures the byte type is a
        ///     POD type, allowing it to be constructed as a global resource.
        ///     This is needed as aligned storage uses a bsl::byte as its
        ///     base type, and aligned storage is needed as a global resource
        ///     to support the bsl::manager.
        ///   @include byte/example_byte_default_constructor.hpp
        ///
        byte() noexcept = default;

        /// <!-- description -->
        ///   @brief Creates a bsl::byte from a value_type
        ///   @include byte/example_byte_by_value_constructor.hpp
        ///
        ///   SUPPRESSION: PRQA 2180 - exception required
        ///   - We suppress this because A12-1-4 states that all constructors
        ///     that are callable from a fundamental type should be marked as
        ///     explicit. This is a fundamental type, but all implicit
        ///     conversions are disabled through the use of the implicit
        ///     general template constructor that is deleted which absorbs all
        ///     incoming potential implicit conversions.
        ///
        /// <!-- inputs/outputs -->
        ///   @param val the value of the integer to create the bsl::byte from.
        ///
        constexpr byte(value_type const val) noexcept    // PRQA S 2180 // NOLINT
            : m_data{val}
        {}

        /// <!-- description -->
        ///   @brief Returns the bsl::byte as a given integer type using a
        ///     static_cast to perform the conversion.
        ///   @include byte/example_byte_to_integer.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam T the type of integer to convert the bsl::byte to
        ///   @return Returns the bsl::byte as a given integer type using a
        ///     static_cast to perform the conversion.
        ///
        template<typename T = value_type, enable_if_t<is_integral<T>::value, bool> = true>
        [[nodiscard]] constexpr T
        to_integer() const noexcept
        {
            return static_cast<T>(m_data);
        }

        /// <!-- description -->
        ///   @brief Destroyes a previously created bsl::byte
        ///
        ~byte() noexcept = default;

        /// <!-- description -->
        ///   @brief copy constructor
        ///
        /// <!-- inputs/outputs -->
        ///   @param o the object being copied
        ///
        constexpr byte(byte const &o) noexcept = default;

        /// <!-- description -->
        ///   @brief move constructor
        ///
        /// <!-- inputs/outputs -->
        ///   @param o the object being moved
        ///
        constexpr byte(byte &&o) noexcept = default;

        /// <!-- description -->
        ///   @brief copy assignment
        ///
        /// <!-- inputs/outputs -->
        ///   @param o the object being copied
        ///   @return a reference to *this
        ///
        constexpr byte &operator=(byte const &o) &noexcept = default;

        /// <!-- description -->
        ///   @brief move assignment
        ///
        /// <!-- inputs/outputs -->
        ///   @param o the object being moved
        ///   @return a reference to *this
        ///
        constexpr byte &operator=(byte &&o) &noexcept = default;

        /// <!-- description -->
        ///   @brief This constructor allows for single argument constructors
        ///     without the need to mark them as explicit as it will absorb
        ///     any incoming potential implicit conversion and prevent it.
        ///
        ///   SUPPRESSION: PRQA 2180 - false positive
        ///   - We suppress this because A12-1-4 states that all constructors
        ///     that are callable from a fundamental type should be marked as
        ///     explicit. This is callable with a fundamental type, but it
        ///     is marked as "delete" which means it does not apply.
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam O the type that could be implicitly converted
        ///   @param val the value that could be implicitly converted
        ///
        template<typename O>
        byte(O val) noexcept = delete;    // PRQA S 2180

    private:
        /// @brief stores the byte itself
        value_type m_data;
    };

    /// <!-- description -->
    ///   @brief The same as lhs.to_integer() == rhs.to_integer()
    ///   @include byte/example_byte_equal.hpp
    ///   @related bsl::byte
    ///
    /// <!-- inputs/outputs -->
    ///   @param lhs the left hand side of the operator
    ///   @param rhs the right hand side of the operator
    ///   @return returns lhs.to_integer() == rhs.to_integer()
    ///
    constexpr bool
    operator==(byte const &lhs, byte const &rhs) noexcept
    {
        return lhs.to_integer() == rhs.to_integer();
    }

    /// <!-- description -->
    ///   @brief The same as !(lhs == rhs)
    ///   @include byte/example_byte_not_equal.hpp
    ///   @related bsl::byte
    ///
    /// <!-- inputs/outputs -->
    ///   @param lhs the left hand side of the operator
    ///   @param rhs the right hand side of the operator
    ///   @return returns !(lhs == rhs)
    ///
    constexpr bool
    operator!=(byte const &lhs, byte const &rhs) noexcept
    {
        return !(lhs == rhs);
    }

    /// <!-- description -->
    ///   @brief The same as b = byte{b.to_integer() << shift}
    ///   @include byte/example_byte_lshift_assign.hpp
    ///   @related bsl::byte
    ///
    /// <!-- inputs/outputs -->
    ///   @param b the bsl::byte to shift
    ///   @param shift the number of bits to shift b
    ///   @return returns a reference to the provided "b"
    ///
    constexpr byte &
    operator<<=(byte &b, bsl::uint32 const shift) noexcept
    {
        b = byte{static_cast<bsl::uint8>(b.to_integer<bsl::uint32>() << shift)};
        return b;
    }

    /// <!-- description -->
    ///   @brief The same as b = byte{b.to_integer() >> shift}
    ///   @include byte/example_byte_rshift_assign.hpp
    ///   @related bsl::byte
    ///
    /// <!-- inputs/outputs -->
    ///   @param b the bsl::byte to shift
    ///   @param shift the number of bits to shift b
    ///   @return returns a reference to the provided "b"
    ///
    constexpr byte &
    operator>>=(byte &b, bsl::uint32 const shift) noexcept
    {
        b = byte{static_cast<bsl::uint8>(b.to_integer<bsl::uint32>() >> shift)};
        return b;
    }

    /// <!-- description -->
    ///   @brief The same as byte tmp{b}; tmp <<= shift;
    ///   @include byte/example_byte_lshift.hpp
    ///   @related bsl::byte
    ///
    /// <!-- inputs/outputs -->
    ///   @param b the bsl::byte to shift
    ///   @param shift the number of bits to shift b
    ///   @return returns byte tmp{b}; tmp <<= shift;
    ///
    constexpr byte
    operator<<(byte const &b, bsl::uint32 const shift) noexcept
    {
        byte tmp{b};
        tmp <<= shift;
        return tmp;
    }

    /// <!-- description -->
    ///   @brief The same as byte tmp{b}; tmp >>= shift;
    ///   @include example_byte_rshift.hpp
    ///   @related bsl::byte
    ///
    /// <!-- inputs/outputs -->
    ///   @param b the bsl::byte to shift
    ///   @param shift the number of bits to shift b
    ///   @return returns byte tmp{b}; tmp >>= shift;
    ///
    constexpr byte
    operator>>(byte const &b, bsl::uint32 const shift) noexcept
    {
        byte tmp{b};
        tmp >>= shift;
        return tmp;
    }

    /// <!-- description -->
    ///   @brief The same as lhs = byte{lhs.to_integer() | rhs.to_integer()};
    ///   @include byte/example_byte_or_assign.hpp
    ///   @related bsl::byte
    ///
    /// <!-- inputs/outputs -->
    ///   @param lhs the left hand side of the binary operation
    ///   @param rhs the right hand side of the binary operation
    ///   @return returns a reference to the provided "lhs"
    ///
    constexpr byte &
    operator|=(byte &lhs, byte const &rhs) noexcept
    {
        auto const lhs32{lhs.to_integer<bsl::uint32>()};
        auto const rhs32{rhs.to_integer<bsl::uint32>()};

        lhs = byte{static_cast<bsl::uint8>(lhs32 | rhs32)};
        return lhs;
    }

    /// <!-- description -->
    ///   @brief The same as lhs = byte{lhs.to_integer() & rhs.to_integer()};
    ///   @include byte/example_byte_and_assign.hpp
    ///   @related bsl::byte
    ///
    /// <!-- inputs/outputs -->
    ///   @param lhs the left hand side of the binary operation
    ///   @param rhs the right hand side of the binary operation
    ///   @return returns a reference to the provided "lhs"
    ///
    constexpr byte &
    operator&=(byte &lhs, byte const &rhs) noexcept
    {
        auto const lhs32{lhs.to_integer<bsl::uint32>()};
        auto const rhs32{rhs.to_integer<bsl::uint32>()};

        lhs = byte{static_cast<bsl::uint8>(lhs32 & rhs32)};
        return lhs;
    }

    /// <!-- description -->
    ///   @brief The same as lhs = byte{lhs.to_integer() ^ rhs.to_integer()};
    ///   @include byte/example_byte_xor_assign.hpp
    ///   @related bsl::byte
    ///
    /// <!-- inputs/outputs -->
    ///   @param lhs the left hand side of the binary operation
    ///   @param rhs the right hand side of the binary operation
    ///   @return returns a reference to the provided "lhs"
    ///
    constexpr byte &
    operator^=(byte &lhs, byte const &rhs) noexcept
    {
        auto const lhs32{lhs.to_integer<bsl::uint32>()};
        auto const rhs32{rhs.to_integer<bsl::uint32>()};

        lhs = byte{static_cast<bsl::uint8>(lhs32 ^ rhs32)};
        return lhs;
    }

    /// <!-- description -->
    ///   @brief The same as tmp{lhs}; tmp |= rhs;
    ///   @include byte/example_byte_or.hpp
    ///   @related bsl::byte
    ///
    /// <!-- inputs/outputs -->
    ///   @param lhs the left hand side of the binary operation
    ///   @param rhs the right hand side of the binary operation
    ///   @return returns tmp{lhs}; tmp |= rhs;
    ///
    constexpr byte
    operator|(byte const &lhs, byte const &rhs) noexcept
    {
        byte tmp{lhs};
        tmp |= rhs;
        return tmp;
    }

    /// <!-- description -->
    ///   @brief The same as tmp{lhs}; tmp &= rhs;
    ///   @include byte/example_byte_and.hpp
    ///   @related bsl::byte
    ///
    /// <!-- inputs/outputs -->
    ///   @param lhs the left hand side of the binary operation
    ///   @param rhs the right hand side of the binary operation
    ///   @return returns tmp{lhs}; tmp &= rhs;
    ///
    constexpr byte
    operator&(byte const &lhs, byte const &rhs) noexcept
    {
        byte tmp{lhs};
        tmp &= rhs;
        return tmp;
    }

    /// <!-- description -->
    ///   @brief The same as tmp{lhs}; tmp ^= rhs;
    ///   @include byte/example_byte_xor.hpp
    ///   @related bsl::byte
    ///
    /// <!-- inputs/outputs -->
    ///   @param lhs the left hand side of the binary operation
    ///   @param rhs the right hand side of the binary operation
    ///   @return returns tmp{lhs}; tmp ^= rhs;
    ///
    constexpr byte
    operator^(byte const &lhs, byte const &rhs) noexcept
    {
        byte tmp{lhs};
        tmp ^= rhs;
        return tmp;
    }

    /// <!-- description -->
    ///   @brief The same as byte{~b.to_integer()}
    ///   @include byte/example_byte_complement.hpp
    ///   @related bsl::byte
    ///
    /// <!-- inputs/outputs -->
    ///   @param b the bsl::byte to invert
    ///   @return returns byte{~b.to_integer()}
    ///
    constexpr byte
    operator~(byte const &b) noexcept
    {
        return byte{static_cast<bsl::uint8>(~b.to_integer<bsl::uint32>())};
    }
}

#endif
