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
///
/// @file char_traits.hpp
///

#ifndef BSL_CHAR_TRAITS_HPP
#define BSL_CHAR_TRAITS_HPP

#include "char_type.hpp"
#include "cstdint.hpp"
#include "discard.hpp"
#include "for_each.hpp"
#include "numeric_limits.hpp"

namespace bsl
{
    /// @cond doxygen off

    /// @class bsl::char_traits
    ///
    /// <!-- description -->
    ///   @brief Provides the generic implementation of char_traits, which
    ///     does not implement any of the char_triats, generating a compiler
    ///     error if you attempt to use it.
    ///
    /// <!-- template parameters -->
    ///   @tparam CharT the character type that is not supported
    ///
    template<typename CharT>
    class char_traits final
    {};

    /// @endcond doxygen on

    /// <!-- description -->
    ///   @brief Implements the char_traits for the type "char_type", which is
    ///     a type alias for "char". In general, you should not need to use
    ///     this class directly, and we only provide it for compatibility.
    ///     Note that there are some BSL specific changes to the library, which
    ///     should not change the "valid" behavior of this class, but will
    ///     change "invalid" behavior to comply better with AUTOSAR.
    ///   @include example_char_traits_overview.hpp
    ///
    template<>
    class char_traits<char_type> final
    {
    public:
        /// <!-- description -->
        ///   @brief Assigns a to r
        ///   @include char_traits/example_char_traits_assign.hpp
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @param r the left hand side of the assignment
        ///   @param a the right hand side of the assignment
        ///
        static constexpr void
        assign(char_type &r, char_type const &a) noexcept
        {
            r = a;
        }

        /// <!-- description -->
        ///   @brief Same as std::memset (with the args rearranged)
        ///   @include char_traits/example_char_traits_assign.hpp
        ///
        /// <!-- notes -->
        ///   @note The BSL adds a nullptr check to this call, and will
        ///     not perform the operation if p == nullptr.
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @param p the location of the string to set to a
        ///   @param count the number of characters to set
        ///   @param a the character to set the string to
        ///   @return returns p
        ///
        [[maybe_unused]] static char_type *
        assign(char_type *const p, bsl::uintmax const count, char_type const a) noexcept
        {
            if (nullptr == p) {
                return nullptr;
            }

            return static_cast<char_type *>(__builtin_memset(p, a, count));
        }

        /// <!-- description -->
        ///   @brief Returns true if "a" == "b"
        ///   @include char_traits/example_char_traits_eq.hpp
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @param a the left hand side of the query
        ///   @param b the right hand side of the query
        ///   @return Returns true if "a" == "b"
        ///
        [[nodiscard]] static constexpr bool
        eq(char_type const a, char_type const b) noexcept
        {
            return a == b;
        }

        /// <!-- description -->
        ///   @brief Returns true if "a" < "b"
        ///   @include char_traits/example_char_traits_lt.hpp
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @param a the left hand side of the query
        ///   @param b the right hand side of the query
        ///   @return Returns true if "a" < "b"
        ///
        [[nodiscard]] static constexpr bool
        lt(char_type const a, char_type const b) noexcept
        {
            return a < b;
        }

        /// <!-- description -->
        ///   @brief Same as std::memmove (which is the same as std::copy
        ///     with the difference that overlapping is supported)
        ///   @include char_traits/example_char_traits_move.hpp
        ///
        /// <!-- notes -->
        ///   @note The BSL adds a nullptr check to this call, and will
        ///     not perform the operation if dst or src == nullptr
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @param dst the destination to copy to
        ///   @param src the source to copy from
        ///   @param count the number of characters to copy
        ///   @return returns dst
        ///
        [[maybe_unused]] static char_type *
        move(char_type *const dst, char_type const *const src, bsl::uintmax const count) noexcept
        {
            if (nullptr == dst || nullptr == src) {
                return nullptr;
            }

            return static_cast<char_type *>(__builtin_memmove(dst, src, count));
        }

        /// <!-- description -->
        ///   @brief Same as std::memcpy
        ///   @include char_traits/example_char_traits_copy.hpp
        ///
        /// <!-- notes -->
        ///   @note The BSL adds a nullptr check to this call, and will
        ///     not perform the operation if dst or src == nullptr
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @param dst the destination to copy to
        ///   @param src the source to copy from
        ///   @param count the number of characters to copy
        ///   @return returns dst
        ///
        [[maybe_unused]] static char_type *
        copy(char_type *const dst, char_type const *const src, bsl::uintmax const count) noexcept
        {
            if (nullptr == dst || nullptr == src) {
                return nullptr;
            }

            return static_cast<char_type *>(__builtin_memcpy(dst, src, count));
        }

        /// <!-- description -->
        ///   @brief Compares two strings. Returns negative value if s1 appears
        ///     before s2 in lexicographical order. Return 0 if s1 and s2
        ///     compare equal, if s1 or s2 are nullptr, or if count is zero.
        ///     Positive value if s1 appears after s2 in lexicographical order.
        ///   @include char_traits/example_char_traits_compare.hpp
        ///
        /// <!-- notes -->
        ///   @note The BSL adds a nullptr check to this call, and will
        ///     return 0 if s1 or s2 are a nullptr (same as if num was set
        ///     to 0).
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @param s1 the left hand side of the query
        ///   @param s2 the right hand side of the query
        ///   @param count the number of characters to compare
        ///   @return Returns negative value if s1 appears before s2 in
        ///     lexicographical order. Return 0 if s1 and s2 compare equal,
        ///     if s1 or s2 are nullptr, or if count is zero. Positive value
        ///     if s1 appears after s2 in lexicographical order.
        ///
        [[nodiscard]] static constexpr bsl::int32
        compare(                          // --
            char_type const *const s1,    // --
            char_type const *const s2,    // --
            bsl::uintmax const count) noexcept
        {
            if (nullptr == s1 || nullptr == s2) {
                return 0;
            }

            return __builtin_strncmp(s1, s2, count);
        }

        /// <!-- description -->
        ///   @brief Returns the length of the provided string.
        ///   @include char_traits/example_char_traits_length.hpp
        ///
        /// <!-- notes -->
        ///   @note The BSL adds a nullptr check to this call, and will
        ///     return 0 if s is a nullptr.
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @param s the string to get the length of
        ///   @return Returns the length of the provided string.
        ///
        [[nodiscard]] static constexpr bsl::uintmax
        length(char_type const *const s) noexcept
        {
            if (nullptr == s) {
                return 0;
            }

            return __builtin_strlen(s);
        }

        /// <!-- description -->
        ///   @brief Returns a pointer to the first occurrence of "ch" in "p".
        ///   @include char_traits/example_char_traits_find.hpp
        ///
        /// <!-- notes -->
        ///   @note The BSL adds a nullptr check to this call, and will
        ///     return a nullptr if p is a nullptr.
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @param p a pointer to the string to search through.
        ///   @param count the total number of characters in the string to
        ///     search through
        ///   @param ch the character to search for.
        ///   @return Returns a pointer to the first occurrence of "ch" in "p".
        ///
        [[nodiscard]] static constexpr char_type const *
        find(char_type const *const p, bsl::uintmax const count, char_type const &ch) noexcept
        {
            if (nullptr == p) {
                return nullptr;
            }

            return static_cast<char_type *>(__builtin_memchr(p, ch, count));
        }

        /// <!-- description -->
        ///   @brief Converts a value of bsl::intmax to char_type. If there is
        ///     no equivalent value (such as when c is a copy of the eof value),
        ///     the results are unspecified.
        ///   @include char_traits/example_char_traits_to_char_type.hpp
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @param c the character to convert
        ///   @return c
        ///
        [[nodiscard]] static constexpr char_type
        to_char_type(bsl::intmax c) noexcept
        {
            return static_cast<char_type>(c);
        }

        /// <!-- description -->
        ///   @brief Converts a value of char_type to bsl::intmax.
        ///   @include char_traits/example_char_traits_to_int_type.hpp
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @param c the character to convert
        ///   @return c
        ///
        [[nodiscard]] static constexpr bsl::intmax
        to_int_type(char_type c) noexcept
        {
            return static_cast<bsl::intmax>(c);
        }

        /// <!-- description -->
        ///   @brief Checks whether two values of type int_type are equal.
        ///   @include char_traits/example_char_traits_eq_int_type.hpp
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @param c1 the left hand side of the query
        ///   @param c2 the right hand side of the query
        ///   @return Returns eq(c1, c2) if c1 and c2 are valid char types.
        ///     Returns true if c1 and c2 are both EOF. Returns false
        ///     otherwise.
        ///
        [[nodiscard]] static constexpr bool
        eq_int_type(bsl::intmax c1, bsl::intmax c2) noexcept
        {
            if ((c1 == to_char_type(c1)) && (c2 == to_char_type(c2))) {
                return eq(to_char_type(c1), to_char_type(c2));
            }

            return (c1 == eof()) && (c2 == eof());
        }

        /// <!-- description -->
        ///   @brief Returns the value of EOF
        ///   @include char_traits/example_char_traits_eof.hpp
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the value of EOF
        ///
        [[nodiscard]] static constexpr bsl::intmax
        eof() noexcept
        {
            constexpr bsl::intmax value_of_eof{-1};
            return value_of_eof;
        }

        /// <!-- description -->
        ///   @brief Returns e if e is not EOF, otherwise returns 0.
        ///   @include char_traits/example_char_traits_not_eof.hpp
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @param e the character to query
        ///   @return Returns e if e is not EOF, otherwise returns 0.
        ///
        [[nodiscard]] static constexpr bsl::intmax
        not_eof(bsl::intmax e) noexcept
        {
            if (!eq_int_type(e, eof())) {
                return e;
            }

            return 0;
        }
    };
}

#endif
