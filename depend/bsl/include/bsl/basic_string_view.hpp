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

#ifndef BSL_BASIC_STRING_VIEW_HPP
#define BSL_BASIC_STRING_VIEW_HPP

#include "details/view.hpp"

#include "char_traits.hpp"
#include "cstdint.hpp"
#include "min.hpp"
#include "npos.hpp"

// TODO:
// - Need to implement the find functions. These need the safe_int class as
//   there is a lot of math that could result in overflow that needs to be
//   accounted for. Unlike functions like for_each, which can isolate
//   potential overflow issues, the find math is far too complicated to
//   get correct without the assistance of safe_int.
//

namespace bsl
{
    /// @class bsl::basic_string_view
    ///
    /// <!-- description -->
    ///   @brief A bsl::basic_string_view is a non-owning, encapsulation of a
    ///     string, providing helper functions for working with strings.
    ///   @include example_basic_string_view_overview.hpp
    ///
    /// <!-- template parameters -->
    ///   @tparam CharT the type of characters in the string
    ///   @tparam Traits the traits class used to work with the string
    ///
    template<typename CharT, typename Traits = char_traits<CharT>>
    class basic_string_view final : public details::view<CharT const>
    {
    public:
        /// <!-- description -->
        ///   @brief Default constructor that creates a basic_string_view with
        ///     data() == nullptr and size()/length() == 0. All accessors
        ///     will return a nullptr if used. Note that like other view types
        ///     in the BSL, the bsl::basic_string_view is a POD type. This
        ///     means that when declaring a global, default constructed
        ///     bsl::basic_string_view, DO NOT include the {} for
        ///     initialization. Instead, remove the {} and the global
        ///     bsl::basic_string_view will be included in the BSS section of
        ///     the executable, and initialized to 0 for you. All other
        ///     instantiations of a bsl::basic_string_view (or any POD
        ///     type), should be initialized using {} to ensure the POD is
        ///     properly initialized. Using the above method for global
        ///     initialization ensures that global constructors are not
        ///     executed at runtime, which is not allowed by AUTOSAR.
        ///   @include  basic_string_view/example_basic_string_view_default_constructor.hpp
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        constexpr basic_string_view() noexcept = default;

        /// <!-- description -->
        ///   @brief ptr/count constructor. Creates a bsl::basic_string_view
        ///     given a pointer to a string and the number of characters in
        ///     the string.
        ///   @include basic_string_view/example_basic_string_view_s_count_constructor.hpp
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @param s a pointer to the string
        ///   @param count the number of characters in the string
        ///
        constexpr basic_string_view(CharT const *const s, bsl::uintmax const count) noexcept
            : details::view<CharT const>{s, count}
        {}

        /// <!-- description -->
        ///   @brief ptr constructor. This creates a bsl::basic_string_view
        ///     given a pointer to a string. The number of characters in the
        ///     string is determined using Traits<CharT>::length,
        ///     which scans for '\0'.
        ///   @include basic_string_view/example_basic_string_view_s_constructor.hpp
        ///   @related
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @param s a pointer to the string
        ///
        constexpr basic_string_view(CharT const *const s) noexcept    // NOLINT
            : details::view<CharT const>{s, Traits::length(s)}
        {}

        /// <!-- description -->
        ///   @brief Returns the length of the string being viewed. This is
        ///     the same as bsl::basic_string_view::size(). Note that the
        ///     length refers to the total number of characters in the
        ///     string and not the number of bytes in the string. For the
        ///     total number of bytes, use bsl::basic_string_view::size_bytes().
        ///   @include basic_string_view/example_basic_string_view_length.hpp
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the length of the string being viewed.
        ///
        [[nodiscard]] constexpr bsl::uintmax
        length() const noexcept
        {
            return this->size();
        }

        /// <!-- description -->
        ///   @brief Moves the start of the view forward by n characters. If
        ///     n >= size(), the bsl::basic_string_view is reset to a NULL
        ///     string, with data() returning a nullptr, and size() returning 0.
        ///   @include basic_string_view/example_basic_string_view_remove_prefix.hpp
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @param n the number of character to remove from the start of
        ///     the string.
        ///
        [[maybe_unused]] constexpr basic_string_view &
        remove_prefix(bsl::uintmax const n) noexcept
        {
            if (n >= this->size()) {
                *this = basic_string_view{};
            }

            *this = basic_string_view{this->at_if(n), this->size() - n};
            return *this;
        }

        /// <!-- description -->
        ///   @brief Moves the end of the view back by n characters. If
        ///     n >= size(), the bsl::basic_string_view is reset to a NULL
        ///     string, with data() returning a nullptr, and size() returning 0.
        ///   @include basic_string_view/example_basic_string_view_remove_suffix.hpp
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @param n the number of character to remove from the end of
        ///     the string.
        ///
        [[maybe_unused]] constexpr basic_string_view &
        remove_suffix(bsl::uintmax const n) noexcept
        {
            if (n >= this->size()) {
                *this = basic_string_view{};
            }

            *this = basic_string_view{this->at_if(0), this->size() - n};
            return *this;
        }

        /// <!-- description -->
        ///   @brief Copies the substring [pos, pos + rcount) to the string
        ///     pointed to by dst, where rcount is the smaller of count and
        ///     size() - pos. If pos is larger than size(), the copy request
        ///     is ignored and 0 is returned.
        ///   @include basic_string_view/example_basic_string_view_copy.hpp
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @param dst the buffer to copy the string to
        ///   @param count the number of characters to copy
        ///   @param pos the starting position in the string that is copied
        ///   @return Returns dst
        ///
        [[maybe_unused]] constexpr bsl::uintmax
        copy(                            // --
            CharT *const dst,            // --
            bsl::uintmax const count,    // --
            bsl::uintmax const pos = 0) const noexcept
        {
            if (pos >= this->size()) {
                return 0;
            }

            bsl::uintmax const rcount{min(count, this->size() - pos)};
            Traits::copy(static_cast<CharT *>(dst), this->at_if(pos), rcount);

            return rcount;
        }

        /// <!-- description -->
        ///   @brief Returns a new bsl::basic_string_view that is a
        ///     substring view of the original. The substring starts at "pos"
        ///     and ends at "pos" + "count". Note that this does not copy
        ///     the string, it simply changes the internal pointer and size
        ///     of the same string that is currently being viewed (meaning
        ///     the lifetime of the new substring cannot outlive the lifetime
        ///     of the string being viewed by the original
        ///     bsl::basic_string_view). If the provided "pos" or "count"
        ///     are invalid, this function returns an empty string view.
        ///   @include basic_string_view/example_basic_string_view_substr.hpp
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @param pos the starting position of the new substring.
        ///   @param count the length of the new bsl::basic_string_view
        ///   @return Returns a new bsl::basic_string_view that is a
        ///     substring view of the original. The substring starts at "pos"
        ///     and ends at "pos" + "count".
        ///
        [[nodiscard]] constexpr basic_string_view
        substr(bsl::uintmax pos = 0, bsl::uintmax count = npos) const noexcept
        {
            if (pos >= this->size()) {
                return basic_string_view{};
            }

            return basic_string_view{this->at_if(pos), min(count, this->size() - pos)};
        }

        /// <!-- description -->
        ///   @brief Compares two strings.
        ///   @include basic_string_view/example_basic_string_view_compare_1.hpp
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @param v the bsl::basic_string_view to compare with
        ///   @return Returns the same results as std::strncmp
        ///
        [[nodiscard]] constexpr bsl::int32
        compare(basic_string_view const &v) const noexcept
        {
            return Traits::compare(this->data(), v.data(), min(this->size(), v.size()));
        }

        /// <!-- description -->
        ///   @brief Same as substr(pos, count).compare(v)
        ///   @include basic_string_view/example_basic_string_view_compare_2.hpp
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @param pos the starting position of "this" to compare from
        ///   @param count the number of characters of "this" to compare
        ///   @param v the bsl::basic_string_view to compare with
        ///   @return Returns the same results as std::strncmp
        ///
        [[nodiscard]] constexpr bsl::int32
        compare(bsl::uintmax pos, bsl::uintmax count, basic_string_view const &v) const noexcept
        {
            return this->substr(pos, count).compare(v);
        }

        /// <!-- description -->
        ///   @brief Same as substr(pos1, count1).compare(v.substr(pos2, count2))
        ///   @include basic_string_view/example_basic_string_view_compare_3.hpp
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @param pos1 the starting position of "this" to compare from
        ///   @param count1 the number of characters of "this" to compare
        ///   @param v the bsl::basic_string_view to compare with
        ///   @param pos2 the starting position of "v" to compare from
        ///   @param count2 the number of characters of "v" to compare
        ///   @return Returns the same results as std::strncmp
        ///
        [[nodiscard]] constexpr bsl::int32
        compare(                           // --
            bsl::uintmax pos1,             // --
            bsl::uintmax count1,           // --
            basic_string_view const &v,    // --
            bsl::uintmax pos2,             // --
            bsl::uintmax count2) const noexcept
        {
            return this->substr(pos1, count1).compare(v.substr(pos2, count2));
        }

        /// <!-- description -->
        ///   @brief Same as compare(basic_string_view{s})
        ///   @include basic_string_view/example_basic_string_view_compare_4.hpp
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @param s a pointer to a string to compare with "this"
        ///   @return Returns the same results as std::strncmp
        ///
        [[nodiscard]] constexpr bsl::int32
        compare(CharT const *const s) const noexcept
        {
            return this->compare(basic_string_view{s});
        }

        /// <!-- description -->
        ///   @brief Same as substr(pos, count).compare(basic_string_view{s})
        ///   @include basic_string_view/example_basic_string_view_compare_5.hpp
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @param pos the starting position of "this" to compare from
        ///   @param count the number of characters of "this" to compare
        ///   @param s a pointer to a string to compare with "this"
        ///   @return Returns the same results as std::strncmp
        ///
        [[nodiscard]] constexpr bsl::int32
        compare(bsl::uintmax pos, bsl::uintmax count, CharT const *const s) const noexcept
        {
            return this->substr(pos, count).compare(basic_string_view{s});
        }

        /// <!-- description -->
        ///   @brief Same as substr(pos, count1).compare(basic_string_view{s, count2})
        ///   @include basic_string_view/example_basic_string_view_compare_6.hpp
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @param pos the starting position of "this" to compare from
        ///   @param count1 the number of characters of "this" to compare
        ///   @param s a pointer to a string to compare with "this"
        ///   @param count2 the number of characters of "s" to compare
        ///   @return Returns the same results as std::strncmp
        ///
        [[nodiscard]] constexpr bsl::int32
        compare(                     // --
            bsl::uintmax pos,        // --
            bsl::uintmax count1,     // --
            CharT const *const s,    // --
            bsl::uintmax count2) const noexcept
        {
            return this->substr(pos, count1).compare(basic_string_view{s, count2});
        }

        /// <!-- description -->
        ///   @brief Checks if the string begins with the given prefix
        ///   @include basic_string_view/example_basic_string_view_starts_with.hpp
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @param v the bsl::basic_string_view to compare with
        ///   @return Returns true if the string begins with the given prefix,
        ///     false otherwise.
        ///
        [[nodiscard]] constexpr bool
        starts_with(basic_string_view const &v) const noexcept
        {
            if (this->size() < v.size()) {
                return false;
            }

            return this->substr(0, v.size()) == v;
        }

        /// <!-- description -->
        ///   @brief Checks if the string begins with the given prefix
        ///   @include basic_string_view/example_basic_string_view_starts_with.hpp
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @param c the CharT to compare with
        ///   @return Returns true if the string begins with the given prefix,
        ///     false otherwise.
        ///
        [[nodiscard]] constexpr bool
        starts_with(CharT const c) const noexcept
        {
            if (auto ptr = this->front_if()) {
                return *ptr == c;
            }

            return false;
        }

        /// <!-- description -->
        ///   @brief Checks if the string begins with the given prefix
        ///   @include basic_string_view/example_basic_string_view_starts_with.hpp
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @param s the string to compare with
        ///   @return Returns true if the string begins with the given prefix,
        ///     false otherwise.
        ///
        [[nodiscard]] constexpr bool
        starts_with(CharT const *const s) const noexcept
        {
            return this->starts_with(basic_string_view{s});
        }

        /// <!-- description -->
        ///   @brief Checks if the string ends with the given suffix
        ///   @include basic_string_view/example_basic_string_view_ends_with.hpp
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @param v the bsl::basic_string_view to compare with
        ///   @return Returns true if the string ends with the given suffix,
        ///     false otherwise.
        ///
        [[nodiscard]] constexpr bool
        ends_with(basic_string_view const &v) const noexcept
        {
            if (this->size() < v.size()) {
                return false;
            }

            return this->compare(this->size() - v.size(), npos, v) == 0;
        }

        /// <!-- description -->
        ///   @brief Checks if the string ends with the given suffix
        ///   @include basic_string_view/example_basic_string_view_ends_with.hpp
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @param c the CharT to compare with
        ///   @return Returns true if the string ends with the given suffix,
        ///     false otherwise.
        ///
        [[nodiscard]] constexpr bool
        ends_with(CharT const c) const noexcept
        {
            if (auto ptr = this->back_if()) {
                return *ptr == c;
            }

            return false;
        }

        /// <!-- description -->
        ///   @brief Checks if the string ends with the given suffix
        ///   @include basic_string_view/example_basic_string_view_ends_with.hpp
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @param s the string to compare with
        ///   @return Returns true if the string ends with the given suffix,
        ///     false otherwise.
        ///
        [[nodiscard]] constexpr bool
        ends_with(CharT const *const s) const noexcept
        {
            return this->ends_with(basic_string_view{s});
        }
    };

    template<typename CharT, typename Traits>
    constexpr bool
    operator==(basic_string_view<CharT, Traits> lhs, basic_string_view<CharT, Traits> rhs) noexcept
    {
        if (lhs.size() != rhs.size()) {
            return false;
        }

        return lhs.compare(rhs) == 0;
    }

    template<typename CharT, typename Traits>
    constexpr bool
    operator==(basic_string_view<CharT, Traits> lhs, CharT const *const rhs) noexcept
    {
        return lhs == basic_string_view<CharT, Traits>{rhs};
    }

    template<typename CharT, typename Traits>
    constexpr bool
    operator==(CharT const *const lhs, basic_string_view<CharT, Traits> rhs) noexcept
    {
        return basic_string_view<CharT, Traits>{lhs} == rhs;
    }

    template<typename CharT, typename Traits>
    constexpr bool
    operator!=(basic_string_view<CharT, Traits> lhs, basic_string_view<CharT, Traits> rhs) noexcept
    {
        return !(lhs == rhs);
    }

    template<typename CharT, typename Traits>
    constexpr bool
    operator!=(basic_string_view<CharT, Traits> lhs, CharT const *const rhs) noexcept
    {
        return !(lhs == rhs);
    }

    template<typename CharT, typename Traits>
    constexpr bool
    operator!=(CharT const *const lhs, basic_string_view<CharT, Traits> rhs) noexcept
    {
        return !(lhs == rhs);
    }
}

#endif
