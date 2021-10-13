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

#ifndef MOCKS_BASIC_IFMAP_T_HPP
#define MOCKS_BASIC_IFMAP_T_HPP

#include <basic_page_4k_t.hpp>

#include <bsl/array.hpp>
#include <bsl/safe_integral.hpp>
#include <bsl/span.hpp>
#include <bsl/string_view.hpp>

namespace lib
{
    /// <!-- description -->
    ///   @brief Maps a file as read-only, and returns a pointer to the file
    ///     via data() as well as the size of the mapped file via size().
    ///
    class basic_ifmap_t final
    {
        /// @brief stores the file.
        basic_page_4k_t m_data{};
        /// @brief stores the GPA associated with the file
        bsl::safe_u64 m_gpa{};
        /// @brief stores whether or not the ifmap should return an error
        bool m_failure{};

    public:
        /// <!-- description -->
        ///   @brief Creates a default basic_ifmap_t that has not yet been mapped.
        ///
        constexpr basic_ifmap_t() noexcept = default;

        /// <!-- description -->
        ///   @brief Creates a lib::basic_ifmap_t given a the filename and path of
        ///     the file to map as read-only.
        ///
        /// <!-- inputs/outputs -->
        ///   @param filename the filename and path of the file to map
        ///
        explicit constexpr basic_ifmap_t(bsl::string_view const &filename) noexcept
        {
            m_failure = filename.starts_with("failure");
        }

        /// <!-- description -->
        ///   @brief Destructor unmaps a previously mapped file.
        ///
        constexpr ~basic_ifmap_t() noexcept = default;

        /// <!-- description -->
        ///   @brief copy constructor
        ///
        /// <!-- inputs/outputs -->
        ///   @param o the object being copied
        ///
        constexpr basic_ifmap_t(basic_ifmap_t const &o) noexcept = delete;

        /// <!-- description -->
        ///   @brief move constructor
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_o the object being moved
        ///
        constexpr basic_ifmap_t(basic_ifmap_t &&mut_o) noexcept = default;

        /// <!-- description -->
        ///   @brief copy assignment
        ///
        /// <!-- inputs/outputs -->
        ///   @param o the object being copied
        ///   @return a reference to *this
        ///
        [[maybe_unused]] constexpr auto operator=(basic_ifmap_t const &o) &noexcept
            -> basic_ifmap_t & = delete;

        /// <!-- description -->
        ///   @brief move assignment
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_o the object being moved
        ///   @return a reference to *this
        ///
        [[maybe_unused]] auto operator=(basic_ifmap_t &&mut_o) &noexcept
            -> basic_ifmap_t & = default;

        /// <!-- description -->
        ///   @brief Closes the file, releasing all of the resource back to
        ///     the OS kernel.
        ///
        constexpr void
        release() noexcept
        {}

        /// <!-- description -->
        ///   @brief Returns a pointer to the read-only mapped file.
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns a pointer to the read-only mapped file.
        ///
        [[nodiscard]] constexpr auto
        view() const noexcept -> bsl::span<bsl::uint8 const>
        {
            if (m_failure) {
                return {};
            }

            return {m_data.data.data(), m_data.data.size()};
        }

        /// <!-- description -->
        ///   @brief Returns a pointer to the read-only mapped file.
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns a pointer to the read-only mapped file.
        ///
        [[nodiscard]] constexpr auto
        data() const noexcept -> void const *
        {
            if (m_failure) {
                return {};
            }

            return m_data.data.data();
        }

        /// <!-- description -->
        ///   @brief Returns m_size.is_zero()
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns m_size.is_zero()
        ///
        [[nodiscard]] constexpr auto
        empty() const noexcept -> bool
        {
            return m_failure;
        }

        /// <!-- description -->
        ///   @brief Returns nullptr == m_data
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns nullptr == m_data
        ///
        [[nodiscard]] explicit constexpr operator bool() const noexcept
        {
            return !m_failure;
        }

        /// <!-- description -->
        ///   @brief Returns the number of bytes in the file being
        ///     mapped.
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the number of bytes in the file being
        ///     mapped.
        ///
        [[nodiscard]] constexpr auto
        size() const noexcept -> bsl::safe_umx
        {
            if (m_failure) {
                return {};
            }

            return m_data.data.size();
        }

        /// <!-- description -->
        ///   @brief Returns the GPA associated with the file
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the GPA associated with the file
        ///
        [[nodiscard]] constexpr auto
        gpa() const noexcept -> bsl::safe_u64
        {
            return m_gpa;
        }

        /// <!-- description -->
        ///   @brief Sets the GPA associated with the file
        ///
        /// <!-- inputs/outputs -->
        ///   @param val the GPA to associate with this file
        ///
        constexpr void
        set_gpa(bsl::safe_u64 const &val) noexcept
        {
            m_gpa = val;
        }
    };
}

#endif
