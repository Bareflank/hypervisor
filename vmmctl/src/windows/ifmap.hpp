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

#ifndef VMMCTL_IFMAP_WINDOWS_HPP
#define VMMCTL_IFMAP_WINDOWS_HPP

// clang-format off

/// NOTE:
/// - The windows includes that we use here need to remain in this order.
///   Otherwise the code will not compile. Also, when using CPP, we need
///   to remove the max/min macros as they are used by the C++ standard.
///

#include <Windows.h>
#undef max
#undef min

// clang-format on

#include <bsl/convert.hpp>
#include <bsl/cstdint.hpp>
#include <bsl/debug.hpp>
#include <bsl/discard.hpp>
#include <bsl/move.hpp>
#include <bsl/safe_integral.hpp>
#include <bsl/span.hpp>
#include <bsl/string_view.hpp>
#include <bsl/swap.hpp>
#include <bsl/touch.hpp>
#include <bsl/unlikely.hpp>
#include <bsl/finally.hpp>

namespace vmmctl
{
    /// @class vmmctl::ifmap
    ///
    /// <!-- description -->
    ///   @brief Maps a file as read-only, and returns a pointer to the file
    ///     via data() as well as the size of the mapped file via size().
    ///
    class ifmap final
    {
        /// @brief stores a handle to the file being mapped
        HANDLE m_file{};
        /// @brief stores a handle to the mapped file.
        HANDLE m_view{};
        /// @brief stores a pointer to the file that was opened.
        void *m_data{};
        /// @brief stores the number of bytes for the open file
        bsl::safe_uintmax m_size{};

        /// <!-- description -->
        ///   @brief Swaps *this with other
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_lhs the left hand side of the exchange
        ///   @param mut_rhs the right hand side of the exchange
        ///
        static constexpr void
        private_swap(ifmap &mut_lhs, ifmap &mut_rhs) noexcept
        {
            bsl::swap(mut_lhs.m_file, mut_rhs.m_file);
            bsl::swap(mut_lhs.m_view, mut_rhs.m_view);
            bsl::swap(mut_lhs.m_data, mut_rhs.m_data);
            bsl::swap(mut_lhs.m_size, mut_rhs.m_size);
        }

    public:
        /// @brief alias for: void
        using value_type = void;
        /// @brief alias for: safe_uintmax
        using size_type = bsl::safe_uintmax;
        /// @brief alias for: safe_uintmax
        using difference_type = bsl::safe_uintmax;
        /// @brief alias for: void *
        using pointer_type = void *;
        /// @brief alias for: void const *
        using const_pointer_type = void const *;

        /// <!-- description -->
        ///   @brief Creates a default ifmap that has not yet been mapped.
        ///
        constexpr ifmap() noexcept = default;

        /// <!-- description -->
        ///   @brief Creates a vmmctl::ifmap given a the filename and path of
        ///     the file to map as read-only.
        ///
        /// <!-- inputs/outputs -->
        ///   @param filename the filename and path of the file to map
        ///
        explicit constexpr ifmap(bsl::string_view const &filename) noexcept
        {
            m_file = CreateFileA(
                filename.data(),
                GENERIC_READ,
                0,
                nullptr,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                nullptr);

            bsl::finally mut_release_on_error{[this]() noexcept -> void {
                this->release();
            }};

            m_view = CreateFileMappingA(m_file, nullptr, PAGE_READONLY, 0, 0, nullptr);
            if (bsl::unlikely(nullptr == m_view)) {
                bsl::alert() << "failed to open read-only file: "    // --
                             << filename                             // --
                             << bsl::endl;
                return;
            }

            DWORD high{};
            DWORD size{GetFileSize(m_file, &high)};

            if (bsl::unlikely(INVALID_FILE_SIZE == size)) {
                bsl::alert() << "failed to get the size of the read-only file: "    // --
                             << filename                                            // --
                             << bsl::endl;
                return;
            }

            if (bsl::unlikely(DWORD{} != high)) {
                bsl::alert() << "file too big: "    // --
                             << filename            // --
                             << bsl::endl;
                return;
            }

            m_data = MapViewOfFile(m_view, FILE_MAP_READ, 0, 0, 0);
            if (bsl::unlikely(nullptr == m_data)) {
                bsl::alert() << "failed to map read-only file: "    // --
                             << filename                            // --
                             << bsl::endl;
                return;
            }

            m_size = bsl::to_umax(static_cast<bsl::uintmax>(size));
            mut_release_on_error.ignore();
        }

        /// <!-- description -->
        ///   @brief Destructor unmaps a previously mapped file.
        ///
        constexpr ~ifmap() noexcept
        {
            this->release();
        }

        /// <!-- description -->
        ///   @brief copy constructor
        ///
        /// <!-- inputs/outputs -->
        ///   @param o the object being copied
        ///
        constexpr ifmap(ifmap const &o) noexcept = delete;

        /// <!-- description -->
        ///   @brief move constructor
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_o the object being moved
        ///
        constexpr ifmap(ifmap &&mut_o) noexcept
            : m_file{bsl::move(mut_o.m_file)}
            , m_view{bsl::move(mut_o.m_view)}
            , m_data{bsl::move(mut_o.m_data)}
            , m_size{bsl::move(mut_o.m_size)}
        {
            mut_o.m_file = {};
            mut_o.m_view = {};
            mut_o.m_data = {};
            mut_o.m_size = {};
        }

        /// <!-- description -->
        ///   @brief copy assignment
        ///
        /// <!-- inputs/outputs -->
        ///   @param o the object being copied
        ///   @return a reference to *this
        ///
        [[maybe_unused]] constexpr auto operator=(ifmap const &o) &noexcept -> ifmap & = delete;

        /// <!-- description -->
        ///   @brief move assignment
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_o the object being moved
        ///   @return a reference to *this
        ///
        [[maybe_unused]] auto
        operator=(ifmap &&mut_o) &noexcept -> ifmap &
        {
            ifmap mut_tmp{bsl::move(mut_o)};
            this->private_swap(*this, mut_tmp);
            return *this;
        }

        /// <!-- description -->
        ///   @brief Closes the file, releasing all of the resource back to
        ///     the OS kernel.
        ///
        constexpr void
        release() noexcept
        {
            if (nullptr != m_data) {
                bsl::discard(UnmapViewOfFile(m_data));
            }
            else {
                bsl::touch();
            }

            if (nullptr != m_view) {
                bsl::discard(CloseHandle(m_view));
            }
            else {
                bsl::touch();
            }

            if (nullptr != m_file) {
                bsl::discard(CloseHandle(m_file));
            }
            else {
                bsl::touch();
            }

            m_size = {};
            m_data = {};
            m_view = {};
            m_file = {};
        }
        /// <!-- description -->
        ///   @brief Returns a pointer to the read-only mapped file.
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns a pointer to the read-only mapped file.
        ///
        [[nodiscard]] constexpr auto
        view() const noexcept -> bsl::span<bsl::uint8 const>
        {
            return {static_cast<bsl::uint8 const *>(m_data), m_size};
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
            return m_data;
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
            return m_size.is_zero();
        }

        /// <!-- description -->
        ///   @brief Returns nullptr == m_data
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns nullptr == m_data
        ///
        [[nodiscard]] explicit constexpr operator bool() const noexcept
        {
            return nullptr != m_data;
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
        size() const noexcept -> bsl::safe_uintmax
        {
            return m_size;
        }
    };
}

#endif
