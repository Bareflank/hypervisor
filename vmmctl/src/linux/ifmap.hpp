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

#ifndef VMMCTL_IFMAP_LINUX_HPP
#define VMMCTL_IFMAP_LINUX_HPP

#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <bsl/convert.hpp>
#include <bsl/cstdint.hpp>
#include <bsl/debug.hpp>
#include <bsl/discard.hpp>
#include <bsl/finally.hpp>
#include <bsl/move.hpp>
#include <bsl/safe_integral.hpp>
#include <bsl/span.hpp>
#include <bsl/string_view.hpp>
#include <bsl/swap.hpp>
#include <bsl/touch.hpp>
#include <bsl/unlikely.hpp>

namespace vmmctl
{
    /// @brief defines what an error looks like from a POSIX call.
    constexpr auto IFMAP_POSIX_ERROR{-1_i32};
    /// @brief defines what an invalid file is.
    constexpr auto IFMAP_INVALID_FILE{-1_i32};

    /// @class bsl::ifmap
    ///
    /// <!-- description -->
    ///   @brief Maps a file as read-only, and returns a pointer to the file
    ///     via data() as well as the size of the mapped file via size().
    ///
    class ifmap final
    {
        /// @brief stores a handle to the mapped file.
        bsl::safe_i32 m_file{IFMAP_INVALID_FILE};
        /// @brief stores a pointer to the file that was opened.
        void *m_data{};
        /// @brief stores the number of bytes for the open file
        bsl::safe_umx m_size{};

        /// <!-- description -->
        ///   @brief Swaps *this with other
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_lhs the left hand side of the exchange
        ///   @param mut_rhs the right hand side of the exchange
        ///
        static constexpr auto
        private_swap(ifmap &mut_lhs, ifmap &mut_rhs) noexcept -> void
        {
            bsl::swap(mut_lhs.m_file, mut_rhs.m_file);
            bsl::swap(mut_lhs.m_data, mut_rhs.m_data);
            bsl::swap(mut_lhs.m_size, mut_rhs.m_size);
        }

    public:
        /// <!-- description -->
        ///   @brief Creates a default ifmap that has not yet been mapped.
        ///
        constexpr ifmap() noexcept = default;

        /// <!-- description -->
        ///   @brief Creates a bsl::ifmap given a the filename and path of
        ///     the file to map as read-only.
        ///
        /// <!-- inputs/outputs -->
        ///   @param filename the filename and path of the file to map
        ///
        explicit constexpr ifmap(bsl::string_view const &filename) noexcept
        {
            using stat_t = struct stat;
            stat_t mut_s{};

            // We don't have a choice here
            // NOLINTNEXTLINE(cppcoreguidelines-pro-type-vararg, hicpp-vararg)
            m_file = open(filename.data(), O_RDONLY);
            if (bsl::unlikely(IFMAP_INVALID_FILE == m_file)) {
                bsl::error() << "failed to open read-only file: "    // --
                             << filename                             // --
                             << bsl::endl;                           // --

                return;
            }

            bsl::finally mut_release_on_error{[this]() noexcept -> void {
                this->release();
            }};

            if (bsl::unlikely(IFMAP_POSIX_ERROR == fstat(m_file.get(), &mut_s))) {
                bsl::error() << "failed to get the size of the read-only file: "    // --
                             << filename                                            // --
                             << bsl::endl;

                return;
            }

            m_data = mmap(
                nullptr,
                static_cast<bsl::uintmx>(mut_s.st_size),
                PROT_READ,
                // We don't have a choice here
                // NOLINTNEXTLINE(hicpp-signed-bitwise, bsl-types-fixed-width-ints-arithmetic-check)
                MAP_SHARED | MAP_POPULATE,
                m_file.get(),
                static_cast<bsl::int64>(0));

            // We don't have a choice here
            // NOLINTNEXTLINE(cppcoreguidelines-pro-type-cstyle-cast)
            if (bsl::unlikely(MAP_FAILED == m_data)) {
                bsl::error() << "failed to map read-only file: "    // --
                             << filename                            // --
                             << bsl::endl;

                return;
            }

            m_size = bsl::to_umx(mut_s.st_size);
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
            , m_data{bsl::move(mut_o.m_data)}
            , m_size{bsl::move(mut_o.m_size)}
        {
            mut_o.m_file = IFMAP_INVALID_FILE;
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
                bsl::discard(munmap(m_data, m_size.get()));
            }
            else {
                bsl::touch();
            }

            if (IFMAP_INVALID_FILE != m_file) {
                bsl::discard(close(m_file.get()));
            }
            else {
                bsl::touch();
            }

            m_size = {};
            m_data = {};
            m_file = IFMAP_INVALID_FILE;
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
        size() const noexcept -> bsl::safe_umx
        {
            return m_size;
        }
    };
}

#endif
