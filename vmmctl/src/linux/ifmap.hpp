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

#include <bsl/byte.hpp>
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

namespace vmmctl
{
    namespace details
    {
        /// @brief defines what an error looks like from a POSIX call.
        constexpr bsl::safe_int32 IFMAP_POSIX_ERROR{-1};
        /// @brief defines what an invalid file is.
        constexpr bsl::safe_int32 IFMAP_INVALID_FILE{-1};
    }

    /// @class bsl::ifmap
    ///
    /// <!-- description -->
    ///   @brief Maps a file as read-only, and returns a pointer to the file
    ///     via data() as well as the size of the mapped file via size().
    ///
    class ifmap final
    {
        /// @brief stores a handle to the mapped file.
        bsl::int32 m_file{details::IFMAP_INVALID_FILE.get()};
        /// @brief stores a view of the file that is mapped.
        bsl::span<bsl::byte const> m_data{};

        /// <!-- description -->
        ///   @brief Swaps *this with other
        ///
        /// <!-- inputs/outputs -->
        ///   @param lhs the left hand side of the exchange
        ///   @param rhs the right hand side of the exchange
        ///
        static constexpr auto
        private_swap(ifmap &lhs, ifmap &rhs) noexcept -> void
        {
            bsl::swap(lhs.m_file, rhs.m_file);
            bsl::swap(lhs.m_data, rhs.m_data);
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
        ifmap() noexcept = default;

        /// <!-- description -->
        ///   @brief Creates a bsl::ifmap given a the filename and path of
        ///     the file to map as read-only.
        ///
        /// <!-- inputs/outputs -->
        ///   @param filename the filename and path of the file to map
        ///
        explicit ifmap(bsl::string_view const &filename) noexcept
        {
            using stat_t = struct stat;

            // We don't have a choice here
            // NOLINTNEXTLINE(cppcoreguidelines-pro-type-vararg, hicpp-vararg)
            m_file = open(filename.data(), O_RDONLY);
            if (bsl::unlikely(details::IFMAP_POSIX_ERROR.get() == m_file)) {
                bsl::alert() << "failed to open read-only file: "    // --
                             << filename                             // --
                             << bsl::endl;

                m_file = details::IFMAP_INVALID_FILE.get();
                return;
            }

            stat_t s{};
            if (bsl::unlikely(details::IFMAP_POSIX_ERROR.get() == fstat(m_file, &s))) {
                bsl::alert() << "failed to get the size of the read-only file: "    // --
                             << filename                                            // --
                             << bsl::endl;

                bsl::discard(close(m_file));
                m_file = details::IFMAP_INVALID_FILE.get();
                return;
            }

            pointer_type const ptr{mmap(
                nullptr,
                static_cast<bsl::uintmax>(s.st_size),
                PROT_READ,
                // We don't have a choice here
                // NOLINTNEXTLINE(hicpp-signed-bitwise)
                MAP_SHARED | MAP_POPULATE,
                m_file,
                static_cast<bsl::intmax>(0))};

            // We don't have a choice here
            // NOLINTNEXTLINE(cppcoreguidelines-pro-type-cstyle-cast)
            if (bsl::unlikely(MAP_FAILED == ptr)) {
                bsl::alert() << "failed to map read-only file: "    // --
                             << filename                            // --
                             << bsl::endl;

                bsl::discard(close(m_file));
                m_file = details::IFMAP_INVALID_FILE.get();
                return;
            }

            m_data = {static_cast<bsl::byte const *>(ptr), bsl::to_umax(s.st_size)};
        }

        /// <!-- description -->
        ///   @brief Destructor unmaps a previously mapped file.
        ///
        ~ifmap() noexcept = default;
        // {
        //     // if (details::IFMAP_INVALID_FILE.get() != m_file) {
        //     //     // Not given a choice here due to the APIs provided by Linux
        //     //     // NOLINTNEXTLINE(cppcoreguidelines-pro-type-const-cast,-warnings-as-errors)
        //     //     bsl::discard(munmap(const_cast<byte *>(m_data.data()), m_data.size().get()));
        //     //     bsl::discard(close(m_file));
        //     //     m_file = details::IFMAP_INVALID_FILE.get();
        //     // }
        //     // else {
        //     //     bsl::touch();
        //     // }
        // }

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
        ///   @param o the object being moved
        ///
        constexpr ifmap(ifmap &&o) noexcept
            : m_file{bsl::move(o.m_file)}, m_data{bsl::move(o.m_data)}
        {
            o.m_file = details::IFMAP_INVALID_FILE.get();
            o.m_data = {};
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
        ///   @param o the object being moved
        ///   @return a reference to *this
        ///
        [[maybe_unused]] auto
        operator=(ifmap &&o) &noexcept -> ifmap &
        {
            ifmap tmp{bsl::move(o)};
            this->private_swap(*this, tmp);
            return *this;
        }

        /// <!-- description -->
        ///   @brief Returns a span to the read-only mapped file.
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns a span to the read-only mapped file.
        ///
        [[nodiscard]] constexpr auto
        view() const noexcept -> bsl::span<bsl::byte const>
        {
            return m_data;
        }

        /// <!-- description -->
        ///   @brief Returns a pointer to the read-only mapped file.
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns a pointer to the read-only mapped file.
        ///
        [[nodiscard]] constexpr auto
        data() const noexcept -> const_pointer_type
        {
            return m_data.data();
        }

        /// <!-- description -->
        ///   @brief Returns true if the file failed to be mapped, false
        ///     otherwise.
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns true if the file failed to be mapped, false
        ///     otherwise.
        ///
        [[nodiscard]] constexpr auto
        empty() const noexcept -> bool
        {
            return m_data.empty();
        }

        /// <!-- description -->
        ///   @brief Returns !empty()
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns !empty()
        ///
        [[nodiscard]] constexpr explicit operator bool() const noexcept
        {
            return !this->empty();
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
        size() const noexcept -> size_type
        {
            return m_data.size();
        }

        /// <!-- description -->
        ///   @brief Returns the max number of bytes the BSL supports.
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the max number of bytes the BSL supports.
        ///
        [[nodiscard]] static constexpr auto
        max_size() noexcept -> size_type
        {
            return bsl::to_umax(size_type::max());
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
        size_bytes() const noexcept -> size_type
        {
            return m_data.size();
        }
    };
}

#endif
