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

#ifndef VMMCTL_IOCTL_LINUX_HPP
#define VMMCTL_IOCTL_LINUX_HPP

#include <fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include <bsl/cstdint.hpp>
#include <bsl/debug.hpp>
#include <bsl/discard.hpp>
#include <bsl/move.hpp>
#include <bsl/safe_integral.hpp>
#include <bsl/swap.hpp>
#include <bsl/touch.hpp>

namespace vmmctl
{
    namespace details
    {
        /// @brief defines what an invalid handle is.
        constexpr bsl::safe_int32 IOCTL_INVALID_HNDL{-1};
    }

    /// @class bsl::ioctl
    ///
    /// <!-- description -->
    ///   @brief Executes IOCTL commands to a driver.
    ///
    // This is a name conflict with external code.
    // NOLINTNEXTLINE(bsl-using-ident-unique-namespace)
    class ioctl final
    {
        /// @brief stores a handle to the device driver.
        bsl::int32 m_hndl{details::IOCTL_INVALID_HNDL.get()};

        /// <!-- description -->
        ///   @brief Swaps *this with other
        ///
        /// <!-- inputs/outputs -->
        ///   @param lhs the left hand side of the exchange
        ///   @param rhs the right hand side of the exchange
        ///
        static constexpr auto
        private_swap(ioctl &lhs, ioctl &rhs) noexcept -> void
        {
            bsl::swap(lhs.m_hndl, rhs.m_hndl);
        }

    public:
        /// <!-- description -->
        ///   @brief Creates a bsl::ioctl that can be used to communicate
        ///     with a device driver through an IOCTL interface.
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam CSTR the string type that used to describe "name"
        ///   @param name the name of the device driver to IOCTL.
        ///
        template<typename CSTR>
        explicit ioctl(CSTR name) noexcept
        {
            // We don't have a choice here
            // NOLINTNEXTLINE(cppcoreguidelines-pro-type-vararg, hicpp-vararg)
            m_hndl = open(name, O_RDWR);
            if (details::IOCTL_INVALID_HNDL.get() == m_hndl) {
                bsl::error() << "ioctl open failed\n";
                return;
            }

            bsl::touch();
        }

        /// <!-- description -->
        ///   @brief Destructor
        ///
        ~ioctl() noexcept
        {
            if (details::IOCTL_INVALID_HNDL.get() != m_hndl) {
                bsl::discard(close(m_hndl));
            }
            else {
                bsl::touch();
            }
        }

        /// <!-- description -->
        ///   @brief copy constructor
        ///
        /// <!-- inputs/outputs -->
        ///   @param o the object being copied
        ///
        constexpr ioctl(ioctl const &o) noexcept = delete;

        /// <!-- description -->
        ///   @brief move constructor
        ///
        /// <!-- inputs/outputs -->
        ///   @param o the object being moved
        ///
        constexpr ioctl(ioctl &&o) noexcept : m_hndl{bsl::move(o.m_hndl)}
        {
            o.m_hndl = details::IOCTL_INVALID_HNDL.get();
        }

        /// <!-- description -->
        ///   @brief copy assignment
        ///
        /// <!-- inputs/outputs -->
        ///   @param o the object being copied
        ///   @return a reference to *this
        ///
        [[maybe_unused]] constexpr auto operator=(ioctl const &o) &noexcept -> ioctl & = delete;

        /// <!-- description -->
        ///   @brief move assignment
        ///
        /// <!-- inputs/outputs -->
        ///   @param o the object being moved
        ///   @return a reference to *this
        ///
        [[maybe_unused]] auto
        operator=(ioctl &&o) &noexcept -> ioctl &
        {
            ioctl tmp{bsl::move(o)};
            this->private_swap(*this, tmp);
            return *this;
        }

        /// <!-- description -->
        ///   @brief Returns true if the ioctl has been opened, false
        ///     otherwise.
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns true if the ioctl has been opened, false
        ///     otherwise.
        ///
        [[nodiscard]] constexpr auto
        is_open() const noexcept -> bool
        {
            return details::IOCTL_INVALID_HNDL.get() != m_hndl;
        }

        /// <!-- description -->
        ///   @brief Returns is_open()
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns is_open()
        ///
        [[nodiscard]] constexpr explicit operator bool() const noexcept
        {
            return this->is_open();
        }

        /// <!-- description -->
        ///   @brief Sends a request to the driver without read or writing
        ///     data.
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam REQUEST the type of request
        ///   @param req the request
        ///   @return Returns true if the IOCTL succeeded, false otherwise.
        ///
        template<typename REQUEST>
        [[nodiscard]] constexpr auto
        send(bsl::safe_integral<REQUEST> const &req) const noexcept -> bool
        {
            if (details::IOCTL_INVALID_HNDL.get() == m_hndl) {
                bsl::error() << "failed to send, ioctl not properly initialized\n";
                return false;
            }

            // We don't have a choice here
            // NOLINTNEXTLINE(cppcoreguidelines-pro-type-vararg, hicpp-vararg)
            if (::ioctl(m_hndl, req.get()) < 0) {
                bsl::error() << "ioctl failed\n";
                return false;
            }

            return true;
        }

        /// <!-- description -->
        ///   @brief Reads data from the device driver
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam REQUEST the type of request
        ///   @param req the request
        ///   @param data a pointer to read data to
        ///   @param size the size of the buffer being read to
        ///   @return Returns true if the IOCTL succeeded, false otherwise.
        ///
        template<typename REQUEST>
        [[nodiscard]] constexpr auto
        // This conflicts with read() from unistd.h when it is included.
        // NOLINTNEXTLINE(bsl-using-ident-unique-namespace)
        read(
            bsl::safe_integral<REQUEST> const &req,
            void *const data,
            bsl::safe_uintmax const &size) const noexcept -> bool
        {
            bsl::discard(size);

            if (details::IOCTL_INVALID_HNDL.get() == m_hndl) {
                bsl::error() << "failed to read, ioctl not properly initialized\n";
                return false;
            }

            // We don't have a choice here
            // NOLINTNEXTLINE(cppcoreguidelines-pro-type-vararg, hicpp-vararg)
            if (::ioctl(m_hndl, req.get(), data) < 0) {
                bsl::error() << "ioctl failed\n";
                return false;
            }

            return true;
        }

        /// <!-- description -->
        ///   @brief Writes data to the device driver
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam REQUEST the type of request
        ///   @param req the request
        ///   @param data a pointer to write data from
        ///   @param size the size of the buffer being written from
        ///   @return Returns true if the IOCTL succeeded, false otherwise.
        ///
        template<typename REQUEST>
        [[nodiscard]] constexpr auto
        write(
            bsl::safe_integral<REQUEST> const &req,
            void const *const data,
            bsl::safe_uintmax const &size) const noexcept -> bool
        {
            bsl::discard(size);

            if (details::IOCTL_INVALID_HNDL.get() == m_hndl) {
                bsl::error() << "failed to write, ioctl not properly initialized\n";
                return false;
            }

            // We don't have a choice here
            // NOLINTNEXTLINE(cppcoreguidelines-pro-type-vararg, hicpp-vararg)
            if (::ioctl(m_hndl, req.get(), data) < 0) {
                bsl::error() << "ioctl failed\n";
                return false;
            }

            return true;
        }

        /// <!-- description -->
        ///   @brief Reads/writes data from/to the device driver
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam REQUEST the type of request
        ///   @param req the request
        ///   @param data a pointer to read/write data to/from
        ///   @param size the size of the buffer being read/written to/from
        ///   @return Returns true if the IOCTL succeeded, false otherwise.
        ///
        template<typename REQUEST>
        [[nodiscard]] constexpr auto
        read_write(
            bsl::safe_integral<REQUEST> const &req,
            void *const data,
            bsl::safe_uintmax const &size) const noexcept -> bool
        {
            bsl::discard(size);

            if (details::IOCTL_INVALID_HNDL.get() == m_hndl) {
                bsl::error() << "failed to read/write, ioctl not properly initialized\n";
                return false;
            }

            // We don't have a choice here
            // NOLINTNEXTLINE(cppcoreguidelines-pro-type-vararg, hicpp-vararg)
            if (::ioctl(m_hndl, req.get(), data) < 0) {
                bsl::error() << "ioctl failed\n";
                return false;
            }

            return true;
        }
    };
}

#endif
