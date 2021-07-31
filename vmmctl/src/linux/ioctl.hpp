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

#include <bsl/convert.hpp>
#include <bsl/debug.hpp>
#include <bsl/discard.hpp>
#include <bsl/safe_integral.hpp>
#include <bsl/string_view.hpp>
#include <bsl/touch.hpp>
#include <bsl/unlikely.hpp>

namespace vmmctl
{
    /// @brief defines what an invalid handle is.
    constexpr auto IOCTL_INVALID_HNDL{-1_i32};

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
        bsl::safe_i32 m_hndl{IOCTL_INVALID_HNDL};

    public:
        /// <!-- description -->
        ///   @brief Creates a bsl::ioctl that can be used to communicate
        ///     with a device driver through an IOCTL interface.
        ///
        /// <!-- inputs/outputs -->
        ///   @param name the name of the device driver to IOCTL.
        ///
        explicit constexpr ioctl(bsl::string_view const &name) noexcept
        {
            // We don't have a choice here
            // NOLINTNEXTLINE(cppcoreguidelines-pro-type-vararg, hicpp-vararg)
            m_hndl = bsl::to_i32(open(name.data(), O_RDWR));
            if (bsl::unlikely(IOCTL_INVALID_HNDL == m_hndl)) {
                bsl::error() << "ioctl open failed\n";
                return;
            }

            bsl::touch();
        }

        /// <!-- description -->
        ///   @brief Destructor
        ///
        constexpr ~ioctl() noexcept
        {
            if (IOCTL_INVALID_HNDL != m_hndl) {
                bsl::discard(close(m_hndl.get()));
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
        ///   @param mut_o the object being moved
        ///
        constexpr ioctl(ioctl &&mut_o) noexcept = delete;

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
        ///   @param mut_o the object being moved
        ///   @return a reference to *this
        ///
        [[maybe_unused]] constexpr auto operator=(ioctl &&mut_o) &noexcept -> ioctl & = delete;

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
            return IOCTL_INVALID_HNDL != m_hndl;
        }

        /// <!-- description -->
        ///   @brief Returns is_open()
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns is_open()
        ///
        [[nodiscard]] explicit constexpr operator bool() const noexcept
        {
            return this->is_open();
        }

        /// <!-- description -->
        ///   @brief Sends a request to the driver without read or writing
        ///     data.
        ///
        /// <!-- inputs/outputs -->
        ///   @param req the request
        ///   @return Returns true if the IOCTL succeeded, false otherwise.
        ///
        [[nodiscard]] constexpr auto
        send(bsl::safe_umx const &req) const noexcept -> bool
        {
            if (bsl::unlikely(IOCTL_INVALID_HNDL == m_hndl)) {
                bsl::error() << "failed to send, ioctl not properly initialized\n";
                return false;
            }

            if (bsl::unlikely(req.is_invalid())) {
                bsl::error() << "invalid request: "    // --
                             << bsl::hex(req)          // --
                             << bsl::endl              // --
                             << bsl::here();           // --

                return false;
            }

            // We don't have a choice here
            // NOLINTNEXTLINE(cppcoreguidelines-pro-type-vararg, hicpp-vararg)
            bsl::safe_i32 const ret{::ioctl(m_hndl.get(), req.get())};
            if (bsl::unlikely(ret.is_neg())) {
                bsl::error() << "ioctl failed\n";
                return false;
            }

            return true;
        }

        /// <!-- description -->
        ///   @brief Reads data from the device driver
        ///
        /// <!-- inputs/outputs -->
        ///   @param req the request
        ///   @param pmut_data a pointer to read data to
        ///   @param size the size of the buffer being read to
        ///   @return Returns true if the IOCTL succeeded, false otherwise.
        ///
        [[nodiscard]] constexpr auto
        read_data(bsl::safe_umx const &req, void *const pmut_data, bsl::safe_umx const &size)
            const noexcept -> bool
        {
            bsl::discard(size);

            if (bsl::unlikely(IOCTL_INVALID_HNDL == m_hndl.get())) {
                bsl::error() << "failed to read, ioctl not properly initialized\n";
                return false;
            }

            if (bsl::unlikely(req.is_invalid())) {
                bsl::error() << "invalid request: "    // --
                             << bsl::hex(req)          // --
                             << bsl::endl              // --
                             << bsl::here();           // --

                return false;
            }

            if (bsl::unlikely(nullptr == pmut_data)) {
                bsl::error() << "invalid pmut_data: "    // --
                             << pmut_data                // --
                             << bsl::endl                // --
                             << bsl::here();             // --

                return false;
            }

            // We don't have a choice here
            // NOLINTNEXTLINE(cppcoreguidelines-pro-type-vararg, hicpp-vararg)
            bsl::safe_i32 const ret{::ioctl(m_hndl.get(), req.get(), pmut_data)};
            if (bsl::unlikely(ret.is_neg())) {
                bsl::error() << "ioctl failed\n";
                return false;
            }

            return true;
        }

        /// <!-- description -->
        ///   @brief Writes data to the device driver
        ///
        /// <!-- inputs/outputs -->
        ///   @param req the request
        ///   @param data a pointer to write data from
        ///   @param size the size of the buffer being written from
        ///   @return Returns true if the IOCTL succeeded, false otherwise.
        ///
        [[nodiscard]] constexpr auto
        write_data(bsl::safe_umx const &req, void const *const data, bsl::safe_umx const &size)
            const noexcept -> bool
        {
            bsl::discard(size);

            if (bsl::unlikely(IOCTL_INVALID_HNDL == m_hndl)) {
                bsl::error() << "failed to write, ioctl not properly initialized\n";
                return false;
            }

            if (bsl::unlikely(req.is_invalid())) {
                bsl::error() << "invalid request: "    // --
                             << bsl::hex(req)          // --
                             << bsl::endl              // --
                             << bsl::here();           // --

                return false;
            }

            if (bsl::unlikely(nullptr == data)) {
                bsl::error() << "invalid data: "    // --
                             << data                // --
                             << bsl::endl           // --
                             << bsl::here();        // --

                return false;
            }

            // We don't have a choice here
            // NOLINTNEXTLINE(cppcoreguidelines-pro-type-vararg, hicpp-vararg)
            bsl::safe_i32 const ret{::ioctl(m_hndl.get(), req.get(), data)};
            if (bsl::unlikely(ret.is_neg())) {
                bsl::error() << "ioctl failed\n";
                return false;
            }

            return true;
        }

        /// <!-- description -->
        ///   @brief Reads/writes data from/to the device driver
        ///
        /// <!-- inputs/outputs -->
        ///   @param req the request
        ///   @param pmut_data a pointer to read/write data to/from
        ///   @param size the size of the buffer being read/written to/from
        ///   @return Returns true if the IOCTL succeeded, false otherwise.
        ///
        [[nodiscard]] constexpr auto
        read_write_data(bsl::safe_umx const &req, void *const pmut_data, bsl::safe_umx const &size)
            const noexcept -> bool
        {
            bsl::discard(size);

            if (bsl::unlikely(IOCTL_INVALID_HNDL == m_hndl)) {
                bsl::error() << "failed to read/write, ioctl not properly initialized\n";
                return false;
            }

            if (bsl::unlikely(req.is_invalid())) {
                bsl::error() << "invalid request: "    // --
                             << bsl::hex(req)          // --
                             << bsl::endl              // --
                             << bsl::here();           // --

                return false;
            }

            if (bsl::unlikely(nullptr == pmut_data)) {
                bsl::error() << "invalid pmut_data: "    // --
                             << pmut_data                // --
                             << bsl::endl                // --
                             << bsl::here();             // --

                return false;
            }

            // We don't have a choice here
            // NOLINTNEXTLINE(cppcoreguidelines-pro-type-vararg, hicpp-vararg)
            bsl::safe_i32 const ret{::ioctl(m_hndl.get(), req.get(), pmut_data)};
            if (bsl::unlikely(ret.is_neg())) {
                bsl::error() << "ioctl failed\n";
                return false;
            }

            return true;
        }
    };
}

#endif
