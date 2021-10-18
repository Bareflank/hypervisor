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

#ifndef BASIC_IOCTL_T_HPP
#define BASIC_IOCTL_T_HPP

#include <fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include <bsl/convert.hpp>
#include <bsl/debug.hpp>
#include <bsl/discard.hpp>
#include <bsl/exchange.hpp>
#include <bsl/expects.hpp>
#include <bsl/safe_integral.hpp>
#include <bsl/string_view.hpp>
#include <bsl/touch.hpp>
#include <bsl/unlikely.hpp>

namespace lib
{
    /// @brief defines what an invalid handle is.
    constexpr auto IOCTL_INVALID_HNDL{-1_i32};

    /// <!-- description -->
    ///   @brief Executes IOCTL commands to a driver.
    ///
    // NOLINTNEXTLINE(bsl-using-ident-unique-namespace)
    class basic_ioctl_t final
    {
        /// @brief stores a handle to the device driver.
        bsl::safe_i32 m_hndl{IOCTL_INVALID_HNDL};

    public:
        /// <!-- description -->
        ///   @brief Default constructor
        ///
        constexpr basic_ioctl_t() noexcept = default;

        /// <!-- description -->
        ///   @brief Creates a lib::ioctl that can be used to communicate
        ///     with a device driver through an IOCTL interface.
        ///
        /// <!-- inputs/outputs -->
        ///   @param name the name of the device driver to IOCTL.
        ///
        explicit constexpr basic_ioctl_t(bsl::string_view const &name) noexcept
        {
            // NOLINTNEXTLINE(cppcoreguidelines-pro-type-vararg, hicpp-vararg)
            m_hndl = bsl::to_i32(open(name.data(), O_RDWR));
            if (bsl::unlikely(IOCTL_INVALID_HNDL == m_hndl)) {
                bsl::error() << "ioctl open failed\n";
                return;
            }

            bsl::touch();
        }

        /// <!-- description -->
        ///   @brief Creates a lib::ioctl that can be used to communicate
        ///     with a device driver through an IOCTL interface.
        ///
        /// <!-- inputs/outputs -->
        ///   @param hndl the handle to an existing IOCTL to use.
        ///
        explicit constexpr basic_ioctl_t(bsl::safe_i32 const hndl) noexcept
        {
            if (hndl.is_neg()) {
                m_hndl = IOCTL_INVALID_HNDL;
            }
            else {
                m_hndl = hndl;
            }
        }

        /// <!-- description -->
        ///   @brief Destructor
        ///
        constexpr ~basic_ioctl_t() noexcept
        {
            this->close();
        }

        /// <!-- description -->
        ///   @brief copy constructor
        ///
        /// <!-- inputs/outputs -->
        ///   @param o the object being copied
        ///
        constexpr basic_ioctl_t(basic_ioctl_t const &o) noexcept = delete;

        /// <!-- description -->
        ///   @brief move constructor
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_o the object being moved
        ///
        constexpr basic_ioctl_t(basic_ioctl_t &&mut_o) noexcept
            : m_hndl{bsl::exchange(mut_o.m_hndl, IOCTL_INVALID_HNDL)}
        {}

        /// <!-- description -->
        ///   @brief copy assignment
        ///
        /// <!-- inputs/outputs -->
        ///   @param o the object being copied
        ///   @return a reference to *this
        ///
        [[maybe_unused]] constexpr auto operator=(basic_ioctl_t const &o) &noexcept
            -> basic_ioctl_t & = delete;

        /// <!-- description -->
        ///   @brief move assignment
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_o the object being moved
        ///   @return a reference to *this
        ///
        [[maybe_unused]] constexpr auto
        operator=(basic_ioctl_t &&mut_o) &noexcept -> basic_ioctl_t &
        {
            /// NOTE:
            /// - For now we do not use the swap technique that AUTOSAR wants
            ///   you to use because we actually need an exchange since we
            ///   are implementing something closer to a unique_ptr.
            ///

            if (this == &mut_o) {
                return *this;
            }

            m_hndl = bsl::exchange(mut_o.m_hndl, IOCTL_INVALID_HNDL);
            return *this;
        }

        /// <!-- description -->
        ///   @brief Closes the IOCTL
        ///
        constexpr void
        // NOLINTNEXTLINE(bsl-using-ident-unique-namespace)
        close() noexcept
        {
            if (IOCTL_INVALID_HNDL != m_hndl) {
                bsl::discard(::close(m_hndl.get()));
                m_hndl = IOCTL_INVALID_HNDL;
            }
            else {
                bsl::touch();
            }
        }

        /// <!-- description -->
        ///   @brief Returns true if the basic_ioctl_t has been opened, false
        ///     otherwise.
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns true if the basic_ioctl_t has been opened, false
        ///     otherwise.
        ///
        [[nodiscard]] constexpr auto
        is_open() const noexcept -> bool
        {
            return IOCTL_INVALID_HNDL != m_hndl;
        }

        /// <!-- description -->
        ///   @brief Returns the handle associated with this IOCTL
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the handle associated with this IOCTL
        ///
        [[nodiscard]] constexpr auto
        handle() const noexcept -> bsl::safe_i32
        {
            return m_hndl;
        }

        /// <!-- description -->
        ///   @brief Sends a request to the driver without read or writing
        ///     data.
        ///
        /// <!-- inputs/outputs -->
        ///   @param req the request
        ///   @return Returns a negative error code on failure, or
        ///     something 0 or positive on success.
        ///
        [[nodiscard]] constexpr auto
        // NOLINTNEXTLINE(bsl-using-ident-unique-namespace)
        send(bsl::safe_umx const &req) const noexcept -> bsl::safe_i64
        {
            if (bsl::unlikely(IOCTL_INVALID_HNDL == m_hndl)) {
                bsl::error() << "ioctl failed because the handle to the driver is invalid\n";
                return bsl::safe_i64::magic_neg_1();
            }

            // NOLINTNEXTLINE(cppcoreguidelines-pro-type-vararg, hicpp-vararg)
            bsl::safe_i32 const ret{::ioctl(m_hndl.get(), req.get(), nullptr)};
            if (bsl::unlikely(ret.is_neg())) {
                bsl::error() << "ioctl failed\n";
                return bsl::to_i64(ret);
            }

            return bsl::to_i64(ret);
        }

        /// <!-- description -->
        ///   @brief Reads data from the device driver
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam T the type of data to read
        ///   @param req the request
        ///   @param pmut_data a pointer to read data to
        ///   @return Returns a negative error code on failure, or
        ///     something 0 or positive on success.
        ///
        template<typename T>
        [[nodiscard]] constexpr auto
        // NOLINTNEXTLINE(bsl-using-ident-unique-namespace)
        read(bsl::safe_umx const &req, T *const pmut_data) const noexcept -> bsl::safe_i64
        {
            bsl::expects(nullptr != pmut_data);

            if (bsl::unlikely(IOCTL_INVALID_HNDL == m_hndl)) {
                bsl::error() << "ioctl failed because the handle to the driver is invalid\n";
                return bsl::safe_i64::magic_neg_1();
            }

            // NOLINTNEXTLINE(cppcoreguidelines-pro-type-vararg, hicpp-vararg)
            bsl::safe_i32 const ret{::ioctl(m_hndl.get(), req.get(), pmut_data)};
            if (bsl::unlikely(ret.is_neg())) {
                bsl::error() << "ioctl failed\n";
                return bsl::to_i64(ret);
            }

            return bsl::to_i64(ret);
        }

        /// <!-- description -->
        ///   @brief Writes data to the device driver
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam T the type of data to write
        ///   @param req the request
        ///   @param data a pointer to write data from
        ///   @return Returns a negative error code on failure, or
        ///     something 0 or positive on success.
        ///
        template<typename T>
        [[nodiscard]] constexpr auto
        // NOLINTNEXTLINE(bsl-using-ident-unique-namespace)
        write(bsl::safe_umx const &req, T const *const data) noexcept -> bsl::safe_i64
        {
            bsl::expects(nullptr != data);

            if (bsl::unlikely(IOCTL_INVALID_HNDL == m_hndl)) {
                bsl::error() << "ioctl failed because the handle to the driver is invalid\n";
                return bsl::safe_i64::magic_neg_1();
            }

            // NOLINTNEXTLINE(cppcoreguidelines-pro-type-vararg, hicpp-vararg)
            bsl::safe_i32 const ret{::ioctl(m_hndl.get(), req.get(), data)};
            if (bsl::unlikely(ret.is_neg())) {
                bsl::error() << "ioctl failed\n";
                return bsl::to_i64(ret);
            }

            return bsl::to_i64(ret);
        }

        /// <!-- description -->
        ///   @brief Writes data to the device driver
        ///
        /// <!-- inputs/outputs -->
        ///   @param req the request
        ///   @param data an integral to write to the IOCTL
        ///   @return Returns a negative error code on failure, or
        ///     something 0 or positive on success.
        ///
        [[nodiscard]] constexpr auto
        // NOLINTNEXTLINE(bsl-using-ident-unique-namespace)
        write(bsl::safe_umx const &req, bsl::safe_i64 const &data) noexcept -> bsl::safe_i64
        {
            bsl::expects(data.is_valid_and_checked());

            if (bsl::unlikely(IOCTL_INVALID_HNDL == m_hndl)) {
                bsl::error() << "ioctl failed because the handle to the driver is invalid\n";
                return bsl::safe_i64::magic_neg_1();
            }

            // NOLINTNEXTLINE(cppcoreguidelines-pro-type-vararg, hicpp-vararg)
            bsl::safe_i32 const ret{::ioctl(m_hndl.get(), req.get(), data.get())};
            if (bsl::unlikely(ret.is_neg())) {
                bsl::error() << "ioctl failed\n";
                return bsl::to_i64(ret);
            }

            return bsl::to_i64(ret);
        }

        /// <!-- description -->
        ///   @brief Reads/writes data from/to the device driver
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam T the type of data to read/write
        ///   @param req the request
        ///   @param pmut_data a pointer to read/write data to/from
        ///   @return Returns a negative error code on failure, or
        ///     something 0 or positive on success.
        ///
        template<typename T>
        [[nodiscard]] constexpr auto
        read_write(bsl::safe_umx const &req, T *const pmut_data) noexcept -> bsl::safe_i64
        {
            bsl::expects(nullptr != pmut_data);

            if (bsl::unlikely(IOCTL_INVALID_HNDL == m_hndl)) {
                bsl::error() << "ioctl failed because the handle to the driver is invalid\n";
                return bsl::safe_i64::magic_neg_1();
            }

            // NOLINTNEXTLINE(cppcoreguidelines-pro-type-vararg, hicpp-vararg)
            bsl::safe_i32 const ret{::ioctl(m_hndl.get(), req.get(), pmut_data)};
            if (bsl::unlikely(ret.is_neg())) {
                bsl::error() << "ioctl failed\n";
                return bsl::to_i64(ret);
            }

            return bsl::to_i64(ret);
        }
    };
}

#endif
