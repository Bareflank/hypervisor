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

#ifndef MOCKS_BASIC_IOCTL_T_HPP
#define MOCKS_BASIC_IOCTL_T_HPP

#if __has_include("ioctl_helpers.hpp")
#include <ioctl_helpers.hpp>    // IWYU pragma: export
#endif

#if __has_include("basic_ioctl_helpers.hpp")
#include <basic_ioctl_helpers.hpp>    // IWYU pragma: export
#endif

// IWYU pragma: no_include "ioctl_helpers.hpp"
// IWYU pragma: no_include "basic_ioctl_helpers.hpp"

#include <bsl/debug.hpp>
#include <bsl/expects.hpp>
#include <bsl/safe_integral.hpp>
#include <bsl/string_view.hpp>
#include <bsl/unordered_map.hpp>

namespace lib
{
    /// <!-- description -->
    ///   @brief Executes IOCTL commands to a driver.
    ///
    // NOLINTNEXTLINE(bsl-using-ident-unique-namespace)
    class basic_ioctl_t final
    {
        /// @brief stores if the IOCTL is open
        bool m_open{};
        /// @brief stores the data associated with a read/write
        bsl::unordered_map<bsl::safe_umx, helpers::ioctl_storage_t> m_reqs{};

    public:
        /// <!-- description -->
        ///   @brief Default constructor
        ///
        constexpr basic_ioctl_t() noexcept = default;

        /// <!-- description -->
        ///   @brief Creates a lib::basic_ioctl_t that can be used to communicate
        ///     with a device driver through an IOCTL interface.
        ///
        /// <!-- inputs/outputs -->
        ///   @param name the name of the device driver to IOCTL.
        ///
        explicit constexpr basic_ioctl_t(bsl::string_view const &name) noexcept
        {
            m_open = !name.starts_with("failure");
        }

        /// <!-- description -->
        ///   @brief Creates a lib::basic_ioctl_t that can be used to communicate
        ///     with a device driver through an IOCTL interface.
        ///
        /// <!-- inputs/outputs -->
        ///   @param hndl the handle to an existing IOCTL to use.
        ///
        explicit constexpr basic_ioctl_t(bsl::safe_i32 const hndl) noexcept
        {
            m_open = hndl.is_valid();
        }

        /// <!-- description -->
        ///   @brief Destructor
        ///
        constexpr ~basic_ioctl_t() noexcept = default;

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
        constexpr basic_ioctl_t(basic_ioctl_t &&mut_o) noexcept = default;

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
        [[maybe_unused]] constexpr auto operator=(basic_ioctl_t &&mut_o) &noexcept
            -> basic_ioctl_t & = default;

        /// <!-- description -->
        ///   @brief Closes the IOCTL
        ///
        constexpr void
        // NOLINTNEXTLINE(bsl-using-ident-unique-namespace)
        close() noexcept
        {
            m_open = false;
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
            return m_open;
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
            if (!m_open) {
                return bsl::safe_i64::magic_neg_1();
            }

            if (!m_reqs.contains(req)) {
                return bsl::safe_i64::magic_neg_1();
            }

            return {};
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

            if (!m_open) {
                return bsl::safe_i64::magic_neg_1();
            }

            if (!m_reqs.contains(req)) {
                return bsl::safe_i64::magic_neg_1();
            }

            *pmut_data = helpers::get_store<T>(m_reqs.at(req));
            return {};
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

            if (!m_open) {
                return bsl::safe_i64::magic_neg_1();
            }

            helpers::set_store<T>(m_reqs.at(req), *data);
            return {};
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

            if (!m_open) {
                return bsl::safe_i64::magic_neg_1();
            }

            helpers::set_store<bsl::safe_i64>(m_reqs.at(req), data);
            return {};
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

            if (!m_open) {
                return bsl::safe_i64::magic_neg_1();
            }

            if (!m_reqs.contains(req)) {
                return bsl::safe_i64::magic_neg_1();
            }

            auto const tmp{helpers::get_store<T>(m_reqs.at(req))};
            helpers::set_store<T>(m_reqs.at(req), *pmut_data);
            *pmut_data = tmp;

            return {};
        }
    };
}

#endif
