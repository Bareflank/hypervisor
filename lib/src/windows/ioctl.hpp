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

#ifndef LIB_IOCTL_HPP
#define LIB_IOCTL_HPP

// clang-format off

/// NOTE:
/// - The windows includes that we use here need to remain in this order.
///   Otherwise the code will not compile. Also, when using CPP, we need
///   to remove the max/min macros as they are used by the C++ standard.
///

#include <Windows.h>
#include <SetupAPI.h>
#undef max
#undef min

// clang-format on

#include <bsl/exchange.hpp>
#include <bsl/debug.hpp>
#include <bsl/move.hpp>
#include <bsl/safe_integral.hpp>
#include <bsl/swap.hpp>
#include <bsl/unlikely.hpp>

namespace lib
{
    /// @class lib::ioctl
    ///
    /// <!-- description -->
    ///   @brief Executes IOCTL commands to a driver.
    ///
    class ioctl final
    {
        /// @brief stores a handle to the device driver.
        HANDLE m_hndl{};

    public:
        /// <!-- description -->
        ///   @brief Default constructor
        ///
        constexpr ioctl() noexcept = default;

        /// <!-- description -->
        ///   @brief Creates a lib::ioctl that can be used to communicate
        ///     with a device driver through an IOCTL interface.
        ///
        /// <!-- inputs/outputs -->
        ///   @param name the name of the device driver to IOCTL.
        ///
        template<typename GUID>
        explicit constexpr ioctl(GUID name) noexcept
        {
            BOOL ret{};
            HANDLE info{};
            DWORD const flags{DIGCF_DEVICEINTERFACE | DIGCF_PRESENT};
            SP_INTERFACE_DEVICE_DETAIL_DATA *dev_data{};

            SP_DEVINFO_DATA dev_info{};
            dev_info.cbSize = sizeof(SP_DEVINFO_DATA);

            SP_INTERFACE_DEVICE_DATA if_info{};
            if_info.cbSize = sizeof(SP_INTERFACE_DEVICE_DATA);

            info = SetupDiGetClassDevsW(&name, nullptr, nullptr, flags);
            if (bsl::unlikely(INVALID_HANDLE_VALUE == info)) {
                bsl::error() << "SetupDiGetClassDevs failed\n";
                return;
            }

            bsl::finally mut_close_info{[&info]() noexcept -> void {
                bsl::discard(CloseHandle(info));
            }};

            ret = SetupDiEnumDeviceInfo(info, 0, &dev_info);
            if (bsl::unlikely(ret == FALSE)) {
                bsl::error() << "SetupDiEnumDeviceInfo failed\n";
                return;
            }

            ret = SetupDiEnumDeviceInterfaces(info, &dev_info, &(name), 0, &if_info);
            if (bsl::unlikely(ret == FALSE)) {
                bsl::error() << "SetupDiEnumDeviceInterfaces failed\n";
                return;
            }

            DWORD size{};
            ret = SetupDiGetDeviceInterfaceDetailA(info, &if_info, nullptr, 0, &size, nullptr);
            if (bsl::unlikely(ret == TRUE)) {
                bsl::error() << "SetupDiGetDeviceInterfaceDetailA failed\n";
                return;
            }

            if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
                bsl::error() << "SetupDiGetDeviceInterfaceDetailA failed\n";
                return;
            }

            dev_data = static_cast<SP_INTERFACE_DEVICE_DETAIL_DATA *>(malloc(size));
            if (bsl::unlikely(nullptr == dev_data)) {
                bsl::error() << "malloc failed in ioctl\n";
                return;
            }

            dev_data->cbSize = sizeof(SP_INTERFACE_DEVICE_DETAIL_DATA);

            bsl::finally mut_free_dev_data{[&dev_data]() noexcept -> void {
                free(dev_data);
            }};

            ret = SetupDiGetDeviceInterfaceDetail(info, &if_info, dev_data, size, nullptr, nullptr);
            if (bsl::unlikely(ret == FALSE)) {
                bsl::error() << "SetupDiGetDeviceInterfaceDetail failed\n";
                return;
            }

            m_hndl = CreateFile(
                dev_data->DevicePath,
                GENERIC_READ | GENERIC_WRITE,
                0,
                nullptr,
                CREATE_ALWAYS,
                FILE_ATTRIBUTE_NORMAL,
                nullptr);

            if (bsl::unlikely(nullptr == m_hndl)) {
                bsl::error() << "ioctl CreateFile failed\n";
                return;
            }
        }

        /// <!-- description -->
        ///   @brief Creates a lib::ioctl that can be used to communicate
        ///     with a device driver through an IOCTL interface.
        ///
        /// <!-- inputs/outputs -->
        ///   @param hndl the handle to an existing IOCTL to use.
        ///
        explicit constexpr ioctl(HANDLE const hndl) noexcept
        {
            m_hndl = hndl;
        }

        /// <!-- description -->
        ///   @brief Destructor
        ///
        constexpr ~ioctl() noexcept
        {
            this->close();
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
        constexpr ioctl(ioctl &&mut_o) noexcept : m_hndl{bsl::exchange(mut_o.m_hndl, nullptr)}
        {}

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
        [[maybe_unused]] constexpr auto
        operator=(ioctl &&mut_o) &noexcept -> ioctl &
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
            if (bsl::unlikely(nullptr != m_hndl)) {
                bsl::discard(CloseHandle(m_hndl));
                m_hndl = nullptr;
            }
            else {
                bsl::touch();
            }
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
            return nullptr != m_hndl;
        }

        /// <!-- description -->
        ///   @brief Returns the handle associated with this IOCTL
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the handle associated with this IOCTL
        ///
        [[nodiscard]] constexpr auto
        handle() const noexcept -> HANDLE
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
            DWORD bytes{};

            if (bsl::unlikely(IOCTL_INVALID_HNDL == m_hndl)) {
                bsl::error() << "ioctl failed because the handle to the driver is invalid\n";
                return bsl::safe_i64::magic_neg_1();
            }

            auto const ret{
                DeviceIoControl(m_hndl, req32.get(), nullptr, 0, nullptr, 0, &bytes, nullptr)};

            if (bsl::unlikely(!ret)) {
                bsl::error() << "DeviceIoControl failed\n";
                return bsl::safe_i64::magic_neg_1();
            }

            return bsl::safe_i64::magic_0();
        }

        /// <!-- description -->
        ///   @brief Reads data from the device driver
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam T the type of data to read
        ///   @param req the request
        ///   @param data a pointer to read data to
        ///   @return Returns true if the IOCTL succeeded, false otherwise.
        ///
        template<typename T>
        [[nodiscard]] constexpr auto
        // NOLINTNEXTLINE(bsl-using-ident-unique-namespace)
        read(bsl::safe_umx const &req, T *const pmut_data) const noexcept -> bsl::safe_i64
        {
            DWORD bytes{};
            bsl::expects(nullptr != pmut_data);

            if (bsl::unlikely(IOCTL_INVALID_HNDL == m_hndl)) {
                bsl::error() << "ioctl failed because the handle to the driver is invalid\n";
                return bsl::safe_i64::magic_neg_1();
            }

            auto const req32{bsl::to_u32(req)};
            bsl::expects(req32.is_invalid());

            auto const size32{bsl::to_u32(sizeof(T))};
            bsl::expects(size32.is_invalid());

            auto const ret{DeviceIoControl(
                m_hndl, req32.get(), nullptr, 0, pmut_data, size32.get(), &bytes, nullptr)};

            if (bsl::unlikely(!ret)) {
                bsl::error() << "DeviceIoControl failed\n";
                return bsl::safe_i64::magic_neg_1();
            }

            return bsl::safe_i64::magic_0();
        }

        /// <!-- description -->
        ///   @brief Writes data to the device driver
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam T the type of data to write
        ///   @param req the request
        ///   @param data a pointer to write data from
        ///   @return Returns true if the IOCTL succeeded, false otherwise.
        ///
        template<typename T>
        [[nodiscard]] constexpr auto
        // NOLINTNEXTLINE(bsl-using-ident-unique-namespace)
        write(bsl::safe_umx const &req, T const *const data) const noexcept -> bsl::safe_i64
        {
            void *const pmut_ptr{const_cast<void *>(data)};

            DWORD bytes{};
            bsl::expects(nullptr != pmut_data);

            if (bsl::unlikely(IOCTL_INVALID_HNDL == m_hndl)) {
                bsl::error() << "ioctl failed because the handle to the driver is invalid\n";
                return bsl::safe_i64::magic_neg_1();
            }

            auto const req32{bsl::to_u32(req)};
            bsl::expects(req32.is_invalid());

            auto const size32{bsl::to_u32(sizeof(T))};
            bsl::expects(size32.is_invalid());

            auto const ret{DeviceIoControl(
                m_hndl, req32.get(), pmut_ptr, size32.get(), nullptr, 0, &bytes, nullptr)};

            if (bsl::unlikely(!ret)) {
                bsl::error() << "DeviceIoControl failed\n";
                return bsl::safe_i64::magic_neg_1();
            }

            return bsl::safe_i64::magic_0();
        }

        /// <!-- description -->
        ///   @brief Reads/writes data from/to the device driver
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam T the type of data to read/write
        ///   @param req the request
        ///   @param data a pointer to read/write data to/from
        ///   @return Returns true if the IOCTL succeeded, false otherwise.
        ///
        template<typename T>
        [[nodiscard]] constexpr auto
        read_write(bsl::safe_umx const &req, T *const data) const noexcept -> bsl::safe_i64
        {
            DWORD bytes{};
            bsl::expects(nullptr != pmut_data);

            if (bsl::unlikely(IOCTL_INVALID_HNDL == m_hndl)) {
                bsl::error() << "ioctl failed because the handle to the driver is invalid\n";
                return bsl::safe_i64::magic_neg_1();
            }

            auto const req32{bsl::to_u32(req)};
            bsl::expects(req32.is_invalid());

            auto const size32{bsl::to_u32(sizeof(T))};
            bsl::expects(size32.is_invalid());

            auto const ret{DeviceIoControl(
                m_hndl, req32.get(), data, size32.get(), data, size32.get(), &bytes, nullptr)};

            if (bsl::unlikely(!ret)) {
                bsl::error() << "DeviceIoControl failed\n";
                return bsl::safe_i64::magic_neg_1();
            }

            return bsl::safe_i64::magic_0();
        }
    };
}

#endif
