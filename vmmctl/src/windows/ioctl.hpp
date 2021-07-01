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

#ifndef VMMCTL_IOCTL_WINDOWS_HPP
#define VMMCTL_IOCTL_WINDOWS_HPP

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

#include <bsl/debug.hpp>
#include <bsl/move.hpp>
#include <bsl/safe_integral.hpp>
#include <bsl/swap.hpp>
#include <bsl/unlikely.hpp>

namespace vmmctl
{
    /// @class vmmctl::ioctl
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
        ///   @brief Creates a vmmctl::ioctl that can be used to communicate
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
        ///   @brief Destructor
        ///
        constexpr ~ioctl() noexcept
        {
            if (bsl::unlikely(nullptr != m_hndl)) {
                bsl::discard(CloseHandle(m_hndl));
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
            return nullptr != m_hndl;
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
        send(bsl::safe_uintmax const &req) const noexcept -> bool
        {
            if (bsl::unlikely(nullptr == m_hndl)) {
                bsl::error() << "failed to send, ioctl not properly initialized\n";
                return false;
            }

            auto const req32{bsl::to_u32(req)};
            if (bsl::unlikely(!req32)) {
                bsl::error() << "invalid request: " << bsl::hex(req) << bsl::endl << bsl::here();
                return false;
            }

            DWORD bytes{};
            auto const ret{
                DeviceIoControl(m_hndl, req32.get(), nullptr, 0, nullptr, 0, &bytes, nullptr)};

            if (bsl::unlikely(!ret)) {
                bsl::error() << "DeviceIoControl failed\n";
                return false;
            }

            return true;
        }

        /// <!-- description -->
        ///   @brief Reads data from the device driver
        ///
        /// <!-- inputs/outputs -->
        ///   @param req the request
        ///   @param data a pointer to read data to
        ///   @param size the size of the buffer being read to
        ///   @return Returns true if the IOCTL succeeded, false otherwise.
        ///
        [[nodiscard]] constexpr auto
        read_data(bsl::safe_uintmax const &req, void *const data, bsl::safe_uintmax const &size)
            const noexcept -> bool
        {
            if (bsl::unlikely(nullptr == m_hndl)) {
                bsl::error() << "failed to read, ioctl not properly initialized\n";
                return false;
            }

            auto const req32{bsl::to_u32(req)};
            if (bsl::unlikely(!req32)) {
                bsl::error() << "invalid request: " << bsl::hex(req) << bsl::endl << bsl::here();
                return false;
            }

            if (bsl::unlikely(nullptr == data)) {
                bsl::error() << "invalid data: " << data << bsl::endl << bsl::here();
                return false;
            }

            auto const size32{bsl::to_u32(size)};
            if (bsl::unlikely(!size32)) {
                bsl::error() << "invalid size: " << bsl::hex(size) << bsl::endl << bsl::here();
                return false;
            }

            DWORD bytes{};
            auto const ret{DeviceIoControl(
                m_hndl, req32.get(), nullptr, 0, data, size32.get(), &bytes, nullptr)};

            if (bsl::unlikely(!ret)) {
                bsl::error() << "DeviceIoControl failed\n";
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
        write_data(
            bsl::safe_uintmax const &req,
            void const *const data,
            bsl::safe_uintmax const &size) const noexcept -> bool
        {
            void *const ptr{const_cast<void *>(data)};

            if (bsl::unlikely(nullptr == m_hndl)) {
                bsl::error() << "failed to write, ioctl not properly initialized\n";
                return false;
            }

            auto const req32{bsl::to_u32(req)};
            if (bsl::unlikely(!req32)) {
                bsl::error() << "invalid request: " << bsl::hex(req) << bsl::endl << bsl::here();
                return false;
            }

            if (bsl::unlikely(nullptr == data)) {
                bsl::error() << "invalid data: " << data << bsl::endl << bsl::here();
                return false;
            }

            auto const size32{bsl::to_u32(size)};
            if (bsl::unlikely(!size32)) {
                bsl::error() << "invalid size: " << bsl::hex(size) << bsl::endl << bsl::here();
                return false;
            }

            DWORD bytes{};
            auto const ret{DeviceIoControl(
                m_hndl, req32.get(), ptr, size32.get(), nullptr, 0, &bytes, nullptr)};

            if (bsl::unlikely(!ret)) {
                bsl::error() << "DeviceIoControl failed\n";
                return false;
            }

            return true;
        }

        /// <!-- description -->
        ///   @brief Reads/writes data from/to the device driver
        ///
        /// <!-- inputs/outputs -->
        ///   @param req the request
        ///   @param data a pointer to read/write data to/from
        ///   @param size the size of the buffer being read/written to/from
        ///   @return Returns true if the IOCTL succeeded, false otherwise.
        ///
        [[nodiscard]] constexpr auto
        read_write_data(
            bsl::safe_uintmax const &req,
            void *const data,
            bsl::safe_uintmax const &size) const noexcept -> bool
        {
            if (bsl::unlikely(nullptr == m_hndl)) {
                bsl::error() << "failed to read/write, ioctl not properly initialized\n";
                return false;
            }

            auto const req32{bsl::to_u32(req)};
            if (bsl::unlikely(!req32)) {
                bsl::error() << "invalid request: " << bsl::hex(req) << bsl::endl << bsl::here();
                return false;
            }

            if (bsl::unlikely(nullptr == data)) {
                bsl::error() << "invalid data: " << data << bsl::endl << bsl::here();
                return false;
            }

            auto const size32{bsl::to_u32(size)};
            if (bsl::unlikely(!size32)) {
                bsl::error() << "invalid size: " << bsl::hex(size) << bsl::endl << bsl::here();
                return false;
            }

            DWORD bytes{};
            auto const ret{DeviceIoControl(
                m_hndl, req32.get(), data, size32.get(), data, size32.get(), &bytes, nullptr)};

            if (bsl::unlikely(!ret)) {
                bsl::error() << "DeviceIoControl failed\n";
                return false;
            }

            return true;
        }
    };
}

#endif
