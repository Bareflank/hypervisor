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

#ifndef BSL_DETAILS_IOCTL_WINDOWS_HPP
#define BSL_DETAILS_IOCTL_WINDOWS_HPP

#include "../../../debug.hpp"
#include "../../../move.hpp"
#include "../../../safe_integral.hpp"
#include "../../../swap.hpp"

#include <SetupAPI.h>
#include <Windows.h>
#undef max
#undef min

namespace bsl
{
    /// @class bsl::ioctl
    ///
    /// <!-- description -->
    ///   @brief Executes IOCTL commands to a driver.
    ///
    class ioctl final
    {
        /// @brief stores a handle to the device driver.
        HANDLE m_hndl{};

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
        ///   @param name the name of the device driver to IOCTL.
        ///
        template<typename GUID>
        explicit ioctl(GUID name) noexcept
        {
            BOOL ret{};
            DWORD size{};
            HANDLE info{};
            SP_INTERFACE_DEVICE_DETAIL_DATA *dev_data{};

            SP_DEVINFO_DATA dev_info{};
            dev_info.cbSize = sizeof(SP_DEVINFO_DATA);

            SP_INTERFACE_DEVICE_DATA if_info{};
            if_info.cbSize = sizeof(SP_INTERFACE_DEVICE_DATA);

            info = SetupDiGetClassDevs(&name, 0, 0, DIGCF_DEVICEINTERFACE | DIGCF_PRESENT);
            if (INVALID_HANDLE_VALUE == info) {
                bsl::error() << "SetupDiGetClassDevs failed\n";
                return;
            }

            ret = SetupDiEnumDeviceInfo(info, 0, &dev_info);
            if (ret == FALSE) {
                bsl::error() << "SetupDiEnumDeviceInfo failed\n";
                bsl::discard(CloseHandle(info));
                return;
            }

            ret = SetupDiEnumDeviceInterfaces(info, &dev_info, &(name), 0, &if_info);
            if (ret == FALSE) {
                bsl::error() << "SetupDiEnumDeviceInterfaces failed\n";
                bsl::discard(CloseHandle(info));
                return;
            }

            ret = SetupDiGetDeviceInterfaceDetail(info, &if_info, nullptr, 0, &size, nullptr);
            if (ret == FALSE) {
                bsl::error() << "SetupDiGetDeviceInterfaceDetail failed\n";
                bsl::discard(CloseHandle(info));
                return;
            }

            dev_data = static_cast<SP_INTERFACE_DEVICE_DETAIL_DATA *>(malloc(size));
            if (nullptr == dev_data) {
                bsl::error() << "malloc failed in ioctl\n";
                bsl::discard(CloseHandle(info));
                return;
            }

            dev_data->cbSize = sizeof(SP_INTERFACE_DEVICE_DETAIL_DATA);

            ret = SetupDiGetDeviceInterfaceDetail(info, &if_info, dev_data, size, nullptr, nullptr);
            if (ret == FALSE) {
                bsl::error() << "SetupDiGetDeviceInterfaceDetail failed\n";
                free(dev_data);
                bsl::discard(CloseHandle(info));
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

            free(dev_data);
            bsl::discard(CloseHandle(info));

            if (nullptr == m_hndl) {
                bsl::error() << "ioctl CreateFile failed\n";
                return;
            }
        }

        /// <!-- description -->
        ///   @brief Destructor
        ///
        ~ioctl() noexcept
        {
            if (nullptr != m_hndl) {
                bsl::discard(CloseHandle(m_hndl));
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
            o.m_hndl = nullptr;
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
            if (nullptr == m_hndl) {
                bsl::error() << "failed to send, ioctl not properly initialized\n";
                return false;
            }

            DWORD bytes{};
            if (!DeviceIoControl(m_hndl, req.get(), nullptr, 0, nullptr, 0, &bytes, nullptr)) {
                bsl::error() << "DeviceIoControl failed\n";
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
        read(bsl::safe_integral<REQUEST> const &req, void *const data, safe_uintmax const &size)
            const noexcept -> bool
        {
            if (nullptr == m_hndl) {
                bsl::error() << "failed to read, ioctl not properly initialized\n";
                return false;
            }

            DWORD bytes{};
            if (!DeviceIoControl(m_hndl, req.get(), nullptr, 0, data, size, &bytes, nullptr)) {
                bsl::error() << "DeviceIoControl failed\n";
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
            safe_uintmax const &size) const noexcept -> bool
        {
            void *const ptr{const_cast<void *>(data)};
            ;

            if (nullptr == m_hndl) {
                bsl::error() << "failed to write, ioctl not properly initialized\n";
                return false;
            }

            DWORD bytes{};
            if (!DeviceIoControl(m_hndl, req.get(), ptr, size, nullptr, 0, &bytes, nullptr)) {
                bsl::error() << "DeviceIoControl failed\n";
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
            safe_uintmax const &size) const noexcept -> bool
        {
            if (nullptr == m_hndl) {
                bsl::error() << "failed to read/write, ioctl not properly initialized\n";
                return false;
            }

            DWORD bytes{};
            if (!DeviceIoControl(m_hndl, req.get(), data, size, data, size, &bytes, nullptr)) {
                bsl::error() << "DeviceIoControl failed\n";
                return false;
            }

            return true;
        }
    };
}

#endif
