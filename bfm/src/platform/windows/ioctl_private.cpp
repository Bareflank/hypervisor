//
// Copyright (C) 2019 Assured Information Security, Inc.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

#include <ioctl_private.h>

#include <bfgsl.h>
#include <bfdriverinterface.h>

#include <SetupAPI.h>

// -----------------------------------------------------------------------------
// Unit Test Seems
// -----------------------------------------------------------------------------

HANDLE
bfm_ioctl_open()
{
    HANDLE hDevInfo;
    SP_INTERFACE_DEVICE_DETAIL_DATA *deviceDetailData = nullptr;

    SP_DEVINFO_DATA devInfo;
    devInfo.cbSize = sizeof(SP_DEVINFO_DATA);

    SP_INTERFACE_DEVICE_DATA ifInfo;
    ifInfo.cbSize = sizeof(SP_INTERFACE_DEVICE_DATA);

    hDevInfo = SetupDiGetClassDevs(&GUID_DEVINTERFACE_bareflank, 0, 0, DIGCF_DEVICEINTERFACE | DIGCF_PRESENT);
    if (hDevInfo == INVALID_HANDLE_VALUE) {
        return hDevInfo;
    }

    if (SetupDiEnumDeviceInfo(hDevInfo, 0, &devInfo) == false) {
        return INVALID_HANDLE_VALUE;
    }

    if (SetupDiEnumDeviceInterfaces(hDevInfo, &devInfo, &(GUID_DEVINTERFACE_bareflank), 0, &ifInfo) == false) {
        return INVALID_HANDLE_VALUE;
    }

    DWORD requiredSize = 0;

    if (SetupDiGetDeviceInterfaceDetail(hDevInfo, &ifInfo, NULL, 0, &requiredSize, NULL) == TRUE) {
        return INVALID_HANDLE_VALUE;
    }

    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
        return INVALID_HANDLE_VALUE;
    }

    deviceDetailData = static_cast<SP_INTERFACE_DEVICE_DETAIL_DATA *>(malloc(requiredSize));

    if (deviceDetailData == nullptr) {
        return INVALID_HANDLE_VALUE;
    }

    auto ___ = gsl::finally([&]
    { free(deviceDetailData); });

    deviceDetailData->cbSize = sizeof(SP_INTERFACE_DEVICE_DETAIL_DATA);

    if (SetupDiGetDeviceInterfaceDetail(hDevInfo, &ifInfo, deviceDetailData, requiredSize, NULL, NULL) == false) {
        return INVALID_HANDLE_VALUE;
    }

    return CreateFile(deviceDetailData->DevicePath,
                      GENERIC_READ | GENERIC_WRITE,
                      0,
                      NULL,
                      CREATE_ALWAYS,
                      FILE_ATTRIBUTE_NORMAL,
                      NULL);
}

int64_t
bfm_send_ioctl(HANDLE fd, DWORD request)
{
    DWORD bytes = 0;
    if (!DeviceIoControl(fd, request, NULL, 0, NULL, 0, &bytes, NULL)) {
        return BF_IOCTL_FAILURE;
    }

    return 0;
}

int64_t
bfm_read_ioctl(HANDLE fd, DWORD request, void *data, DWORD size)
{
    DWORD bytes = 0;
    if (!DeviceIoControl(fd, request, NULL, 0, data, size, &bytes, NULL)) {
        return BF_IOCTL_FAILURE;
    }

    return 0;
}

int64_t
bfm_write_ioctl(HANDLE fd, DWORD request, const void *data, DWORD size)
{
    DWORD bytes = 0;
    if (!DeviceIoControl(fd, request, const_cast<void *>(data), size, NULL, 0, &bytes, NULL)) {
        return BF_IOCTL_FAILURE;
    }

    return 0;
}

int64_t
bfm_read_write_ioctl(HANDLE fd, DWORD request, void *data, DWORD size)
{
    DWORD bytes = 0;
    if (!DeviceIoControl(fd, request, data, size, data, size, &bytes, NULL)) {
        return BF_IOCTL_FAILURE;
    }

    return 0;
}

// -----------------------------------------------------------------------------
// Implementation
// -----------------------------------------------------------------------------

ioctl_private::ioctl_private() :
    fd(INVALID_HANDLE_VALUE)
{
}

ioctl_private::~ioctl_private()
{
    if (fd != INVALID_HANDLE_VALUE) {
        CloseHandle(fd);
    }
}

void
ioctl_private::open()
{
    if ((fd = bfm_ioctl_open()) == INVALID_HANDLE_VALUE) {
        throw std::runtime_error("failed to open to bfdriver");
    }
}

#ifdef __GNUC__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wconversion"
#pragma GCC diagnostic ignored "-Wsign-conversion"
#endif

void
ioctl_private::call_ioctl_add_module(gsl::not_null<module_data_type> data, module_len_type len)
{
    expects(len > 0);

    if (bfm_write_ioctl(fd, IOCTL_ADD_MODULE, data, gsl::narrow_cast<DWORD>(len)) == BF_IOCTL_FAILURE) {
        throw std::runtime_error("ioctl failed: IOCTL_ADD_MODULE");
    }
}

void
ioctl_private::call_ioctl_load_vmm()
{
    if (bfm_send_ioctl(fd, IOCTL_LOAD_VMM) == BF_IOCTL_FAILURE) {
        throw std::runtime_error("ioctl failed: IOCTL_LOAD_VMM");
    }
}

void
ioctl_private::call_ioctl_unload_vmm()
{
    if (bfm_send_ioctl(fd, IOCTL_UNLOAD_VMM) == BF_IOCTL_FAILURE) {
        throw std::runtime_error("ioctl failed: IOCTL_UNLOAD_VMM");
    }
}

void
ioctl_private::call_ioctl_start_vmm()
{
    if (bfm_send_ioctl(fd, IOCTL_START_VMM) == BF_IOCTL_FAILURE) {
        throw std::runtime_error("ioctl failed: IOCTL_START_VMM");
    }
}

void
ioctl_private::call_ioctl_stop_vmm()
{
    if (bfm_send_ioctl(fd, IOCTL_STOP_VMM) == BF_IOCTL_FAILURE) {
        throw std::runtime_error("ioctl failed: IOCTL_STOP_VMM");
    }
}

void
ioctl_private::call_ioctl_dump_vmm(gsl::not_null<drr_pointer> drr, vcpuid_type vcpuid)
{
    if (bfm_write_ioctl(fd, IOCTL_SET_VCPUID, &vcpuid, sizeof(vcpuid)) == BF_IOCTL_FAILURE) {
        throw std::runtime_error("ioctl failed: IOCTL_SET_VCPUID");
    }

    if (bfm_read_ioctl(fd, IOCTL_DUMP_VMM, drr, sizeof(*drr)) == BF_IOCTL_FAILURE) {
        throw std::runtime_error("ioctl failed: IOCTL_DUMP_VMM");
    }
}

void
ioctl_private::call_ioctl_vmm_status(gsl::not_null<status_pointer> status)
{
    if (bfm_read_ioctl(fd, IOCTL_VMM_STATUS, status, sizeof(*status)) == BF_IOCTL_FAILURE) {
        throw std::runtime_error("ioctl failed: IOCTL_VMM_STATUS");
    }
}

#ifdef __GNUC__
#pragma GCC diagnostic pop
#endif
