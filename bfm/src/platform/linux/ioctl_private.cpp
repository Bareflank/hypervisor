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

// TIDY_EXCLUSION=-cppcoreguidelines-pro-type-vararg
//
// Reason:
//    The Linux APIs require the use of var-args, so this test has to be
//    disabled.
//

#include <ioctl_private.h>

#include <bfgsl.h>
#include <bfdriverinterface.h>

#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>

// -----------------------------------------------------------------------------
// Unit Test Seems
// -----------------------------------------------------------------------------

int
bfm_ioctl_open()
{
    return open("/dev/bareflank", O_RDWR);
}

int64_t
bfm_send_ioctl(int fd, unsigned long request)
{
    return ioctl(fd, request);
}

int64_t
bfm_read_ioctl(int fd, unsigned long request, void *data)
{
    return ioctl(fd, request, data);
}

int64_t
bfm_write_ioctl(int fd, unsigned long request, const void *data)
{
    return ioctl(fd, request, data);
}

// -----------------------------------------------------------------------------
// Implementation
// -----------------------------------------------------------------------------

ioctl_private::ioctl_private() :
    fd(0)
{
}

ioctl_private::~ioctl_private()
{
    if (fd >= 0) {
        close(fd);
    }
}

void
ioctl_private::open()
{
    if ((fd = bfm_ioctl_open()) < 0) {
        throw std::runtime_error("failed to open to bfdriver");
    }
}

void
ioctl_private::call_ioctl_add_module_length(module_len_type len)
{
    expects(len > 0);

    if (bfm_write_ioctl(fd, IOCTL_ADD_MODULE_LENGTH, &len) < 0) {
        throw std::runtime_error("ioctl failed: IOCTL_ADD_MODULE_LENGTH");
    }
}

void
ioctl_private::call_ioctl_add_module(gsl::not_null<module_data_type> data)
{
    if (bfm_write_ioctl(fd, IOCTL_ADD_MODULE, data) < 0) {
        throw std::runtime_error("ioctl failed: IOCTL_ADD_MODULE");
    }
}

void
ioctl_private::call_ioctl_load_vmm()
{
    if (bfm_send_ioctl(fd, IOCTL_LOAD_VMM) < 0) {
        throw std::runtime_error("ioctl failed: IOCTL_LOAD_VMM");
    }
}

void
ioctl_private::call_ioctl_unload_vmm()
{
    if (bfm_send_ioctl(fd, IOCTL_UNLOAD_VMM) < 0) {
        throw std::runtime_error("ioctl failed: IOCTL_UNLOAD_VMM");
    }
}

void
ioctl_private::call_ioctl_start_vmm()
{
    if (bfm_send_ioctl(fd, IOCTL_START_VMM) < 0) {
        throw std::runtime_error("ioctl failed: IOCTL_START_VMM");
    }
}

void
ioctl_private::call_ioctl_stop_vmm()
{
    if (bfm_send_ioctl(fd, IOCTL_STOP_VMM) < 0) {
        throw std::runtime_error("ioctl failed: IOCTL_STOP_VMM");
    }
}

void
ioctl_private::call_ioctl_dump_vmm(gsl::not_null<drr_pointer> drr, vcpuid_type vcpuid)
{
    if (bfm_write_ioctl(fd, IOCTL_SET_VCPUID, &vcpuid) < 0) {
        throw std::runtime_error("ioctl failed: IOCTL_SET_VCPUID");
    }

    if (bfm_read_ioctl(fd, IOCTL_DUMP_VMM, drr) < 0) {
        throw std::runtime_error("ioctl failed: IOCTL_DUMP_VMM");
    }
}

void
ioctl_private::call_ioctl_vmm_status(gsl::not_null<status_pointer> status)
{
    if (bfm_read_ioctl(fd, IOCTL_VMM_STATUS, status) < 0) {
        throw std::runtime_error("ioctl failed: IOCTL_VMM_STATUS");
    }
}
