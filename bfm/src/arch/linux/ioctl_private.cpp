//
// Bareflank Hypervisor
//
// Copyright (C) 2015 Assured Information Security, Inc.
// Author: Rian Quinn        <quinnr@ainfosec.com>
// Author: Brendan Kerrigan  <kerriganb@ainfosec.com>
//
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 2.1 of the License, or (at your option) any later version.
//
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
// Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public
// License along with this library; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA

#include <exception.h>
#include <ioctl_private.h>
#include <driver_entry_interface.h>

#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>

// -----------------------------------------------------------------------------
// Unit Test Seems
// -----------------------------------------------------------------------------

int
__attribute__((weak)) bf_ioctl_open()
{
    return open("/dev/bareflank", O_RDWR);
}

int64_t
__attribute__((weak)) bf_send_ioctl(int fd, unsigned long request)
{
    return ioctl(fd, request);
}

int64_t
__attribute__((weak)) bf_read_ioctl(int fd, unsigned long request, void *data)
{
    return ioctl(fd, request, data);
}

int64_t
__attribute__((weak)) bf_write_ioctl(int fd, unsigned long request, const void *data)
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
    if (fd >= 0)
        close(fd);
}

void
ioctl_private::open()
{
    if ((fd = bf_ioctl_open()) < 0)
        throw driver_inaccessible();
}

void
ioctl_private::call_ioctl_add_module_length(module_len_type len)
{
    expects(len > 0);

    if (bf_write_ioctl(fd, IOCTL_ADD_MODULE_LENGTH, &len) < 0)
        throw ioctl_failed(IOCTL_ADD_MODULE_LENGTH);
}

void
ioctl_private::call_ioctl_add_module(gsl::not_null<module_data_type> data)
{
    if (bf_write_ioctl(fd, IOCTL_ADD_MODULE, data) < 0)
        throw ioctl_failed(IOCTL_ADD_MODULE);
}

void
ioctl_private::call_ioctl_load_vmm()
{
    if (bf_send_ioctl(fd, IOCTL_LOAD_VMM) < 0)
        throw ioctl_failed(IOCTL_LOAD_VMM);
}

void
ioctl_private::call_ioctl_unload_vmm()
{
    if (bf_send_ioctl(fd, IOCTL_UNLOAD_VMM) < 0)
        throw ioctl_failed(IOCTL_UNLOAD_VMM);
}

void
ioctl_private::call_ioctl_start_vmm()
{
    if (bf_send_ioctl(fd, IOCTL_START_VMM) < 0)
        throw ioctl_failed(IOCTL_START_VMM);
}

void
ioctl_private::call_ioctl_stop_vmm()
{
    if (bf_send_ioctl(fd, IOCTL_STOP_VMM) < 0)
        throw ioctl_failed(IOCTL_STOP_VMM);
}

void
ioctl_private::call_ioctl_dump_vmm(gsl::not_null<drr_pointer> drr, vcpuid_type vcpuid)
{
    if (bf_write_ioctl(fd, IOCTL_SET_VCPUID, &vcpuid) < 0)
        throw ioctl_failed(IOCTL_SET_VCPUID);

    if (bf_read_ioctl(fd, IOCTL_DUMP_VMM, drr) < 0)
        throw ioctl_failed(IOCTL_DUMP_VMM);
}

void
ioctl_private::call_ioctl_vmm_status(gsl::not_null<status_pointer> status)
{
    if (bf_read_ioctl(fd, IOCTL_VMM_STATUS, status) < 0)
        throw ioctl_failed(IOCTL_VMM_STATUS);
}

void
ioctl_private::call_ioctl_vmcall(gsl::not_null<registers_pointer> regs, cpuid_type cpuid)
{
    if (bf_write_ioctl(fd, IOCTL_SET_CPUID, &cpuid) < 0)
        throw ioctl_failed(IOCTL_SET_CPUID);

    if (bf_write_ioctl(fd, IOCTL_VMCALL, regs) < 0)
        throw ioctl_failed(IOCTL_VMCALL);
}
