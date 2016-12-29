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

#include <ioctl.h>

// -----------------------------------------------------------------------------
// Unit Test Seems
// -----------------------------------------------------------------------------

int
__attribute__((weak)) bf_ioctl_open()
{ return 0; }

int64_t
__attribute__((weak)) bf_send_ioctl(int fd, unsigned long request)
{
    (void) fd;
    (void) request;

    return 0;
}

int64_t
__attribute__((weak)) bf_read_ioctl(int fd, unsigned long request, void *data)
{
    (void) fd;
    (void) request;
    (void) data;

    return 0;
}

int64_t
__attribute__((weak)) bf_write_ioctl(int fd, unsigned long request, const void *data)
{
    (void) fd;
    (void) request;
    (void) data;

    return 0;
}

// -----------------------------------------------------------------------------
// Unit Test Seems
// -----------------------------------------------------------------------------

ioctl::ioctl()
{ }

void
ioctl::open()
{ }

void
ioctl::call_ioctl_add_module(const binary_data &module_data)
{ (void) module_data; }

void
ioctl::call_ioctl_load_vmm()
{ }

void
ioctl::call_ioctl_unload_vmm()
{ }

void
ioctl::call_ioctl_start_vmm()
{ }

void
ioctl::call_ioctl_stop_vmm()
{ }

void
ioctl::call_ioctl_dump_vmm(gsl::not_null<drr_pointer> drr, vcpuid_type vcpuid)
{ (void) drr; (void) vcpuid; }

void
ioctl::call_ioctl_vmm_status(gsl::not_null<status_pointer> status)
{ (void) status; }

void
ioctl::call_ioctl_vmcall(gsl::not_null<registers_pointer> regs, cpuid_type cpuid)
{ (void) regs; (void) cpuid; }
