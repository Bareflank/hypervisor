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

int64_t
bf_ioctl_open()
{
    return 5;
}

int64_t
bf_send_ioctl(int64_t fd, unsigned long request)
{
    (void)fd;
    (void)request;

    return 0;
}

int64_t
bf_read_ioctl(int64_t fd, unsigned long request, void *data)
{
    (void)fd;
    (void)request;
    (void)data;

    return 0;
}

int64_t
bf_write_ioctl(int64_t fd, unsigned long request, const void *data)
{
    (void)fd;
    (void)request;
    (void)data;

    return 0;
}

// -----------------------------------------------------------------------------
// Implementation
// -----------------------------------------------------------------------------

ioctl_private::ioctl_private()
{
}

ioctl_private::~ioctl_private()
{
    IOServiceClose(m_connect);
}

void ioctl_private::ioctl_write(bf_ioctl_t *in, bf_ioctl_t *out)
{
    size_t inStructSize = sizeof(bf_ioctl_t);
    size_t outStructSize = sizeof(bf_ioctl_t);

    // Send the message to the kernel.
    IOConnectCallStructMethod(m_connect, 1, in, inStructSize, out, &outStructSize);
}

void ioctl_private::ioctl_read(bf_ioctl_t *in, bf_ioctl_t *out)
{
    size_t inStructSize = sizeof(bf_ioctl_t);
    size_t outStructSize = sizeof(bf_ioctl_t);

    // Send the message to the kernel.
    IOConnectCallStructMethod(m_connect, 1, in, inStructSize, out, &outStructSize);
}
#include <iostream>
void
ioctl_private::open()
{
    io_iterator_t iterator;
    io_service_t service;
    kern_return_t kernResult = IOServiceGetMatchingServices(kIOMasterPortDefault, IOServiceMatching("org_bareflank_osx"), &iterator);

    // Make sure the service was located.
    if (kernResult != KERN_SUCCESS)
    {
        throw unknown_command("IOServiceGetMatchingServices failed.\n");
    }

    // Get the service from the criteria listed above.
    if ((service = IOIteratorNext(iterator)) != IO_OBJECT_NULL)
    {

        // Now that the service is located, setup a connection to that service.
        kernResult = IOServiceOpen(service, mach_task_self(), 0, &m_connect);

        // Make sure a connection was made.
        if (kernResult != KERN_SUCCESS)
        {

            throw unknown_command("Unabled to get handle to the driver.\n");
        }
    }
}

int64_t
ioctl_private::bf_write_ioctl(int fd, uint32_t cmd, void *arg)
{
    (void)fd;

    bf_ioctl_t in = { 0, 0, 0 };
    bf_ioctl_t out = { 0, 0, 0 };

    in.command = cmd;
    in.addr = arg;
    in.size = 0;

    ioctl_write(&in, &out);

    return out.command;
}

int64_t
ioctl_private::bf_read_ioctl(int fd, uint32_t cmd, void *arg)
{
    (void)fd;

    bf_ioctl_t in = { 0, 0, 0 };
    bf_ioctl_t out = { 0, 0, 0 };

    in.command = cmd;
    in.addr = arg;
    in.size = 0;

    ioctl_write(&in, &out);

    return out.command;
}

int64_t
ioctl_private::bf_send_ioctl(int fd, uint32_t cmd)
{
    (void)fd;

    bf_ioctl_t in = { 0, 0, 0 };
    bf_ioctl_t out = { 0, 0, 0 };

    in.command = cmd;
    in.addr = 0;
    in.size = 0;

    ioctl_write(&in, &out);

    return out.command;
}


void
ioctl_private::call_ioctl_add_module_length(int64_t len)
{
    int fd = 0;

    if (len <= 0)
        throw unknown_command("len <= 0");

    if (bf_write_ioctl(fd, IOCTL_ADD_MODULE_LENGTH, &len) < 0)
        throw ioctl_failed(IOCTL_ADD_MODULE_LENGTH);
}

void
ioctl_private::call_ioctl_add_module(const char *data)
{
    int fd = 0;

    if (data == nullptr)
        throw unknown_command("data == NULL");

    if (bf_write_ioctl(fd, IOCTL_ADD_MODULE, (void *)data) < 0)
        throw ioctl_failed(IOCTL_ADD_MODULE);
}

void
ioctl_private::call_ioctl_load_vmm()
{
    int fd = 0;

    if (bf_send_ioctl(fd, IOCTL_LOAD_VMM) < 0)
        throw ioctl_failed(IOCTL_LOAD_VMM);
}

void
ioctl_private::call_ioctl_unload_vmm()
{
    int fd = 0;

    if (bf_send_ioctl(fd, IOCTL_UNLOAD_VMM) < 0)
        throw ioctl_failed(IOCTL_UNLOAD_VMM);
}

void
ioctl_private::call_ioctl_start_vmm()
{
    int fd = 0;

    if (bf_send_ioctl(fd, IOCTL_START_VMM) < 0)
        throw ioctl_failed(IOCTL_START_VMM);
}

void
ioctl_private::call_ioctl_stop_vmm()
{
    int fd = 0;

    if (bf_send_ioctl(fd, IOCTL_STOP_VMM) < 0)
        throw ioctl_failed(IOCTL_STOP_VMM);
}

void
ioctl_private::call_ioctl_dump_vmm(debug_ring_resources_t *drr)
{
    int fd = 0;

    if (drr == nullptr)
        throw unknown_command("drr == NULL");

    if (bf_read_ioctl(fd, IOCTL_DUMP_VMM, drr) < 0)
        throw ioctl_failed(IOCTL_DUMP_VMM);
}

void
ioctl_private::call_ioctl_vmm_status(int64_t *status)
{
    int fd = 0;

    if (status == nullptr)
        throw unknown_command("status == NULL");

    if (bf_read_ioctl(fd, IOCTL_VMM_STATUS, status) < 0)
        throw ioctl_failed(IOCTL_VMM_STATUS);
}
