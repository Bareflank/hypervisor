//
// Bareflank Hypervisor
// Copyright (C) 2015 Assured Information Security, Inc.
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

#ifndef TEST_SUPPORT_H
#define TEST_SUPPORT_H

#include <catch/catch.hpp>
#include <hippomocks.h>

#include <bftypes.h>
#include <bfvcpuid.h>
#include <bfelf_loader.h>
#include <bfdriverinterface.h>

#include <ioctl.h>
#include <ioctl_driver.h>
#include <command_line_parser.h>

ioctl::ioctl() :
    m_d{nullptr}
{ }

void
ioctl::open()
{ }

void
ioctl::call_ioctl_add_module(const binary_data &module_data)
{
    bfignored(module_data);
}

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
{
    bfignored(drr);
    bfignored(vcpuid);
}

void
ioctl::call_ioctl_vmm_status(gsl::not_null<status_pointer> status)
{
    bfignored(status);
}

TEST_CASE("support")
{
    ioctl ctl{};
    int64_t status;
    auto drr = ioctl::drr_type{};
    auto data = ioctl::binary_data{};

    CHECK_NOTHROW(ctl.call_ioctl_add_module(data));
    CHECK_NOTHROW(ctl.call_ioctl_load_vmm());
    CHECK_NOTHROW(ctl.call_ioctl_unload_vmm());
    CHECK_NOTHROW(ctl.call_ioctl_start_vmm());
    CHECK_NOTHROW(ctl.call_ioctl_stop_vmm());
    CHECK_NOTHROW(ctl.call_ioctl_dump_vmm(&drr, 0));
    CHECK_NOTHROW(ctl.call_ioctl_vmm_status(&status));
}

#endif
