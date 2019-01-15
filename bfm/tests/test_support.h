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
