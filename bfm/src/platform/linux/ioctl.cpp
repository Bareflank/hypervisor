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

#include <ioctl.h>
#include <ioctl_private.h>

ioctl::ioctl() :
    m_d {std::make_unique<ioctl_private>()}
{ }

void
ioctl::open()
{
    auto d = static_cast<ioctl_private *>(m_d.get());
    d->open();
}

void
ioctl::call_ioctl_add_module(const binary_data &module_data)
{
    auto d = static_cast<ioctl_private *>(m_d.get());
    d->call_ioctl_add_module_length(module_data.size());
    d->call_ioctl_add_module(module_data.data());
}

void
ioctl::call_ioctl_load_vmm()
{
    auto d = static_cast<ioctl_private *>(m_d.get());
    d->call_ioctl_load_vmm();
}

void
ioctl::call_ioctl_unload_vmm()
{
    auto d = static_cast<ioctl_private *>(m_d.get());
    d->call_ioctl_unload_vmm();
}

void
ioctl::call_ioctl_start_vmm()
{
    auto d = static_cast<ioctl_private *>(m_d.get());
    d->call_ioctl_start_vmm();
}

void
ioctl::call_ioctl_stop_vmm()
{
    auto d = static_cast<ioctl_private *>(m_d.get());
    d->call_ioctl_stop_vmm();
}

void
ioctl::call_ioctl_dump_vmm(gsl::not_null<drr_pointer> drr, vcpuid_type vcpuid)
{
    auto d = static_cast<ioctl_private *>(m_d.get());
    d->call_ioctl_dump_vmm(drr, vcpuid);
}

void
ioctl::call_ioctl_vmm_status(gsl::not_null<status_pointer> status)
{
    auto d = static_cast<ioctl_private *>(m_d.get());
    d->call_ioctl_vmm_status(status);
}
