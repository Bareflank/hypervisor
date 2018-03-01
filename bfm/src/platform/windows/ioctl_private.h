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

#ifndef IOCTL_PRIVATE_H
#define IOCTL_PRIVATE_H

#include <ioctl.h>
#include <windows.h>

#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable : 4251)
#endif

// -----------------------------------------------------------------------------
// Definitions
// -----------------------------------------------------------------------------

class ioctl_private : public ioctl_private_base
{
public:

    using module_len_type = size_t;
    using module_data_type = const char *;
    using drr_pointer = ioctl::drr_pointer;
    using vcpuid_type = ioctl::vcpuid_type;
    using status_pointer = ioctl::status_pointer;
    using handle_type = int;

    ioctl_private();
    ~ioctl_private() override;

    virtual void open();
    virtual void call_ioctl_add_module(gsl::not_null<module_data_type> data, module_len_type len);
    virtual void call_ioctl_load_vmm();
    virtual void call_ioctl_unload_vmm();
    virtual void call_ioctl_start_vmm();
    virtual void call_ioctl_stop_vmm();
    virtual void call_ioctl_dump_vmm(gsl::not_null<drr_pointer> drr, vcpuid_type vcpuid);
    virtual void call_ioctl_vmm_status(gsl::not_null<status_pointer> status);

private:
    HANDLE fd;
};

#ifdef _MSC_VER
#pragma warning(pop)
#endif

#endif
