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

#include <gsl/gsl>

#include <debug.h>
#include <vcpuid.h>
#include <user_data.h>

#include <entry/entry.h>
#include <guard_exceptions.h>
#include <vcpu/vcpu_manager.h>

user_data *
__attribute__((weak)) pre_create_vcpu(vcpuid::type id)
{ (void) id; return nullptr; }

user_data *
__attribute__((weak)) pre_run_vcpu(vcpuid::type id)
{ (void) id; return nullptr; }

extern "C" int64_t
start_vmm(uint64_t arg) noexcept
{
    return guard_exceptions(ENTRY_ERROR_VMM_START_FAILED, [&]()
    {
        g_vcm->create_vcpu(arg, pre_create_vcpu(arg));

        auto ___ = gsl::on_failure([&]
        { g_vcm->delete_vcpu(arg); });

        g_vcm->run_vcpu(arg, pre_run_vcpu(arg));

        bfdebug << "success: host os is " << bfcolor_green "now " << bfcolor_end
                << "in a vm on vcpuid = " << arg << bfendl;

        return ENTRY_SUCCESS;
    });
}

user_data *
__attribute__((weak)) pre_hlt_vcpu(vcpuid::type id)
{ (void) id; return nullptr; }

user_data *
__attribute__((weak)) pre_delete_vcpu(vcpuid::type id)
{ (void) id; return nullptr; }

extern "C" int64_t
stop_vmm(uint64_t arg) noexcept
{
    return guard_exceptions(ENTRY_ERROR_VMM_STOP_FAILED, [&]()
    {
        g_vcm->hlt_vcpu(arg, pre_hlt_vcpu(arg));
        g_vcm->delete_vcpu(arg, pre_delete_vcpu(arg));

        bfdebug << "success: host os is " << bfcolor_red "not " << bfcolor_end
                << "in a vm on vcpuid = " << arg << bfendl;

        return ENTRY_SUCCESS;
    });
}
