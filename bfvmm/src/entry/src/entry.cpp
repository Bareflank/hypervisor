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

#include <entry/entry.h>
#include <guard_exceptions.h>
#include <vcpu/vcpu_manager.h>

extern "C" int64_t
start_vmm(uint64_t arg) noexcept
{
    return guard_exceptions(ENTRY_ERROR_VMM_START_FAILED, [&]()
    {
        g_vcm->create_vcpu(arg);

        auto ___ = gsl::on_failure([&]
        { g_vcm->delete_vcpu(arg); });

        g_vcm->run_vcpu(arg);

        return ENTRY_SUCCESS;
    });
}

extern "C" int64_t
stop_vmm(uint64_t arg) noexcept
{
    return guard_exceptions(ENTRY_ERROR_VMM_STOP_FAILED, [&]()
    {
        g_vcm->hlt_vcpu(arg);
        g_vcm->delete_vcpu(arg);

        return ENTRY_SUCCESS;
    });
}
