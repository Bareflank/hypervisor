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

#include <bfgsl.h>
#include <bfdebug.h>
#include <bfvcpuid.h>
#include <bfexports.h>
#include <bfsupport.h>
#include <bfexception.h>

#include <user_data.h>

#include <vcpu/vcpu_manager.h>
#include <debug_ring/debug_ring.h>
#include <memory_manager/memory_manager_x64.h>

extern "C" int64_t
private_add_md(struct memory_descriptor *md) noexcept
{
    return guard_exceptions(MEMORY_MANAGER_FAILURE, [&] {

        auto &&virt = static_cast<memory_manager_x64::integer_pointer>(md->virt);
        auto &&phys = static_cast<memory_manager_x64::integer_pointer>(md->phys);
        auto &&type = static_cast<memory_manager_x64::attr_type>(md->type);

        g_mm->add_md(virt, phys, type);
    });
}

user_data *
WEAK_SYM pre_create_vcpu(vcpuid::type id)
{ (void) id; return nullptr; }

user_data *
WEAK_SYM pre_run_vcpu(vcpuid::type id)
{ (void) id; return nullptr; }

extern "C" int64_t
private_init_vmm(uint64_t arg) noexcept
{
    return guard_exceptions(ENTRY_ERROR_VMM_START_FAILED, [&]() {

        g_vcm->create_vcpu(arg, pre_create_vcpu(arg));

        auto ___ = gsl::on_failure([&]
        { g_vcm->delete_vcpu(arg); });

        g_vcm->run_vcpu(arg, pre_run_vcpu(arg));

        return ENTRY_SUCCESS;
    });
}

user_data *
WEAK_SYM pre_hlt_vcpu(vcpuid::type id)
{ (void) id; return nullptr; }

user_data *
WEAK_SYM pre_delete_vcpu(vcpuid::type id)
{ (void) id; return nullptr; }

extern "C" int64_t
private_fini_vmm(uint64_t arg) noexcept
{
    return guard_exceptions(ENTRY_ERROR_VMM_STOP_FAILED, [&]() {

        g_vcm->hlt_vcpu(arg, pre_hlt_vcpu(arg));
        g_vcm->delete_vcpu(arg, pre_delete_vcpu(arg));

        return ENTRY_SUCCESS;
    });
}

extern "C" int64_t
bfmain(uintptr_t request, uintptr_t arg1, uintptr_t arg2, uintptr_t arg3)
{
    bfignored(arg2);
    bfignored(arg3);

    switch (request) {
        case BF_REQUEST_INIT:
        case BF_REQUEST_FINI:
            return ENTRY_SUCCESS;

        case BF_REQUEST_ADD_MDL:
            return private_add_md(reinterpret_cast<memory_descriptor *>(arg1));

        case BF_REQUEST_GET_DRR:
            return get_drr(arg1, reinterpret_cast<debug_ring_resources_t **>(arg2));

        case BF_REQUEST_VMM_INIT:
            return private_init_vmm(arg1);

        case BF_REQUEST_VMM_FINI:
            return private_fini_vmm(arg1);

        default:
            break;
    }

    return ENTRY_ERROR_UNKNOWN;
}
