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

// TIDY_EXCLUSION=-cppcoreguidelines-pro-type-reinterpret-cast
//
// Reason:
//     Although in general this is a good rule, for hypervisor level code that
//     interfaces with the kernel, and raw hardware, this rule is
//     impractical.
//

#include <bfgsl.h>
#include <bfdebug.h>
#include <bfvcpuid.h>
#include <bfobject.h>
#include <bfexports.h>
#include <bfsupport.h>
#include <bfexception.h>
#include <bftypes.h>
#include <bfcallonce.h>

#include <vcpu/vcpu_manager.h>
#include <debug/debug_ring/debug_ring.h>
#include <memory_manager/memory_manager.h>

#include "entry/entry.h"
#include "bfvmm.h"

static bfn::once_flag g_init_flag;

extern "C" int64_t
private_init(void)
{ return ENTRY_SUCCESS; }

extern "C" int64_t
private_fini(void)
{ return ENTRY_SUCCESS; }

extern "C" int64_t
private_add_md(struct memory_descriptor *md) noexcept
{
    return guard_exceptions(MEMORY_MANAGER_FAILURE, [&] {

        auto virt = static_cast<bfvmm::memory_manager::integer_pointer>(md->virt);
        auto phys = static_cast<bfvmm::memory_manager::integer_pointer>(md->phys);
        auto type = static_cast<bfvmm::memory_manager::attr_type>(md->type);

        g_mm->add_md(virt, phys, type);
    });
}

extern "C" int64_t
private_set_rsdp(uintptr_t rsdp) noexcept
{
    g_rsdp = rsdp;
    return ENTRY_SUCCESS;
}

bool
WEAK_SYM vmm_init()
{ return true; }

bool
WEAK_SYM vmm_main(vcpu_t vcpu)
{ bfignored(vcpu); return true; }

bool
WEAK_SYM vmm_fini(vcpu_t vcpu)
{ bfignored(vcpu); return true; }

extern "C" int64_t
private_fini_vmm(uint64_t arg) noexcept
{
    return guard_exceptions(ENTRY_ERROR_VMM_STOP_FAILED, [&]() {
        g_vcm->hlt(arg);
        g_vcm->destroy(arg);

        return ENTRY_SUCCESS;
    });
}

extern "C" bool
private_init_vmm(uint64_t arg) noexcept
{
    return guard_exceptions(ENTRY_ERROR_VMM_START_FAILED, [&]() {

        bfn::call_once(g_init_flag, vmm_init);

        g_vcm->create(arg, nullptr);

        auto ___ = gsl::on_failure([&]
        { g_vcm->destroy(arg); });

        g_vcm->run(arg, nullptr);

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
            return private_init();

        case BF_REQUEST_FINI:
            return private_fini();

        case BF_REQUEST_ADD_MDL:
            return private_add_md(reinterpret_cast<memory_descriptor *>(arg1));

        case BF_REQUEST_SET_RSDP:
            return private_set_rsdp(arg1);

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
