/*
 * Bareflank Hypervisor
 * Copyright (C) 2015 Assured Information Security, Inc.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <bfarch.h>
#include <bftypes.h>
#include <bfdebug.h>
#include <bfplatform.h>
#include <bfelf_loader.h>
#include <common.h>

#include <efi.h>
#include <efilib.h>
#include "MpService.h"

EFI_MP_SERVICES_PROTOCOL *g_mp_services = nullptr;

void _set_ne(void);

int64_t
platform_init(void)
{
    EFI_STATUS status;
    EFI_GUID gEfiMpServiceProtocolGuid = EFI_MP_SERVICES_PROTOCOL_GUID;

    status =
        gBS->LocateProtocol(
            &gEfiMpServiceProtocolGuid,
            nullptr,
            (VOID **)&g_mp_services
        );

    if (EFI_ERROR(status)) {
        BFALERT("locate_mp_services_protocol: LocateProtocol failed: %r\n", status);
        return -1;
    }

    _set_ne();
    return BF_SUCCESS;
}

void *
platform_alloc_rw(uint64_t len)
{
    EFI_STATUS status;
    EFI_PHYSICAL_ADDRESS addr = 0;

    if (len == 0) {
        BFALERT("platform_alloc_rw: invalid length\n");
        return (void *)addr;
    }

    status = gBS->AllocatePages(
        AllocateAnyPages, EfiRuntimeServicesData, (len / EFI_PAGE_SIZE) + 1, &addr
    );

    if (EFI_ERROR(status)) {
        BFALERT("platform_alloc_rw: AllocatePages failed: %lld\n", len);
    }

    return (void *)addr;
}

void *
platform_alloc_rwe(uint64_t len)
{
    EFI_STATUS status;
    EFI_PHYSICAL_ADDRESS addr = 0;

    if (len == 0) {
        BFALERT("platform_alloc_rw: invalid length\n");
        return (void *)addr;
    }

    status = gBS->AllocatePages(
        AllocateAnyPages, EfiRuntimeServicesCode, (len / EFI_PAGE_SIZE) + 1, &addr
    );

    if (EFI_ERROR(status)) {
        BFALERT("platform_alloc_rw: AllocatePages failed: %lld\n", len);
    }

    return (void *)addr;
}

void
platform_free_rw(const void *addr, uint64_t len)
{
    if (addr == nullptr) {
        BFALERT("platform_free_rw: invalid address %p\n", addr);
        return;
    }

    gBS->FreePages(
        (EFI_PHYSICAL_ADDRESS) addr, (len / EFI_PAGE_SIZE) + 1
    );
}

void
platform_free_rwe(const void *addr, uint64_t len)
{
    if (addr == nullptr) {
        BFALERT("platform_free_rw: invalid address %p\n", addr);
        return;
    }

    gBS->FreePages(
        (EFI_PHYSICAL_ADDRESS) addr, (len / EFI_PAGE_SIZE) + 1
    );
}

void *
platform_virt_to_phys(void *virt)
{
    return virt;
}

void *
platform_memset(void *ptr, char value, uint64_t num)
{
    gBS->SetMem(ptr, num, value);
    return ptr;
}

void *
platform_memcpy(void *dst, const void *src, uint64_t num)
{
    gBS->CopyMem((VOID *)dst, (VOID *)src, num);
    return dst;
}

int64_t
platform_num_cpus(void)
{
    UINTN NumberOfProcessors;
    UINTN NumberOfEnabledProcessors;

    EFI_STATUS status =
        g_mp_services->GetNumberOfProcessors(
            g_mp_services,
            &NumberOfProcessors,
            &NumberOfEnabledProcessors
        );

    if (EFI_ERROR(status)) {
        BFALERT("platform_num_cpus: GetNumberOfProcessors failed\n");
        return 0;
    }

    return (int64_t)NumberOfProcessors;
}

struct call_vmm_args {
    uint64_t cpuid;
    uint64_t request;
    uintptr_t arg1;
    uintptr_t arg2;
    int64_t ret;
};

EFI_FUNCTION static void
call_vmm(struct call_vmm_args *args)
{
    _set_ne();

    args->ret =
        common_call_vmm(args->cpuid, args->request, args->arg1, args->arg2);
}

int64_t
platform_call_vmm_on_core(
    uint64_t cpuid, uint64_t request, uintptr_t arg1, uintptr_t arg2)
{
    struct call_vmm_args args = {
        cpuid, request, arg1, arg2, 0
    };

    if (cpuid == 0) {
        return common_call_vmm(cpuid, request, arg1, arg2);
    }

    EFI_STATUS status =
        g_mp_services->StartupThisAP(
            g_mp_services,
            (EFI_AP_PROCEDURE)call_vmm,
            cpuid,
            nullptr,
            0,
            &args,
            nullptr
        );

    if (EFI_ERROR(status)) {
        BFALERT("platform_num_cpus: StartupThisAP failed\n");
        return -1;
    }

    return args.ret;
}

void *
platform_get_rsdp(void)
{ return 0; }
