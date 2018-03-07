//
// Bareflank Hypervisor
// Copyright (C) 2018 Assured Information Security, Inc.
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

// gnu-efi wrappers

#include "bfefi.h"
#include "bfloader.h"


VOID bf_init_lib(EFI_HANDLE hnd, EFI_SYSTEM_TABLE *systab)
{
    InitializeLib(hnd, systab);
    this_image_h = hnd;
}

UINTN bf_num_cpus()
{
    EFI_STATUS status;
    UINTN cpus;
    UINTN ecpus;
    EFI_MP_SERVICES_PROTOCOL *mp_services;

    EFI_GUID gEfiMpServiceProtocolGuid = EFI_MP_SERVICES_PROTOCOL_GUID;
    status = gBS->LocateProtocol(&gEfiMpServiceProtocolGuid,
                                 NULL,
                                 (VOID **)&mp_services);
    if (EFI_ERROR(status)) {
        PRINT_ERROR(status);
        goto fail;
    }

    status = g_mp_services->GetNumberOfProcessors(g_mp_services,
             &cpus,
             &ecpus);
    if (EFI_ERROR(status)) {
        PRINT_ERROR(status);
        goto fail;
    }

    if (cpus != ecpus) {
        Print(L"Warning: disabled cpus present\n");
    }
    return ecpus;

fail:
    return 0;
}

VOID bf_dump_hex(UINTN indent, UINTN offset, UINTN size, VOID *ptr)
{
    DumpHex(indent, offset, size, ptr);
}

BOOLEAN bf_match_device_paths(EFI_DEVICE_PATH *multi, EFI_DEVICE_PATH *single)
{
    return LibMatchDevicePaths(multi, single);
}

VOID *bf_allocate_runtime_zero_pool(UINTN size)
{
    EFI_STATUS status;
    VOID *ret = NULL;
    status = gBS->AllocatePool(EfiRuntimeServicesCode,
                               size,
                               &ret);

    if (!EFI_ERROR(status)) {
        gBS->SetMem(ret, size, 0);
    }

    return ret;
}

VOID *bf_allocate_zero_pool(UINTN size)
{
    return AllocateZeroPool(size);
}

VOID *bf_get_variable(CHAR16 *name, EFI_GUID *guid, UINTN *size)
{
    return LibGetVariableAndSize(name, guid, size);
}

VOID bf_free_pool(VOID *ptr)
{
    FreePool(ptr);
}