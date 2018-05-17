/*
 * Bareflank Hypervisor
 * Copyright (C) 2018 Assured Information Security, Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of
 * this software and associated documentation files (the "Software"), to deal in
 * the Software without restriction, including without limitation the rights to
 * use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
 * of the Software, and to permit persons to whom the Software is furnished to do
 * so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */

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
