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

#include "bfefi.h"
#include "bflib.h"
#include "bfloader.h"
#include "common.h"

EFI_HANDLE this_image_h;
EFI_MP_SERVICES_PROTOCOL *g_mp_services;

extern char target_module_start[];
extern uint64_t target_module_size;

EFI_STATUS efi_main(EFI_HANDLE image_in, EFI_SYSTEM_TABLE *st_in)
{

    bf_init_lib(image_in, st_in);

    Print(L"=======================================\n");
    Print(L" ___                __ _           _   \n");
    Print(L"| _ ) __ _ _ _ ___ / _| |__ _ _ _ | |__\n");
    Print(L"| _ \\/ _` | '_/ -_)  _| / _` | ' \\| / /\n");
    Print(L"|___/\\__,_|_| \\___|_| |_\\__,_|_||_|_\\_\\\n");
    Print(L"     EFI Loader  \n");
    Print(L"=======================================\n");

    EFI_STATUS status;

    EFI_GUID gEfiMpServiceProtocolGuid = EFI_MP_SERVICES_PROTOCOL_GUID;
    status = gBS->LocateProtocol(&gEfiMpServiceProtocolGuid,
                                 NULL,
                                 (VOID **)&g_mp_services);
    if (EFI_ERROR(status)) {
        PRINT_ERROR(status);
        goto fail;
    }

    Print(L"Adding hypervisor module..\n");
    int64_t ret = common_add_module((const char *)target_module_start,
                                    (uint64_t)target_module_size);
    if (ret < 0) {
        Print(L"common_add_module returned %a\n", ec_to_str(ret));
        goto fail;
    }

    Print(L"Loading modules..\n");
    ret = common_load_vmm();
    if (ret < 0) {
        Print(L"common_load_vmm returned %a\n", ec_to_str(ret));
        goto fail;
    }

    bf_start_by_startupallaps();

    Print(L"Press any key to boot next image in BootOrder.\n");
    console_get_keystroke(NULL);

    // returning EFI_NOT_FOUND generally causes firmware to boot next
    // image in boot order without further prompting
    return EFI_NOT_FOUND;

fail:

    console_get_keystroke(NULL);
    return EFI_ABORTED;
}
