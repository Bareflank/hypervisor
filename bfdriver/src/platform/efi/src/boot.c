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

EFI_STATUS bf_boot_next_by_order()
{
    EFI_GUID global_guid = EFI_GLOBAL_VARIABLE;

    EFI_STATUS status;
    EFI_LOADED_IMAGE *li;
    status = gBS->HandleProtocol(this_image_h,
                                 &gEfiLoadedImageProtocolGuid,
                                 (VOID **)&li);

    if (EFI_ERROR(status)) {
        Print(L"Unable to fetch loaded image information.\n");
        return status;
    }

    EFI_DEVICE_PATH *dev = DevicePathFromHandle(li->DeviceHandle);
    if (!dev) {
        Print(L"Unable to get boot device path.\n");
        return EFI_NOT_FOUND;
    }

    EFI_DEVICE_PATH *loaded = AppendDevicePath(dev, li->FilePath);
    if (!loaded) {
        Print(L"Unable to assemble image device path.\n");
        return EFI_NOT_FOUND;
    }
    Print(DevicePathToStr(loaded));

    VOID *order = NULL;
    UINTN size;
    order = bf_get_variable(L"BootOrder", &global_guid, &size);
    if (!order) {
        Print(L"Unable to fetch BootOrder variable.\n");
        return EFI_NOT_FOUND;
    }

    UINTN count = size / 2;
    UINT16 *next = order;

    UINTN bootnow = 0;
    while (count > 0) {
        CHAR16 buf[18] = {0};
        SPrint(buf, 18, L"Boot%04x", (UINT32)*next);
        Print(buf);
        Print(L"\n");
        VOID *boot = bf_get_variable(buf, &global_guid, &size);
        if (!boot) {
            Print(L"Unable to fetch variable ");
            Print(buf);
            Print(L".\n");
            return EFI_NOT_FOUND;
        }

        if (bootnow) {
            Print(L"Booting ");
            Print(buf);
            Print(L".\n");
            return EFI_SUCCESS;
        }

        VOID *desc = boot + sizeof(EFI_LOAD_OPTION);
        VOID *dp = desc + StrSize(desc);
        if (LibMatchDevicePaths(loaded, dp)) {
            Print(L"Match!\n");
            Print(DevicePathToStr(dp));
            bootnow = 1;
        }

        next++;
        count--;
    }

    return EFI_NOT_FOUND;
}
