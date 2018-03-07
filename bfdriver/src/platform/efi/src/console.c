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
#include "bfloader.h"

int printf(const char *format, ...)
{

    if (!format) {
        return 0;
    }
    CHAR8 *traveler = (CHAR8 *)format;
    UINTN counter = 1;
    while (*traveler != '\0') {
        traveler++;
        counter++;
    }

    CHAR16 *buf = (CHAR16 *)AllocateZeroPool(counter << 1);
    if (!buf) {
        return 0;
    }

    traveler = (CHAR8 *)format;
    CHAR16 *setter = buf;
    while (counter > 0) {
        *setter = (CHAR16) * traveler;
        setter++; traveler++;
        counter--;
    }

    va_list args;
    va_start(args, format);
    VPrint(buf, args);
    va_end(args);

    FreePool(buf);
    return 1;
}

EFI_STATUS console_get_keystroke(EFI_INPUT_KEY *key)
{
    UINTN EventIndex;
    EFI_STATUS status;

    do {
        gBS->WaitForEvent(1, &gST->ConIn->WaitForKey, &EventIndex);
        status = gST->ConIn->ReadKeyStroke(gST->ConIn, key);
    }
    while (status == EFI_NOT_READY);

    return status;
}
