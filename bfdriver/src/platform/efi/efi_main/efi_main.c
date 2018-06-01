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

#include <efi.h>
#include <efilib.h>
#include "boot.h"

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

#define EFI_MODULE(name) \
    extern boot_ret_t register_module_##name(void);
#include "module.h"
#undef EFI_MODULE

void register_modules()
{
#define EFI_MODULE(name) \
    register_module_##name();
#include "module.h"
#undef EFI_MODULE
}

EFI_STATUS efi_main(EFI_HANDLE image_in, EFI_SYSTEM_TABLE *st_in)
{
    InitializeLib(image_in, st_in);

    Print(L"=======================================\n");
    Print(L" ___                __ _           _   \n");
    Print(L"| _ ) __ _ _ _ ___ / _| |__ _ _ _ | |__\n");
    Print(L"| _ \\/ _` | '_/ -_)  _| / _` | ' \\| / /\n");
    Print(L"|___/\\__,_|_| \\___|_| |_\\__,_|_||_|_\\_\\\n");
    Print(L"     EFI Loader  \n");
    Print(L"=======================================\n");

    register_modules();
    boot_ret_t ret = boot_start();

    if (ret != BOOT_NOT_FOUND) {
        Print(L"boot_start returned %d\n", ret);
    }

    console_get_keystroke(NULL);

    return EFI_NOT_FOUND;
}
