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
