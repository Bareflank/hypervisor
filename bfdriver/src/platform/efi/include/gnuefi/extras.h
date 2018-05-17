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

// extras.h - structs either not implemented or renamed by gnu-efi

#ifndef EXTRAS_H
#define EXTRAS_H

#include "bfefi.h"

typedef EFI_LOADED_IMAGE EFI_LOADED_IMAGE_PROTOCOL;

#pragma pack(1)
typedef struct _EFI_LOAD_OPTION {
    ///
    /// The attributes for this load option entry. All unused bits must be zero
    /// and are reserved by the UEFI specification for future growth.
    ///
    UINT32                           Attributes;
    ///
    /// Length in bytes of the FilePathList. OptionalData starts at offset
    /// sizeof(UINT32) + sizeof(UINT16) + StrSize(Description) + FilePathListLength
    /// of the EFI_LOAD_OPTION descriptor.
    ///
    UINT16                           FilePathListLength;
    ///
    /// The user readable description for the load option.
    /// This field ends with a Null character.
    ///
    CHAR16                        *Description;
    ///
    /// A packed array of UEFI device paths. The first element of the array is a
    /// device path that describes the device and location of the Image for this
    /// load option. The FilePathList[0] is specific to the device type. Other
    /// device paths may optionally exist in the FilePathList, but their usage is
    /// OSV specific. Each element in the array is variable length, and ends at
    /// the device path end structure. Because the size of Description is
    /// arbitrary, this data structure is not guaranteed to be aligned on a
    /// natural boundary. This data structure may have to be copied to an aligned
    /// natural boundary before it is used.
    ///
    EFI_DEVICE_PATH_PROTOCOL      *FilePathList;
    ///
    /// The remaining bytes in the load option descriptor are a binary data buffer
    /// that is passed to the loaded image. If the field is zero bytes long, a
    /// NULL pointer is passed to the loaded image. The number of bytes in
    /// OptionalData can be computed by subtracting the starting offset of
    /// OptionalData from total size in bytes of the EFI_LOAD_OPTION.
    ///
    UINT8                         *OptionalData;
} EFI_LOAD_OPTION;
#pragma pack()

#endif
