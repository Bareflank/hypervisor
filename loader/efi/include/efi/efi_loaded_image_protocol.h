/**
 * @copyright
 * Copyright (C) 2020 Assured Information Security, Inc.
 * Copyright (C) 2021 TK Chia
 *
 * @copyright
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * @copyright
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * @copyright
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#ifndef EFI_LOADED_IMAGE_PROTOCOL_H
#define EFI_LOADED_IMAGE_PROTOCOL_H

#include <efi/efi_device_path_protocol.h>
#include <efi/efi_system_table.h>
#include <efi/efi_types.h>

/** @brief defines the GUID for EFI_LOADED_IMAGE_PROTOCOL_GUID */
#define EFI_LOADED_IMAGE_PROTOCOL_GUID                                                             \
    {                                                                                              \
        0x5b1b31a1, 0x9562, 0x11d2,                                                                \
        {                                                                                          \
            0x8e, 0x3f, 0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b                                         \
        }                                                                                          \
    }

/** @brief defines the Revision Number 1 for EFI_LOADED_IMAGE_PROTOCOL */
#define EFI_LOADED_IMAGE_PROTOCOL_REVISION 0x1000

/** @brief prototype for _EFI_LOADED_IMAGE_PROTOCOL */
struct _EFI_LOADED_IMAGE_PROTOCOL;

/** @brief prototype for EFI_LOADED_IMAGE_PROTOCOL */
typedef struct _EFI_LOADED_IMAGE_PROTOCOL EFI_LOADED_IMAGE_PROTOCOL;

/**
 * <!-- description -->
 *   @brief Unloads an image from memory.
 *
 * <!-- inputs/outputs -->
 *   @param ImageHandle The hnadle to the image to unload
 *   @return Returns an EFI_STATUS
 */
typedef EFI_STATUS(EFIAPI *EFI_IMAGE_UNLOAD)(IN EFI_HANDLE ImageHandle);

/**
 * <!-- description -->
 *   @brief Defines the layout of the EFI_LOADED_IMAGE_PROTOCOL struct:
 *     https://uefi.org/sites/default/files/resources/UEFI_Spec_2_9_2021_03_18.pdf
 */
typedef struct _EFI_LOADED_IMAGE_PROTOCOL
{
    /**
     * @brief Defines the revision of the EFI_LOADED_IMAGE_PROTOCOL
     *   structure. All future revisions will be backward compatible to
     *   the current revision.
     */
    UINT32 Revision;

    /**
     * @brief Parent image's image handle.  NULL if the image is loaded
     *   directly from the firmware's boot manager.
     */
    EFI_HANDLE ParentHandle;

    /**
     * @brief The image's EFI system table pointer.
     */
    EFI_SYSTEM_TABLE *SystemTable;

    /**
     * @brief The device handle that the EFI Image was loaded from.
     */
    EFI_HANDLE DeviceHandle;

    /**
     * @brief A pointer to the file path portion specific to DeviceHandle
     *   that the EFI Image was loaded from.
     */
    EFI_DEVICE_PATH_PROTOCOL *FilePath;

    /**
     * @brief Reserved.  DO NOT USE.
     */
    VOID *Reserved;

    /**
     * @brief The size in bytes of LoadOptions.
     */
    UINT32 LoadOptionsSize;

    /**
     * @brief A pointer to the image's binary load options.
     */
    VOID *LoadOptions;

    /**
     * @brief The base address at which the image was loaded.
     */
    VOID *ImageBase;

    /**
     * @brief The size in bytes of the loaded image.
     */
    UINT64 ImageSize;

    /**
     * @brief The memory type that the code sections were loaded as.
     */
    EFI_MEMORY_TYPE ImageCodeType;

    /**
     * @brief The memory type that the data sections were loaded as.
     */
    EFI_MEMORY_TYPE ImageDataType;

    /**
     * @brief Unloads an image from memory.
     */
    EFI_IMAGE_UNLOAD Unload;

} EFI_LOADED_IMAGE_PROTOCOL;

#endif
