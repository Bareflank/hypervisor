/**
 * @copyright
 * Copyright (C) 2020 Assured Information Security, Inc.
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

#include <arch_locate_protocols.h>
#include <debug.h>
#include <dump_vmm_on_error_if_needed.h>
#include <efi/efi_loaded_image_protocol.h>
#include <efi/efi_simple_file_system_protocol.h>
#include <efi/efi_status.h>
#include <efi/efi_system_table.h>
#include <efi/efi_types.h>
#include <loader_init.h>
#include <platform.h>
#include <serial_init.h>
#include <span_t.h>
#include <start_vmm.h>
#include <start_vmm_args_t.h>

/**
 * NOTE:
 * - We always return EFI_SUCCESS, even on failure as on some systems,
 *   returning something else will cause the system to halt.
 */

/** @brief defines the global pointer to the EFI_SYSTEM_TABLE */
EFI_SYSTEM_TABLE *g_st = NULL;

/** @brief defines the global pointer to the EFI_LOADED_IMAGE_PROTOCOL */
EFI_LOADED_IMAGE_PROTOCOL *g_loaded_image_protocol = NULL;

/** @brief defines the global pointer to the EFI_SIMPLE_FILE_SYSTEM_PROTOCOL */
EFI_SIMPLE_FILE_SYSTEM_PROTOCOL *g_simple_file_system_protocol = NULL;

/**
 * <!-- description -->
 *   @brief Returns the size (in bytes) of the provided file
 *
 * <!-- inputs/outputs -->
 *   @param file_protocol the file protocol for the file to query
 *   @param file_size where to return the resulting file size
 *   @return returns EFI_SUCCESS on success, and a non-EFI_SUCCESS value on
 *     failure.
 */
EFI_STATUS
get_file_size(EFI_FILE_PROTOCOL *const file_protocol, UINTN *const file_size)
{
    EFI_STATUS status = EFI_SUCCESS;
    EFI_GUID efi_file_info_guid = EFI_FILE_INFO_ID;
    EFI_FILE_INFO *efi_file_info = NULL;
    UINTN efi_file_info_size = 0;

    /**
     * NOTE:
     * - We don't know what the size of the EFI_FILE_INFO is. To get that,
     *   we need to run GetInfo with the size set to 0. It will return the
     *   size that we need, and then from there we have to allocate a buffer,
     *   get the file size, and then free this buffer.
     */

    status = file_protocol->GetInfo(file_protocol, &efi_file_info_guid, &efi_file_info_size, NULL);
    if (status != EFI_BUFFER_TOO_SMALL) {
        bferror_x64("GetInfo failed", status);
        goto get_info_failed_size;
    }

    status = g_st->BootServices->AllocatePool(
        EfiLoaderData, efi_file_info_size, ((VOID **)&efi_file_info));
    if (EFI_ERROR(status)) {
        bferror_x64("AllocatePool failed", status);
        goto allocate_pool_failed;
    }

    status = file_protocol->GetInfo(
        file_protocol, &efi_file_info_guid, &efi_file_info_size, efi_file_info);
    if (EFI_ERROR(status)) {
        bferror_x64("GetInfo failed", status);
        goto get_info_failed;
    }

    *file_size = efi_file_info->FileSize;

    g_st->BootServices->FreePool(efi_file_info);
    return EFI_SUCCESS;

get_info_failed:
    g_st->BootServices->FreePool(efi_file_info);
allocate_pool_failed:
get_info_failed_size:

    *file_size = 0;
    return status;
}

/**
 * <!-- description -->
 *   @brief Allocates a buffer and fills the buffer with the contents of the
 *     provided file.
 *
 * <!-- inputs/outputs -->
 *   @param volume_protocol the file protocol for the boot volume
 *   @param filename the file to read
 *   @param file where to store the resulting buffer containing the file
 *     contents. This buffer must be freed by the caller.
 *   @return returns EFI_SUCCESS on success, and a non-EFI_SUCCESS value on
 *     failure.
 */
EFI_STATUS
read_file(
    EFI_FILE_PROTOCOL *const volume_protocol, CHAR16 *const filename, struct span_t *const file)
{
    EFI_STATUS status = EFI_SUCCESS;
    EFI_FILE_PROTOCOL *file_protocol = NULL;

    status =
        volume_protocol->Open(volume_protocol, &file_protocol, filename, EFI_FILE_MODE_READ, 0);
    if (EFI_ERROR(status)) {
        bferror_x64("Open failed", status);
        goto open_failed;
    }

    status = get_file_size(file_protocol, &file->size);
    if (EFI_ERROR(status)) {
        bferror_x64("get_file_size failed", status);
        goto get_file_size_failed;
    }

    status =
        g_st->BootServices->AllocatePool(EfiRuntimeServicesData, file->size, (VOID **)&file->addr);
    if (EFI_ERROR(status)) {
        bferror_x64("AllocatePool failed", status);
        goto allocate_pool_failed;
    }

    status = file_protocol->Read(file_protocol, &file->size, (VOID *)file->addr);
    if (EFI_ERROR(status)) {
        bferror_x64("Read failed", status);
        goto read_failed;
    }

    file_protocol->Close(file_protocol);
    return EFI_SUCCESS;

read_failed:
    g_st->BootServices->FreePool((VOID *)file->addr);
    file->addr = NULL;
    file->size = ((uint64_t)0);
allocate_pool_failed:
get_file_size_failed:
    file_protocol->Close(file_protocol);
open_failed:

    return status;
}

/**
 * <!-- description -->
 *   @brief Locates all of the protocols that are needed
 *
 * <!-- inputs/outputs -->
 *   @return returns EFI_SUCCESS on success, and a non-EFI_SUCCESS value on
 *     failure.
 */
EFI_STATUS
locate_protocols(EFI_HANDLE ImageHandle)
{
    EFI_STATUS status = EFI_SUCCESS;
    EFI_GUID efi_loaded_image_protocol_guid = EFI_LOADED_IMAGE_PROTOCOL_GUID;
    EFI_GUID efi_simple_file_system_protocol_guid = EFI_SIMPLE_FILE_SYSTEM_PROTOCOL_GUID;

    status = arch_locate_protocols();
    if (EFI_ERROR(status)) {
        bferror_x64("arch_locate_protocols failed", status);
        return status;
    }

    status = g_st->BootServices->HandleProtocol(
        ImageHandle, &efi_loaded_image_protocol_guid, (VOID **)&g_loaded_image_protocol);
    if (EFI_ERROR(status)) {
        bferror_x64("HandleProtocol EFI_LOADED_IMAGE_PROTOCOL failed", status);
        return status;
    }

    status = g_st->BootServices->HandleProtocol(
        g_loaded_image_protocol->DeviceHandle,
        &efi_simple_file_system_protocol_guid,
        (VOID **)&g_simple_file_system_protocol);
    if (EFI_ERROR(status)) {
        bferror_x64("HandleProtocol EFI_SIMPLE_FILE_SYSTEM_PROTOCOL failed", status);
        return status;
    }

    return EFI_SUCCESS;
}

/**
 * <!-- description -->
 *   @brief Loads the ELF images from the EFI partition and starts the VMM.
 *
 * <!-- inputs/outputs -->
 *   @return returns EFI_SUCCESS on success, and a non-EFI_SUCCESS value on
 *     failure.
 */
EFI_STATUS
load_images_and_start(void)
{
    EFI_STATUS status = EFI_SUCCESS;
    EFI_FILE_PROTOCOL *volume_protocol = NULL;
    struct start_vmm_args_t start_args = {0};

    status =
        g_simple_file_system_protocol->OpenVolume(g_simple_file_system_protocol, &volume_protocol);
    if (EFI_ERROR(status)) {
        bferror_x64("OpenVolume failed", status);
        return status;
    }

    status = read_file(volume_protocol, L"bareflank_kernel", &start_args.mk_elf_file);
    if (EFI_ERROR(status)) {
        bferror_x64("open_kernel failed", status);
        return status;
    }

    status = read_file(volume_protocol, L"bareflank_extension0", &(start_args.ext_elf_files[0]));
    if (EFI_ERROR(status)) {
        bferror_x64("open_extensions failed", status);
        return status;
    }

    start_args.ver = ((uint64_t)1);
    start_args.num_pages_in_page_pool = ((uint32_t)0);

    if (start_vmm(&start_args)) {
        bferror("start_vmm failed");
        return EFI_LOAD_ERROR;
    }

    return EFI_SUCCESS;
}

void serial_write_hex(uint64_t const val);

/**
 * <!-- description -->
 *   @brief Defines the main EFI entry pointer
 *
 * <!-- inputs/outputs -->
 *   @param ImageHandle ignored
 *   @param SystemTable stores a pointer to the global EFI stytem table
 *   @return returns EFI_SUCCESS on success, and a non-EFI_SUCCESS value on
 *     failure.
 */
EFI_STATUS
efi_main(EFI_HANDLE ImageHandle, EFI_SYSTEM_TABLE *SystemTable)
{
    EFI_STATUS status = EFI_SUCCESS;

    /**
     * NOTE:
     * - This function needs to be kept pretty simple as if you attempt to
     *   do too much, you might cause memcpy/memset to be called prior to
     *   the system table being saved.
     */

    g_st = SystemTable;
    if (g_st->Hdr.Revision < EFI_1_10_SYSTEM_TABLE_REVISION) {
        g_st->ConOut->OutputString(g_st->ConOut, L"EFI version not supported\r\n");
        return EFI_SUCCESS;
    }

    serial_init();

    status = locate_protocols(ImageHandle);
    if (EFI_ERROR(status)) {
        bferror_x64("locate_protocols failed", status);
        return EFI_SUCCESS;
    }

    if (loader_init()) {
        bferror("loader_init failed");
        return EFI_SUCCESS;
    }

    status = load_images_and_start();
    if (EFI_ERROR(status)) {
        bferror_x64("load_images_and_start failed", status);
        platform_dump_vmm();
        return EFI_SUCCESS;
    }

    platform_dump_vmm();

    g_st->ConOut->OutputString(g_st->ConOut, L"bareflank successfully started\r\n");
    return EFI_SUCCESS;
}
