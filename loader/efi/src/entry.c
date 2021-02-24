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

#include <debug.h>
#include <efi/efi_mp_services_protocol.h>
#include <efi/efi_simple_file_system_protocol.h>
#include <efi/efi_status.h>
#include <efi/efi_system_table.h>
#include <efi/efi_types.h>
#include <loader_init.h>
#include <serial_init.h>
#include <span_t.h>
#include <start_vmm.h>
#include <start_vmm_args_t.h>

/** @brief defines the global pointer to the EFI_SYSTEM_TABLE */
EFI_SYSTEM_TABLE *g_st = NULL;

/** @brief defines the global pointer to the EFI_MP_SERVICES_PROTOCOL */
EFI_MP_SERVICES_PROTOCOL *g_mp_services_protocol = NULL;

/** @brief defines the global pointer to the EFI_SIMPLE_FILE_SYSTEM_PROTOCOL */
EFI_SIMPLE_FILE_SYSTEM_PROTOCOL *g_simple_file_system = NULL;

/**
 * <!-- description -->
 *   @brief Returns the size (in bytes) of the provided file
 *
 * <!-- inputs/outputs -->
 *   @param file_protocol the file protocol to use to get the file info
 *   @param hndl a handle to the file to query
 *   @param file_size where to return the resulting file size
 *   @return returns EFI_SUCCESS on success, and a non-EFI_SUCCESS value on
 *     failure.
 */
EFI_STATUS
get_file_size(
    EFI_FILE_PROTOCOL *const file_protocol, EFI_FILE_PROTOCOL *const hndl, UINTN *const file_size)
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

    status = file_protocol->GetInfo(hndl, &efi_file_info_guid, &efi_file_info_size, NULL);
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

    status = file_protocol->GetInfo(hndl, &efi_file_info_guid, &efi_file_info_size, efi_file_info);
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
 *   @param file_protocol the file protocol to use to get the file contents
 *   @param filename the file to read
 *   @param file where to store the resulting buffer containing the file
 *     contents. This buffer must be freed by the caller.
 *   @return returns EFI_SUCCESS on success, and a non-EFI_SUCCESS value on
 *     failure.
 */
EFI_STATUS
read_file(EFI_FILE_PROTOCOL *const file_protocol, CHAR16 *const filename, struct span_t *const file)
{
    EFI_STATUS status = EFI_SUCCESS;
    EFI_FILE_PROTOCOL *hndl = NULL;

    status = file_protocol->Open(file_protocol, &hndl, filename, EFI_FILE_MODE_READ, EFI_FILE_NONE);
    if (EFI_ERROR(status)) {
        bferror_x64("Open failed", status);
        goto open_failed;
    }

    status = get_file_size(file_protocol, hndl, &file->size);
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

    status = file_protocol->Read(hndl, &file->size, (VOID *)file->addr);
    if (EFI_ERROR(status)) {
        bferror_x64("Read failed", status);
        goto read_failed;
    }

    file_protocol->Close(hndl);
    return EFI_SUCCESS;

read_failed:
    g_st->BootServices->FreePool((VOID *)file->addr);
    file->addr = NULL;
    file->size = ((uint64_t)0);
allocate_pool_failed:
get_file_size_failed:
    file_protocol->Close(hndl);
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
locate_protocols(void)
{
    EFI_STATUS status = EFI_SUCCESS;
    EFI_GUID efi_mp_services_protocol_guid = EFI_MP_SERVICES_PROTOCOL_GUID;
    EFI_GUID efi_simple_file_system_protocol_guid = EFI_SIMPLE_FILE_SYSTEM_PROTOCOL_GUID;

    status = g_st->BootServices->LocateProtocol(
        &efi_mp_services_protocol_guid, NULL, (VOID **)&g_mp_services_protocol);
    if (EFI_ERROR(status)) {
        bferror_x64("LocateProtocol EFI_MP_SERVICES_PROTOCOL failed", status);
        return status;
    }

    status = g_st->BootServices->LocateProtocol(
        &efi_simple_file_system_protocol_guid, NULL, (VOID **)&g_simple_file_system);
    if (EFI_ERROR(status)) {
        bferror_x64("LocateProtocol EFI_SIMPLE_FILE_SYSTEM_PROTOCOL failed", status);
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
    EFI_FILE_PROTOCOL *file_protocol = NULL;
    struct start_vmm_args_t start_args = {0};

    status = g_simple_file_system->OpenVolume(g_simple_file_system, &file_protocol);
    if (EFI_ERROR(status)) {
        bferror_x64("OpenVolume failed", status);
        return status;
    }

    status = read_file(file_protocol, L"bareflank_kernel", &start_args.mk_elf_file);
    if (EFI_ERROR(status)) {
        bferror_x64("open_kernel failed", status);
        return status;
    }

    status = read_file(file_protocol, L"bareflank_extension0", &(start_args.ext_elf_files[0]));
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
        return EFI_UNSUPPORTED;
    }

    serial_init();

    /**
     * TODO:
     * - Need to process the command line arguments so that we can load
     *   an image that the user provides.
     * - Also need to add a CMAKE var for where to load the UEFI stuff.
     */

    if (loader_init()) {
        bferror("loader_init failed");
        return EFI_LOAD_ERROR;
    }

    status = locate_protocols();
    if (EFI_ERROR(status)) {
        bferror_x64("locate_protocols failed", status);
        return status;
    }

    status = load_images_and_start();
    if (EFI_ERROR(status)) {
        bferror_x64("load_images_and_start failed", status);
        return status;
    }

    g_st->ConOut->OutputString(g_st->ConOut, L"bareflank successfully started\r\n");
    return EFI_SUCCESS;
}

/**
 * <!-- description -->
 *   @brief Same as std::memcpy.
 *
 * <!-- inputs/outputs -->
 *   @param dst a pointer to the memory to copy to
 *   @param src a pointer to the memory to copy from
 *   @param count the total number of bytes to copy
 *   @return Returns the same result as std::memcpy.
 */
void *
memcpy(void *const dst, void const *const src, uint64_t const count)
{
    g_st->BootServices->CopyMem(dst, ((VOID *)src), count);
    return dst;
}

/**
 * <!-- description -->
 *   @brief Same as std::memset.
 *
 * <!-- inputs/outputs -->
 *   @param dst a pointer to the memory to set
 *   @param ch the value to set the memory to
 *   @param num the total number of bytes to set
 *   @return Returns the same result as std::memset.
 */
void *
memset(void *const dst, char const ch, uint64_t const num)
{
    g_st->BootServices->SetMem(dst, num, ((UINT8)ch));
    return dst;
}
