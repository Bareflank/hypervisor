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
#include <efi/efi_status.h>
#include <efi/efi_system_table.h>
#include <efi/efi_types.h>

/** @brief defines the global pointer to the EFI_MP_SERVICES_PROTOCOL */
EFI_MP_SERVICES_PROTOCOL *g_mp_services_protocol = NULL;

/**
 * <!-- description -->
 *   @brief Locates all of the protocols that are needed by this architecture
 *
 * <!-- inputs/outputs -->
 *   @return returns EFI_SUCCESS on success, and a non-EFI_SUCCESS value on
 *     failure.
 */
EFI_STATUS
arch_locate_protocols(void)
{
    EFI_STATUS status = EFI_SUCCESS;
    EFI_GUID efi_mp_services_protocol_guid = EFI_MP_SERVICES_PROTOCOL_GUID;

    status = g_st->BootServices->LocateProtocol(
        &efi_mp_services_protocol_guid, NULL, (VOID **)&g_mp_services_protocol);
    if (EFI_ERROR(status)) {
        bferror_x64("LocateProtocol EFI_MP_SERVICES_PROTOCOL failed", status);
        return status;
    }

    return EFI_SUCCESS;
}
