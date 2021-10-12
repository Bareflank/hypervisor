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

#ifndef EFI_SYSTEM_TABLE_H
#define EFI_SYSTEM_TABLE_H

#include <efi/efi_boot_services.h>
#include <efi/efi_configuration_table.h>
#include <efi/efi_runtime_services.h>
#include <efi/efi_simple_text_input_protocol.h>
#include <efi/efi_simple_text_output_protocol.h>
#include <efi/efi_table_header.h>
#include <efi/efi_types.h>

/** @brief Defines EFI_SYSTEM_TABLE_SIGNATURE */
#define EFI_SYSTEM_TABLE_SIGNATURE 0x5453595320494249
/** @brief Defines EFI_2_80_SYSTEM_TABLE_REVISION */
#define EFI_2_80_SYSTEM_TABLE_REVISION ((2 << 16) | (80))
/** @brief Defines EFI_2_70_SYSTEM_TABLE_REVISION */
#define EFI_2_70_SYSTEM_TABLE_REVISION ((2 << 16) | (70))
/** @brief Defines EFI_2_60_SYSTEM_TABLE_REVISION */
#define EFI_2_60_SYSTEM_TABLE_REVISION ((2 << 16) | (60))
/** @brief Defines EFI_2_50_SYSTEM_TABLE_REVISION */
#define EFI_2_50_SYSTEM_TABLE_REVISION ((2 << 16) | (50))
/** @brief Defines EFI_2_40_SYSTEM_TABLE_REVISION */
#define EFI_2_40_SYSTEM_TABLE_REVISION ((2 << 16) | (40))
/** @brief Defines EFI_2_31_SYSTEM_TABLE_REVISION */
#define EFI_2_31_SYSTEM_TABLE_REVISION ((2 << 16) | (31))
/** @brief Defines EFI_2_30_SYSTEM_TABLE_REVISION */
#define EFI_2_30_SYSTEM_TABLE_REVISION ((2 << 16) | (30))
/** @brief Defines EFI_2_20_SYSTEM_TABLE_REVISION */
#define EFI_2_20_SYSTEM_TABLE_REVISION ((2 << 16) | (20))
/** @brief Defines EFI_2_10_SYSTEM_TABLE_REVISION */
#define EFI_2_10_SYSTEM_TABLE_REVISION ((2 << 16) | (10))
/** @brief Defines EFI_2_00_SYSTEM_TABLE_REVISION */
#define EFI_2_00_SYSTEM_TABLE_REVISION ((2 << 16) | (00))
/** @brief Defines EFI_1_10_SYSTEM_TABLE_REVISION */
#define EFI_1_10_SYSTEM_TABLE_REVISION ((1 << 16) | (10))
/** @brief Defines EFI_1_02_SYSTEM_TABLE_REVISION */
#define EFI_1_02_SYSTEM_TABLE_REVISION ((1 << 16) | (02))
/** @brief Defines EFI_SPECIFICATION_VERSION */
#define EFI_SPECIFICATION_VERSION EFI_SYSTEM_TABLE_REVISION
/** @brief Defines EFI_SYSTEM_TABLE_REVISION */
#define EFI_SYSTEM_TABLE_REVISION EFI_2_8_SYSTEM_TABLE_REVISION

/**
 * <!-- description -->
 *   @brief Defines the layout of the EFI_SYSTEM_TABLE struct:
 *     https://uefi.org/sites/default/files/resources/UEFI_Spec_2_8_final.pdf
 */
typedef struct
{
    /**
     * @brief The table header for the EFI System Table. This header contains
     *   the EFI_SYSTEM_TABLE_SIGNATURE and EFI_SYSTEM_TABLE_REVISION values
     *   along with the size of the EFI_SYSTEM_TABLE structure and a 32-bit
     *   CRC to verify that the contents of the EFI System Table are valid.
     */
    EFI_TABLE_HEADER Hdr;

    /**
     * @brief A pointer to a null terminated string that identifies the vendor
     *   that produces the system firmware for the platform.
     */
    CHAR16 *FirmwareVendor;

    /**
     * @brief A firmware vendor specific value that identifies the revision
     *   of the system firmware for the platform.
     */
    UINT32 FirmwareRevision;

    /**
     * @brief The handle for the active console input device. This handle must
     *   support EFI_SIMPLE_TEXT_INPUT_PROTOCOL and
     *   EFI_SIMPLE_TEXT_INPUT_EX_PROTOCOL.
     */
    EFI_HANDLE ConsoleInHandle;

    /**
     * @brief A pointer to the EFI_SIMPLE_TEXT_INPUT_PROTOCOL interface that
     *   is associated with ConsoleInHandle.
     */
    EFI_SIMPLE_TEXT_INPUT_PROTOCOL *ConIn;

    /**
     * @brief The handle for the active console output device. This handle
     *   must support the EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL.
     */
    EFI_HANDLE ConsoleOutHandle;

    /**
     * @brief A pointer to the EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL interface that
     *   is associated with ConsoleOutHandle.
     */
    EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *ConOut;

    /**
     * @brief The handle for the active standard error console device. This
     *   handle must support the EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL.
     */
    EFI_HANDLE StandardErrorHandle;

    /**
     * @brief A pointer to the EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL interface that
     *   is associated with StandardErrorHandle.
     */
    EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *StdErr;

    /**
     * @brief A pointer to the EFI Runtime Services Table.
     */
    EFI_RUNTIME_SERVICES *RuntimeServices;

    /**
     * @brief A pointer to the EFI Boot Services Table.
     */
    EFI_BOOT_SERVICES *BootServices;

    /**
     * @brief The number of system configuration tables in the buffer
     *   ConfigurationTable.
     */
    UINTN NumberOfTableEntries;

    /**
     * @brief A pointer to the system configuration tables. The number of
     *   entries in the table is NumberOfTableEntries.
     */
    EFI_CONFIGURATION_TABLE *ConfigurationTable;

} EFI_SYSTEM_TABLE;

/** @brief defines the global pointer to the EFI_SYSTEM_TABLE */
extern EFI_SYSTEM_TABLE *g_st;

#endif
