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

#ifndef EFI_TYPES_H
#define EFI_TYPES_H

#include <types.h>

/**
 * @brief Logical Boolean. 1-byte value containing a 0 for FALSE or a 1 for
 *   TRUE. Other values are undefined.
 */
typedef uint8_t BOOLEAN;

/** @brief */
#define FALSE ((BOOLEAN)0)
/** @brief */
#define TRUE ((BOOLEAN)1)

/**
 * @brief Signed value of native width. (4 bytes on supported 32-bit
 *   processor instructions, 8 bytes on supported 64-bit processor
 *   instructions, 16 bytes on supported 128-bit processor instructions)
 */
typedef int64_t INTN;

/**
 * @brief Unsigned value of native width. (4 bytes on supported 32-bit
 *   processor instructions, 8 bytes on supported 64-bit processor
 *   instructions, 16 bytes on supported 128-bit processor instructions)
 */
typedef uint64_t UINTN;

/** @brief 1-byte signed value. */
typedef int8_t INT8;

/** @brief 1-byte unsigned value. */
typedef uint8_t UINT8;

/** @brief 2-byte signed value. */
typedef int16_t INT16;

/** @brief 2-byte unsigned value. */
typedef uint16_t UINT16;

/** @brief 4-byte signed value. */
typedef int32_t INT32;

/** @brief 4-byte unsigned value. */
typedef uint32_t UINT32;

/** @brief 8-byte signed value. */
typedef int64_t INT64;

/** @brief 8-byte unsigned value. */
typedef uint64_t UINT64;

/** @brief 16-byte signed value. */
/** unsupported typedef ??? INT128; */

/** @brief 16-byte unsigned value. */
/** unsupported typedef ??? UINT128; */

/**
 * @brief 1-byte character. Unless otherwise specified, all 1-byte or ASCII
 *   characters and strings are stored in 8-bit ASCII encoding format, using
 *   the ISO-Latin-1 character set.
 */
typedef uint8_t CHAR8;

/**
 * @brief 2-byte Character. Unless otherwise specified all characters and
 *   strings are stored in the UCS-2 encoding format as defined by Unicode
 *   2.1 and ISO/IEC 10646 standards.
 */
typedef uint16_t CHAR16;

/** @brief Undeclared type. */
typedef void VOID;

/** @brief NULL type*/
#define NULL ((VOID *)0)

/** @brief A collection of related interfaces. Type VOID *. */
typedef VOID *EFI_HANDLE;

/** @brief Handle to an event structure. Type VOID *. */
typedef VOID *EFI_EVENT;

/** @brief Logical block address. Type UINT64. */
typedef UINT64 EFI_LBA;

/** @brief Task priority level. Type UINTN. */
typedef UINTN EFI_TPL;

/** @brief Datum is passed to the function. */
#define IN

/** @brief Datum is returned from the function. */
#define OUT

/**
 * @brief Passing the datum to the function is optional, and a NULL may be
 *   passed if the value is not supplied.
 */
#define OPTIONAL

/** @brief Datum is read-only. */
#define CONST const

/** @brief Defines the calling convention for UEFI interfaces.  */
#define EFIAPI

/** @brief Defined in EFI_BOOT_SERVICES.GetMemoryMap() */
typedef UINT64 EFI_VIRTUAL_ADDRESS;

/** @brief Defined in EFI_BOOT_SERVICES.AllocatePages() */
typedef UINT64 EFI_PHYSICAL_ADDRESS;

#endif
