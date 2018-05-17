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

#ifndef HYP_LIB_H
#define HYP_LIB_H

#include "bfefi.h"

/**
 * Initialize library
 *
 * This function should be called immediately (i.e. before Printing anything)
 * to initialize the loader.
 *
 * @param handle Handle of loaded image, passed to efi_main by firmware
 * @param systab EFI system table, passed to efi_main by firmware
 */
VOID bf_init_lib(EFI_HANDLE handle, EFI_SYSTEM_TABLE *systab);

/**
 * Get number of CPU cores on system
 *
 * Get number of CPU cores on system
 *
 * @return UINTN number of CPU cores on system
 */
UINTN bf_num_cpus();

/**
 * Get variable from EFI nvram
 *
 * Get variable from EFI nvram
 *
 * @param name IN: Name of variable to fetch
 * @param guid IN: GUID of variable vendor, or global variable GUID
 * @param guid OUT: Size in bytes of variable returned
 * @return Pointer to variable contents, or NULL if failed
 */
VOID *bf_get_variable(CHAR16 *name, EFI_GUID *guid, UINTN *);

/**
 * Dump memory to console
 *
 * Print a hex dump of memory to console
 *
 * @param indent Size of indent
 * @param offset Offset to print at the beginning of first line
 * @param size Length of dump in bytes
 * @param addr Address to dump from
 */
VOID bf_dump_hex(UINTN indent, UINTN offset, UINTN size, VOID *addr);

/**
 * Match device paths
 *
 * Determine if a single device path is present in a multi device path
 *
 * @param multi List of device paths to match from
 * @param single Device path to find in multi
 * @return BOOLEAN TRUE if single is present in multi, FALSE otherwise
 */
BOOLEAN bf_match_device_paths(EFI_DEVICE_PATH *multi, EFI_DEVICE_PATH *single);

/**
 * Allocate zero pool
 *
 * Allocate zeroed pool memory
 *
 * @param size Size in bytes of allocation request
 * @return VOID* Address of allocated memory, or NULL on failure
 */
VOID *bf_allocate_zero_pool(UINTN size);

/**
 * Allocate runtime zero pool
 *
 * Allocate zeroed pool memory of type EfiRuntimeServicesCode
 *
 * @param size Size in bytes of allocation request
 * @return VOID* Address of allocated memory, or NULL on failure
 */
VOID *bf_allocate_runtime_zero_pool(UINTN size);

/**
 * Free pool memory
 *
 * Free memory previously allocated from pool
 *
 * @param addr Address of allocated memory
 */
VOID bf_free_pool(VOID *addr);

#endif
