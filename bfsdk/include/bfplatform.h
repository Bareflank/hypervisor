/*
 * Bareflank Hypervisor
 * Copyright (C) 2015 Assured Information Security, Inc.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

/**
 * @file bfplatform.h
 */

#ifndef BFPLATFORM_H
#define BFPLATFORM_H

#include <bftypes.h>
#include <bfsupport.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Initalize Platform Logic
 *
 * @expects none
 * @ensures none
 *
 * @return BF_SUCCESS on success, negative error code on failure
 */
int64_t platform_init(void);

/**
 * Allocate Memory
 *
 * @expects none
 * @ensures none
 *
 * @note: If this function is used in userspace, it must be assumed that free()
 * can be used to free this memory. In the kernel, it can be assumed that
 * platform_free_rw is used instead, which provides the length field.
 *
 * @param len the size of memory to allocate in bytes.
 * @return returns the address of the newly allocated memory
 */
void *platform_alloc_rw(uint64_t len);

/**
 * Allocate Executable Memory
 *
 * @expects none
 * @ensures none
 *
 * @note: memory allocated from this function must be 4k aligned. If this
 * function is used in userspace, it must be assumed that free() can be
 * used to free this memory. In the kernel, it can be assumed that
 * platform_free_rwe is used instead, which provides the length field.
 *
 * @param len the size of memory to allocate in bytes.
 * @return returns the address of the newly allocated, executable memory
 */
void *platform_alloc_rwe(uint64_t len);

/**
 * Free Memory
 *
 * @expects none
 * @ensures none
 *
 * @param addr the address of memory allocated using platform_alloc_rw
 * @param len the size of the memory allocated using platform_alloc_rw
 */
void platform_free_rw(const void *addr, uint64_t len);

/**
 * Free Executable Memory
 *
 * @expects none
 * @ensures none
 *
 * @param addr the address of memory allocated using platform_alloc_rwe
 * @param len the size of the memory allocated using platform_alloc_rwe
 */
void platform_free_rwe(const void *addr, uint64_t len);

/**
 * Convert Virtual Address to Physical Address
 *
 * @expects none
 * @ensures none
 *
 * @param virt the virtual address to convert
 * @return the physical address associated with the provided virtual address
 */
void *platform_virt_to_phys(void *virt);

/**
 * Memset
 *
 * @expects none
 * @ensures none
 *
 * @param ptr a pointer to the memory to set
 * @param value the value to set each byte to
 * @param num the number of bytes to set
 */
void *platform_memset(void *ptr, char value, uint64_t num);

/**
 * Memcpy
 *
 * @expects none
 * @ensures none
 *
 * @param dst a pointer to the memory to copy to
 * @param src a pointer to the memory to copy from
 * @param num the number of bytes to copy
 */
void *platform_memcpy(void *dst, const void *src, uint64_t num);

/**
 * Get Number of CPUs
 *
 * @expects none
 * @ensures none
 *
 * @return returns the total number of CPUs available.
 */
int64_t platform_num_cpus(void);

/**
 * Call VMM on Core
 *
 * Executes the VMM. The VMM has a single entry point, with a switch statement
 * that executes the provided "request". When this occurs, arg1 and arg2 are
 * provided to the requested function. Note that the first arg takes a cpuid,
 * which is the core number want to execute the VMM on. If a -1 is provided,
 * the currently executing core will be used.
 *
 * @param cpuid the core id this code is to be execute on
 * @param request the requested function in the VMM to execute
 * @param arg1 arg #1
 * @param arg2 arg #2
 * @return BF_SUCCESS on success, negative error code on failure
 */
int64_t platform_call_vmm_on_core(
    uint64_t cpuid, uint64_t request, uintptr_t arg1, uintptr_t arg2);

/**
 * Get RSDP
 *
 * Returns the address of the Root System Description Pointer for ACPI.
 * If ACPI is not supported, return 0.
 *
 * @expects none
 * @ensures none
 *
 * @return returns the RSDP or 0 if ACPI is not supported
 */
void *platform_get_rsdp(void);

#ifdef __cplusplus
}
#endif

#endif
