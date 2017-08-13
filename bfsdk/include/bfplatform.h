/*
 * Bareflank Hypervisor
 *
 * Copyright (C) 2015 Assured Information Security, Inc.
 * Author: Rian Quinn        <quinnr@ainfosec.com>
 * Author: Brendan Kerrigan  <kerriganb@ainfosec.com>
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

#ifdef __cplusplus
extern "C" {
#endif

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
void platform_free_rw(void *addr, uint64_t len);

/**
 * Free Executable Memory
 *
 * @expects none
 * @ensures none
 *
 * @param addr the address of memory allocated using platform_alloc_rwe
 * @param len the size of the memory allocated using platform_alloc_rwe
 */
void platform_free_rwe(void *addr, uint64_t len);

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
 * Start
 *
 * Run after the start function has been executed.
 *
 * @expects none
 * @ensures none
 */
void platform_start(void);

/**
 * Stop
 *
 * Run after the stop function has been executed.
 *
 * @expects none
 * @ensures none
 */
void platform_stop(void);

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
 * Set CPU affinity
 *
 * @expects none
 * @ensures none
 *
 * @param affinity the cpu number to change to
 * @return The affinity of the CPU before the change
 */
int64_t platform_set_affinity(int64_t affinity);

/**
 * Restore CPU affinity
 *
 * @expects none
 * @ensures none
 *
 * @param affinity the cpu number to change to
 */
void platform_restore_affinity(int64_t affinity);

/**
 * Get CPU Number
 *
 * @expects none
 * @ensures none
 *
 * @return returns the current CPU number and on some systems, disables
 *     preemption
 */
int64_t platform_get_current_cpu_num(void);

/**
 * Restore Preemption
 *
 * @expects none
 * @ensures none
 */
void platform_restore_preemption(void);

#ifdef __cplusplus
}
#endif

#endif
