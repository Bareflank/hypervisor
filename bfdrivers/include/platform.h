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

#ifndef PLATFORM_H
#define PLATFORM_H

#include <types.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Allocate Memory
 *
 * Used by the common code to allocate virtual memory.
 *
 * @param len the size of virtual memory to be allocated in bytes.
 * @return a virtual address pointing to the newly allocated memory
 */
void *platform_alloc_rw(int64_t len);

/**
 * Allocate Executable Memory
 *
 * Used by the common code to allocate executable virtual memory.
 *
 * @param len the size of virtual memory to be allocated in bytes.
 * @return a virtual address pointing to the newly allocated memory
 */
void *platform_alloc_rwe(int64_t len);

/**
 * Free Memory
 *
 * Used by the common code to free virtual memory that was allocated
 * using the platform_alloc function.
 *
 * @param addr the virtual address returned from platform_alloc
 * @param len the size of the memory allocated
 */
void platform_free_rw(void *addr, int64_t len);

/**
 * Free Executable Memory
 *
 * Used by the common code to free virtual memory that was allocated
 * using the platform_alloc_exec function.
 *
 * @param addr the virtual address returned from platform_alloc_exec
 * @param len the size of the memory allocated
 */
void platform_free_rwe(void *addr, int64_t len);

/**
 * Convert Virtual Address to Physical Address
 *
 * Given a virtual address, this function returns the associated physical
 * address. Note that any page pool issues should be handle by the platform
 * (i.e. the users of this function should be able to provide any virtual
 * address, regardless of where the address originated from).
 *
 * @param virt the virtual address to convert
 * @return the physical address assocaited with the provided virtual address
 */
void *platform_virt_to_phys(void *virt);

/**
 * Memset
 *
 * @param ptr a pointer to the memory to set
 * @param value the value to set each byte to
 * @param num the number of bytes to set
 */
void platform_memset(void *ptr, char value, int64_t num);

/**
 * Memcpy
 *
 * @param dst a pointer to the memory to copy to
 * @param src a pointer to the memory to copy from
 * @param num the number of bytes to copy
 */
void platform_memcpy(void *dst, const void *src, int64_t num);

/**
 * Start
 *
 * Run after the start function has been executed.
 */
void platform_start(void);

/**
 * Stop
 *
 * Run after the stop function has been executed.
 */
void platform_stop(void);

/**
 * Get Number of CPUs
 *
 * @return returns the total number of CPUs available to the driver.
 */
int64_t
platform_num_cpus(void);

/**
 * Set CPU affinity
 *
 * Changes the current core that the driver is running on.
 *
 * @param affinity the cpu number to change to
 * @return The affinity mask of the CPU before the change
 */
int64_t
platform_set_affinity(int64_t affinity);

/**
 * Restore CPU affinity
 *
 * If an OS requires the cores used by the user space thread
 * to match on return from a call into the kernel (e.g. IOCTL),
 * reset the affinity to it's previous state.
 *
 * @param affinity the cpu affinity mask.
 *
 */
void
platform_restore_affinity(int64_t affinity_mask);
#ifdef __cplusplus
}
#endif

#endif
