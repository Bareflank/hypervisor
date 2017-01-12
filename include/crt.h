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

#ifndef CRT_H
#define CRT_H

#include <types.h>
#include <error_codes.h>

#pragma pack(push, 1)

#ifdef __cplusplus
extern "C" {
#endif

struct section_info_t;

/**
 * Local Init
 *
 * Initialized a binary / module. This is very similar to _init that GCC
 * uses on Linux.This is called by the driver entry as each module. Each
 * module has this function as it is statically linked with each module as
 * it is compiled by the gcc wrapper
 *
 * @expects info != nullptr
 * @ensures none
 *
 * @param info a pointer to the section info structure that is used by the
 *     init funcion.
 */
typedef int64_t (*local_init_t)(struct section_info_t *info);

/**
 * Local Fini
 *
 * Initialized a binary / module. This is very similar to _fini that GCC
 * uses on Linux. This is called by the driver entry as each module. Each
 * module has this function as it is statically linked with each module as
 * it is compiled by the gcc wrapper
 *
 * @expects info != nullptr
 * @ensures none
 *
 * @param info a pointer to the section info structure that is used by the
 *     fini funcion.
 */
typedef int64_t (*local_fini_t)(struct section_info_t *info);

/**
 * Local Init
 *
 * Initialized a binary / module. This is very similar to _init that GCC
 * uses on Linux.This is called by the driver entry as each module. Each
 * module has this function as it is statically linked with each module as
 * it is compiled by the gcc wrapper
 *
 * @expects info != nullptr
 * @ensures none
 *
 * @param info a pointer to the section info structure that is used by the
 *     init funcion.
 */
int64_t local_init(struct section_info_t *info);

/**
 * Local Fini
 *
 * Initialized a binary / module. This is very similar to _fini that GCC
 * uses on Linux. This is called by the driver entry as each module. Each
 * module has this function as it is statically linked with each module as
 * it is compiled by the gcc wrapper
 *
 * @expects info != nullptr
 * @ensures none
 *
 * @param info a pointer to the section info structure that is used by the
 *     fini funcion.
 */
int64_t local_fini(struct section_info_t *info);

/**
 * Info Struct
 *
 * Provides information about the ELF file that is used to init/fini the
 * file.
 */
struct section_info_t
{
    void *init_addr;
    void *fini_addr;

    void *init_array_addr;
    uint64_t init_array_size;

    void *fini_array_addr;
    uint64_t fini_array_size;

    void *eh_frame_addr;
    uint64_t eh_frame_size;
};

#ifdef __cplusplus
}
#endif

#pragma pack(pop)

#endif
