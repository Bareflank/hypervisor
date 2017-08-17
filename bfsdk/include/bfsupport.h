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
 * @file bfsupport.h
 */

#ifndef BFSUPPORT_H
#define BFSUPPORT_H

#include <bftypes.h>
#include <bfconstants.h>

/**
 * @struct section_info_t
 *
 * Provides information about the ELF file that is used to init/fini the
 * file.
 *
 * @var section_info_t::init_addr
 *      the virtual address of ".init" after relocation
 * @var section_info_t::fini_addr
 *      the virtual address of ".fini" after relocation
 * @var section_info_t::init_array_addr
 *      the virtual address of ".init_array" after relocation
 * @var section_info_t::init_array_size
 *      the size of ".init_array"
 * @var section_info_t::fini_array_addr
 *      the virtual address of ".fini_array" after relocation
 * @var section_info_t::fini_array_size
 *      the size of ".fini_array"
 * @var section_info_t::eh_frame_addr
 *      the virtual address of ".eh_frame" after relocation
 * @var section_info_t::eh_frame_size
 *      the size of ".eh_frame"
 * @var section_info_t::debug_info_addr
 *      the virtual address of ".debug_info" after relocation
 * @var section_info_t::debug_info_size
 *      the size of ".debug_info"
 * @var section_info_t::debug_abbrev_addr
 *      the virtual address of ".debug_abbrev" after relocation
 * @var section_info_t::debug_abbrev_size
 *      the size of ".debug_abbrev"
 * @var section_info_t::debug_line_addr
 *      the virtual address of ".debug_line" after relocation
 * @var section_info_t::debug_line_size
 *      the size of ".debug_line"
 * @var section_info_t::debug_str_addr
 *      the virtual address of ".debug_str" after relocation
 * @var section_info_t::debug_str_size
 *      the size of ".debug_str"
 * @var section_info_t::debug_ranges_addr
 *      the virtual address of ".debug_ranges" after relocation
 * @var section_info_t::debug_ranges_size
 *      the size of ".debug_ranges"
 */
struct section_info_t {
    void *init_addr;
    void *fini_addr;

    void *init_array_addr;
    uint64_t init_array_size;

    void *fini_array_addr;
    uint64_t fini_array_size;

    void *eh_frame_addr;
    uint64_t eh_frame_size;

    void *debug_info_addr;
    uint64_t debug_info_size;

    void *debug_abbrev_addr;
    uint64_t debug_abbrev_size;

    void *debug_line_addr;
    uint64_t debug_line_size;

    void *debug_str_addr;
    uint64_t debug_str_size;

    void *debug_ranges_addr;
    uint64_t debug_ranges_size;
};

/**
 * @struct crt_info_t
 *
 * Provides information for executing an application including section
 * information, the program break and arguments.
 *
 * @var crt_info_t::arg_type
 *     0 = argc/argv, 1 == arg#, undefined otherwise
 * @var crt_info_t::argc
 *     the number of arguments
 * @var crt_info_t::argv
 *     the arguments
* @var crt_info_t::request
 *     -
 * @var crt_info_t::arg1
 *     integer argument #1
 * @var crt_info_t::arg2
 *     integer argument #2
 * @var crt_info_t::arg3
 *     integer argument #3
 * @var crt_info_t::info_num
 *     the number of modules
 * @var crt_info_t::info
 *     the section info for each module
 * @var crt_info_t::func
 *     (optional) function to call
 * @var crt_info_t::vcpuid
 *     (optional) vcpuid the executable is running on
 * @var crt_info_t::program_break
 *     (optional) the executable's program break
 */
struct crt_info_t {

    int arg_type;

    int argc;
    const char **argv;

    uintptr_t request;
    uintptr_t arg1;
    uintptr_t arg2;
    uintptr_t arg3;

    int info_num;
    struct section_info_t info[MAX_NUM_MODULES];

    uintptr_t func;
    uintptr_t vcpuid;
    uintptr_t program_break;
};

/**
 * Request IDs
 *
 * The following defines the different types of requests that can be made
 * when calling bfmain instead of main. Note that these are simply the
 * currently defined requests, users can add to this as needed.
 *
 * @cond
 */

#define BF_REQUEST_INIT 0
#define BF_REQUEST_FINI 1
#define BF_REQUEST_VMM_INIT 2
#define BF_REQUEST_VMM_FINI 3
#define BF_REQUEST_ADD_MDL 4
#define BF_REQUEST_GET_DRR 5
#define BF_REQUEST_END 0xFFFF

/* @endcond */

/**
 * Start
 *
 * Defines the function signature for the _start function
 */
#ifdef __cplusplus
using _start_t = int64_t (*)(char *stack, const struct crt_info_t *);
#else
typedef int64_t (*_start_t)(char *stack, const struct crt_info_t *);
#endif

#endif
