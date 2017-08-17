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
 * @file bfdwarf.h
 */

#ifndef BFDWARF_H
#define BFDWARF_H

#include <bftypes.h>
#include <bferrorcodes.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @struct dwarf_sections_t
 *
 * Struct to hold pointers to all the used DWARF sections
 *
 * @var dwarf_sections_t::debug_info_addr
 *      the virtual address of ".debug_info" after relocation
 * @var dwarf_sections_t::debug_info_size
 *      the size of ".debug_info"
 * @var dwarf_sections_t::debug_abbrev_addr
 *      the virtual address of ".debug_abbrev" after relocation
 * @var dwarf_sections_t::debug_abbrev_size
 *      the size of ".debug_abbrev"
 * @var dwarf_sections_t::debug_line_addr
 *      the virtual address of ".debug_line" after relocation
 * @var dwarf_sections_t::debug_line_size
 *      the size of ".debug_line"
 * @var dwarf_sections_t::debug_str_addr
 *      the virtual address of ".debug_str" after relocation
 * @var dwarf_sections_t::debug_str_size
 *      the size of ".debug_str"
 * @var dwarf_sections_t::debug_ranges_addr
 *      the virtual address of ".debug_ranges" after relocation
 * @var dwarf_sections_t::debug_ranges_size
 *      the size of ".debug_ranges"
 */
struct dwarf_sections_t {
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
 * Get DWARF sections
 *
 * @expects none
 * @ensures ret != nullptr
 *
 * Returns a list containing pointers to the found DWARF sections. These
 * sections are used to map instruction pointers to function names in the
 * unwinder.
 *
 * @return dwarf_sections_t pointer
 */
struct dwarf_sections_t *
get_dwarf_sections() noexcept;

#ifdef __cplusplus
}
#endif

#endif
