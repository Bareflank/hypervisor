/*
 * Copyright (C) 2019 Assured Information Security, Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
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
