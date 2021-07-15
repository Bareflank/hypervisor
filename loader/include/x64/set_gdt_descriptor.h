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

#ifndef SET_GDT_DESCRIPTOR_H
#define SET_GDT_DESCRIPTOR_H

#include <global_descriptor_table_register_t.h>
#include <types.h>

/**
 * <!-- description -->
 *   @brief Sets a GDT's descriptor given a selector into the GDT to
 *     set and the base, limit and attribute values to set the descriptor
 *     to. If the attribute flags set the global flag, the limit
 *
 * <!-- inputs/outputs -->
 *   @param gdtr a pointer to the gdtr that stores the GDT to set
 *   @param selector the selector of the descriptor in the provided GDT
 *     to get from
 *   @param base the base address to set the decriptor to in the provided GDT
 *     at the provided index
 *   @param limit the limit to set the decriptor to in the provided GDT
 *     at the provided index
 *   @param attrib the attributes to set the decriptor to in the provided GDT
 *     at the provided index
 *   @return LOADER_SUCCESS on success, LOADER_FAILURE on failure.
 */
int64_t set_gdt_descriptor(
    struct global_descriptor_table_register_t const *const gdtr,
    uint16_t const selector,
    uint64_t const base,
    uint32_t const limit,
    uint16_t const attrib);

#endif
