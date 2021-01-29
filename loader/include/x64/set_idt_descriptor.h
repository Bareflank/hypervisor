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

#ifndef SET_IDT_DESCRIPTOR_H
#define SET_IDT_DESCRIPTOR_H

#include <interrupt_descriptor_table_register_t.h>
#include <types.h>

/**
 * <!-- description -->
 *   @brief Sets an IDT's descriptor given an index into the IDT to
 *     set and the offset, selector and attribute values to set the descriptor
 *     to.
 *
 * <!-- inputs/outputs -->
 *   @param idtr a pointer to the idtr that stores the IDT to set
 *   @param idx the index of the descriptor in the provided IDT to set
 *   @param offset the offset to set the decriptor to in the provided IDT
 *     at the provided index
 *   @param selector the selector to set the decriptor to in the provided IDT
 *     at the provided index
 *   @param attrib the attributes to set the decriptor to in the provided IDT
 *     at the provided index
 *   @return 0 on success, LOADER_FAILURE on failure.
 */
int64_t set_idt_descriptor(
    struct interrupt_descriptor_table_register_t const *const idtr,
    uint32_t const idx,
    uint64_t const offset,
    uint16_t const selector,
    uint16_t const attrib);

#endif
