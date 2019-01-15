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
 * @file bfmemory.h
 */

#ifndef BFMEMORY_H
#define BFMEMORY_H

#include <bftypes.h>
#include <bfconstants.h>
#include <bferrorcodes.h>

#pragma pack(push, 1)

#ifdef __cplusplus
extern "C" {
#endif

/* @cond */

#define MEMORY_TYPE_R 0x1U
#define MEMORY_TYPE_W 0x2U
#define MEMORY_TYPE_E 0x4U

/* @endcond */

/**
 * @struct memory_descriptor
 *
 * Memory Descriptor
 *
 * A memory descriptor provides information about a block of memory.
 * Typically, each page of memory that the VMM uses will have a memory
 * descriptor associated with it. The VMM will use this information to create
 * its resources, as well as generate page tables as needed.
 *
 * @var memory_descriptor::phys
 *     the starting physical address of the block of memory
 * @var memory_descriptor::virt
 *     the starting virtual address of the block of memory
 * @var memory_descriptor::type
 *     the type of memory block. This is likely architecture specific as
 *     this holds information about access rights, etc...
 */
struct memory_descriptor {
    uint64_t phys;
    uint64_t virt;
    uint64_t type;
};

#ifdef __cplusplus
}
#endif

#pragma pack(pop)

#endif
