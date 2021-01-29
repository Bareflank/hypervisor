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

#ifndef START_VMM_ARGS_T_H
#define START_VMM_ARGS_T_H

#include "span_t.h"

#include <stdint.h>

#pragma pack(push, 1)

/** @brief defines the IOCTL index for starting the VMM */
#define LOADER_START_VMM_CMD ((uint32_t)0xBF01)

/**
 * @struct start_vmm_args_t
 *
 * <!-- description -->
 *   @brief Defines the information that a userspace application needs to
 *     provide to start the VMM.
 */
struct start_vmm_args_t
{
    /** @brief set to HYPERVISOR_VERSION */
    uint64_t ver;

    /** @brief stores the number of pages the kernel should reserve for
     *    the microkernel's page pool. If this is set to 0, the loader
     *    will reserve the default number of pages. */
    uint32_t page_pool_size;

    /** @brief reserved */
    uint32_t reserved;

    /** @brief stores the ELF file associated with the microkernel */
    struct span_t mk_elf_file;
    /** @brief stores the ELF files associated with the extensions */
    struct span_t ext_elf_files[HYPERVISOR_MAX_EXTENSIONS];
};

#pragma pack(pop)

#endif
