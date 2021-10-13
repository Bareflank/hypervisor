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

#ifndef MK_ARGS_T_H
#define MK_ARGS_T_H

#include <bfelf/bfelf_elf64_ehdr_t.h>
#include <constants.h>
#include <debug_ring_t.h>
#include <mutable_span_t.h>
#include <state_save_t.h>
#include <types.h>

#ifdef __cplusplus
extern "C"
{
#endif

#pragma pack(push, 1)

    /**
     * <!-- description -->
     *   @brief Defines the arguments sent to the _start function of the
     *     microkernel. The microkernel will have it's own C++ version of this
     *     struct that provides the actual types for each of the arguments as
     *     it expects them.
     */
    struct mk_args_t
    {
        /** @brief stores the current ppid (0x000) */
        uint16_t ppid;
        /** @brief stores the number of online pps (0x002) */
        uint16_t online_pps;
        /** @brief reserved (0x004) */
        uint32_t reserved;
        /** @brief stores the location of the microkernel's state (0x008) */
        struct state_save_t *mk_state;
        /** @brief stores the location of the root vp state (0x010) */
        struct state_save_t *root_vp_state;
        /** @brief stores the location of the debug ring (0x018) */
        struct debug_ring_t *debug_ring;
        /** @brief stores the location of the microkernel's ELF file */
        struct bfelf_elf64_ehdr_t const *mk_elf_file;
        /** @brief stores the location of the extension's ELF files */
        struct bfelf_elf64_ehdr_t const *ext_elf_files[HYPERVISOR_MAX_EXTENSIONS];
        /** @brief stores the virtual address of the MK's RPT for this CPU */
        void *rpt;
        /** @brief stores the physical address of the MK's RPT for this CPU */
        uint64_t rpt_phys;
        /** @brief stores the location of the microkernel's page pool */
        struct mutable_span_t page_pool;
        /** @brief stores the location of the microkernel's huge pool */
        struct mutable_span_t huge_pool;
    };

#pragma pack(pop)

#ifdef __cplusplus
}
#endif

#endif
