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

#include <bfelf_elf64_ehdr_t.h>
#include <bfelf_elf64_phdr_t.h>
#include <constants.h>
#include <debug.h>
#include <elf_segment_t.h>
#include <platform.h>
#include <span_t.h>
#include <types.h>

/**
 * <!-- description -->
 *   @brief This function provides the guts of the
 *     alloc_and_copy_mk_elf_segments function, by performing the
 *     allocation and copy operation for a single elf segment.
 *
 * <!-- inputs/outputs -->
 *   @param phdr the program header describing the ELF segment to copy
 *   @param mk_elf_file the ELF file to copy the ELF segment from
 *   @param mk_elf_segment where to copy the ELF segment too
 *   @return 0 on success, LOADER_FAILURE on failure.
 */
int64_t
alloc_and_copy_mk_elf_segment(
    struct bfelf_elf64_phdr_t const *const phdr,
    struct span_t const *const mk_elf_file,
    struct elf_segment_t *const mk_elf_segment)
{
    uint8_t const *const src_addr = &mk_elf_file->addr[phdr->p_offset];
    uint64_t const dst_size = phdr->p_memsz;

    uint8_t *const dst_addr = (uint8_t *)platform_alloc(dst_size);
    if (NULL == dst_addr) {
        BFERROR("platform_alloc failed\n");
        goto platform_alloc_failed;
    }

    if (platform_memcpy(dst_addr, src_addr, phdr->p_filesz)) {
        BFERROR("platform_memcpy failed\n");
        goto platform_memcpy_failed;
    }

    mk_elf_segment->addr = dst_addr;
    mk_elf_segment->size = dst_size;
    mk_elf_segment->virt = phdr->p_vaddr;
    mk_elf_segment->flags = phdr->p_flags;

    return LOADER_SUCCESS;

platform_memcpy_failed:

    platform_free(dst_addr, dst_size);
platform_alloc_failed:

    platform_memset(mk_elf_segment, 0, sizeof(struct elf_segment_t));
    return LOADER_FAILURE;
}

/**
 * <!-- description -->
 *   @brief When the start VMM function is executed, the user must provide
 *     the address and size of the microkernel ELF file to be loaded and
 *     executed. Once this memory is mapped into the kernel address space,
 *     we need to allocate memory for each program segment in the ELF file
 *     and copy the contents of each ELF segment into the newly allocated
 *     memory. This is because we cannot execute directly from the ELF file
 *     itself, but instead of execute from the "loaded" version of the ELF
 *     file. Later, we will take each ELF segment and map it into the
 *     microkernel's memory space, ensuring the microkernel is capable of
 *     being executed given it's memory space.
 *
 * <!-- inputs/outputs -->
 *   @param mk_elf_file the ELF file to copy the segments from
 *   @param mk_elf_segments where to copy the ELF segments too
 *   @return 0 on success, LOADER_FAILURE on failure.
 */
int64_t
alloc_and_copy_mk_elf_segments(
    struct span_t const *const mk_elf_file,
    struct elf_segment_t *const mk_elf_segments)
{
    int64_t ret = LOADER_SUCCESS;
    uint64_t idx = ((uint64_t)0);
    bfelf_elf64_half phdr_idx;
    struct bfelf_elf64_ehdr_t const *ehdr = NULL;
    struct bfelf_elf64_phdr_t const *phdrtab = NULL;

    for (idx = ((uint64_t)0); idx < HYPERVISOR_MAX_SEGMENTS; ++idx) {
        struct elf_segment_t *const segment = &mk_elf_segments[idx];
        platform_memset(segment, 0, sizeof(struct elf_segment_t));
    }

    if (validate_elf64_ehdr(mk_elf_file->addr)) {
        BFERROR("validate_elf64_ehdr failed\n");
        return LOADER_FAILURE;
    }

    if (get_elf64_ehdr(mk_elf_file->addr, &ehdr)) {
        BFERROR("get_elf64_ehdr failed\n");
        return LOADER_FAILURE;
    }

    if (get_elf64_phdrtab(mk_elf_file->addr, &phdrtab)) {
        BFERROR("get_elf64_phdrtab failed\n");
        return LOADER_FAILURE;
    }

    idx = ((uint64_t)0);
    for (phdr_idx = 0; phdr_idx < ehdr->e_phnum; ++phdr_idx) {
        struct bfelf_elf64_phdr_t const *const phdr = &phdrtab[phdr_idx];

        if (bfelf_pt_load != phdr->p_type) {
            continue;
        }

        if (idx < HYPERVISOR_MAX_SEGMENTS) {
            struct elf_segment_t *const dst = &mk_elf_segments[idx];
            ret = alloc_and_copy_mk_elf_segment(phdr, mk_elf_file, dst);
            if (ret) {
                BFERROR("alloc_and_copy_mk_elf_segment failed\n");
                break;
            }

            ++idx;
        }
        else {
            BFERROR("provided ELF file has too many PT_LOAD segments\n");
            ret = LOADER_FAILURE;
            break;
        }
    }

    if (ret) {
        for (idx = ((uint64_t)0); idx < HYPERVISOR_MAX_SEGMENTS; ++idx) {
            struct elf_segment_t *const segment = &mk_elf_segments[idx];
            platform_free(segment->addr, segment->size);
            platform_memset(segment, 0, sizeof(struct elf_segment_t));
        }

        return LOADER_FAILURE;
    }

    return LOADER_SUCCESS;
}
