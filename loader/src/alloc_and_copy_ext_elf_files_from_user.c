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

#include <constants.h>
#include <debug.h>
#include <platform.h>
#include <span_t.h>
#include <types.h>

/**
 * <!-- description -->
 *   @brief This function provides the guts of the
 *     alloc_and_copy_ext_elf_files_from_user function, by performing the
 *     allocation and copy operation for a single elf file.
 *
 * <!-- inputs/outputs -->
 *   @param ext_elf_files_from_user the ELF files to copy
 *   @param copied_ext_elf_files where to copy the ELF files too
 *   @return 0 on success, LOADER_FAILURE on failure.
 */
static int64_t
alloc_and_copy_ext_elf_file_from_user(
    struct span_t const *const ext_elf_file_from_user,
    struct span_t *const copied_ext_elf_file)
{
    uint8_t const *const src_addr = ext_elf_file_from_user->addr;
    uint64_t const dst_size = ext_elf_file_from_user->size;

    uint8_t *const dst_addr = (uint8_t *)platform_alloc(dst_size);
    if (NULL == dst_addr) {
        BFERROR("platform_alloc failed\n");
        goto platform_alloc_failed;
    }

    if (platform_copy_from_user(dst_addr, src_addr, dst_size)) {
        BFERROR("platform_copy_from_user failed\n");
        goto platform_copy_from_user_failed;
    }

    copied_ext_elf_file->addr = dst_addr;
    copied_ext_elf_file->size = dst_size;

    return LOADER_SUCCESS;

platform_copy_from_user_failed:

    platform_free(dst_addr, dst_size);
platform_alloc_failed:

    platform_memset(copied_ext_elf_file, 0, sizeof(struct span_t));
    return LOADER_FAILURE;
}

/**
 * <!-- description -->
 *   @brief When the start VMM function is executed, the user must provide
 *     the address and size of the extension ELF files to be loaded and
 *     executed. This ELF files exist in user-space memory and cannot be
 *     directly accessed. As a result, we must copy the arrays from user
 *     space into arrays in the kernel where the loader exists. This
 *     function performs this copy by first allocating arrays the size
 *     of the ELF files being copied and then copies the contents to these
 *     newly allocated arrays. For this reason, once this ELF files are no
 *     longer needed, you must free the ELF files as memory was previously
 *     allocated.
 *
 * <!-- inputs/outputs -->
 *   @param ext_elf_files_from_user the ELF files to copy
 *   @param copied_ext_elf_files where to copy the ELF files too
 *   @return 0 on success, LOADER_FAILURE on failure.
 */
int64_t
alloc_and_copy_ext_elf_files_from_user(
    struct span_t const *const ext_elf_files_from_user,
    struct span_t *const copied_ext_elf_files)
{
    int64_t ret = LOADER_SUCCESS;
    uint64_t idx;

    for (idx = 0; idx < HYPERVISOR_MAX_EXTENSIONS; ++idx) {
        struct span_t *const file = &copied_ext_elf_files[idx];
        platform_memset(file, 0, sizeof(struct span_t));
    }

    for (idx = ((uint64_t)0); idx < HYPERVISOR_MAX_EXTENSIONS; ++idx) {
        struct span_t const *const src = &ext_elf_files_from_user[idx];
        struct span_t *const dst = &copied_ext_elf_files[idx];
        if (src->addr != NULL && src->size != ((uint64_t)0)) {
            ret = alloc_and_copy_ext_elf_file_from_user(src, dst);
            if (ret) {
                break;
            }
        }
        else {
            break;
        }
    }

    if (ret) {
        for (idx = ((uint64_t)0); idx < HYPERVISOR_MAX_EXTENSIONS; ++idx) {
            struct span_t *const file = &copied_ext_elf_files[idx];
            platform_free(file->addr, file->size);
            platform_memset(file, 0, sizeof(struct span_t));
        }

        return LOADER_FAILURE;
    }

    return LOADER_SUCCESS;
}
