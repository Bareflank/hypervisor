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

#include <debug.h>
#include <dump_ext_elf_files.h>
#include <elf_file_t.h>
#include <platform.h>
#include <types.h>

/**
 * <!-- description -->
 *   @brief Outputs the contents of a provided array of extension ELF files
 *
 * <!-- inputs/outputs -->
 *   @param files the array of extension ELF files to output
 */
void
dump_ext_elf_files(struct elf_file_t const *const files) NOEXCEPT
{
    uint64_t mut_i;
    platform_expects(NULLPTR != files);

    for (mut_i = ((uint64_t)0); mut_i < HYPERVISOR_MAX_EXTENSIONS; ++mut_i) {
        if (NULLPTR != files[mut_i].addr) {
            bfdebug_d32("ext elf file", (uint32_t)mut_i);
            bfdebug_x64(" - addr", (uint64_t)files[mut_i].addr);
            bfdebug_x64(" - size", files[mut_i].size);
        }
        else {
            bf_touch();
        }
    }
}
