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
 * @file bfelf_loader_reloc_x64.h
 */

/*
 * System V ABI 64bit Relocations
 *
 * The following is defined in the ELF 64bit file format specification:
 * http://www.x86-64.org/documentation/abi.pdf, page 71
 *
 * @cond
 */
#define BFR_X86_64_64 bfscast(bfelf64_xword, 1)
#define BFR_X86_64_GLOB_DAT bfscast(bfelf64_xword, 6)
#define BFR_X86_64_JUMP_SLOT bfscast(bfelf64_xword, 7)
#define BFR_X86_64_RELATIVE bfscast(bfelf64_xword, 8)

/* @endcond */

/* ---------------------------------------------------------------------------------------------- */
/* ELF Relocations Implementation                                                                 */
/* ---------------------------------------------------------------------------------------------- */

/* @cond */

static inline int64_t
private_relocate_symbol(
    struct bfelf_loader_t *loader, struct bfelf_file_t *ef, const struct bfelf_rela *rela)
{
    const char *str = nullptr;
    const struct bfelf_sym *found_sym = nullptr;
    struct bfelf_file_t *found_ef = ef;
    bfelf64_addr *ptr = bfrcast(bfelf64_addr *, ef->exec_addr + rela->r_offset - ef->start_addr);

    if (BFELF_REL_TYPE(rela->r_info) == BFR_X86_64_RELATIVE) {
        *ptr = bfrcast(bfelf64_addr, ef->exec_virt + rela->r_addend);
        return BFELF_SUCCESS;
    }

    found_sym = &(ef->symtab[BFELF_REL_SYM(rela->r_info)]);

    if (BFELF_SYM_BIND(found_sym->st_info) == bfstb_weak) {
        found_ef = nullptr;
    }

    if (found_sym->st_value == 0 || found_ef == nullptr) {
        int64_t ret = 0;
        str = &(ef->strtab[found_sym->st_name]);

        ret = private_get_sym_global(loader, str, &found_ef, &found_sym);
        if (ret != BFELF_SUCCESS) {
            return ret;
        }
    }

    *ptr = bfrcast(bfelf64_addr, found_ef->exec_virt + found_sym->st_value);

    switch (BFELF_REL_TYPE(rela->r_info)) {
        case BFR_X86_64_64:
            *ptr += bfscast(bfelf64_addr, rela->r_addend);
            break;

        case BFR_X86_64_GLOB_DAT:
        case BFR_X86_64_JUMP_SLOT:
            break;

        default:
            return bfunsupported_rel(str);
    }

    return BFELF_SUCCESS;
}

/* @endcond */
