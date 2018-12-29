/*
 * Bareflank Hypervisor
 * Copyright (C) 2017 Assured Information Security, Inc.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
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
