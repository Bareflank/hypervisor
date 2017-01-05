/*
 * Bareflank Hypervisor
 *
 * Copyright (C) 2015 Assured Information Security, Inc.
 * Author: Rian Quinn        <quinnr@ainfosec.com>
 * Author: Brendan Kerrigan  <kerriganb@ainfosec.com>
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

#include <bfelf_loader.h>

#ifdef ENABLE_BFELF_DEBUGGING
#ifndef BFELF_PRINTF
#include <stdio.h>
#define BFELF_PRINTF printf
#endif
#define DEBUG(...) BFELF_PRINTF("[ELF DEBUG]: " __VA_ARGS__)
#define INFO(...) BFELF_PRINTF(__VA_ARGS__)
#else
#define DEBUG(...)
#define INFO(...)
#endif

#ifdef KERNEL
#if defined(__linux__)
#include <linux/module.h>
#define ALERT(...) printk("[ELF ALERT]: " __VA_ARGS__)
#elif defined(__darwin__)
#define ALERT(...) IOLog("[ELF ALERT]: " __VA_ARGS__)
#elif defined(_WIN32)
#include <ntddk.h>
#pragma warning(disable : 4242)
#pragma warning(disable : 4244)
#define ALERT(...) DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,"[ELF ALERT]: " __VA_ARGS__)
#endif
#else
#ifdef __linux__
#include <stdio.h>
#define ALERT(...) printf("[ELF ALERT]: " __VA_ARGS__)
#endif
#endif

/* -------------------------------------------------------------------------- */
/* ELF Error Codes                                                            */
/* -------------------------------------------------------------------------- */

const char *
bfelf_error(bfelf64_sword value)
{
    return ec_to_str(value);
}

int64_t
private_error(const char *header,
              const char *msg,
              const char *func,
              int line,
              int64_t code)
{
    ALERT("%s [%d] %s: %s\n", func, line, header, msg);
    return code;
}

#define invalid_argument(a) \
    private_error("invalid argument", a, __func__, __LINE__, \
                  BFELF_ERROR_INVALID_ARG);

#define invalid_file(a) \
    private_error("invalid file", a, __func__, __LINE__, \
                  BFELF_ERROR_INVALID_FILE);

#define invalid_index(a) \
    private_error("invalid index", a, __func__, __LINE__, \
                  BFELF_ERROR_INVALID_INDEX);

#define invalid_string(a) \
    private_error("invalid string", a, __func__, __LINE__, \
                  BFELF_ERROR_INVALID_STRING);

#define invalid_signature(a) \
    private_error("invalid signature", a, __func__, __LINE__, \
                  BFELF_ERROR_INVALID_SIGNATURE);

#define unsupported_file(a) \
    private_error("unsupported elf file", a, __func__, __LINE__, \
                  BFELF_ERROR_UNSUPPORTED_FILE);

#define invalid_segment(a) \
    private_error("invalid segment", a, __func__, __LINE__, \
                  BFELF_ERROR_INVALID_SEGMENT);

#define invalid_section(a) \
    private_error("invalid section", a, __func__, __LINE__, \
                  BFELF_ERROR_INVALID_SECTION);

#define loader_full(a) \
    private_error("loader full", a, __func__, __LINE__, \
                  BFELF_ERROR_LOADER_FULL);

#define no_such_symbol(a) \
    private_error("no such symbol", a, __func__, __LINE__, \
                  BFELF_ERROR_NO_SUCH_SYMBOL);

#define unsupported_rel(a) \
    private_error("unsupported relocation", a, __func__, __LINE__, \
                  BFELF_ERROR_UNSUPPORTED_RELA);

#define out_of_order(a) \
    private_error("ELF API called out of order", a, __func__, __LINE__, \
                  BFELF_ERROR_OUT_OF_ORDER);

/* -------------------------------------------------------------------------- */
/* ELF Helpers                                                                */
/* -------------------------------------------------------------------------- */

int64_t
private_elf_string_equals(struct e_string_t *str1, struct e_string_t *str2)
{
    bfelf64_xword i = 0;

    if (str1->len != str2->len)
        return BFELF_ERROR_MISMATCH;

    if (str1->len == 0)
        return BFELF_ERROR_MISMATCH;

    for (i = 0; i < str1->len; i++)
    {
        if (str1->buf[i] != str2->buf[i])
            return BFELF_ERROR_MISMATCH;
    }

    return BFELF_SUCCESS;
}

int64_t
private_get_string(struct bfelf_file_t *ef,
                   struct bfelf_shdr *strtab,
                   bfelf64_word offset,
                   struct e_string_t *str)
{
    bfelf64_xword max = strtab->sh_size - offset;

    if (offset > strtab->sh_size)
        goto failure;

    str->buf = ef->file + strtab->sh_offset + offset;
    str->len = 0;

    for (str->len = 0; str->len < max; str->len++)
    {
        if (str->buf[str->len] == 0)
            break;
    }

    if (str->len >= max)
        goto failure;

    return BFELF_SUCCESS;

failure:

    str->buf = 0;
    str->len = 0;

    return invalid_file("the dynamic string table is corrupt");
}

/* -------------------------------------------------------------------------- */
/* ELF Dynamic Symbol Table                                                   */
/* -------------------------------------------------------------------------- */

int64_t
private_symbol_by_index(struct bfelf_file_t *ef,
                        bfelf64_xword index,
                        struct bfelf_sym **sym)
{
    if (index >= ef->symnum)
        return invalid_index("index out of bounds");

    *sym = &(ef->symtab[index]);

    return BFELF_SUCCESS;
}

unsigned long
private_hash(const char *name)
{
    unsigned long h = 0, g;

    while (*name)
    {
        char c = *name++;
        unsigned char uc = (unsigned char)c;

        if (c >= 0)
            h = (h << 4) + uc;
        else
            h = (h << 4) - uc;

        if ((g = (h & 0xf0000000)))
            h ^= g >> 24;

        h &= 0x0fffffff;
    }

    return h;
}

int64_t
private_check_symbol(struct bfelf_file_t *ef,
                     bfelf64_word index,
                     struct e_string_t *name,
                     struct bfelf_sym **sym)
{
    int64_t ret = 0;
    struct e_string_t str = {0, 0};

    ret = private_symbol_by_index(ef, index, sym);
    if (ret != BFELF_SUCCESS)
        goto failure;

    ret = private_get_string(ef, ef->strtab, (*sym)->st_name, &str);
    if (ret != BFELF_SUCCESS)
        goto failure;

    ret = private_elf_string_equals(name, &str);
    if (ret != BFELF_SUCCESS)
        goto failure;

    return BFELF_SUCCESS;

failure:

    *sym = 0;
    return BFELF_ERROR_MISMATCH;
}

int64_t
private_symbol_by_hash(struct bfelf_file_t *ef,
                       struct e_string_t *name,
                       struct bfelf_sym **sym)
{
    int64_t ret = 0;
    bfelf64_word i = 0;
    unsigned long x = private_hash(name->buf);

    i = ef->bucket[x % ef->nbucket];
    while (i > STN_UNDEF && i < ef->nchain)
    {
        ret = private_check_symbol(ef, i, name, sym);
        if (ret == BFELF_ERROR_MISMATCH)
        {
            i = ef->chain[i];
            continue;
        }

        return BFELF_SUCCESS;
    }

    return BFELF_ERROR_NO_SUCH_SYMBOL;
}

int64_t
private_symbol_by_name(struct bfelf_file_t *ef,
                       struct e_string_t *name,
                       struct bfelf_sym **sym)
{
    int64_t ret = 0;
    bfelf64_word i = 0;

    if (ef->hashtab != 0)
        return private_symbol_by_hash(ef, name, sym);

    for (i = 0; i < ef->symnum; i++)
    {
        ret = private_check_symbol(ef, i, name, sym);
        if (ret == BFELF_ERROR_MISMATCH)
            continue;

        return BFELF_SUCCESS;
    }

    return BFELF_ERROR_NO_SUCH_SYMBOL;
}

int64_t
private_symbol_global(struct bfelf_loader_t *loader,
                      struct e_string_t *name,
                      struct bfelf_file_t **ef_found,
                      struct bfelf_sym **sym)
{
    int64_t ret = 0;
    bfelf64_word i = 0;
    struct bfelf_sym *found_sym = 0;
    struct bfelf_file_t *ef_ignore = *ef_found;

    *sym = 0;
    *ef_found = 0;

    for (i = 0; i < loader->num; i++)
    {
        if (loader->efs[i] == ef_ignore)
            continue;

        ret = private_symbol_by_name(loader->efs[i], name, &found_sym);
        if (ret == BFELF_ERROR_NO_SUCH_SYMBOL)
            continue;

        if (ret != BFELF_SUCCESS)
            return ret;

        if (found_sym->st_value == 0)
            continue;

        *sym = found_sym;
        *ef_found = loader->efs[i];

        if (BFELF_SYM_BIND(found_sym->st_info) == bfstb_weak)
            continue;

        return BFELF_SUCCESS;
    }

    if (*sym != 0)
        return BFELF_SUCCESS;

    return no_such_symbol(name->buf);
}

/* -------------------------------------------------------------------------- */
/* ELF Relocations                                                            */
/* -------------------------------------------------------------------------- */

int64_t
private_relocate_symbol(struct bfelf_loader_t *loader,
                        struct bfelf_file_t *ef,
                        struct bfelf_rela *rela)
{
    int64_t ret = 0;
    struct e_string_t name = {0, 0};
    struct bfelf_sym *found_sym = 0;
    struct bfelf_file_t *found_ef = ef;
    bfelf64_addr *ptr = (bfelf64_addr *)(ef->exec + rela->r_offset);

    if (BFELF_REL_TYPE(rela->r_info) == BFR_X86_64_RELATIVE)
    {
        *ptr = (bfelf64_addr)(ef->exec + rela->r_addend);
        return BFELF_SUCCESS;
    }

    ret = private_symbol_by_index(ef, BFELF_REL_SYM(rela->r_info), &found_sym);
    if (ret != BFELF_SUCCESS)
        return ret;

    if (BFELF_SYM_BIND(found_sym->st_info) == bfstb_weak)
        found_ef = 0;

    if (found_sym->st_value == 0 || found_ef == 0)
    {
        ret = private_get_string(ef, ef->strtab, found_sym->st_name, &name);
        if (ret != BFELF_SUCCESS)
            return ret;

        ret = private_symbol_global(loader, &name, &found_ef, &found_sym);
        if (ret != BFELF_SUCCESS)
            return ret;
    }

    *ptr = (bfelf64_addr)(found_ef->exec + found_sym->st_value);

    switch (BFELF_REL_TYPE(rela->r_info))
    {
        case BFR_X86_64_64:
            *ptr += (bfelf64_addr)(rela->r_addend);
            break;

        case BFR_X86_64_GLOB_DAT:
        case BFR_X86_64_JUMP_SLOT:
            break;

        default:
            return unsupported_rel(name.buf);
    }

    return BFELF_SUCCESS;
}

int64_t
private_relocate_symbols(struct bfelf_loader_t *loader,
                         struct bfelf_file_t *ef)
{
    int64_t ret = 0;
    bfelf64_word r = 0;
    bfelf64_word t = 0;

    for (t = 0; t < ef->num_rela; t++)
    {
        for (r = 0; r < ef->relatab[t].num; r++)
        {
            ret = private_relocate_symbol(loader, ef, &(ef->relatab[t].tab[r]));
            if (ret != BFELF_SUCCESS)
                return ret;
        }
    }

    return BFELF_SUCCESS;
}

int64_t
private_resolve_symbol(struct bfelf_file_t *ef,
                       struct bfelf_sym *sym,
                       void **addr)
{
    *addr = ef->exec + sym->st_value;
    return BFELF_SUCCESS;
}

/* -------------------------------------------------------------------------- */
/* ELF File                                                                   */
/* -------------------------------------------------------------------------- */

int64_t
private_check_signature(struct bfelf_file_t *ef)
{
    if (ef->ehdr->e_ident[bfei_mag0] != 0x7F)
        return invalid_signature("magic #0 has unexpected value");

    if (ef->ehdr->e_ident[bfei_mag1] != 'E')
        return invalid_signature("magic #1 has unexpected value");

    if (ef->ehdr->e_ident[bfei_mag2] != 'L')
        return invalid_signature("magic #2 has unexpected value");

    if (ef->ehdr->e_ident[bfei_mag3] != 'F')
        return invalid_signature("magic #3 has unexpected value");

    return BFELF_SUCCESS;
}

int64_t
private_check_support(struct bfelf_file_t *ef)
{
    if (ef->ehdr->e_ident[bfei_class] != bfelfclass64)
        return unsupported_file("file is not 64bit");

    if (ef->ehdr->e_ident[bfei_data] != bfelfdata2lsb)
        return unsupported_file("file is not little endian");

    if (ef->ehdr->e_ident[bfei_version] != bfev_current)
        return unsupported_file("unsupported version");

    /*
     * if (ef->ehdr->e_ident[bfei_osabi] != bfelfosabi_sysv)
     *     return unsupported_file("file does not use the system v abi");
     */

    if (ef->ehdr->e_ident[bfei_abiversion] != 0)
        return unsupported_file("unsupported abi version");

    if (ef->ehdr->e_type != bfet_dyn &&
        ef->ehdr->e_type != bfet_exec)
        return unsupported_file("file must be an executable or shared library");

    if (ef->ehdr->e_machine != bfem_x86_64)
        return unsupported_file("file must be compiled for x86_64");

    if (ef->ehdr->e_version != bfev_current)
        return unsupported_file("unsupported version");

    if (ef->ehdr->e_flags != 0)
        return unsupported_file("unsupported flags");

    return BFELF_SUCCESS;
}

int64_t
private_validate_bounds(struct bfelf_file_t *ef)
{
    bfelf64_xword phtab_size = (bfelf64_xword)(ef->ehdr->e_phoff) +
                               (bfelf64_xword)(ef->ehdr->e_phentsize * ef->ehdr->e_phnum);
    bfelf64_xword shtab_size = (bfelf64_xword)(ef->ehdr->e_shoff) +
                               (bfelf64_xword)(ef->ehdr->e_shentsize * ef->ehdr->e_shnum);

    if (ef->ehdr->e_ehsize != sizeof(struct bfelf64_ehdr))
        return invalid_file("unexpected header size");

    if (ef->ehdr->e_phentsize != sizeof(struct bfelf_phdr))
        return invalid_file("unexpected program header size");

    if (ef->ehdr->e_shentsize != sizeof(struct bfelf_shdr))
        return invalid_file("unexpected section header size");

    if (phtab_size > ef->fsize)
        return invalid_file("corrupt program header table");

    if (shtab_size > ef->fsize)
        return invalid_file("corrupt section header table");

    if (ef->ehdr->e_shstrndx >= ef->ehdr->e_shnum)
        return invalid_file("section header string table index out of bounds");

    return BFELF_SUCCESS;
}

struct bfelf_phdr *
private_get_segment(struct bfelf_file_t *ef,
                    bfelf64_xword index)
{
    return &(ef->phdrtab[index]);
}

struct bfelf_shdr *
private_get_section(struct bfelf_file_t *ef,
                    bfelf64_xword index)
{
    return &(ef->shdrtab[index]);
}

int64_t
private_get_section_by_name(struct bfelf_file_t *ef,
                            struct e_string_t *name,
                            struct bfelf_shdr **shdr)
{
    int64_t ret = 0;
    bfelf64_xword i = 0;

    for (i = 0, *shdr = 0; i < ef->ehdr->e_shnum; i++)
    {
        struct e_string_t _name = {0, 0};
        struct bfelf_shdr *_shdr = private_get_section(ef, i);

        ret = private_get_string(ef, ef->shstrtab, _shdr->sh_name, &_name);
        if (ret != BFELF_SUCCESS)
            return ret;

        ret = private_elf_string_equals(name, &_name);
        if (ret == BFELF_SUCCESS)
        {
            *shdr = _shdr;
            break;
        }
    }

    return BFELF_SUCCESS;
}

int64_t
private_check_segments(struct bfelf_file_t *ef)
{
    bfelf64_xword i = 0;

    for (i = 0; i < ef->ehdr->e_phnum; i++)
    {
        struct bfelf_phdr *phdr = private_get_segment(ef, i);

        if (phdr->p_type != bfpt_load)
            continue;

        if (ef->num_loadable_segments >= BFELF_MAX_SEGMENTS)
            return loader_full("increase BFELF_MAX_SEGMENTS");

        if (phdr->p_memsz < phdr->p_filesz)
            return invalid_segment("segment mem size is less then file size");

        if (phdr->p_vaddr != phdr->p_paddr)
            return invalid_segment("expect p_vaddr == p_paddr");

        if (phdr->p_align != 0x1000 && phdr->p_align != 0x200000)
            return invalid_segment("expect 4k or 2M alignment");

        if (phdr->p_offset >= ef->fsize)
            return invalid_segment("segment offset out of bounds");

        ef->loadable_segments[ef->num_loadable_segments] = phdr;
        ef->num_loadable_segments++;
    }

    return BFELF_SUCCESS;
}

int64_t
private_check_sections(struct bfelf_file_t *ef)
{
    bfelf64_xword i = 0;
    bfelf64_xword j = 0;
    struct bfelf_shdr *shstrtab = private_get_section(ef, ef->ehdr->e_shstrndx);

    for (i = 0; i < ef->ehdr->e_shnum; i++)
    {
        bfelf64_sword valid_addr = 0;
        struct bfelf_shdr *shdr = private_get_section(ef, i);

        if (shdr->sh_type != bfsht_nobits)
        {
            if (shdr->sh_offset + shdr->sh_size > ef->fsize)
                return invalid_section("section offset / size is corrupt");
        }

        if (shdr->sh_name >= shstrtab->sh_size)
            return invalid_section("invalid section name offset");

        if (shdr->sh_link >= ef->ehdr->e_shnum)
            return invalid_section("invalid section link");

        for (j = 0; j < ef->ehdr->e_phnum; j++)
        {
            struct bfelf_phdr *phdr = private_get_segment(ef, j);

            if (shdr->sh_addr >= phdr->p_vaddr &&
                shdr->sh_addr + shdr->sh_size <= phdr->p_vaddr + phdr->p_memsz)
            {
                valid_addr = 1;
                break;
            }
        }

        if (shdr->sh_addr != 0 && valid_addr == 0)
            return invalid_section("section address is out of bounds");
    }

    return BFELF_SUCCESS;
}

int64_t
private_check_entry(struct bfelf_file_t *ef)
{
    bfelf64_xword i = 0;
    bfelf64_sword valid_addr = 0;

    for (i = 0; i < ef->ehdr->e_phnum; i++)
    {
        struct bfelf_phdr *phdr = private_get_segment(ef, i);

        if (ef->ehdr->e_entry >= phdr->p_vaddr &&
            ef->ehdr->e_entry < phdr->p_vaddr + phdr->p_memsz)
        {
            valid_addr = 1;
            break;
        }
    }

    if (ef->ehdr->e_entry != 0 && valid_addr == 0)
        return invalid_file("ELF entry corrupt");

    return BFELF_SUCCESS;
}

int64_t
private_check_section(struct bfelf_shdr *shdr,
                      bfelf64_word type,
                      bfelf64_xword flags,
                      bfelf64_xword addralign,
                      bfelf64_xword entsize)
{
    /*
     * All of the section types that we support exist in the lower 8 bits.
     * The exception to that is SHT_X86_64_UNWIND which is a processor
     * specific type for SHT_PROGBITS defined in the 64bit System V ABI.
     * Since we look for SHT_PROGBITS when we see SHT_X86_64_UNWIND, the below
     * mask fixes the issue.
     */

    if ((shdr->sh_type & 0xFF) != type)
        return invalid_section("type mismatch");

    if ((shdr->sh_flags & ~flags) != 0)
        return invalid_section("flags mismatch");

    if (shdr->sh_addralign != addralign)
        return invalid_section("address alignment mismatch");

    if (shdr->sh_entsize != 0 && shdr->sh_entsize != entsize)
        return invalid_section("entry size mismatch");

    return BFELF_SUCCESS;
}

int64_t
private_symbol_table_sections(struct bfelf_file_t *ef)
{
    int64_t ret = 0;
    bfelf64_xword i = 0;

    for (i = 0; i < ef->ehdr->e_shnum; i++)
    {
        struct bfelf_shdr *shdr = private_get_section(ef, i);

        if (shdr->sh_type == bfsht_dynsym)
        {
            ret = private_check_section(shdr, bfsht_dynsym, bfshf_a, 8,
                                        sizeof(struct bfelf_sym));
            if (ret != BFELF_SUCCESS)
                return ret;

            ef->dynsym = shdr;
            continue;
        }

        if (shdr->sh_type == bfsht_hash)
        {
            ret = private_check_section(shdr, bfsht_hash, bfshf_a, 8, 0x04);
            if (ret != BFELF_SUCCESS)
                return ret;

            ef->hashtab = shdr;
            continue;
        }
    }

    if (!ef->dynsym)
        return invalid_file("unable to locate dynammic symbol table");

    return BFELF_SUCCESS;
}

int64_t
private_get_string_table_sections(struct bfelf_file_t *ef)
{
    int64_t ret = 0;

    ef->strtab = private_get_section(ef, ef->dynsym->sh_link);
    ef->shstrtab = private_get_section(ef, ef->ehdr->e_shstrndx);

    ret = private_check_section(ef->strtab, bfsht_strtab, bfshf_a, 1, 0);
    if (ret != BFELF_SUCCESS)
        return ret;

    ret = private_check_section(ef->shstrtab, bfsht_strtab, 0, 1, 0);
    if (ret != BFELF_SUCCESS)
        return ret;

    return BFELF_SUCCESS;
}

void
private_get_symbol_tables(struct bfelf_file_t *ef)
{
    ef->symnum = ef->dynsym->sh_size / sizeof(struct bfelf_sym);
    ef->symtab = (struct bfelf_sym *)(ef->file + ef->dynsym->sh_offset);
}

int64_t
private_get_relocation_tables(struct bfelf_file_t *ef)
{
    int64_t ret = 0;
    bfelf64_xword i = 0;

    for (i = 0; i < ef->ehdr->e_shnum; i++)
    {
        struct bfelf_shdr *shdr = private_get_section(ef, i);

        if (shdr->sh_type == bfsht_rel)
            return unsupported_rel("the ELF loader does not support modules with REL "
                                   "type relocation sections");

        if (shdr->sh_type == bfsht_rela)
        {
            if (ef->num_rela >= BFELF_MAX_RELATAB)
                return loader_full("increase BFELF_MAX_RELATAB");

            ret = private_check_section(shdr, bfsht_rela, bfshf_ai, 8,
                                        sizeof(struct bfelf_rela));
            if (ret != BFELF_SUCCESS)
                return ret;

            ef->relatab[ef->num_rela].num =
                shdr->sh_size / sizeof(struct bfelf_rela);
            ef->relatab[ef->num_rela].tab =
                (struct bfelf_rela *)(ef->file + shdr->sh_offset);
            ef->num_rela++;
        }
    }

    return BFELF_SUCCESS;
}

int64_t
private_get_hash_table(struct bfelf_file_t *ef)
{
    if (ef->hashtab)
    {
        bfelf64_xword total = 0;
        bfelf64_word *p = (bfelf64_word *)(ef->hashtab->sh_offset + ef->file);

        if (sizeof(bfelf64_word) * 2 > ef->hashtab->sh_size)
            return invalid_section("hash table contents corrupt");

        ef->nbucket = p[0];
        ef->nchain = p[1];

        total = (ef->nbucket + ef->nchain + 2) * sizeof(bfelf64_word);
        if (total > ef->hashtab->sh_size)
            return invalid_section("hash table contents corrupt");

        ef->bucket = &(p[2]);
        ef->chain = &(p[2 + ef->nbucket]);
    }

    return BFELF_SUCCESS;
}

int64_t
bfelf_file_init(const char *file, uint64_t fsize, struct bfelf_file_t *ef)
{
    int64_t ret = 0;
    bfelf64_word i = 0;

    if (!file)
        return invalid_argument("file == NULL");

    if (!ef)
        return invalid_argument("ef == NULL");

    if (fsize == 0 || fsize < sizeof(struct bfelf64_ehdr))
        return invalid_argument("fsize invalid");

    for (i = 0; i < sizeof(struct bfelf_file_t); i++)
        ((char *)ef)[i] = 0;

    ef->file = file;
    ef->fsize = fsize;

    ef->ehdr = (struct bfelf64_ehdr *)file;
    ef->shdrtab = (struct bfelf_shdr *)(file + ef->ehdr->e_shoff);
    ef->phdrtab = (struct bfelf_phdr *)(file + ef->ehdr->e_phoff);

    ret = private_check_signature(ef);
    if (ret != BFELF_SUCCESS)
        goto failure;

    ret = private_check_support(ef);
    if (ret != BFELF_SUCCESS)
        goto failure;

    ret = private_validate_bounds(ef);
    if (ret != BFELF_SUCCESS)
        goto failure;

    ret = private_check_segments(ef);
    if (ret != BFELF_SUCCESS)
        goto failure;

    ret = private_check_sections(ef);
    if (ret != BFELF_SUCCESS)
        goto failure;

    ret = private_check_entry(ef);
    if (ret != BFELF_SUCCESS)
        goto failure;

    ret = private_symbol_table_sections(ef);
    if (ret != BFELF_SUCCESS)
        goto failure;

    ret = private_get_string_table_sections(ef);
    if (ret != BFELF_SUCCESS)
        goto failure;

    private_get_symbol_tables(ef);

    ret = private_get_relocation_tables(ef);
    if (ret != BFELF_SUCCESS)
        goto failure;

    ret = private_get_hash_table(ef);
    if (ret != BFELF_SUCCESS)
        goto failure;

    return BFELF_SUCCESS;

failure:

    for (i = 0; i < sizeof(struct bfelf_file_t); i++)
        ((char *)ef)[i] = 0;

    return ret;
}

int64_t
bfelf_file_num_segments(struct bfelf_file_t *ef)
{
    if (!ef)
        return invalid_argument("ef == NULL");

    return ef->num_loadable_segments;
}

int64_t
bfelf_file_get_segment(struct bfelf_file_t *ef,
                       int64_t index,
                       struct bfelf_phdr **phdr)
{
    if (!ef)
        return invalid_argument("ef == NULL");

    if (!phdr)
        return invalid_argument("phdr == NULL");

    if (index >= ef->num_loadable_segments)
        return invalid_index("index >= number of segments");

    *phdr = ef->loadable_segments[index];

    return BFELF_SUCCESS;
}

int64_t
bfelf_file_resolve_symbol(struct bfelf_file_t *ef,
                          struct e_string_t *name,
                          void **addr)
{
    int64_t ret = 0;
    struct bfelf_sym *found_sym = 0;

    if (!ef)
        return invalid_argument("ef == NULL");

    if (!name)
        return invalid_argument("name == NULL");

    if (!addr)
        return invalid_argument("addr == NULL");

    if (ef->relocated == 0)
        return out_of_order("you need to call bfelf_loader_relocate first");

    ret = private_symbol_by_name(ef, name, &found_sym);
    if (ret != BFELF_SUCCESS)
        return ret;

    ret = private_resolve_symbol(ef, found_sym, addr);
    if (ret != BFELF_SUCCESS)
        return ret;

    return BFELF_SUCCESS;
}

/* -------------------------------------------------------------------------- */
/* ELF Loader                                                                 */
/* -------------------------------------------------------------------------- */

int64_t
bfelf_loader_add(struct bfelf_loader_t *loader,
                 struct bfelf_file_t *ef,
                 char *exec)
{
    if (!loader)
        return invalid_argument("loader == NULL");

    if (!ef)
        return invalid_argument("ef == NULL");

    if (loader->num >= BFELF_MAX_MODULES)
        return loader_full("increase BFELF_MAX_MODULES");

    ef->exec = exec;
    loader->efs[loader->num++] = ef;

    return BFELF_SUCCESS;
}

int64_t
bfelf_loader_relocate(struct bfelf_loader_t *loader)
{
    int64_t ret = 0;
    bfelf64_word i = 0;

    if (!loader)
        return invalid_argument("loader == NULL");

    if (loader->relocated == 1)
        return BFELF_SUCCESS;

    for (i = 0; i < loader->num; i++)
    {
        ret = private_relocate_symbols(loader, loader->efs[i]);
        if (ret != BFELF_SUCCESS)
            return ret;

        loader->efs[i]->relocated = 1;
    }

    loader->relocated = 1;

    return BFELF_SUCCESS;
}

int64_t
bfelf_loader_resolve_symbol(struct bfelf_loader_t *loader,
                            struct e_string_t *name,
                            void **addr)
{
    int64_t ret = 0;

    struct bfelf_sym *found_sym = 0;
    struct bfelf_file_t *found_ef = 0;

    if (!loader)
        return invalid_argument("loader == NULL");

    if (!name)
        return invalid_argument("name == NULL");

    if (!addr)
        return invalid_argument("addr == NULL");

    if (loader->relocated == 0)
        return out_of_order("you need to call bfelf_loader_relocate first");

    ret = private_symbol_global(loader, name, &found_ef, &found_sym);
    if (ret != BFELF_SUCCESS)
        return ret;

    ret = private_resolve_symbol(found_ef, found_sym, addr);
    if (ret != BFELF_SUCCESS)
        return ret;

    return BFELF_SUCCESS;
}

int64_t
bfelf_loader_get_info(struct bfelf_loader_t *loader,
                      struct bfelf_file_t *ef,
                      struct section_info_t *info)
{
    int64_t ret = 0;
    struct bfelf_shdr *shdr = 0;
    struct e_string_t name_ctors = {".ctors", 6};
    struct e_string_t name_dtors = {".dtors", 6};
    struct e_string_t name_init_array = {".init_array", 11};
    struct e_string_t name_fini_array = {".fini_array", 11};
    struct e_string_t name_eh_frame = {".eh_frame", 9};
    struct section_info_t blank_info = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

    if (!loader)
        return invalid_argument("loader == NULL");

    if (!ef)
        return invalid_argument("ef == NULL");

    if (!info)
        return invalid_argument("info == NULL");

    if (loader->relocated == 0)
        return out_of_order("you need to call bfelf_loader_relocate first");

    *info = blank_info;

    ret = private_get_section_by_name(ef, &name_ctors, &shdr);
    if (ret != BFELF_SUCCESS)
        goto failure;

    if (shdr != 0)
    {
        ret = private_check_section(shdr, bfsht_progbits, bfshf_wa, 8, 0);
        if (ret != BFELF_SUCCESS)
            goto failure;

        info->ctors_addr = shdr->sh_addr + ef->exec;
        info->ctors_size = shdr->sh_size;
    }

    ret = private_get_section_by_name(ef, &name_dtors, &shdr);
    if (ret != BFELF_SUCCESS)
        goto failure;

    if (shdr != 0)
    {
        ret = private_check_section(shdr, bfsht_progbits, bfshf_wa, 8, 0);
        if (ret != BFELF_SUCCESS)
            goto failure;

        info->dtors_addr = shdr->sh_addr + ef->exec;
        info->dtors_size = shdr->sh_size;
    }

    ret = private_get_section_by_name(ef, &name_init_array, &shdr);
    if (ret != BFELF_SUCCESS)
        goto failure;

    if (shdr != 0)
    {
        ret = private_check_section(shdr, bfsht_init_array, bfshf_wa, 8, 8);
        if (ret != BFELF_SUCCESS)
            goto failure;

        info->init_array_addr = shdr->sh_addr + ef->exec;
        info->init_array_size = shdr->sh_size;
    }

    ret = private_get_section_by_name(ef, &name_fini_array, &shdr);
    if (ret != BFELF_SUCCESS)
        goto failure;

    if (shdr != 0)
    {
        ret = private_check_section(shdr, bfsht_fini_array, bfshf_wa, 8, 8);
        if (ret != BFELF_SUCCESS)
            goto failure;

        info->fini_array_addr = shdr->sh_addr + ef->exec;
        info->fini_array_size = shdr->sh_size;
    }

    ret = private_get_section_by_name(ef, &name_eh_frame, &shdr);
    if (ret != BFELF_SUCCESS)
        goto failure;

    if (shdr != 0)
    {
        ret = private_check_section(shdr, bfsht_progbits, bfshf_wa, 8, 0);
        if (ret != BFELF_SUCCESS)
            goto failure;

        info->eh_frame_addr = shdr->sh_addr + ef->exec;
        info->eh_frame_size = shdr->sh_size;
    }

    return BFELF_SUCCESS;

failure:

    *info = blank_info;
    return ret;
}
