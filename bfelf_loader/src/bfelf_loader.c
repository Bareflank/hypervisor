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
#include <stdlib.h>
#define ALERT(...) printf("[ELF ALERT]: " __VA_ARGS__)
#endif
#endif

/* -------------------------------------------------------------------------- */
/* ELF Error Codes                                                            */
/* -------------------------------------------------------------------------- */

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

#define invalid_signature(a) \
    private_error("invalid signature", a, __func__, __LINE__, \
                  BFELF_ERROR_INVALID_SIGNATURE);

#define unsupported_file(a) \
    private_error("unsupported elf file", a, __func__, __LINE__, \
                  BFELF_ERROR_UNSUPPORTED_FILE);

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
    private_error("elf api called out of order", a, __func__, __LINE__, \
                  BFELF_ERROR_OUT_OF_ORDER);

/* -------------------------------------------------------------------------- */
/* ELF Helpers                                                                */
/* -------------------------------------------------------------------------- */

int64_t
private_strcmp(const char *s1, const char *s2)
{
    while (*s1 && (*s1 == *s2))
        s1++, s2++;

    return *s1 == *s2 ? BFELF_SUCCESS : BFELF_ERROR_MISMATCH;
}

/* -------------------------------------------------------------------------- */
/* ELF Symbol Table                                                           */
/* -------------------------------------------------------------------------- */

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
private_get_sym_by_hash(struct bfelf_file_t *ef,
                        const char *name,
                        struct bfelf_sym **sym)
{
    int64_t ret = 0;
    bfelf64_word i = 0;
    unsigned long x = private_hash(name);

    i = ef->bucket[x % ef->nbucket];
    while (i > STN_UNDEF && i < ef->nchain)
    {
        char *str = 0;

        *sym = &(ef->symtab[i]);
        str = &(ef->strtab[(*sym)->st_name]);

        ret = private_strcmp(name, str);
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
private_get_sym_by_name(struct bfelf_file_t *ef,
                        const char *name,
                        struct bfelf_sym **sym)
{
    int64_t ret = 0;
    bfelf64_word i = 0;

    if (ef->hash != 0)
        return private_get_sym_by_hash(ef, name, sym);

    for (i = 0; i < ef->symnum; i++)
    {
        char *str = 0;

        *sym = &(ef->symtab[i]);
        str = &(ef->strtab[(*sym)->st_name]);

        ret = private_strcmp(name, str);
        if (ret == BFELF_ERROR_MISMATCH)
            continue;

        return BFELF_SUCCESS;
    }

    return BFELF_ERROR_NO_SUCH_SYMBOL;
}

int64_t
private_get_sym_global(struct bfelf_loader_t *loader,
                       const char *name,
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

        ret = private_get_sym_by_name(loader->efs[i], name, &found_sym);
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

    return no_such_symbol(name);
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
    const char *str = 0;
    struct bfelf_sym *found_sym = 0;
    struct bfelf_file_t *found_ef = ef;
    bfelf64_addr *ptr = (bfelf64_addr *)(ef->exec_addr + rela->r_offset - ef->start_addr);

    if (BFELF_REL_TYPE(rela->r_info) == BFR_X86_64_RELATIVE)
    {
        *ptr = (bfelf64_addr)(ef->exec_virt + rela->r_addend);
        return BFELF_SUCCESS;
    }

    found_sym = &(ef->symtab[BFELF_REL_SYM(rela->r_info)]);

    if (BFELF_SYM_BIND(found_sym->st_info) == bfstb_weak)
        found_ef = 0;

    if (found_sym->st_value == 0 || found_ef == 0)
    {
        str = &(ef->strtab[found_sym->st_name]);

        ret = private_get_sym_global(loader, str, &found_ef, &found_sym);
        if (ret != BFELF_SUCCESS)
            return ret;
    }

    *ptr = (bfelf64_addr)(found_ef->exec_virt + found_sym->st_value);

    switch (BFELF_REL_TYPE(rela->r_info))
    {
        case BFR_X86_64_64:
            *ptr += (bfelf64_addr)(rela->r_addend);
            break;

        case BFR_X86_64_GLOB_DAT:
        case BFR_X86_64_JUMP_SLOT:
            break;

        default:
            return unsupported_rel(str);
    }

    return BFELF_SUCCESS;
}

int64_t
private_relocate_symbols(struct bfelf_loader_t *loader,
                         struct bfelf_file_t *ef)
{
    int64_t ret = 0;
    bfelf64_word i = 0;

    for (i = 0; i < ef->relanum; i++)
    {
        struct bfelf_rela *rela = &(ef->relatab[i]);

        ret = private_relocate_symbol(loader, ef, rela);
        if (ret != BFELF_SUCCESS)
            return ret;
    }

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

    if (ef->ehdr->e_ident[bfei_osabi] != bfelfosabi_sysv)
        return unsupported_file("file does not use the system v abi");

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
private_process_segments(struct bfelf_file_t *ef)
{
    bfelf64_xword i = 0;

    for (i = 0; i < ef->ehdr->e_phnum; i++)
    {
        struct bfelf_phdr *phdr = &(ef->phdrtab[i]);

        switch (phdr->p_type)
        {
            case bfpt_load:

                if (ef->num_loadable_segments < BFELF_MAX_SEGMENTS)
                {
                    ef->total_memsz = phdr->p_vaddr + phdr->p_memsz;
                    ef->loadable_segments[ef->num_loadable_segments++] = phdr;
                }

                break;

            case bfpt_dynamic:
                ef->dynoff = phdr->p_offset;
                ef->dynnum = phdr->p_filesz / sizeof(struct bfelf_dyn);
                break;

            case bfpt_gnu_stack:
                ef->stack_flags = phdr->p_flags;
                break;

            case bfpt_gnu_relro:
                ef->relaro_vaddr = phdr->p_vaddr;
                ef->relaro_memsz = phdr->p_memsz;
                break;
        }
    }

    if (ef->num_loadable_segments == 0)
        return invalid_file("there are no loaded segments");

    ef->start_addr = ef->loadable_segments[0]->p_vaddr;
    ef->total_memsz -= ef->start_addr;

    for (i = 0; i < ef->num_loadable_segments; i++)
    {
        struct bfelf_phdr *phdr = ef->loadable_segments[i];

        ef->load_instr[i].perm = phdr->p_flags;
        ef->load_instr[i].mem_offset = phdr->p_vaddr - ef->start_addr;
        ef->load_instr[i].file_offset = phdr->p_offset;
        ef->load_instr[i].memsz = phdr->p_memsz;
        ef->load_instr[i].filesz = phdr->p_filesz;
        ef->load_instr[i].virt_addr = phdr->p_vaddr;

        ef->num_load_instr++;
    }

    return BFELF_SUCCESS;
}

int64_t
bfelf_file_init(const char *file, uint64_t filesz, struct bfelf_file_t *ef)
{
    int64_t ret = 0;
    bfelf64_word i = 0;

    if (!file)
        return invalid_argument("file == NULL");

    if (!ef)
        return invalid_argument("ef == NULL");

    if (filesz == 0 || filesz < sizeof(struct bfelf_ehdr))
        return invalid_argument("filesz invalid");

    for (i = 0; i < sizeof(struct bfelf_file_t); i++)
        ((char *)ef)[i] = 0;

    ef->file = file;
    ef->filesz = filesz;

    ef->ehdr = (struct bfelf_ehdr *)file;
    ef->phdrtab = (struct bfelf_phdr *)(file + ef->ehdr->e_phoff);
    ef->shdrtab = (struct bfelf_shdr *)(file + ef->ehdr->e_shoff);

    ret = private_check_signature(ef);
    if (ret != BFELF_SUCCESS)
        goto failure;

    ret = private_check_support(ef);
    if (ret != BFELF_SUCCESS)
        goto failure;

    ret = private_process_segments(ef);
    if (ret != BFELF_SUCCESS)
        goto failure;

    ef->entry = ef->ehdr->e_entry;

    /*
     * We need to take one extra step to get the .eh_frame section since there
     * is no information in the program headers about it's location or it's
     * size. We could use the .eh_frame_hdr to get the location, but it does
     * not contain the size, so we use this hack below. It locates the
     * section information in the ELF file, and records it. It just so happens
     * that .eh_frame will be loaded into the first segment of the executable
     * with a 0 offset, which means the .eh_frame location is the same in both
     * the file, and the exec_* memory.
     */

    for (i = 0; i < ef->ehdr->e_shnum; i++)
    {
        struct bfelf_shdr *shdr = &(ef->shdrtab[i]);

        if (shdr->sh_type == bfsht_x86_64_unwind)
        {
            ef->eh_frame = shdr->sh_offset;
            ef->eh_framesz = shdr->sh_size;
            break;
        }
    }

    return BFELF_SUCCESS;

failure:

    for (i = 0; i < sizeof(struct bfelf_file_t); i++)
        ((char *)ef)[i] = 0;

    return ret;
}

int64_t
bfelf_file_num_load_instrs(struct bfelf_file_t *ef)
{
    if (!ef)
        return invalid_argument("ef == NULL");

    return (int64_t)ef->num_load_instr;
}

int64_t
bfelf_file_get_load_instr(struct bfelf_file_t *ef,
                          uint64_t index,
                          struct bfelf_load_instr **instr)
{
    if (!ef)
        return invalid_argument("ef == NULL");

    if (!instr)
        return invalid_argument("phdr == NULL");

    if (index >= ef->num_load_instr)
        return invalid_index("index >= number of load instructions");

    *instr = &(ef->load_instr[index]);
    return BFELF_SUCCESS;
}

int64_t
bfelf_file_resolve_symbol(struct bfelf_file_t *ef,
                          const char *name,
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

    ret = private_get_sym_by_name(ef, name, &found_sym);
    if (ret != BFELF_SUCCESS)
        return ret;

    *addr = ef->exec_virt + found_sym->st_value;
    return BFELF_SUCCESS;
}

int64_t
bfelf_file_get_section_info(struct bfelf_file_t *ef,
                            struct section_info_t *info)
{
    bfelf64_word i = 0;

    if (!ef)
        return invalid_argument("ef == NULL");

    if (!info)
        return invalid_argument("info == NULL");

    for (i = 0; i < sizeof(struct section_info_t); i++)
        ((char *)info)[i] = 0;

    if (ef->init != 0)
        info->init_addr = ef->init + ef->exec_virt;

    if (ef->fini != 0)
        info->fini_addr = ef->fini + ef->exec_virt;

    if (ef->init_array != 0)
    {
        info->init_array_addr = ef->init_array + ef->exec_virt;
        info->init_array_size = ef->init_arraysz;
    }

    if (ef->fini_array != 0)
    {
        info->fini_array_addr = ef->fini_array + ef->exec_virt;
        info->fini_array_size = ef->fini_arraysz;
    }

    if (ef->eh_frame != 0)
    {
        info->eh_frame_addr = ef->eh_frame + ef->exec_virt;
        info->eh_frame_size = ef->eh_framesz;
    }

    return BFELF_SUCCESS;
}

int64_t
bfelf_file_get_entry(struct bfelf_file_t *ef,
                     void **addr)
{
    if (!ef)
        return invalid_argument("ef == NULL");

    if (!addr)
        return invalid_argument("addr == NULL");

    *addr = (void *)(ef->entry + ef->exec_virt);
    return BFELF_SUCCESS;
}

int64_t
bfelf_file_get_stack_perm(struct bfelf_file_t *ef,
                          bfelf64_xword *perm)
{
    if (!ef)
        return invalid_argument("ef == NULL");

    if (!perm)
        return invalid_argument("perm == NULL");

    *perm = ef->stack_flags;
    return BFELF_SUCCESS;
}

int64_t
bfelf_file_get_relro(struct bfelf_file_t *ef,
                     bfelf64_addr *addr,
                     bfelf64_xword *size)
{
    if (!ef)
        return invalid_argument("ef == NULL");

    if (!addr)
        return invalid_argument("addr == NULL");

    if (!size)
        return invalid_argument("size == NULL");

    *addr = ef->relaro_vaddr + (bfelf64_addr)ef->exec_virt;
    *size = ef->relaro_memsz;
    return BFELF_SUCCESS;
}

int64_t
bfelf_file_get_num_needed(struct bfelf_file_t *ef)
{
    if (!ef)
        return invalid_argument("ef == NULL");

    return (int64_t)ef->num_needed;
}

int64_t
bfelf_file_get_needed(struct bfelf_file_t *ef,
                      uint64_t index,
                      char **needed)
{
    if (!ef)
        return invalid_argument("ef == NULL");

    if (!needed)
        return invalid_argument("needed == NULL");

    if (index >= ef->num_needed)
        return invalid_index("index >= number of needed");

    *needed = &(ef->strtab[ef->needed[index]]);
    return BFELF_SUCCESS;
}

int64_t
bfelf_file_get_total_size(struct bfelf_file_t *ef)
{
    if (!ef)
        return invalid_argument("ef == NULL");

    return (int64_t)ef->total_memsz;
}

int64_t
bfelf_file_get_pic_pie(struct bfelf_file_t *ef)
{
    if (!ef)
        return invalid_argument("ef == NULL");

    return ef->start_addr == 0 ? 1 : 0;
}

/* -------------------------------------------------------------------------- */
/* ELF Loader                                                                 */
/* -------------------------------------------------------------------------- */

void
private_process_dynamic_section(struct bfelf_file_t *ef)
{
    bfelf64_xword i = 0;
    bfelf64_xword relasz = 0;
    bfelf64_xword relaent = 0;

    ef->num_needed = 0;

    for (i = 0; i < ef->dynnum; i++)
    {
        struct bfelf_dyn *dyn = &(ef->dyntab[i]);

        switch (dyn->d_tag)
        {
            case bfdt_null:
                goto done;

            case bfdt_needed:

                if (ef->num_needed < BFELF_MAX_NEEDED)
                    ef->needed[ef->num_needed++] = dyn->d_val;

                break;

            case bfdt_hash:

                ef->hash = (bfelf64_word *)(dyn->d_val + ef->exec_addr - ef->start_addr);

                ef->nbucket = ef->hash[0];
                ef->nchain = ef->hash[1];
                ef->bucket = &(ef->hash[2]);
                ef->chain = &(ef->hash[2 + ef->nbucket]);

                break;

            case bfdt_strtab:
                ef->strtab = (char *)(dyn->d_val + ef->exec_addr - ef->start_addr);
                break;

            case bfdt_symtab:
                ef->symtab = (struct bfelf_sym *)(dyn->d_val + ef->exec_addr - ef->start_addr);
                break;

            case bfdt_rela:
                ef->relatab = (struct bfelf_rela *)(dyn->d_val + ef->exec_addr - ef->start_addr);
                break;

            case bfdt_relasz:
                relasz = dyn->d_val;
                break;

            case bfdt_relaent:
                relaent = dyn->d_val;
                break;

            case bfdt_init:
                ef->init = dyn->d_val;
                break;

            case bfdt_fini:
                ef->fini = dyn->d_val;
                break;

            case bfdt_init_array:
                ef->init_array = dyn->d_val;
                break;

            case bfdt_fini_array:
                ef->fini_array = dyn->d_val;
                break;

            case bfdt_init_arraysz:
                ef->init_arraysz = dyn->d_val;
                break;

            case bfdt_fini_arraysz:
                ef->fini_arraysz = dyn->d_val;
                break;

            case bfdt_flags_1:
                ef->flags_1 = dyn->d_val;
                break;

            default:
                break;
        }
    }

done:

    /*
     * Sadly, the only way to determine the total size of the dynamic symbol
     * table is to assume that the dynamic string table is always after the
     * dynamic symbol table. :(
     */
    ef->symnum = ((bfelf64_xword)ef->strtab - (bfelf64_xword)ef->symtab) / sizeof(struct bfelf_sym);

    if (relaent != 0)
        ef->relanum = relasz / relaent;
}

int64_t
bfelf_loader_add(struct bfelf_loader_t *loader,
                 struct bfelf_file_t *ef,
                 char *exec_addr,
                 char *exec_virt)
{
    if (!loader)
        return invalid_argument("loader == NULL");

    if (!ef)
        return invalid_argument("ef == NULL");

    if (!exec_addr)
        return invalid_argument("exec_addr == NULL");

    if (loader->num >= MAX_NUM_MODULES)
        return loader_full("increase MAX_NUM_MODULES");

    ef->exec_addr = exec_addr;
    ef->dyntab = (struct bfelf_dyn *)(ef->file + ef->dynoff);

    if (ef->dyntab != 0)
        private_process_dynamic_section(ef);

    if (ef->start_addr == 0)
        ef->exec_virt = exec_virt;

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
    }

    loader->relocated = 1;
    return BFELF_SUCCESS;
}

int64_t
bfelf_loader_resolve_symbol(struct bfelf_loader_t *loader,
                            const char *name,
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

    ret = private_get_sym_global(loader, name, &found_ef, &found_sym);
    if (ret != BFELF_SUCCESS)
        return ret;

    *addr = found_ef->exec_virt + found_sym->st_value;
    return BFELF_SUCCESS;
}
