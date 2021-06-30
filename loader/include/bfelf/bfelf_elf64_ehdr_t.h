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

#ifndef BFELF_ELF64_EHDR_T_H
#define BFELF_ELF64_EHDR_T_H

#include <bfelf/bfelf_types.h>
#include <debug.h>

#pragma pack(push, 1)

/** @brief e_ident[bfelf_ei_mag0] contains 0x7FU for file identification */
#define bfelf_ei_mag0 ((uint64_t)0U)
/** @brief e_ident[bfelf_ei_mag1] contains 0x45U for file identification */
#define bfelf_ei_mag1 ((uint64_t)1U)
/** @brief e_ident[bfelf_ei_mag2] contains 0x4CU for file identification */
#define bfelf_ei_mag2 ((uint64_t)2U)
/** @brief e_ident[bfelf_ei_mag3] contains 0x46U for file identification */
#define bfelf_ei_mag3 ((uint64_t)3U)
/** @brief e_ident[bfelf_ei_class] identifies if the file is 32bit or 64 bit */
#define bfelf_ei_class ((uint64_t)4U)
/** @brief e_ident[bfelf_ei_data] specifies the data bit encoding of the file */
#define bfelf_ei_data ((uint64_t)5U)
/** @brief e_ident[bfelf_ei_version] identifies the version of the file */
#define bfelf_ei_version ((uint64_t)6U)
/** @brief e_ident[bfelf_ei_osabi] identifies file's ABI scheme */
#define bfelf_ei_osabi ((uint64_t)7U)
/** @brief e_ident[bfelf_ei_abiversion] identifies file's ABI version */
#define bfelf_ei_abiversion ((uint64_t)8U)
/** @brief defines the size of e_ident */
#define bfelf_ei_nident ((uint64_t)16U)

/** @brief defines the expected e_ident[bfelf_ei_mag0] value */
#define bfelf_elfmag0 ((uint8_t)0x7FU)
/** @brief defines the expected e_ident[bfelf_ei_mag1] value */
#define bfelf_elfmag1 ((uint8_t)0x45U)
/** @brief defines the expected e_ident[bfelf_ei_mag2] value */
#define bfelf_elfmag2 ((uint8_t)0x4CU)
/** @brief defines the expected e_ident[bfelf_ei_mag3] value */
#define bfelf_elfmag3 ((uint8_t)0x46U)

/** @brief defines e_ident[bfelf_ei_class] for 32bit objects */
#define bfelf_elfclass32 ((uint8_t)1U)
/** @brief defines e_ident[bfelf_ei_class] for 64bit objects */
#define bfelf_elfclass64 ((uint8_t)2U)

/** @brief defines e_ident[bfelf_ei_data] for little endian */
#define bfelf_elfdata2lsb ((uint8_t)1U)
/** @brief defines e_ident[bfelf_ei_data] for big endian */
#define bfelf_elfdata2msb ((uint8_t)2U)

/** @brief defines e_ident[bfelf_ei_osabi] for system v abi */
#define bfelf_elfosabi_sysv ((uint8_t)0U)
/** @brief defines e_ident[bfelf_ei_osabi] for hp-ux operating system */
#define bfelf_elfosabi_hpux ((uint8_t)1U)
/** @brief defines e_ident[bfelf_ei_osabi] for standalone applications */
#define bfelf_elfosabi_standalone ((uint8_t)255U)

/** @brief defines e_type for no file type */
#define bfelf_et_none ((bfelf_elf64_half)0U)
/** @brief defines e_type for an relocatable object file */
#define bfelf_et_rel ((bfelf_elf64_half)1U)
/** @brief defines e_type for an executable file */
#define bfelf_et_exec ((bfelf_elf64_half)2U)
/** @brief defines e_type for an shared object file */
#define bfelf_et_dyn ((bfelf_elf64_half)3U)
/** @brief defines e_type for an core file */
#define bfelf_et_core ((bfelf_elf64_half)4U)
/** @brief defines e_type for an environment-specific use (lo) */
#define bfelf_et_loos ((bfelf_elf64_half)0xFE00U)
/** @brief defines e_type for an environment-specific use (hi) */
#define bfelf_et_hios ((bfelf_elf64_half)0xFEFFU)
/** @brief defines e_type for an processor-specific use (lo) */
#define bfelf_et_loproc ((bfelf_elf64_half)0xFF00U)
/** @brief defines e_type for an processor-specific use (hi) */
#define bfelf_et_hiproc ((bfelf_elf64_half)0xFFFFU)

/**
 * @struct bfelf_elf64_ehdr_t
 *
 * <!-- description -->
 *   @brief The file header is located at the beginning of the file,
 *     and is used to locate the other parts of the file
 */
struct bfelf_elf64_ehdr_t
{
    uint8_t e_ident[bfelf_ei_nident]; /**< ELF identification */
    bfelf_elf64_half e_type;          /**< Object file type */
    bfelf_elf64_half e_machine;       /**< Machine type */
    bfelf_elf64_word e_version;       /**< Object file version */
    bfelf_elf64_addr e_entry;         /**< Entry point address */
    bfelf_elf64_off e_phoff;          /**< Program header offset */
    bfelf_elf64_off e_shoff;          /**< Section header offset */
    bfelf_elf64_word e_flags;         /**< Processor-specific flags */
    bfelf_elf64_half e_ehsize;        /**< ELF header size */
    bfelf_elf64_half e_phentsize;     /**< Size of program header entry */
    bfelf_elf64_half e_phnum;         /**< Number of program header entries */
    bfelf_elf64_half e_shentsize;     /**< Size of section header entry */
    bfelf_elf64_half e_shnum;         /**< Number of section header entries */
    bfelf_elf64_half e_shstrndx;      /**< Section name string table index */
};

/** @brief converts a uint8_t * to a struct bfelf_elf64_ehdr_t * */
#define to_ehdr(a) ((struct bfelf_elf64_ehdr_t *)a)

/**
 * <!-- description -->
 *   @brief Returns a pointer to the ELF header pointer to an ELF file.
 *
 * <!-- inputs/outputs -->
 *   @param file a pointer to the ELF file to get the ELF header from.
 *   @param ehdr where to output the ELF header.
 *   @return returns 0 on success or an error code otherwise.
 */
static inline int64_t
get_elf64_ehdr(uint8_t const *const file, struct bfelf_elf64_ehdr_t const **const ehdr)
{
    if (((void *)0) == file) {
        return BFELF_INVALID_ARGUMENT;
    }

    if (((void *)0) == ehdr) {
        return BFELF_INVALID_ARGUMENT;
    }

    *ehdr = to_ehdr(file);
    return 0;
}

/**
 * <!-- description -->
 *   @brief Checks whether or not a given ELF file is in a format that
 *     this ELF loader can handle.
 *
 * <!-- inputs/outputs -->
 *   @param file a pointer to the elf file
 *   @return Returns 0 on success or an error code on failure.
 */
static inline int64_t
validate_elf64_ehdr(uint8_t const *const file)
{
    if (((void *)0) == file) {
        bferror("file is NULL");
        return BFELF_INVALID_ARGUMENT;
    }

    if (to_ehdr(file)->e_ident[bfelf_ei_mag0] != bfelf_elfmag0) {
        bferror_x64("invalid bfelf_ei_mag0", to_ehdr(file)->e_ident[bfelf_ei_mag0]);
        return BFELF_INVALID_MAG0;
    }

    if (to_ehdr(file)->e_ident[bfelf_ei_mag1] != bfelf_elfmag1) {
        bferror_x64("invalid bfelf_ei_mag1", to_ehdr(file)->e_ident[bfelf_ei_mag1]);
        return BFELF_INVALID_MAG1;
    }

    if (to_ehdr(file)->e_ident[bfelf_ei_mag2] != bfelf_elfmag2) {
        bferror_x64("invalid bfelf_ei_mag2", to_ehdr(file)->e_ident[bfelf_ei_mag2]);
        return BFELF_INVALID_MAG2;
    }

    if (to_ehdr(file)->e_ident[bfelf_ei_mag3] != bfelf_elfmag3) {
        bferror_x64("invalid bfelf_ei_mag3", to_ehdr(file)->e_ident[bfelf_ei_mag3]);
        return BFELF_INVALID_MAG3;
    }

    if (to_ehdr(file)->e_ident[bfelf_ei_class] != bfelf_elfclass64) {
        bferror_x64("invalid bfelf_ei_class", to_ehdr(file)->e_ident[bfelf_ei_class]);
        return BFELF_INVALID_CLASS;
    }

    if (to_ehdr(file)->e_ident[bfelf_ei_osabi] != bfelf_elfosabi_sysv) {
        bferror_x64("invalid bfelf_ei_osabi", to_ehdr(file)->e_ident[bfelf_ei_osabi]);
        return BFELF_INVALID_OSABI;
    }

    if (to_ehdr(file)->e_type != bfelf_et_exec) {
        bferror_x64("invalid e_type", to_ehdr(file)->e_type);
        return BFELF_INVALID_TYPE;
    }

    return 0;
}

#pragma pack(pop)

#endif
