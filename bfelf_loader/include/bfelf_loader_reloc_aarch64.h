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
 * @file bfelf_loader_reloc_aarch64.h
 */

/*
 * AArch64 Relocations
 *
 * The following is defined in the "ELF for the ARM 64-bit architecture"
 * specification:
 * http://infocenter.arm.com/help/topic/com.arm.doc.ihi0056b/IHI0056B_aaelf64.pdf
 *
 * @cond
 */

/* ---------------------------------------------------------------------------------------------- */
/* Miscellaneous relocations                                                                      */
/* ---------------------------------------------------------------------------------------------- */
#define BFR_AARCH64_NONE bfscast(bfelf64_xword, 0)

/* ---------------------------------------------------------------------------------------------- */
/* Static data relocations                                                                        */
/* ---------------------------------------------------------------------------------------------- */
/* Data relocations */
#define BFR_AARCH64_ABS64 bfscast(bfelf64_xword, 257)
#define BFR_AARCH64_ABS32 bfscast(bfelf64_xword, 258)
#define BFR_AARCH64_ABS16 bfscast(bfelf64_xword, 259)
#define BFR_AARCH64_PREL64 bfscast(bfelf64_xword, 260)
#define BFR_AARCH64_PREL32 bfscast(bfelf64_xword, 261)
#define BFR_AARCH64_PREL16 bfscast(bfelf64_xword, 262)

/* ---------------------------------------------------------------------------------------------- */
/* Static AArch64 relocations                                                                     */
/* ---------------------------------------------------------------------------------------------- */
/* Group relocations to create an unsigned data value or address inline */
#define BFR_AARCH64_MOVW_UABS_G0 bfscast(bfelf64_xword, 263)
#define BFR_AARCH64_MOVW_UABS_G0_NC bfscast(bfelf64_xword, 264)
#define BFR_AARCH64_MOVW_UABS_G1 bfscast(bfelf64_xword, 265)
#define BFR_AARCH64_MOVW_UABS_G1_NC bfscast(bfelf64_xword, 266)
#define BFR_AARCH64_MOVW_UABS_G2 bfscast(bfelf64_xword, 267)
#define BFR_AARCH64_MOVW_UABS_G2_NC bfscast(bfelf64_xword, 268)
#define BFR_AARCH64_MOVW_UABS_G3 bfscast(bfelf64_xword, 269)

/* Group relocations to create a signed data or offset value inline */
#define BFR_AARCH64_MOVW_SABS_G0 bfscast(bfelf64_xword, 270)
#define BFR_AARCH64_MOVW_SABS_G1 bfscast(bfelf64_xword, 271)
#define BFR_AARCH64_MOVW_SABS_G2 bfscast(bfelf64_xword, 272)

/* Relocations to generate PC-relative addresses */
#define BFR_AARCH64_LD_PREL_LO19 bfscast(bfelf64_xword, 273)
#define BFR_AARCH64_ADR_PREL_LO21 bfscast(bfelf64_xword, 274)
#define BFR_AARCH64_ADR_PREL_PG_HI21 bfscast(bfelf64_xword, 275)
#define BFR_AARCH64_ADR_PREL_PG_HI21_NC bfscast(bfelf64_xword, 276)
#define BFR_AARCH64_ADD_ABS_LO12_NC bfscast(bfelf64_xword, 277)
#define BFR_AARCH64_LDST8_ABS_LO12_NC bfscast(bfelf64_xword, 278)
#define BFR_AARCH64_LDST16_ABS_LO12_NC bfscast(bfelf64_xword, 284)
#define BFR_AARCH64_LDST32_ABS_LO12_NC bfscast(bfelf64_xword, 285)
#define BFR_AARCH64_LDST64_ABS_LO12_NC bfscast(bfelf64_xword, 286)
#define BFR_AARCH64_LDST128_ABS_LO12_NC bfscast(bfelf64_xword, 299)

/* Relocations for control-flow instructions */
#define BFR_AARCH64_TSTBR14 bfscast(bfelf64_xword, 279)
#define BFR_AARCH64_CONDBR19 bfscast(bfelf64_xword, 280)
#define BFR_AARCH64_JUMP26 bfscast(bfelf64_xword, 282)
#define BFR_AARCH64_CALL26 bfscast(bfelf64_xword, 283)

/* Group relocations to create a PC-relative offset inline */
#define BFR_AARCH64_MOVW_PREL_G0 bfscast(bfelf64_xword, 287)
#define BFR_AARCH64_MOVW_PREL_G0_NC bfscast(bfelf64_xword, 288)
#define BFR_AARCH64_MOVW_PREL_G1 bfscast(bfelf64_xword, 289)
#define BFR_AARCH64_MOVW_PREL_G1_NC bfscast(bfelf64_xword, 290)
#define BFR_AARCH64_MOVW_PREL_G2 bfscast(bfelf64_xword, 291)
#define BFR_AARCH64_MOVW_PREL_G2_NC bfscast(bfelf64_xword, 292)
#define BFR_AARCH64_MOVW_PREL_G3 bfscast(bfelf64_xword, 293)

/* Group relocations to create a GOT-relative offset inline */
#define BFR_AARCH64_MOVW_GOTOFF_G0 bfscast(bfelf64_xword, 300)
#define BFR_AARCH64_MOVW_GOTOFF_G0_NC bfscast(bfelf64_xword, 301)
#define BFR_AARCH64_MOVW_GOTOFF_G1 bfscast(bfelf64_xword, 302)
#define BFR_AARCH64_MOVW_GOTOFF_G1_NC bfscast(bfelf64_xword, 303)
#define BFR_AARCH64_MOVW_GOTOFF_G2 bfscast(bfelf64_xword, 304)
#define BFR_AARCH64_MOVW_GOTOFF_G2_NC bfscast(bfelf64_xword, 305)
#define BFR_AARCH64_MOVW_GOTOFF_G3 bfscast(bfelf64_xword, 306)

/* GOT-relative data relocations */
#define BFR_AARCH64_GOTREL64 bfscast(bfelf64_xword, 307)
#define BFR_AARCH64_GOTREL32 bfscast(bfelf64_xword, 308)

/* GOT-relative instruction relocations */
#define BFR_AARCH64_GOT_LD_PREL19 bfscast(bfelf64_xword, 309)
#define BFR_AARCH64_LD64_GOTOFF_LO15 bfscast(bfelf64_xword, 310)
#define BFR_AARCH64_ADR_GOT_PAGE bfscast(bfelf64_xword, 311)
#define BFR_AARCH64_LD64_GOT_LO12_NC bfscast(bfelf64_xword, 312)
#define BFR_AARCH64_LD64_GOTPAGE_LO15 bfscast(bfelf64_xword, 313)

/* ---------------------------------------------------------------------------------------------- */
/* Relocations for thread-local storage                                                           */
/* ---------------------------------------------------------------------------------------------- */
/* General dynamic TLS relocations */
#define BFR_AARCH64_TLSGD_ADR_PREL21 bfscast(bfelf64_xword, 512)
#define BFR_AARCH64_TLSGD_ADR_PAGE21 bfscast(bfelf64_xword, 513)
#define BFR_AARCH64_TLSGD_ADD_LO12_NC bfscast(bfelf64_xword, 514)
#define BFR_AARCH64_TLSGD_MOVW_G1 bfscast(bfelf64_xword, 515)
#define BFR_AARCH64_TLSGD_MOVW_G0_NC bfscast(bfelf64_xword, 516)

/* Local dynamic TLS relocations */
#define BFR_AARCH64_TLSLD_ADR_PREL21 bfscast(bfelf64_xword, 517)
#define BFR_AARCH64_TLSLD_ADR_PAGE21 bfscast(bfelf64_xword, 518)
#define BFR_AARCH64_TLSLD_ADD_LO12_NC bfscast(bfelf64_xword, 519)
#define BFR_AARCH64_TLSLD_MOVW_G1 bfscast(bfelf64_xword, 520)
#define BFR_AARCH64_TLSLD_MOVW_G0_NC bfscast(bfelf64_xword, 521)
#define BFR_AARCH64_TLSLD_LD_PREL19 bfscast(bfelf64_xword, 522)
#define BFR_AARCH64_TLSLD_MOVW_DTPREL_G2 bfscast(bfelf64_xword, 523)
#define BFR_AARCH64_TLSLD_MOVW_DTPREL_G1 bfscast(bfelf64_xword, 524)
#define BFR_AARCH64_TLSLD_MOVW_DTPREL_G1_NC bfscast(bfelf64_xword, 525)
#define BFR_AARCH64_TLSLD_MOVW_DTPREL_G0 bfscast(bfelf64_xword, 526)
#define BFR_AARCH64_TLSLD_MOVW_DTPREL_G0_NC bfscast(bfelf64_xword, 527)
#define BFR_AARCH64_TLSLD_ADD_DTPREL_HI12 bfscast(bfelf64_xword, 528)
#define BFR_AARCH64_TLSLD_ADD_DTPREL_LO12 bfscast(bfelf64_xword, 529)
#define BFR_AARCH64_TLSLD_ADD_DTPREL_LO12_NC bfscast(bfelf64_xword, 530)
#define BFR_AARCH64_TLSLD_LDST8_DTPREL_LO12 bfscast(bfelf64_xword, 531)
#define BFR_AARCH64_TLSLD_LDST8_DTPREL_LO12_NC bfscast(bfelf64_xword, 532)
#define BFR_AARCH64_TLSLD_LDST16_DTPREL_LO12 bfscast(bfelf64_xword, 533)
#define BFR_AARCH64_TLSLD_LDST16_DTPREL_LO12_NC bfscast(bfelf64_xword, 534)
#define BFR_AARCH64_TLSLD_LDST32_DTPREL_LO12 bfscast(bfelf64_xword, 535)
#define BFR_AARCH64_TLSLD_LDST32_DTPREL_LO12_NC bfscast(bfelf64_xword, 536)
#define BFR_AARCH64_TLSLD_LDST64_DTPREL_LO12 bfscast(bfelf64_xword, 537)
#define BFR_AARCH64_TLSLD_LDST64_DTPREL_LO12_NC bfscast(bfelf64_xword, 538)
#define BFR_AARCH64_TLSLD_LDST128_DTPREL_LO12 bfscast(bfelf64_xword, 572)
#define BFR_AARCH64_TLSLD_LDST128_DTPREL_LO12_NC bfscast(bfelf64_xword, 573)

/* Initial exec TLS relocations */
#define BFR_AARCH64_TLSIE_MOVW_GOTTPREP_G1 bfscast(bfelf64_xword, 539)
#define BFR_AARCH64_TLSIE_MOVW_GOTTPREL_G0_NC bfscast(bfelf64_xword, 540)
#define BFR_AARCH64_TLSIE_ADR_GOTTPREL_PAGE21 bfscast(bfelf64_xword, 541)
#define BFR_AARCH64_TLSIE_LD64_GOTTPREL_LO12_NC bfscast(bfelf64_xword, 542)
#define BFR_AARCH64_TLSIE_LD_GOTTPREL_PREL19 bfscast(bfelf64_xword, 543)

/* Local exec TLS relocations */
#define BFR_AARCH64_TLSLE_MOVW_TPREL_G2 bfscast(bfelf64_xword, 544)
#define BFR_AARCH64_TLSLE_MOVW_TPREL_G1 bfscast(bfelf64_xword, 545)
#define BFR_AARCH64_TLSLE_MOVW_TPREL_G1_NC bfscast(bfelf64_xword, 546)
#define BFR_AARCH64_TLSLE_MOVW_TPREL_G0 bfscast(bfelf64_xword, 547)
#define BFR_AARCH64_TLSLE_MOVW_TPREL_G0_NC bfscast(bfelf64_xword, 548)
#define BFR_AARCH64_TLSLE_ADD_TPREL_HI12 bfscast(bfelf64_xword, 549)
#define BFR_AARCH64_TLSLE_ADD_TPREL_LO12 bfscast(bfelf64_xword, 550)
#define BFR_AARCH64_TLSLE_ADD_TPREL_LO12_NC bfscast(bfelf64_xword, 551)
#define BFR_AARCH64_TLSLE_LDST8_TPREL_LO12 bfscast(bfelf64_xword, 552)
#define BFR_AARCH64_TLSLE_LDST8_TPREL_LO12_NC bfscast(bfelf64_xword, 553)
#define BFR_AARCH64_TLSLE_LDST16_TPREL_LO12 bfscast(bfelf64_xword, 554)
#define BFR_AARCH64_TLSLE_LDST16_TPREL_LO12_NC bfscast(bfelf64_xword, 555)
#define BFR_AARCH64_TLSLE_LDST32_TPREL_LO12 bfscast(bfelf64_xword, 556)
#define BFR_AARCH64_TLSLE_LDST32_TPREL_LO12_NC bfscast(bfelf64_xword, 557)
#define BFR_AARCH64_TLSLE_LDST64_TPREL_LO12 bfscast(bfelf64_xword, 558)
#define BFR_AARCH64_TLSLE_LDST64_TPREL_LO12_NC bfscast(bfelf64_xword, 559)
#define BFR_AARCH64_TLSLE_LDST128_TPREL_LO12 bfscast(bfelf64_xword, 570)
#define BFR_AARCH64_TLSLE_LDST128_TPREL_LO12_NC bfscast(bfelf64_xword, 571)

/* TLS descriptor relocations */
#define BFR_AARCH64_TLSDESC_LD_PREL19 bfscast(bfelf64_xword, 560)
#define BFR_AARCH64_TLSDESC_ADR_PREL21 bfscast(bfelf64_xword, 561)
#define BFR_AARCH64_TLSDESC_ADR_PAGE21 bfscast(bfelf64_xword, 562)
#define BFR_AARCH64_TLSDESC_LD64_LO12 bfscast(bfelf64_xword, 563)
#define BFR_AARCH64_TLSDESC_ADD_LO12 bfscast(bfelf64_xword, 564)
#define BFR_AARCH64_TLSDESC_OFF_G1 bfscast(bfelf64_xword, 656)
#define BFR_AARCH64_TLSDESC_OFF_G0_NC bfscast(bfelf64_xword, 566)
#define BFR_AARCH64_TLSDESC_LDR bfscast(bfelf64_xword, 567)
#define BFR_AARCH64_TLSDESC_ADD bfscast(bfelf64_xword, 568)
#define BFR_AARCH64_TLSDESC_CALL bfscast(bfelf64_xword, 569)

/* ---------------------------------------------------------------------------------------------- */
/* Dynamic relocations                                                                            */
/* ---------------------------------------------------------------------------------------------- */
#define BFR_AARCH64_COPY bfscast(bfelf64_xword, 1024)
#define BFR_AARCH64_GLOB_DAT bfscast(bfelf64_xword, 1025)
#define BFR_AARCH64_JUMP_SLOT bfscast(bfelf64_xword, 1026)
#define BFR_AARCH64_RELATIVE bfscast(bfelf64_xword, 1027)
#define BFR_AARCH64_TLS_DTPREL64 bfscast(bfelf64_xword, 1028)
#define BFR_AARCH64_TLS_DTPMOD64 bfscast(bfelf64_xword, 1029)
#define BFR_AARCH64_TLS_TPREL64 bfscast(bfelf64_xword, 1030)
#define BFR_AARCH64_TLSDESC bfscast(bfelf64_xword, 1031)
#define BFR_AARCH64_IRELATIVE bfscast(bfelf64_xword, 1032)

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

    if (BFELF_REL_TYPE(rela->r_info) == BFR_AARCH64_RELATIVE) {
        *ptr = bfrcast(bfelf64_addr, ef->exec_virt + rela->r_addend);
        return BFELF_SUCCESS;
    }

    found_sym = &(ef->symtab[BFELF_REL_SYM(rela->r_info)]);

    if (BFELF_SYM_BIND(found_sym->st_info) == bfstb_weak) {
        found_ef = nullptr;
    }

    if (found_sym->st_value == 0 || found_ef == nullptr) {
        int64_t ret;

        str = &(ef->strtab[found_sym->st_name]);
        ret = private_get_sym_global(loader, str, &found_ef, &found_sym);

        if (ret != BFELF_SUCCESS) {
            return ret;
        }
    }

    switch (BFELF_REL_TYPE(rela->r_info)) {
        case BFR_AARCH64_GLOB_DAT:
        case BFR_AARCH64_JUMP_SLOT:
        case BFR_AARCH64_ABS64:
            *ptr = bfrcast(bfelf64_addr, found_ef->exec_virt + found_sym->st_value);
            break;

        case BFR_AARCH64_ABS32:
            *(uint32_t *) ptr = bfrcast(uint32_t, found_ef->exec_virt + found_sym->st_value);
            break;

        case BFR_AARCH64_ABS16:
            *(uint16_t *) ptr = bfrcast(uint16_t, found_ef->exec_virt + found_sym->st_value);
            break;

        default:
            return bfunsupported_rel(str);
    }

    return BFELF_SUCCESS;
}

/* @endcond */
