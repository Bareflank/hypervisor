/* SPDX-License-Identifier: SPDX-License-Identifier: GPL-2.0 OR MIT */

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

#ifndef LOADER_INTRINSICS_H
#define LOADER_INTRINSICS_H

#include <loader_types.h>

/* -------------------------------------------------------------------------- */
/* - CPUID                                                                  - */
/* -------------------------------------------------------------------------- */

/**
 * <!-- description -->
 *   @brief Executes the CPUID instruction given the provided EAX and ECX
 *     and returns the results
 *
 * <!-- inputs/outputs -->
 *   @param eax the index used by CPUID, returns resulting eax
 *   @param ebx returns resulting ebx
 *   @param ecx the subindex used by CPUID, returns the resulting ecx
 *   @param edx returns resulting edx
 *     to.
 */
void arch_cpuid(uint32_t *const eax, uint32_t *const ebx, uint32_t *const ecx, uint32_t *const edx);

/* -------------------------------------------------------------------------- */
/* - MSRS                                                                   - */
/* -------------------------------------------------------------------------- */

/**
 * <!-- description -->
 *   @brief Executes the RDMSR instruction given the provided MSR
 *     and returns the results
 *
 * <!-- inputs/outputs -->
 *   @param ecx the MSR to read
 *   @return Returns the resulting MSR value
 */
uint64_t arch_rdmsr(uint32_t const ecx);

/**
 * <!-- description -->
 *   @brief Executes the WRMSR instruction given the provided MSR
 *     and value
 *
 * <!-- inputs/outputs -->
 *   @param ecx the MSR to write to the value
 *   @param val the value to write to the given MSR
 */
void arch_wrmsr(uint32_t const ecx, uint64_t val);

/* -------------------------------------------------------------------------- */
/* - GDT                                                                    - */
/* -------------------------------------------------------------------------- */

/**
 * <!-- description -->
 *   @brief Executes the SGDT instruction given a pointer to a
 *     global_descriptor_table_register.
 *
 * <!-- inputs/outputs -->
 *   @param reg a pointer to a global_descriptor_table_register
 */
void arch_sgdt(void *reg);

/**
 * <!-- description -->
 *   @brief Executes the LGDT instruction given a pointer to a
 *     global_descriptor_table_register.
 *
 * <!-- inputs/outputs -->
 *   @param reg a pointer to a global_descriptor_table_register
 */
void arch_lgdt(void *reg);

/* -------------------------------------------------------------------------- */
/* - IDT                                                                    - */
/* -------------------------------------------------------------------------- */

/**
 * <!-- description -->
 *   @brief Executes the SIDT instruction given a pointer to a
 *     interrupt_descriptor_table_register.
 *
 * <!-- inputs/outputs -->
 *   @param reg a pointer to a interrupt_descriptor_table_register
 */
void arch_sidt(void *reg);

/**
 * <!-- description -->
 *   @brief Executes the LIDT instruction given a pointer to a
 *     interrupt_descriptor_table_register.
 *
 * <!-- inputs/outputs -->
 *   @param reg a pointer to a interrupt_descriptor_table_register
 */
void arch_lidt(void *reg);

/* -------------------------------------------------------------------------- */
/* - Segment Registers                                                      - */
/* -------------------------------------------------------------------------- */

/**
 * <!-- description -->
 *   @brief Reads the ES segment register and returns the result.
 *
 * <!-- inputs/outputs -->
 *   @return Reads the ES segment register and returns the result.
 */
uint16_t arch_reades(void);

/**
 * <!-- description -->
 *   @brief Reads the CS segment register and returns the result.
 *
 * <!-- inputs/outputs -->
 *   @return Reads the CS segment register and returns the result.
 */
uint16_t arch_readcs(void);

/**
 * <!-- description -->
 *   @brief Reads the SS segment register and returns the result.
 *
 * <!-- inputs/outputs -->
 *   @return Reads the SS segment register and returns the result.
 */
uint16_t arch_readss(void);

/**
 * <!-- description -->
 *   @brief Reads the DS segment register and returns the result.
 *
 * <!-- inputs/outputs -->
 *   @return Reads the DS segment register and returns the result.
 */
uint16_t arch_readds(void);

/**
 * <!-- description -->
 *   @brief Reads the FS segment register and returns the result.
 *
 * <!-- inputs/outputs -->
 *   @return Reads the FS segment register and returns the result.
 */
uint16_t arch_readfs(void);

/**
 * <!-- description -->
 *   @brief Reads the GS segment register and returns the result.
 *
 * <!-- inputs/outputs -->
 *   @return Reads the GS segment register and returns the result.
 */
uint16_t arch_readgs(void);

/* -------------------------------------------------------------------------- */
/* - Control Registers                                                      - */
/* -------------------------------------------------------------------------- */

/**
 * <!-- description -->
 *   @brief Reads the CR0 register and returns the result.
 *
 * <!-- inputs/outputs -->
 *   @return Reads the CR0 register and returns the result.
 */
uint64_t arch_readcr0(void);

/**
 * <!-- description -->
 *   @brief Reads the CR2 register and returns the result.
 *
 * <!-- inputs/outputs -->
 *   @return Reads the CR2 register and returns the result.
 */
uint64_t arch_readcr2(void);

/**
 * <!-- description -->
 *   @brief Reads the CR3 register and returns the result.
 *
 * <!-- inputs/outputs -->
 *   @return Reads the CR3 register and returns the result.
 */
uint64_t arch_readcr3(void);

/**
 * <!-- description -->
 *   @brief Reads the CR4 register and returns the result.
 *
 * <!-- inputs/outputs -->
 *   @return Reads the CR4 register and returns the result.
 */
uint64_t arch_readcr4(void);

/**
 * <!-- description -->
 *   @brief Reads the CR8 register and returns the result.
 *
 * <!-- inputs/outputs -->
 *   @return Reads the CR8 register and returns the result.
 */
uint64_t arch_readcr8(void);

/* -------------------------------------------------------------------------- */
/* - Debug Registers                                                        - */
/* -------------------------------------------------------------------------- */

/**
 * <!-- description -->
 *   @brief Reads the DR0 register and returns the result.
 *
 * <!-- inputs/outputs -->
 *   @return Reads the DR0 register and returns the result.
 */
uint64_t arch_readdr0(void);

/**
 * <!-- description -->
 *   @brief Reads the DR1 register and returns the result.
 *
 * <!-- inputs/outputs -->
 *   @return Reads the DR1 register and returns the result.
 */
uint64_t arch_readdr1(void);

/**
 * <!-- description -->
 *   @brief Reads the DR2 register and returns the result.
 *
 * <!-- inputs/outputs -->
 *   @return Reads the DR2 register and returns the result.
 */
uint64_t arch_readdr2(void);

/**
 * <!-- description -->
 *   @brief Reads the DR3 register and returns the result.
 *
 * <!-- inputs/outputs -->
 *   @return Reads the DR3 register and returns the result.
 */
uint64_t arch_readdr3(void);

/**
 * <!-- description -->
 *   @brief Reads the DR6 register and returns the result.
 *
 * <!-- inputs/outputs -->
 *   @return Reads the DR6 register and returns the result.
 */
uint64_t arch_readdr6(void);

/**
 * <!-- description -->
 *   @brief Reads the DR7 register and returns the result.
 *
 * <!-- inputs/outputs -->
 *   @return Reads the DR7 register and returns the result.
 */
uint64_t arch_readdr7(void);

#endif
