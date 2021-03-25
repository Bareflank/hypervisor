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

    /** @brief defines the offset of state_save_t.x0 */
    #define SS_OFFSET_X0 0x000
    /** @brief defines the offset of state_save_t.x19 */
    #define SS_OFFSET_X19 0x098
    /** @brief defines the offset of state_save_t.x20 */
    #define SS_OFFSET_X20 0x0A0
    /** @brief defines the offset of state_save_t.x21 */
    #define SS_OFFSET_X21 0x0A8
    /** @brief defines the offset of state_save_t.x22 */
    #define SS_OFFSET_X22 0x0B0
    /** @brief defines the offset of state_save_t.x23 */
    #define SS_OFFSET_X23 0x0B8
    /** @brief defines the offset of state_save_t.x24 */
    #define SS_OFFSET_X24 0x0C0
    /** @brief defines the offset of state_save_t.x25 */
    #define SS_OFFSET_X25 0x0C8
    /** @brief defines the offset of state_save_t.x26 */
    #define SS_OFFSET_X26 0x0D0
    /** @brief defines the offset of state_save_t.x27 */
    #define SS_OFFSET_X27 0x0D8
    /** @brief defines the offset of state_save_t.x28 */
    #define SS_OFFSET_X28 0x0E0
    /** @brief defines the offset of state_save_t.x29 */
    #define SS_OFFSET_X29 0x0E8
    /** @brief defines the offset of state_save_t.x30 */
    #define SS_OFFSET_X30 0x0F0
    /** @brief defines the offset of state_save_t.sp_el2 */
    #define SS_OFFSET_SP_EL2 0x0F8
    /** @brief defines the offset of state_save_t.pc_el2 */
    #define SS_OFFSET_PC_EL2 0x100

    /** @brief defines the offset of state_save_t.daif */
    #define SS_OFFSET_DAIF 0x108
    /** @brief defines the offset of state_save_t.spsel */
    #define SS_OFFSET_SPSEL 0x110

    /** @brief defines the offset of state_save_t.vbar_el2 */
    #define SS_OFFSET_VBAR_EL2 0x188

    /** @brief defines the offset of state_save_t.hcr_el2 */
    #define SS_OFFSET_HCR_EL2 0x190
    /** @brief defines the offset of state_save_t.mair_el2 */
    #define SS_OFFSET_MAIR_EL2 0x198
    /** @brief defines the offset of state_save_t.sctlr_el2 */
    #define SS_OFFSET_SCTLR_EL2 0x1A0
    /** @brief defines the offset of state_save_t.tcr_el2 */
    #define SS_OFFSET_TCR_EL2 0x1A8
    /** @brief defines the offset of state_save_t.ttbr0_el2 */
    #define SS_OFFSET_TTBR0_EL2 0x1B0
    /** @brief defines the offset of state_save_t.tpidr_el2 */
    #define SS_OFFSET_TPIDR_EL2 0x1B8

	.global promote
	.align 12
promote:

    /**************************************************************************/
    /* Stack                                                                  */
    /**************************************************************************/

    add  x12, x2, #SS_OFFSET_SP_EL2
    ldr  x10, [x12]
    mov  sp, x10

    /**************************************************************************/
    /* System Registers                                                       */
    /**************************************************************************/

    add  x12, x2, #SS_OFFSET_TPIDR_EL2
    ldr  x10, [x12]
    msr  tpidr_el2, x10

    add  x12, x2, #SS_OFFSET_TTBR0_EL2
    ldr  x10, [x12]
    msr  ttbr0_el2, x10

    tlbi alle2
    isb  sy
    dsb  sy

    add  x12, x2, #SS_OFFSET_TCR_EL2
    ldr  x10, [x12]
    msr  tcr_el2, x10

    add  x12, x2, #SS_OFFSET_SCTLR_EL2
    ldr  x10, [x12]
    msr  sctlr_el2, x10

    add  x12, x2, #SS_OFFSET_MAIR_EL2
    ldr  x10, [x12]
    msr  mair_el2, x10

    /**************************************************************************/
    /* Exceptions                                                             */
    /**************************************************************************/

    add  x12, x2, #SS_OFFSET_VBAR_EL2
    ldr  x10, [x12]
    msr  vbar_el2, x10

    /**************************************************************************/
    /* Saved Program Status Registers (SPSR)                                  */
    /**************************************************************************/

    /**
     * TODO:
     * - We probably need to restore more of these as we support more ARM
     *   archiectures. Just depends on whether or not we use the feature
     *   in the microkernel. For now, this is all we need.
     */

    add  x12, x2, #SS_OFFSET_DAIF
    ldr  x10, [x12]
    msr  daif, x10

    add  x12, x2, #SS_OFFSET_SPSEL
    ldr  x10, [x12]
    msr  spsel, x10

    /**************************************************************************/
    /* Enable Interrupts                                                      */
    /**************************************************************************/

    add  x12, x2, #SS_OFFSET_HCR_EL2
    ldr  x10, [x12]
    msr  hcr_el2, x10

    /**************************************************************************/
    /* General Purpose Registers (non-volatile)                               */
    /**************************************************************************/

    add  x12, x2, #SS_OFFSET_PC_EL2
    ldr  x10, [x12]

    add  x12, x2, #SS_OFFSET_X30
    ldr  x30, [x12]
    add  x12, x2, #SS_OFFSET_X29
    ldr  x29, [x12]
    add  x12, x2, #SS_OFFSET_X28
    ldr  x28, [x12]
    add  x12, x2, #SS_OFFSET_X27
    ldr  x27, [x12]
    add  x12, x2, #SS_OFFSET_X26
    ldr  x26, [x12]
    add  x12, x2, #SS_OFFSET_X25
    ldr  x25, [x12]
    add  x12, x2, #SS_OFFSET_X24
    ldr  x24, [x12]
    add  x12, x2, #SS_OFFSET_X23
    ldr  x23, [x12]
    add  x12, x2, #SS_OFFSET_X22
    ldr  x22, [x12]
    add  x12, x2, #SS_OFFSET_X21
    ldr  x21, [x12]
    add  x12, x2, #SS_OFFSET_X20
    ldr  x20, [x12]
    add  x12, x2, #SS_OFFSET_X19
    ldr  x19, [x12]

    add  x12, x2, #SS_OFFSET_X0
    ldr  x0,  [x12]

    ret  x10
