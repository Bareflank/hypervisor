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

    /** @brief defines the offset of state_save_t.rax */
    #define SS_OFFSET_RAX 0x000
    /** @brief defines the offset of state_save_t.promote_handler */
    #define SS_OFFSET_PROMOTE_HANDLER 0x2E8
    /** @brief defines the offset of state_save_t.esr_default_handler */
    #define SS_OFFSET_ESR_DEFAULT_HANDLER 0x2F0
    /** @brief defines the offset of state_save_t.esr_df_handler */
    #define SS_OFFSET_ESR_DF_HANDLER 0x2F8
    /** @brief defines the offset of state_save_t.esr_gpf_handler */
    #define SS_OFFSET_ESR_GPF_HANDLER 0x300
    /** @brief defines the offset of state_save_t.esr_nmi_handler */
    #define SS_OFFSET_ESR_NMI_HANDLER 0x308
    /** @brief defines the offset of state_save_t.esr_pf_handler */
    #define SS_OFFSET_ESR_PF_HANDLER 0x310

    .code64
    .intel_syntax noprefix

    .globl  promote
    .type   promote, @function
promote:

    /**
     * NOTE:
     * - Save off the first argument just in case we need to call other
     *   functions including debugging. The first argument in this case
     *   is a pointer to the root VP's state save.
     */

    mov r15, rdi

    /**
     * NOTE:
     * - Store the return value for the demote() function. Once this function
     *   is done, it will return to the loader's promote() function which
     *   will return to the C portion of the loader as if demote() had returned
     *   and this is where we store the return value. Note that promote()
     *   can be called on error, or when the hypervisor is stopping.
     */

    mov [r15 + SS_OFFSET_RAX], rsi

    /**
     * NOTE:
     * - Restore the exception vectors. This is needed because we will no
     *   longer be able to use the exception vectores from the microkernel
     *   as we unload it, so we will use the exception vectors from the
     *   loader instead.
     */

    mov rdi, 0
    mov rsi, [r15 + SS_OFFSET_ESR_DEFAULT_HANDLER]
    call set_esr

    mov rdi, 1
    mov rsi, [r15 + SS_OFFSET_ESR_DEFAULT_HANDLER]
    call set_esr

    mov rdi, 2
    mov rsi, [r15 + SS_OFFSET_ESR_NMI_HANDLER]
    call set_esr

    mov rdi, 3
    mov rsi, [r15 + SS_OFFSET_ESR_DEFAULT_HANDLER]
    call set_esr

    mov rdi, 4
    mov rsi, [r15 + SS_OFFSET_ESR_DEFAULT_HANDLER]
    call set_esr

    mov rdi, 5
    mov rsi, [r15 + SS_OFFSET_ESR_DEFAULT_HANDLER]
    call set_esr

    mov rdi, 6
    mov rsi, [r15 + SS_OFFSET_ESR_DEFAULT_HANDLER]
    call set_esr

    mov rdi, 7
    mov rsi, [r15 + SS_OFFSET_ESR_DEFAULT_HANDLER]
    call set_esr

    mov rdi, 8
    mov rsi, [r15 + SS_OFFSET_ESR_DF_HANDLER]
    call set_esr

    mov rdi, 10
    mov rsi, [r15 + SS_OFFSET_ESR_DEFAULT_HANDLER]
    call set_esr

    mov rdi, 11
    mov rsi, [r15 + SS_OFFSET_ESR_DEFAULT_HANDLER]
    call set_esr

    mov rdi, 12
    mov rsi, [r15 + SS_OFFSET_ESR_DEFAULT_HANDLER]
    call set_esr

    mov rdi, 13
    mov rsi, [r15 + SS_OFFSET_ESR_GPF_HANDLER]
    call set_esr

    mov rdi, 14
    mov rsi, [r15 + SS_OFFSET_ESR_PF_HANDLER]
    call set_esr

    mov rdi, 16
    mov rsi, [r15 + SS_OFFSET_ESR_DEFAULT_HANDLER]
    call set_esr

    mov rdi, 17
    mov rsi, [r15 + SS_OFFSET_ESR_DEFAULT_HANDLER]
    call set_esr

    mov rdi, 18
    mov rsi, [r15 + SS_OFFSET_ESR_DEFAULT_HANDLER]
    call set_esr

    mov rdi, 19
    mov rsi, [r15 + SS_OFFSET_ESR_DEFAULT_HANDLER]
    call set_esr

    /**
     * NOTE:
     * - Call the loader's promote() handler. This will conclude execution
     *   from the microkernel.
     */

    call set_up_target
capture_spec:
    pause
    jmp capture_spec
set_up_target:
    mov rax, [r15 + SS_OFFSET_PROMOTE_HANDLER]
    mov [rsp], rax
    ret
    int 3

    .size promote, .-promote
