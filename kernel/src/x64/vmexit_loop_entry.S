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

    .code64
    .intel_syntax noprefix

    .globl  vmexit_loop_entry
    .type   vmexit_loop_entry, @function
vmexit_loop_entry:

    /**************************************************************************/
    /* Call VMExit Handler                                                      */
    /**************************************************************************/

    mov rdi, gs:[0x200]
    call vmexit_loop_trampoline

    /**************************************************************************/
    /* First Exit Logic                                                       */
    /**************************************************************************/

    /**
     * NOTE:
     * - If this is the first VMExit, we handle how we loop differently, as we
     *   are still able to return back to the loader in this specific case.
     * - The following checks to see if this is our first exit
     */

    push rax

    mov rax, gs:[0x270]
    cmp rax, 0x0
    jne skip_first_launch_logic

    pop rax

    cmp rax, 0x0
    je install_fast_fail_and_continue_loop

    /**
     * NOTE:
     * - If we get here, it is because our first exit failed, in which case
     *   we can return from this function, and a proper exit will occur
     */

    mov rax, 0x1
    ret
    int 3

install_fast_fail_and_continue_loop:

    /**
     * NOTE:
     * - If we get here, it is because the VMExit was successful, in which
     *   case, we need to state that the next exit will not be our first,
     *   and then insteall our fast fail entry point which is what will
     *   execute in the event of an error instead of the current fast fail
     *   entry point, which depends on what was executing at the time of the
     *   error occuring.
     */

    mov rax, 0x1
    mov gs:[0x270], rax

    lea rax, [rip + fast_fail_entry]
    mov gs:[0x180], rax
    mov rax, 0x0
    mov gs:[0x188], rax

    lea rax, [rip + fast_fail_entry]
    mov gs:[0x190], rax
    mov rax, 0x0
    mov gs:[0x198], rax

    jmp vmexit_loop_entry

skip_first_launch_logic:

    pop rax

    /**************************************************************************/
    /* Remaining Exit Logic                                                   */
    /**************************************************************************/

    /**
     * NOTE:
     * - If got here, it means that this is the second (or more) VMExit.
     *   This is the typical path that the code will take. In this path, we
     *   need to determine if an error occured.
     * - If the VMExit handler returned an error, we need to call the fast
     *   fail path, which will allow the extension to decide what to do. If
     *   the extension doesn't know what to do, we will have to halt. If it
     *   handles the issue, we can continue the loop.
     */


    cmp rax, 0x0
    je vmexit_loop_entry

    mov rdi, gs:[0x200]
    call fast_fail_entry

    cmp rax, 0x0
    je vmexit_loop_entry

    /**
     * Note:
     * - The following should be unreachable, but is here just in case that
     *   assumption becomes invalid.
     */

    jmp intrinsic_halt

    .size vmexit_loop_entry, .-vmexit_loop_entry
