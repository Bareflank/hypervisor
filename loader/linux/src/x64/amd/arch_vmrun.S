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

    .code64
    .intel_syntax noprefix

    .globl  arch_vmrun
    .type   arch_vmrun, @function
arch_vmrun:

    call arch_vmrun_success
    ret

arch_vmrun_success:

    /*************************************************************************/
    /* Guest VMCB Setup                                                      */
    /*************************************************************************/

    mov rsi, [rdi + 0x30]

    /**
     * Store the guest's rip. Note that the vmrun instruction is what will
     * branch the guest and host, so the RIP value is the return address of
     * the next instruction after the call above.
     */
    pop rax
    mov [rsi + 0x0578], rax

    /**
     * Store the guest's rflags. Since a call instruction does not modify the
     * flags, the rflags are whatever we were given when arch_vmrun was
     * called.
     */
    pushfq
    pop rax
    mov [rsi + 0x0570], rax

    /**
     * Store the rsp. Since we popped return return address to get the RIP,
     * the stack pointer is now pointing to the stack that is used by the
     * arch_vmrun function. Since RIP is set to the instruction after the
     * call, the stack is in the right place for returning from this function.
     */
    mov [rsi + 0x05D8], rsp

    /*************************************************************************/
    /* Guest VMCB Physical Address                                           */
    /*************************************************************************/

    /**
     * We need to store the Guest's VMCB physical address in rax so that the
     * VMRUN instruction can execute. From this point on, rax cannot be
     * touched.
     */

    mov rax, [rdi + 0x38]

    /*************************************************************************/
    /* Host Stack Setup                                                      */
    /*************************************************************************/

    mov rsi, [rdi + 0x020]

    /**
     * Store the host's stack. The host and the guest cannot share the same
     * stack. Since the guest state is set up properly, once the vmrun
     * executes, this function will return from the guest as if setting the
     * host stack never happened. The host will have it's own stack to
     * execute from. Note that this host can never go back, meaning, it must
     * enter a while(1) and attempt to return without the stack being put
     * back, otherwise the host will crash (as it no longer has the stack
     * information to leave it's current position in the stack). To ensure
     * this function can at least return, we grab the return address and use
     * it to initialize our new stack.
     */
    mov rsp, [rsi + 0x05D8]

    /**
     * Store the guest state save and the arch context to the stack. The
     * VMRUN loop will use both of these to save the state of the guest
     * and then bring up the host state, reversing this on before returning
     * to the guest.
     */
    mov rsi, [rdi + 0x50]

    push rsi      /** contains the guest save */
    push rdi      /** contains the arch context */

    /*************************************************************************/
    /* VMRUN loop                                                            */
    /*************************************************************************/

arch_vmrun_loop:

    vmload rax
    vmrun rax
    vmsave rax

    /**
     * After the vmrun instruction returns, we need to handle the VMEXIT.
     * The state associated with the guest is sitting in the general purpose
     * registers, except for RIP, RSP and RAX. The stack has the arch context
     * and the state save in it, which we will need to safely store the
     * guest state the the VMEXIT didn't save for us. So to handle this, we
     * save off RDI and RSI so that we can save them to the guest state save.
     */

    push rsi
    push rdi

    mov rdi, [rsp + 0x10]
    mov rsi, [rsp + 0x18]

    pop rax
    mov [rsi + 0x020], rax
    pop rax
    mov [rsi + 0x028], rax

    /**
     * At this point, we have loaded RSI and RDI with the guest state save
     * and the arch context, and we have also saved off the guest's values
     * for RSI and RDI, so we can safely save the rest of the general
     * purpose registers and the debug registers.
     */

    mov [rsi + 0x000], rcx
    mov [rsi + 0x008], rdx
    mov [rsi + 0x010], rbx
    mov [rsi + 0x018], rbp
    mov [rsi + 0x030], r8
    mov [rsi + 0x038], r9
    mov [rsi + 0x040], r10
    mov [rsi + 0x048], r11
    mov [rsi + 0x050], r12
    mov [rsi + 0x058], r13
    mov [rsi + 0x060], r14
    mov [rsi + 0x068], r15

    mov rax, dr0
    mov [rsi + 0x070], rax
    mov rax, dr1
    mov [rsi + 0x078], rax
    mov rax, dr2
    mov [rsi + 0x080], rax
    mov rax, dr3
    mov [rsi + 0x088], rax
    mov rax, cr8
    mov [rsi + 0x090], rax

    xor ecx, ecx
    xgetbv
    mov [rsi + 0x098], eax

    xor edx, edx
    mov eax, 0xFFFFFFFF
    mov rcx, [rdi + 0x70]
    xsaves64 [rcx]

    /**
     * The next step is set up the host state to a set of initial values.
     * This will ensure the host's registers make sense when having to debug
     * issues, and it also ensures nothing in the guest can touch the host.
     */
    mov rax, [rdi + 0x28]
    vmload rax

    mov rax, 0
    mov dr0, rax
    mov rax, 0
    mov dr1, rax
    mov rax, 0
    mov dr2, rax
    mov rax, 0
    mov dr3, rax
    mov rax, 0xFFFF0FF0
    mov dr6, rax
    mov rax, 0x00000400
    mov dr7, rax
    mov rax, 0
    mov cr2, rax
    mov rax, 0xF
    mov cr8, rax

    mov rcx, [rdi + 0x60]
    mov al, 0x80
    mov [rcx + 0x20F], al
    xor edx, edx
    mov eax, 0xFFFFFFFF
    xrstors64 [rcx]

    /**
     * Finally, call the exit handler so that it can deal with the VMEXIT.
     */

    mov rax, [rdi + 0x80]
    call rax

    mov rdi, [rsp + 0x0]
    mov rsi, [rsp + 0x8]

    /**
     * At this point, we are done handling the VMEXIT and we must return to
     * the guest. To do this, we simply reverse everything we did above.
     * The only difference is, we do not attempt to hold save the host state
     * as we assume a fresh start on every VMEXIT, so it is fine to trash the
     * host state on the way out.
     */

    xor edx, edx
    mov eax, 0xFFFFFFFF
    mov rcx, [rdi + 0x70]
    xrstors64 [rcx]

    xor edx, edx
    mov eax, [rsi + 0x098]
    xor ecx, ecx
    xsetbv

    mov rax, [rsi + 0x090]
    mov cr8, rax
    mov rax, [rsi + 0x088]
    mov dr3, rax
    mov rax, [rsi + 0x080]
    mov dr2, rax
    mov rax, [rsi + 0x078]
    mov dr1, rax
    mov rax, [rsi + 0x070]
    mov dr0, rax

    mov r15, [rsi + 0x068]
    mov r14, [rsi + 0x060]
    mov r13, [rsi + 0x058]
    mov r12, [rsi + 0x050]
    mov r11, [rsi + 0x048]
    mov r10, [rsi + 0x040]
    mov r9,  [rsi + 0x038]
    mov r8,  [rsi + 0x030]
    mov rbp, [rsi + 0x018]
    mov rbx, [rsi + 0x010]
    mov rdx, [rsi + 0x008]
    mov rcx, [rsi + 0x000]

    mov rax, [rsi + 0x028]
    push rax
    mov rax, [rsi + 0x020]
    push rax

    mov rax, [rdi + 0x38]

    pop rdi
    pop rsi

    jmp arch_vmrun_loop

    .size arch_vmrun, .-arch_vmrun
