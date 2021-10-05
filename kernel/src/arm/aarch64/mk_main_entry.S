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

    /** @brief defines the offset of mk_args_t.ppid */
    #define ARGS_OFFSET_PPID 0x0
    /** @brief defines the offset of mk_args_t.online_pps */
    #define ARGS_OFFSET_ONLINE_PPS 0x002
    /** @brief defines the offset of mk_args_t.mk_state */
    #define ARGS_OFFSET_MK_STATE 0x008
    /** @brief defines the offset of mk_args_t.root_vp_state */
    #define ARGS_OFFSET_ROOT_VP_STATE 0x010
    /** @brief defines the offset of mk_args_t.debug_ring */
    #define ARGS_OFFSET_DEBUG_RING 0x018

    /** @brief defines the size of the TLS block */
    #define TLS_SIZE 0x400
    /** @brief defines the offset of tls_t.current_fast_fail_ip */
    #define TLS_OFFSET_CURRENT_FAST_FAIL_IP 0x290
    /** @brief defines the offset of tls_t.current_fast_fail_sp */
    #define TLS_OFFSET_CURRENT_FAST_FAIL_SP 0x298
    /** @brief defines the offset of tls_t.mk_main_fast_fail_ip */
    #define TLS_OFFSET_MK_MAIN_FAST_FAIL_IP 0x2A0
    /** @brief defines the offset of tls_t.mk_main_fast_fail_sp */
    #define TLS_OFFSET_MK_MAIN_FAST_FAIL_SP 0x2A8
    /** @brief defines the offset of tls_t.call_ext_fast_fail_ip */
    #define TLS_OFFSET_CALL_EXT_FAST_FAIL_IP 0x2B0
    /** @brief defines the offset of tls_t.dispatch_syscall_fast_fail_ip */
    #define TLS_OFFSET_DISPATCH_SYSCALL_FAST_FAIL_IP 0x2C0
    /** @brief defines the offset of tls_t.self */
    #define TLS_OFFSET_SELF 0x300
    /** @brief defines the offset of tls_t.ppid */
    #define TLS_OFFSET_PPID 0x308
    /** @brief defines the offset of tls_t.online_pps */
    #define TLS_OFFSET_ONLINE_PPS 0x30A
    /** @brief defines the offset of tls_t.mk_state */
    #define TLS_OFFSET_MK_STATE 0x328
    /** @brief defines the offset of tls_t.root_vp_state */
    #define TLS_OFFSET_ROOT_VP_STATE 0x330
    /** @brief defines the offset of tls_t.active_<>id */
    #define TLS_OFFSET_ACTIVE_IDS 0x338

    .text

    .globl  mk_main_entry
    .type   mk_main_entry, @function
mk_main_entry:

    /**
     * NOTE:
     * - The first thing we need to do is save off RDI for the fast fail
     *   handler. If it is called, it will need the args that this function
     *   was provided, so we leave this on the stack for it. Since the state
     *   save has the correct stack pointer, we can leave it in this state
     *   as a safe return that uses the Root VP state will use the correct
     *   stack pointer, while a failure will use the current stack pointer
     *   with this return address on it.
     * - On ARMv8, we push x1 as well because all stack operations must be
     *   16 byte aligned, so we just add x1 as a place holder.
     * - We also store x0 into x20 so that we can call functions if needed
     *   without losing the arguments.
     */

    stp  x0, x1, [sp, #-0x10]!
    mov  x20, x0

    /**
     * NOTE:
     * - The next thing to do is get the TLS block for this PP. Each PP has
     *   it's own TLS block (both in the microkernel, and in each extension)
     *   which means that our definition of a thread is similar to that of
     *   Intel's and AMD's, meaning each PP is a thread.
     * - The loader will tell us in the args that it provided what the PPID
     *   is. Remember that this entry point will be called for each PP, so it
     *   is called more than once. Once we have the PPID, we can calculate
     *   which TLS block to grab based on the size of each TLS block.
     */

    mvn  x23, xzr
    add  x21, x20, #ARGS_OFFSET_PPID
    ldrh w23, [x21]

    mov  x21, #TLS_SIZE
    mul  x22, x21, x23
    adrp x21, g_tls_blocks
    add  x22, x21, x22

    /**
     * NOTE:
     * - Next we program the platform register with the location of the TLS
     *   block so that we can index into the TLS block using x18. We also
     *   put the TLS block into TPIDR_EL2 so that we can restore x18 when
     *   an exception is taken.
     */

    mov  x18, x22
    msr  tpidr_el2, x22

    /**
     * NOTE:
     * - From here we need to set the "self" pointer in the TLS block as
     *   well as the PPID to the TLS block so that we always know what the
     *   PPID is no matter where we are.
     */

    add  x21, x18, #TLS_OFFSET_SELF
    str  x18, [x21]
    add  x21, x18, #TLS_OFFSET_PPID
    str  x23, [x21]

    /**
     * NOTE:
     * - To start, there are no active extensions, VMs, VPs or VSs.
     */

    mvn  x22, xzr
    add  x21, x18, #TLS_OFFSET_ACTIVE_IDS
    str  x22, [x21]

    /**
     * NOTE:
     * - Next we set some of the fast fail entry points in the TLS block.
     *   These will be used when an error or exception occurs so that
     *   we can gracefully handle issues.
     */

    adr  x22, mk_main_fast_fail_entry
    add  x21, x18, #TLS_OFFSET_MK_MAIN_FAST_FAIL_IP
    str  x22, [x21]

    adr  x22, call_ext_fast_fail_entry
    add  x21, x18, #TLS_OFFSET_CALL_EXT_FAST_FAIL_IP
    str  x22, [x21]

    adr  x22, dispatch_syscall_fast_fail_entry
    add  x21, x18, #TLS_OFFSET_DISPATCH_SYSCALL_FAST_FAIL_IP
    str  x22, [x21]

    /**
     * NOTE:
     * - Next we need to set the number of online PPs on the system.
     *   The microkernel will need to know this so that it can properly set
     *   up it's internal resources.
     */

    add  x21, x20, #ARGS_OFFSET_ONLINE_PPS
    ldrh w22, [x21]
    add  x21, x18, #TLS_OFFSET_ONLINE_PPS
    strh w22, [x21]

    /**
     * NOTE:
     * - Next we store the location of the MK and Root VP state save areas
     *   that the loader created for us. For the most part, we only really
     *   need the Root VP state as we will use this to return back to the
     *   Root VP once we start the hypervisor on this PP, but just in case,
     *   we also provide the MK state as well. In general, the microkernel
     *   is really unware of the state that the loader gives it.
     */

    add  x21, x20, #ARGS_OFFSET_MK_STATE
    ldr  x22, [x21]
    add  x21, x18, #TLS_OFFSET_MK_STATE
    str  x22, [x21]

    add  x21, x20, #ARGS_OFFSET_ROOT_VP_STATE
    ldr  x22, [x21]
    add  x21, x18, #TLS_OFFSET_ROOT_VP_STATE
    str  x22, [x21]

    /**
     * NOTE:
     * - Next we store the pointer to the debug ring that the loader has
     *   set up for us. This is needed so that we have somewhere to put
     *   debug information.
     */

    add  x21, x20, #ARGS_OFFSET_DEBUG_RING
    ldr  x22, [x21]
    adr  x21, g_debug_ring
    str  x22, [x21]

    /**
     * NOTE:
     * - Set up the exception vectors. Currently we are using exception
     *   vectors provided by the loader. This loads the exception vectors
     *   that the actual kernel will use.
     */

    /** TODO */

    /**
     * NOTE:
     * - This next block of assembly is seen throughout the assembly code.
     *   Basically, it stores the information needed for fast failing. Each
     *   time we enter a new context like calling into an extension, handling
     *   a syscall, etc, we need to swap around the fast fail handler and RSP
     *   so that we know where to return to in the event of an error.
     */

    mov  x22, sp
    add  x21, x18, #TLS_OFFSET_MK_MAIN_FAST_FAIL_SP
    str  x22, [x21]
    add  x21, x18, #TLS_OFFSET_CURRENT_FAST_FAIL_SP
    str  x22, [x21]

    add  x21, x18, #TLS_OFFSET_MK_MAIN_FAST_FAIL_IP
    ldr  x22, [x21]
    add  x21, x18, #TLS_OFFSET_CURRENT_FAST_FAIL_IP
    str  x22, [x21]

    /**
     * NOTE:
     * - Finally, call the main trampoline.
     */

    mov  x0, x20
    mov  x1, x18
    bl   mk_main_trampoline

    /**
     * NOTE:
     * - If we get here, it is because an error occurred and we need to
     *   fast fail.
     */

    b    return_to_current_fast_fail

    .size mk_main_entry, .-mk_main_entry

    /**************************************************************************/
    /* Fast Fail Routine                                                      */
    /**************************************************************************/

    .globl  mk_main_fast_fail_entry
    .type   mk_main_fast_fail_entry, @function
mk_main_fast_fail_entry:

    /**
     * NOTE:
     * - In the beginning of mk_main_entry, we saved the original arguments
     *   to the stack which we will use here.
     * - On ARMv8, we pop x1 as well because all stack operations must be
     *   16 byte aligned, so we just add x1 as a place holder.
     */

    ldp  x0, x1, [sp], #0x10

    /**
     * NOTE:
     * - Promote back to the root OS on failure.
     */

    add  x1, x0, #ARGS_OFFSET_ROOT_VP_STATE
    ldr  x0, [x1]
    mov  x1, #1
    b    promote

    .size mk_main_fast_fail_entry, .-mk_main_fast_fail_entry



    /**************************************************************************/
    /* Runtime Helpers                                                        */
    /**************************************************************************/

    .rodata

    .globl  __stack_chk_guard
__stack_chk_guard:
    .quad 0xDEADBEEFDEADBEEF
