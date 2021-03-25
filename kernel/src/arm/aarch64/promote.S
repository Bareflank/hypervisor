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
    /** @brief defines the offset of state_save_t.promote_handler */
    #define SS_OFFSET_PROMOTE_HANDLER 0x210
    /** @brief defines the offset of state_save_t.exception_vectors */
    #define SS_OFFSET_EXCEPTION_VECTORS 0x218

    .text

    .globl  promote
    .type   promote, @function
promote:

    /**
     * NOTE:
     * - Save off the first argument just in case we need to call other
     *   functions including debugging. The first argument in this case
     *   is a pointer to the root VP's state save.
     */
    mov  x20, x0

    /**
     * NOTE:
     * - Store the return value for the demote() function. Once this function
     *   is done, it will return to the loader's promote() function which
     *   will return to the C portion of the loader as if demote() had returned
     *   and this is where we store the return value. Note that promote()
     *   can be called on error, or when the hypervisor is stopping.
     */

    add  x21, x20, #SS_OFFSET_X0
    str  x1,  [x21]

    /**
     * NOTE:
     * - Restore the exception vectors. This is needed because we will no
     *   longer be able to use the exception vectores from the microkernel
     *   as we unload it, so we will use the exception vectors from the
     *   loader instead.
     */

    add  x21, x20, #SS_OFFSET_EXCEPTION_VECTORS
    ldr  x22, [x21]
    msr  vbar_el2, x22

    /**
     * NOTE:
     * - Call the loader's promote() handler. This will conclude execution
     *   from the microkernel.
     */

    add  x21, x20, #SS_OFFSET_PROMOTE_HANDLER
    ldr  x22, [x21]

    mov  x2, x20
    ret  x22

    .size promote, .-promote
