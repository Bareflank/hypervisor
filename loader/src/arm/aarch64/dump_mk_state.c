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

#include <debug.h>
#include <state_save_t.h>
#include <types.h>

/**
 * <!-- description -->
 *   @brief Outputs the contents of a provided mk state.
 *
 * <!-- inputs/outputs -->
 *   @param state the mk state to output
 *   @param cpu the CPU that this mk state belongs to
 */
void
dump_mk_state(struct state_save_t *const state, uint32_t const cpu) NOEXCEPT
{
    if (NULLPTR == state) {
        bferror("state is NULL");
        return;
    }

    bfdebug_d32("mk state on cpu", cpu);
    bfdebug_ptr(" - virt", state);

    bfdebug_x64(" - x0", state->x0);
    bfdebug_x64(" - x1", state->x1);
    bfdebug_x64(" - x2", state->x2);
    bfdebug_x64(" - x3", state->x3);
    bfdebug_x64(" - x4", state->x4);
    bfdebug_x64(" - x5", state->x5);
    bfdebug_x64(" - x6", state->x6);
    bfdebug_x64(" - x7", state->x7);
    bfdebug_x64(" - x8", state->x8);
    bfdebug_x64(" - x9", state->x9);
    bfdebug_x64(" - x10", state->x10);
    bfdebug_x64(" - x11", state->x11);
    bfdebug_x64(" - x12", state->x12);
    bfdebug_x64(" - x13", state->x13);
    bfdebug_x64(" - x14", state->x14);
    bfdebug_x64(" - x15", state->x15);
    bfdebug_x64(" - x16", state->x16);
    bfdebug_x64(" - x17", state->x17);
    bfdebug_x64(" - x18", state->x18);
    bfdebug_x64(" - x19", state->x19);
    bfdebug_x64(" - x20", state->x20);
    bfdebug_x64(" - x21", state->x21);
    bfdebug_x64(" - x22", state->x22);
    bfdebug_x64(" - x23", state->x23);
    bfdebug_x64(" - x24", state->x24);
    bfdebug_x64(" - x25", state->x25);
    bfdebug_x64(" - x26", state->x26);
    bfdebug_x64(" - x27", state->x27);
    bfdebug_x64(" - x28", state->x28);
    bfdebug_x64(" - x29", state->x29);
    bfdebug_x64(" - x30", state->x30);
    bfdebug_x64(" - sp_el2", state->sp_el2);
    bfdebug_x64(" - pc_el2", state->pc_el2);

    bfdebug_x64(" - daif", state->daif);
    bfdebug_x64(" - spsel", state->spsel);

    bfdebug_x64(" - vbar_el2", state->vbar_el2);
    bfdebug_ptr(" - vbar_el2 addr", &state->vbar_el2);

    bfdebug_x64(" - hcr_el2", state->hcr_el2);
    bfdebug_x64(" - mair_el2", state->mair_el2);
    bfdebug_x64(" - sctlr_el2", state->sctlr_el2);
    bfdebug_x64(" - tcr_el2", state->tcr_el2);
    bfdebug_x64(" - ttbr0_el2", state->ttbr0_el2);
}
