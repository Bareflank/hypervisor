//
// Copyright (C) 2019 Assured Information Security, Inc.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

// TIDY_EXCLUSION=-cppcoreguidelines-pro*
//
// Reason:
//     Although written in C++, this code needs to implement C specific logic
//     that by its very definition will not adhere to the core guidelines
//     similar to libc which is needed by all C++ implementations.
//

#include <abort.h>
#include <dwarf4.h>
#include <eh_frame.h>
#include <registers.h>
#include <ia64_cxx_abi.h>

#include <bfexports.h>

// -----------------------------------------------------------------------------
// Context
// -----------------------------------------------------------------------------

struct _Unwind_Context {
    fd_entry fde;
    register_state *state;
    _Unwind_Exception *exception_object;

    _Unwind_Context(register_state *s, _Unwind_Exception *eo) :
        state(s),
        exception_object(eo)
    {
    }
};

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

static _Unwind_Reason_Code
private_personality(_Unwind_Action action, _Unwind_Context *context)
{
    if (auto pl = context->fde.cie().personality_function()) {
        if (auto pr = *(reinterpret_cast<__personality_routine *>(pl))) {
            return pr(1, action,
                      context->exception_object->exception_class,
                      context->exception_object, context);
        }
    }

    return _URC_CONTINUE_UNWIND;
}

// -----------------------------------------------------------------------------
// Implementation
// -----------------------------------------------------------------------------

static _Unwind_Reason_Code
find_and_store_fde(_Unwind_Context *context)
{
    if (!(context->fde = eh_frame::find_fde(context->state))) {
        return _URC_END_OF_STACK;
    }

    return _URC_CONTINUE_UNWIND;
}

static _Unwind_Reason_Code
private_phase1(_Unwind_Context *context)
{
    auto result = _URC_CONTINUE_UNWIND;

    result = find_and_store_fde(context);
    if (result != _URC_CONTINUE_UNWIND) {
        return result;
    }

    dwarf4::unwind(context->fde, context->state);

    while (true) {
        result = find_and_store_fde(context);
        if (result != _URC_CONTINUE_UNWIND) {
            return result;
        }

        switch (private_personality(_UA_SEARCH_PHASE, context)) {
            case _URC_HANDLER_FOUND:
                context->exception_object->private_1 = context->fde.pc_begin();
                return _URC_NO_REASON;

            case _URC_CONTINUE_UNWIND:
                break;

            default:
                ABORT("phase 1 personality routine failed");
        }

        dwarf4::unwind(context->fde, context->state);
    }
}

static _Unwind_Reason_Code
private_phase2(_Unwind_Context *context)
{
    auto result = _URC_CONTINUE_UNWIND;

    result = find_and_store_fde(context);
    if (result != _URC_CONTINUE_UNWIND) {
        return result;
    }

    dwarf4::unwind(context->fde, context->state);

    while (true) {
        auto action = _UA_CLEANUP_PHASE;

        result = find_and_store_fde(context);
        if (result != _URC_CONTINUE_UNWIND) {
            return result;
        }

        if (context->exception_object->private_1 == context->fde.pc_begin()) {
            action |= _UA_HANDLER_FRAME;
        }

        switch (private_personality(action, context)) {
            case _URC_INSTALL_CONTEXT:
                context->state->resume(); __builtin_unreachable();

            case _URC_CONTINUE_UNWIND:
                break;

            default:
                ABORT("phase 2 personality routine failed");
        }

        dwarf4::unwind(context->fde, context->state);
    }
}

extern "C" _Unwind_Reason_Code
_Unwind_RaiseException(_Unwind_Exception *exception_object)
{
    auto ret = _URC_END_OF_STACK;

    auto registers = registers_intel_x64_t();
    __store_registers_intel_x64(&registers);

    exception_object->private_1 = 0;
    exception_object->private_2 = 0;

    auto state = register_state_intel_x64(registers);
    auto context = _Unwind_Context(&state, exception_object);

    ret = private_phase1(&context);
    if (ret != _URC_NO_REASON) {
        return ret;
    }

    state = register_state_intel_x64(registers);
    context = _Unwind_Context(&state, exception_object);

    ret = private_phase2(&context);
    if (ret != _URC_NO_REASON) {
        return ret;
    }

    return _URC_FATAL_PHASE2_ERROR;
}

extern "C" void
_Unwind_Resume(_Unwind_Exception *exception_object)
{
    auto registers = registers_intel_x64_t();
    __store_registers_intel_x64(&registers);

    auto state = register_state_intel_x64(registers);
    auto context = _Unwind_Context(&state, exception_object);

    private_phase2(&context);
}

extern "C" void
_Unwind_DeleteException(_Unwind_Exception *exception_object)
{
    if (exception_object->exception_cleanup != nullptr) {
        (*exception_object->exception_cleanup)(_URC_FOREIGN_EXCEPTION_CAUGHT, exception_object);
    }
}

extern "C" uintptr_t
_Unwind_GetGR(_Unwind_Context *context, int index)
{
    return context->state->get(static_cast<uint64_t>(index));
}

extern "C" void
_Unwind_SetGR(_Unwind_Context *context, int index, uintptr_t value)
{
    context->state->set(static_cast<uint64_t>(index), value);
    context->state->commit();
}

extern "C" uintptr_t
_Unwind_GetIP(_Unwind_Context *context)
{
    return context->state->get_ip();
}

extern "C" void
_Unwind_SetIP(_Unwind_Context *context, uintptr_t value)
{
    context->state->set_ip(value);
    context->state->commit();
}

extern "C" uintptr_t
_Unwind_GetLanguageSpecificData(_Unwind_Context *context)
{
    return context->fde.lsda();
}

extern "C" uintptr_t
_Unwind_GetRegionStart(_Unwind_Context *context)
{
    return context->fde.pc_begin();
}

extern "C" uintptr_t
_Unwind_GetIPInfo(_Unwind_Context *context, int *ip_before_insn)
{
    if (ip_before_insn == nullptr) {
        ABORT("ip_before_insn == 0");
    }

    *ip_before_insn = 0;
    return _Unwind_GetIP(context);
}
