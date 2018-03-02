//
// Bareflank Unwind Library
//
// Copyright (C) 2015 Assured Information Security, Inc.
// Author: Rian Quinn        <quinnr@ainfosec.com>
// Author: Brendan Kerrigan  <kerriganb@ainfosec.com>
//
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 2.1 of the License, or (at your option) any later version.
//
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
// Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public
// License along with this library; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA

#ifndef IA64_CXX_ABI_H
#define IA64_CXX_ABI_H

#include <stdint.h>

struct _Unwind_Exception;

// -----------------------------------------------------------------------------
// Overview
// -----------------------------------------------------------------------------
//
// The IA64 C++ ABI specification describes a set of functions that are used
// to perform stack unwinding for exception support. This implementation uses
// the following documentation:
//
// http://mentorembedded.github.io/cxx-abi/abi-eh.html#cxx-abi
//
// Also note that this information can also be found in the System V 64bit
// ABI specification:
//
// http://www.x86-64.org/documentation/abi.pdf
//

// -----------------------------------------------------------------------------
// 1.1 Exception Handler Framework
// -----------------------------------------------------------------------------

// The exception framework can be broken up into three layers:
//
// - Layer 3: Defines the language specific keywords for exception support.
//   In C++, this is the "throw" and "catch" keywords that the programmer
//   is actually using.
//
// - Layer 2: The compiler, using the layer 3 keywords, will automatically
//   generate calls to layer 2 functions. These functions are provided by the
//   ABI (for GCC this is libsupc++, and for LLVM, this is libcxxabi). These
//   functions include __cxa_throw, __cxa_catch_begin, etc... These ABIs also
//   provide the "personality" function that is used to determine which catch
//   blocks we should stop unwinding to.
//
// - Layer 3: This layer defines the actual unwinding code. Layer two is an ABI
//   specific abstraction layer, but layer 3 is actually performing the
//   unwinding. This layer is usually provided by the compiler, as it is
//   architecture specific. The problem with most implementations is, they
//   require user space code to work. This one does not. The code defined here
//   belongs to this layer

// -----------------------------------------------------------------------------
// 1.2 Data Structures
// -----------------------------------------------------------------------------

/// _Unwind_Reason_Code
///
/// The "reason code" is an enum that is used by the following functions:
///
/// - _Unwind_Exception_Cleanup_Fn
/// - _Unwind_RaiseException
/// - _Unwind_Stop_Fn
/// - _Unwind_ForcedUnwind
/// - __personality_routine
///
/// It is used to both signal that an error has occurred, as well as tell
/// callback functions what to do, so view it as nothing more than a global
/// enum, were each value has it's own meaning.
///
typedef enum
{
    _URC_NO_REASON = 0,
    _URC_FOREIGN_EXCEPTION_CAUGHT = 1,
    _URC_FATAL_PHASE2_ERROR = 2,
    _URC_FATAL_PHASE1_ERROR = 3,
    _URC_NORMAL_STOP = 4,
    _URC_END_OF_STACK = 5,
    _URC_HANDLER_FOUND = 6,
    _URC_INSTALL_CONTEXT = 7,
    _URC_CONTINUE_UNWIND = 8

} _Unwind_Reason_Code;

/// _Unwind_Exception_Cleanup_Fn
///
/// This function is used delete the _Unwind_Exception. Basically, the
/// _Unwind_Exception structure is made up of two parts, the level I part,
/// and the level II part. Since the structure can be larger
/// than what is defined by this spec (i.e. could contain a level II part),
/// the language needs to provide the deleter. The following defines the
/// acceptable reasons:
///
/// - _URC_FOREIGN_EXCEPTION_CAUGHT: This indicates that a different runtime
///     caught this exception. Nested foreign exceptions, or rethrowing a
///     foreign exception, result in undefined behavior
///
/// - _URC_FATAL_PHASE1_ERROR: The personality routine encountered an error
///     during phase 1
///
/// - _URC_FATAL_PHASE2_ERROR: The personality routine encountered an error
///     during phase 2
///
/// @param reason the reason for deleting exc
/// @param exc the _Unwind_Exception to delete
///
typedef void (*_Unwind_Exception_Cleanup_Fn)(
    _Unwind_Reason_Code reason,
    _Unwind_Exception *exc);

/// _Unwind_Exception
///
/// This structure contains both the independent part of the exception, as
/// well as the dependent part (which is opaque to this library).
///
/// ---------------------
/// - 64 bits           -
/// - 64 bits           -
/// - 64 bits           -
/// - 64 bits           -
/// ---------------------
/// - Level II Part     -
/// - ...               -
/// ---------------------
///
/// @var _Unwind_Exception::exception_class
///     This is defined as the a language- and implementation-specific
///     identifier for the kind of exception this structure is. It's used by
///     the personality routine.
/// @var _Unwind_Exception::exception_cleanup
///     This is the function that will delete "this" structure. The level II
///     code will create this structure, and thus it is the only thing that
///     knows how to delete the structure. If level I needs to delete the
///     structure for whatever reason, it uses this function, provided by
///     level II
/// @var _Unwind_Exception::private_1
///     Used by level I as a state save area. This should not be touched by
///     level II at all.
/// @var _Unwind_Exception::private_2
///     Used by level I as a state save area. This should not be touched by
///     level II at all.
///
struct _Unwind_Exception
{
    uint64_t exception_class;
    _Unwind_Exception_Cleanup_Fn exception_cleanup;
    uint64_t private_1;
    uint64_t private_2;
};

/// The Unwind Context, is a pointer that is opaque to layers 1 and 2, and
/// is used by layer 3 to store the information needed to do stack unwinding.
///
struct _Unwind_Context;

// -----------------------------------------------------------------------------
// 1.3 Throwing an Exception
// -----------------------------------------------------------------------------
//
// Throwing an exception can be done with two different functions:
// - _Unwind_RaiseException
// - _Unwind_Resume
//
// These functions are basically identical. They both get the current register
// state, and then unwind the stack until the personality function says to stop.
// The difference is, _Unwind_RaiseException is executed in two phases, a
// search phase and a cleanup phase, while _Unwind_Resume only performs the
// cleanup phase.
//
// It should be noted that if code contains RAII and has to preform cleanup,
// it's likely the _Unwind_RaiseException will be told to jump into the code,
// as if the "catch" block was identified, even though it wasn't the compiler
// will throw again by calling _Unwind_Resume. This code really doesn't
// know the difference between a real "throw, rethrow, catch" and a "throw,
// cleanup, catch" as they look identical
//

extern "C" _Unwind_Reason_Code
_Unwind_RaiseException(_Unwind_Exception *exception_object);

extern "C" void
_Unwind_Resume(_Unwind_Exception *exception_object);

// -----------------------------------------------------------------------------
// 1.4 Exception Object Management
// -----------------------------------------------------------------------------
//
// The exception object is created by layer 2, and contains more information
// than what is visible in layer 3, so layer 2 has to provide the delete
// function, which is located in the exception object itself.
//

extern "C" void
_Unwind_DeleteException(_Unwind_Exception *exception_object);

// -----------------------------------------------------------------------------
// 1.5 Context Management
// -----------------------------------------------------------------------------
//
// These functions are basically just wrappers around the functionality that
// we store in the context. For example, layer 2 needs to be able to to set
// and get registers (both general purpose registers as well as the
// instruction pointer). Layer 2, which has the personality function, will also
// need to know where the LSDA is, so that it can use this information to
// find each catch block (view the LSDA as nothing more than a giant list
// of C++ typeinfo blocks, that can be used in giant switch statement). Layer
// 2 also need to know where the start of the FDE is (i.e. pc_begin)
//

extern "C" uintptr_t
_Unwind_GetGR(_Unwind_Context *context, int index);

extern "C" void
_Unwind_SetGR(_Unwind_Context *context, int index, uintptr_t value);

extern "C" uintptr_t
_Unwind_GetIP(_Unwind_Context *context);

extern "C" void
_Unwind_SetIP(_Unwind_Context *context, uintptr_t value);

extern "C" uintptr_t
_Unwind_GetLanguageSpecificData(_Unwind_Context *context);

extern "C" uintptr_t
_Unwind_GetRegionStart(_Unwind_Context *context);

// -----------------------------------------------------------------------------
// 1.6 Personality Routine
// -----------------------------------------------------------------------------
//
// The personality routine is called by this code, and it tells us when to stop
// looking for a catch block. It uses information in the LSDA to determine if
// a catch block is in the current CFA. Layer 3 has to search in two phases.
// The first phase tells the personality function just to tell us when to stop.
// The second phase does the actual cleanup and then stops. Note that if a
// custom personality function was created, you could reduce this to a single
// cleanup phase, as the initial search phase is a not needed in most cases.
//
// Also note that since this is only meant to be used by C++, we don't need
// the force unwind functionality
//

typedef int _Unwind_Action;
static const _Unwind_Action _UA_SEARCH_PHASE = 1;
static const _Unwind_Action _UA_CLEANUP_PHASE = 2;
static const _Unwind_Action _UA_HANDLER_FRAME = 4;
static const _Unwind_Action _UA_FORCE_UNWIND = 8;

typedef _Unwind_Reason_Code(*__personality_routine)(int version,
        _Unwind_Action actions, uint64_t exceptionClass,
        _Unwind_Exception *exceptionObject,
        _Unwind_Context *context);

// -----------------------------------------------------------------------------
// GNU Extensions
// -----------------------------------------------------------------------------
//
// GCC adds some additional functions that are only needed by the unit test,
// as LLVM doesn't add any additional functionality.
//

extern "C" uintptr_t
_Unwind_GetIPInfo(_Unwind_Context *context, int *ip_before_insn);

#endif
