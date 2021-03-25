/// @copyright
/// Copyright (C) 2020 Assured Information Security, Inc.
///
/// @copyright
/// Permission is hereby granted, free of charge, to any person obtaining a copy
/// of this software and associated documentation files (the "Software"), to deal
/// in the Software without restriction, including without limitation the rights
/// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
/// copies of the Software, and to permit persons to whom the Software is
/// furnished to do so, subject to the following conditions:
///
/// @copyright
/// The above copyright notice and this permission notice shall be included in
/// all copies or substantial portions of the Software.
///
/// @copyright
/// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
/// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
/// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
/// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
/// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
/// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
/// SOFTWARE.

#ifndef DISPATCH_SYSCALL_DEBUG_OP_FAILURE_HPP
#define DISPATCH_SYSCALL_DEBUG_OP_FAILURE_HPP

#include <bf_constants.hpp>
#include <tls_t.hpp>

#include <bsl/char_type.hpp>
#include <bsl/cstr_type.hpp>
#include <bsl/debug.hpp>
#include <bsl/unlikely.hpp>

namespace mk
{
    /// <!-- description -->
    ///   @brief Dispatches the bf_debug_op syscalls
    ///
    /// <!-- inputs/outputs -->
    ///   @param tls the current TLS block
    ///
    constexpr void
    dispatch_syscall_debug_op_failure(tls_t &tls) noexcept
    {
        switch (syscall::bf_syscall_index(tls.ext_syscall).get()) {
            case syscall::BF_DEBUG_OP_OUT_IDX_VAL.get(): {
                break;
            }

            case syscall::BF_DEBUG_OP_DUMP_VM_IDX_VAL.get(): {
                break;
            }

            case syscall::BF_DEBUG_OP_DUMP_VP_IDX_VAL.get(): {
                break;
            }

            case syscall::BF_DEBUG_OP_DUMP_VPS_IDX_VAL.get(): {
                break;
            }

            case syscall::BF_DEBUG_OP_DUMP_VMEXIT_LOG_IDX_VAL.get(): {
                break;
            }

            case syscall::BF_DEBUG_OP_WRITE_C_IDX_VAL.get(): {
                break;
            }

            case syscall::BF_DEBUG_OP_WRITE_STR_IDX_VAL.get(): {
                break;
            }

            case syscall::BF_DEBUG_OP_DUMP_EXT_IDX_VAL.get(): {
                break;
            }

            case syscall::BF_DEBUG_OP_DUMP_PAGE_POOL_IDX_VAL.get(): {
                break;
            }

            case syscall::BF_DEBUG_OP_DUMP_HUGE_POOL_IDX_VAL.get(): {
                break;
            }

            default: {
                break;
            }
        }
    }
}

#endif
