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

#ifndef VMEXIT_LOG_RECORD_T
#define VMEXIT_LOG_RECORD_T

#include <bsl/safe_integral.hpp>

namespace mk
{
    /// @struct mk::vmexit_log_record_t
    ///
    /// <!-- description -->
    ///   @brief Stores information about each VMExit
    ///
    struct vmexit_log_record_t final
    {
        /// @brief stores the VMID that generated the exit
        bsl::safe_uint16 vmid;
        /// @brief stores the VPID that generated the exit
        bsl::safe_uint16 vpid;
        /// @brief stores the VPSID that generated the exit
        bsl::safe_uint16 vpsid;
        /// @brief stores the exit reason
        bsl::safe_uintmax exit_reason;
        /// @brief stores the exit qualification (Intel) or exit_info1 (AMD)
        bsl::safe_uintmax ei1;
        /// @brief stores the exit information (Intel) or exit_info2 (AMD)
        bsl::safe_uintmax ei2;
        /// @brief stores the exit input information (AMD) or ignored (Intel)
        bsl::safe_uintmax ei3;
        /// @brief stores rax
        bsl::safe_uintmax rax;
        /// @brief stores rbx
        bsl::safe_uintmax rbx;
        /// @brief stores rcx
        bsl::safe_uintmax rcx;
        /// @brief stores rdx
        bsl::safe_uintmax rdx;
        /// @brief stores rbp
        bsl::safe_uintmax rbp;
        /// @brief stores rsi
        bsl::safe_uintmax rsi;
        /// @brief stores rdi
        bsl::safe_uintmax rdi;
        /// @brief stores r8
        bsl::safe_uintmax r8;
        /// @brief stores r9
        bsl::safe_uintmax r9;
        /// @brief stores r10
        bsl::safe_uintmax r10;
        /// @brief stores r11
        bsl::safe_uintmax r11;
        /// @brief stores r12
        bsl::safe_uintmax r12;
        /// @brief stores r13
        bsl::safe_uintmax r13;
        /// @brief stores r14
        bsl::safe_uintmax r14;
        /// @brief stores r15
        bsl::safe_uintmax r15;
        /// @brief stores rsp
        bsl::safe_uintmax rsp;
        /// @brief stores rip
        bsl::safe_uintmax rip;
    };
}

#endif
