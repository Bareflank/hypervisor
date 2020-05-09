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

#ifndef SYSCALL_VCPU_H
#define SYSCALL_VCPU_H

#include <bsl/errc_type.hpp>

namespace syscall
{
    // TODO: move me
    struct vcpu_context;

    /// <!-- description -->
    ///   @brief Tells the microkernel to execute a vCPU. This can be used
    ///     to return from a VMExit, or to switch the vCPU to a new one.
    ///     This syscall does not return on success, and instead executes
    ///     the desired vCPU. On failure, this function will return a
    ///     bsl::errc_type.
    ///   @include example/syscall/run_vcpu/x64/intel/main.cpp
    ///
    /// <!-- inputs/outputs -->
    ///   @param vc a pointer to the vcpu_context associated with the
    ///     vCPU you wish to run.
    ///   @return Does not return on success. Returns a bsl::errc_type
    ///     on failure.
    ///
    extern "C" [[nodiscard]] bsl::errc_type run_vcpu(vcpu_context *const vc) noexcept;
}

#endif
