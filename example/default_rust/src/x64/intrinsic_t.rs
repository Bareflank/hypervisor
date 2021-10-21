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

#[path = "intrinsic_cpuid_impl.rs"]
#[doc(hidden)]
pub mod intrinsic_cpuid_impl;
pub use intrinsic_cpuid_impl::*;

#[derive(Debug, Copy, Clone)]
pub struct IntrinsicT {}

impl IntrinsicT {
    /// <!-- description -->
    ///   @brief creates a new IntrinsicT
    ///
    pub const fn new() -> Self {
        Self {}
    }

    /// <!-- description -->
    ///   @brief Executes the CPUID instruction given the provided
    ///     EAX and ECX and returns the results.
    ///
    /// <!-- inputs/outputs -->
    ///   @param rax the index used by CPUID, returns resulting rax
    ///   @param rbx returns resulting rbx
    ///   @param rcx the subindex used by CPUID, returns the resulting rcx
    ///   @param rdx returns resulting rdx
    ///
    pub fn cpuid(
        &self,
        rax: &mut bsl::SafeU64,
        rbx: &mut bsl::SafeU64,
        rcx: &mut bsl::SafeU64,
        rdx: &mut bsl::SafeU64,
    ) {
        bsl::discard(self);

        unsafe {
            intrinsic_cpuid_impl(rax.data(), rbx.data(), rcx.data(), rdx.data());
        }
    }
}
