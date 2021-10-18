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

/// <!-- description -->
///   @brief Defines the extension's Global Storage (GS).
///     Extensions can use this to store global variables as needed.
///     The gs_t can also be used during unit testing to store testing
///     specific logic and data to ensure tests can support constexpr
///     style unit testing. Also note that this is stored in the arch
///     specific folders as it usually needs to store arch specific
///     resources.
///
#[derive(Debug, Copy, Clone)]
pub struct GsT {
    /// @brief stores the MSR bitmap used by this vs_t
    pub msr_bitmap: *mut u8,
    /// @brief stores the physical address of the MSR bitmap above
    pub msr_bitmap_phys: bsl::SafeU64,
}

impl GsT {
    /// <!-- description -->
    ///   @brief creates a new GsT
    ///
    pub const fn new() -> Self {
        Self {
            msr_bitmap: core::ptr::null_mut(),
            msr_bitmap_phys: bsl::SafeU64::new(0),
        }
    }
}
