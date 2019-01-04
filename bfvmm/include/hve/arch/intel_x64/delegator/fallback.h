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

#ifndef BFVMM_DELEGATOR_FALLBACK_INTEL_X64_H
#define BFVMM_DELEGATOR_FALLBACK_INTEL_X64_H

#include <stdint.h>
#include <bfdelegate.h>
#include <bfgsl.h>

#include "../../../../vmm_types.h"

// -----------------------------------------------------------------------------
// Exports
// -----------------------------------------------------------------------------

#include <bfexports.h>

#ifndef STATIC_HVE
#ifdef SHARED_HVE
#define EXPORT_HVE EXPORT_SYM
#else
#define EXPORT_HVE IMPORT_SYM
#endif
#else
#define EXPORT_HVE
#endif

namespace bfvmm::intel_x64::fallback
{

/// Fallback delegator
///
/// Delegates processing of vmexits that were not handled by any exit handlers
///
class EXPORT_HVE delegator
{

public:

    /// Default Constructor
    ///
    /// @expects none
    /// @ensures none
    ///
    delegator() = default;

    /// Destructor
    ///
    /// @expects none
    /// @ensures none
    ///
    ~delegator() = default;

    /// Handle
    ///
    /// Handle an unhandled vmexit using registered handlers
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param vcpu The vcpu the vmexit occurred on
    ///
    /// @return True if the vmexit was successfully handled, false otherwise
    ///
    bool handle(vcpu_t vcpu);
};

}

#endif
