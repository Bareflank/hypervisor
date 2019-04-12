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

#ifndef INTERFACE_TYPES_INTEL_X64_H
#define INTERFACE_TYPES_INTEL_X64_H

#include <bftypes.h>
#include <bfdelegate.h>

#ifndef VCPU_HEADER_PATH

namespace bfvmm::intel_x64
{ class vcpu; }

/// vCPU Type
///
/// This type defines the vCPU type used by the base. By default, this is the
/// architectural vCPU defined by the base, but this can be overridden by
/// extensions that provide their own vCPU types such that the base will use
/// that type instead of its own. This allows the base APIs to provide the
/// extension with the vCPU it defines and not the vCPU that the base provides
///
/// Also note that the base will only use vcpu_t to define its external APIs.
/// Since an extension's vCPU will inherit the architectural vCPU, the APIs
/// can continue to use the base vCPU without issue. Its only the APIs
/// that provide callbacks/delegates that need to use vcpu_t to ensure that
/// the extension's APIs are receiving a vCPU that they define.
///
using vcpu_t = bfvmm::intel_x64::vcpu;

#else

#include <VCPU_HEADER_PATH>

#endif

/// Register Type
///
/// This defines the type used to express a vCPU register.
///
using reg_t = uint64_t;

/// Handler Type
///
/// This defines the function prototype for an exit handler. Any exit handler
/// that an extension of the base registers with the vCPU must have this
/// same signature.
///
using handler_t = bool(vcpu_t *);

/// Handler Delegate Type
///
/// This defines the delegate type used for exit handlers. This type will be
/// used when creating exit handler delegates both in the base and in a user
/// extension.
///
using handler_delegate_t = delegate<handler_t>;

#endif
