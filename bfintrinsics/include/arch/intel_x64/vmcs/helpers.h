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

#ifndef VMCS_INTEL_X64_HELPERS_H
#define VMCS_INTEL_X64_HELPERS_H

#include <bfdebug.h>
#include <bfbitmanip.h>

#include <arch/x64/misc.h>
#include <arch/x64/cpuid.h>
#include <arch/intel_x64/vmx.h>
#include <arch/intel_x64/msrs.h>

// *INDENT-OFF*

namespace intel_x64
{
namespace vmcs
{

using field_type = uint64_t;
using value_type = uint64_t;

inline value_type
get_vmcs_field(
    field_type addr, const char *name, bool exists)
{
    if (!exists) {
        throw std::logic_error("field doesn't exist: " + std::string(name));
    }

    return intel_x64::vm::read(addr, name);
}

inline value_type
get_vmcs_field_if_exists(
    field_type addr, const char *name, bool verbose, bool exists)
{
    if (exists) {
        return intel_x64::vm::read(addr, name);
    }
    else {
        if (verbose) {
            bfalert_text(0, "field doesn't exist: ", name);
        }
    }

    return 0ULL;
}

inline void
set_vmcs_field(
    value_type val, field_type addr, const char *name, bool exists)
{
    if (!exists) {
        throw std::logic_error("field doesn't exist: " + std::string(name));
    }

    intel_x64::vm::write(addr, val, name);
}

inline void
set_vmcs_field_if_exists(
    value_type val, field_type addr, const char *name, bool verbose, bool exists)
{
    if (exists) {
        intel_x64::vm::write(addr, val, name);
    }
    else {
        if (verbose) {
            bfalert_text(0, "field doesn't exist: ", name);
        }
    }
}

inline void
set_vmcs_field_bits(
    value_type val, field_type addr, value_type mask, value_type from, const char *name, bool exists)
{
    auto field = get_vmcs_field(addr, name, exists);
    set_vmcs_field(set_bits(field, mask, (val << from)), addr, name, exists);
}

inline void
set_vmcs_field_bits_if_exists(
    value_type val, field_type addr, value_type mask, value_type from, const char *name, bool verbose, bool exists)
{
    auto field = get_vmcs_field_if_exists(addr, name, verbose, exists);
    set_vmcs_field_if_exists(set_bits(field, mask, (val << from)), addr, name, verbose, exists);
}

inline void
set_vmcs_field_bit(
    field_type addr, value_type from, const char *name, bool exists)
{
    auto field = get_vmcs_field(addr, name, exists);
    set_vmcs_field(set_bit(field, from), addr, name, exists);
}

inline void
set_vmcs_field_bit_if_exists(
    field_type addr, value_type from, const char *name, bool verbose, bool exists)
{
    auto field = get_vmcs_field_if_exists(addr, name, verbose, exists);
    set_vmcs_field_if_exists(set_bit(field, from), addr, name, verbose, exists);
}

inline void
clear_vmcs_field_bit(
    field_type addr, value_type from, const char *name, bool exists)
{
    auto field = get_vmcs_field(addr, name, exists);
    set_vmcs_field(clear_bit(field, from), addr, name, exists);
}

inline void
clear_vmcs_field_bit_if_exists(
    field_type addr, value_type from, const char *name, bool verbose, bool exists)
{
    auto field = get_vmcs_field_if_exists(addr, name, verbose, exists);
    set_vmcs_field_if_exists(clear_bit(field, from), addr, name, verbose, exists);
}

inline void
enable_vm_control(
    field_type addr, value_type from, bool is_allowed1, const char *name, bool exists)
{
    if (!exists) {
        throw std::logic_error("field doesn't exist: " + std::string(name));
    }

    if (!is_allowed1) {
        throw std::logic_error("field is_allowed1 false: " + std::string(name));
    }

    intel_x64::vm::write(addr, set_bit(intel_x64::vm::read(addr, name), from), name);
}

inline void
enable_vm_control_if_allowed(
    field_type addr, value_type from, bool is_allowed1, const char *name, bool verbose, bool exists)
{
    if (!exists) {
        if (verbose) {
            bfalert_text(0, "field doesn't exist: ", name);
        }
        return;
    }

    if (!is_allowed1) {
        if (verbose) {
            bfalert_text(0, "field is_allowed1 false: ", name);
        }
        return;
    }

    intel_x64::vm::write(addr, set_bit(intel_x64::vm::read(addr, name), from), name);
}

inline void
disable_vm_control(
    field_type addr, value_type from, bool is_allowed0, const char *name, bool exists)
{
    if (!exists) {
        throw std::logic_error("field doesn't exist: " + std::string(name));
    }

    if (!is_allowed0) {
        throw std::logic_error("field is_allowed0 false: " + std::string(name));
    }

    intel_x64::vm::write(addr, clear_bit(intel_x64::vm::read(addr, name), from), name);
}

inline void
disable_vm_control_if_allowed(
    field_type addr, value_type from, bool is_allowed0, const char *name, bool verbose, bool exists)
{
    if (!exists) {
        if (verbose) {
            bfalert_text(0, "field doesn't exist: ", name);
        }
        return;
    }

    if (!is_allowed0) {
        if (verbose) {
            bfalert_text(0, "field is_allowed0 false: ", name);
        }
        return;
    }

    intel_x64::vm::write(addr, clear_bit(intel_x64::vm::read(addr, name), from), name);
}

inline void
dump_vm_control(int level, bool exists, bool is_allowed1, bool enabled, const char *name, std::string *msg)
{
    if (!exists || !is_allowed1) {
        bfdebug_subtext(level, name, "unsupported", msg);
        return;
    }

    bfdebug_subbool(level, name, enabled, msg);
}

inline auto
memory_type_reserved(value_type memory_type)
{
    switch (memory_type) {
        case x64::memory_type::uncacheable:
        case x64::memory_type::write_combining:
        case x64::memory_type::write_through:
        case x64::memory_type::write_protected:
        case x64::memory_type::write_back:
        case x64::memory_type::uncacheable_minus:
            return false;

        default:
            return true;
    }
}

#define dump_vmcs_nhex(a,b)                                                                        \
    if (exists()) {                                                                                \
        bfdebug_nhex(a, name, get(), b);                                                           \
    }                                                                                              \
    else {                                                                                         \
        bfdebug_text(a, name, "unsupported", b);                                                   \
    }

#define dump_vmcs_subnhex(a,b)                                                                     \
    if (exists()) {                                                                                \
        bfdebug_subnhex(a, name, get(), b);                                                        \
    }                                                                                              \
    else {                                                                                         \
        bfdebug_subtext(a, name, "unsupported", b);                                                \
    }

#define dump_vmcs_bool(a,b)                                                                        \
    if (exists()) {                                                                                \
        bfdebug_bool(a, name, is_enabled(), b);                                                    \
    }                                                                                              \
    else {                                                                                         \
        bfdebug_text(a, name, "unsupported", b);                                                   \
    }

#define dump_vmcs_subbool(a,b)                                                                     \
    if (exists()) {                                                                                \
        bfdebug_subbool(a, name, is_enabled(), b);                                                 \
    }                                                                                              \
    else {                                                                                         \
        bfdebug_subtext(a, name, "unsupported", b);                                                \
    }

#define dump_vmcs_text(a,b)                                                                        \
    if (exists()) {                                                                                \
        bfdebug_text(a, name, description(), b);                                                   \
    }                                                                                              \
    else {                                                                                         \
        bfdebug_text(a, name, "unsupported", b);                                                   \
    }

#define dump_vmcs_subtext(a,b)                                                                     \
    if (exists()) {                                                                                \
        bfdebug_subtext(a, name, description(), b);                                                \
    }                                                                                              \
    else {                                                                                         \
        bfdebug_subtext(a, name, "unsupported", b);                                                \
    }

}
}

// *INDENT-ON*

#endif
