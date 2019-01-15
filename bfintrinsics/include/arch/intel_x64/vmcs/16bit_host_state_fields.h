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

#ifndef VMCS_INTEL_X64_16BIT_HOST_STATE_FIELDS_H
#define VMCS_INTEL_X64_16BIT_HOST_STATE_FIELDS_H

#include <arch/intel_x64/vmcs/helpers.h>

/// Intel x86_64 VMCS 16-Bit Host-State Fields
///
/// The following provides the interface for the 16-bit host-state VMCS
/// fields as defined in Appendix B.1.3, Vol. 3 of the Intel Software Developer's
/// Manual.
///

// *INDENT-OFF*

namespace intel_x64
{
namespace vmcs
{

namespace host_es_selector
{
    constexpr const auto addr = 0x0000000000000C00ULL;
    constexpr const auto name = "host_es_selector";

    inline bool exists()
    { return true; }

    inline auto get()
    { return get_vmcs_field(addr, name, exists()); }

    inline auto get_if_exists(bool verbose = false)
    { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }

    inline void set(value_type val)
    { set_vmcs_field(val, addr, name, exists()); }

    inline void set_if_exists(value_type val, bool verbose = false)
    { set_vmcs_field_if_exists(val, addr, name, verbose, exists()); }

    namespace rpl
    {
        constexpr const auto mask = 0x00000003ULL;
        constexpr const auto from = 0ULL;
        constexpr const auto name = "rpl";

        inline auto get()
        { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

        inline auto get(value_type field)
        { return get_bits(field, mask) >> from; }

        inline auto get_if_exists(bool verbose = false)
        { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }

        inline void set(value_type val)
        { set_vmcs_field_bits(val, addr, mask, from, name, exists()); }

        inline void set(value_type &field, value_type val)
        { field = set_bits(field, mask, (val << from)); }

        inline void set_if_exists(value_type val, bool verbose = false)
        { set_vmcs_field_bits_if_exists(val, addr, mask, from, name, verbose, exists()); }

        inline void dump(int level, std::string *msg = nullptr)
        { dump_vmcs_subnhex(level, msg); }
    }

    namespace ti
    {
        constexpr const auto mask = 0x00000004ULL;
        constexpr const auto from = 2ULL;
        constexpr const auto name = "ti";

        inline auto is_enabled()
        { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_enabled(value_type field)
        { return is_bit_set(field, from); }

        inline auto is_enabled_if_exists(bool verbose = false)
        { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_disabled()
        { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_disabled(value_type field)
        { return is_bit_cleared(field, from); }

        inline auto is_disabled_if_exists(bool verbose = false)
        { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline void enable()
        { set_vmcs_field_bit(addr, from, name, exists()); }

        inline void enable(value_type &field)
        { field = set_bit(field, from); }

        inline void enable_if_exists(bool verbose = false)
        { set_vmcs_field_bit_if_exists(addr, from, name, verbose, exists()); }

        inline void disable()
        { clear_vmcs_field_bit(addr, from, name, exists()); }

        inline void disable(value_type &field)
        { field = clear_bit(field, from); }

        inline void disable_if_exists(bool verbose = false)
        { clear_vmcs_field_bit_if_exists(addr, from, name, verbose, exists()); }

        inline void set(bool val)
        { val ? enable() : disable(); }

        inline void set(value_type &field, bool val)
        { val ? enable(field) : disable(field); }

        inline void set_if_exists(bool val, bool verbose = false)
        { val ? enable_if_exists(verbose) : disable_if_exists(verbose); }

        inline void dump(int level, std::string *msg = nullptr)
        { dump_vmcs_subbool(level, msg); }
    }

    namespace index
    {
        constexpr const auto mask = 0x0000FFF8ULL;
        constexpr const auto from = 3ULL;
        constexpr const auto name = "index";

        inline auto get()
        { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

        inline auto get(value_type field)
        { return get_bits(field, mask) >> from; }

        inline auto get_if_exists(bool verbose = false)
        { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }

        inline void set(value_type val)
        { set_vmcs_field_bits(val, addr, mask, from, name, exists()); }

        inline void set(value_type &field, value_type val)
        { field = set_bits(field, mask, (val << from)); }

        inline void set_if_exists(value_type val, bool verbose = false)
        { set_vmcs_field_bits_if_exists(val, addr, mask, from, name, verbose, exists()); }

        inline void dump(int level, std::string *msg = nullptr)
        { dump_vmcs_subnhex(level, msg); }
    }

    inline void dump(int level, std::string *msg = nullptr)
    {
        dump_vmcs_nhex(level, msg);
        rpl::dump(level, msg);
        ti::dump(level, msg);
        index::dump(level, msg);
    }
}

namespace host_cs_selector
{
    constexpr const auto addr = 0x0000000000000C02ULL;
    constexpr const auto name = "host_cs_selector";

    inline bool exists()
    { return true; }

    inline auto get()
    { return get_vmcs_field(addr, name, exists()); }

    inline auto get_if_exists(bool verbose = false)
    { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }

    inline void set(value_type val)
    { set_vmcs_field(val, addr, name, exists()); }

    inline void set_if_exists(value_type val, bool verbose = false)
    { set_vmcs_field_if_exists(val, addr, name, verbose, exists()); }

    namespace rpl
    {
        constexpr const auto mask = 0x00000003ULL;
        constexpr const auto from = 0ULL;
        constexpr const auto name = "rpl";

        inline auto get()
        { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

        inline auto get(value_type field)
        { return get_bits(field, mask) >> from; }

        inline auto get_if_exists(bool verbose = false)
        { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }

        inline void set(value_type val)
        { set_vmcs_field_bits(val, addr, mask, from, name, exists()); }

        inline void set(value_type &field, value_type val)
        { field = set_bits(field, mask, (val << from)); }

        inline void set_if_exists(value_type val, bool verbose = false)
        { set_vmcs_field_bits_if_exists(val, addr, mask, from, name, verbose, exists()); }

        inline void dump(int level, std::string *msg = nullptr)
        { dump_vmcs_subnhex(level, msg); }
    }

    namespace ti
    {
        constexpr const auto mask = 0x00000004ULL;
        constexpr const auto from = 2ULL;
        constexpr const auto name = "ti";

        inline auto is_enabled()
        { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_enabled(value_type field)
        { return is_bit_set(field, from); }

        inline auto is_enabled_if_exists(bool verbose = false)
        { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_disabled()
        { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_disabled(value_type field)
        { return is_bit_cleared(field, from); }

        inline auto is_disabled_if_exists(bool verbose = false)
        { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline void enable()
        { set_vmcs_field_bit(addr, from, name, exists()); }

        inline void enable(value_type &field)
        { field = set_bit(field, from); }

        inline void enable_if_exists(bool verbose = false)
        { set_vmcs_field_bit_if_exists(addr, from, name, verbose, exists()); }

        inline void disable()
        { clear_vmcs_field_bit(addr, from, name, exists()); }

        inline void disable(value_type &field)
        { field = clear_bit(field, from); }

        inline void disable_if_exists(bool verbose = false)
        { clear_vmcs_field_bit_if_exists(addr, from, name, verbose, exists()); }

        inline void set(bool val)
        { val ? enable() : disable(); }

        inline void set(value_type &field, bool val)
        { val ? enable(field) : disable(field); }

        inline void set_if_exists(bool val, bool verbose = false)
        { val ? enable_if_exists(verbose) : disable_if_exists(verbose); }

        inline void dump(int level, std::string *msg = nullptr)
        { dump_vmcs_subbool(level, msg); }
    }

    namespace index
    {
        constexpr const auto mask = 0x0000FFF8ULL;
        constexpr const auto from = 3ULL;
        constexpr const auto name = "index";

        inline auto get()
        { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

        inline auto get(value_type field)
        { return get_bits(field, mask) >> from; }

        inline auto get_if_exists(bool verbose = false)
        { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }

        inline void set(value_type val)
        { set_vmcs_field_bits(val, addr, mask, from, name, exists()); }

        inline void set(value_type &field, value_type val)
        { field = set_bits(field, mask, (val << from)); }

        inline void set_if_exists(value_type val, bool verbose = false)
        { set_vmcs_field_bits_if_exists(val, addr, mask, from, name, verbose, exists()); }

        inline void dump(int level, std::string *msg = nullptr)
        { dump_vmcs_subnhex(level, msg); }
    }

    inline void dump(int level, std::string *msg = nullptr)
    {
        dump_vmcs_nhex(level, msg);
        rpl::dump(level, msg);
        ti::dump(level, msg);
        index::dump(level, msg);
    }
}

namespace host_ss_selector
{
    constexpr const auto addr = 0x0000000000000C04ULL;
    constexpr const auto name = "host_ss_selector";

    inline bool exists()
    { return true; }

    inline auto get()
    { return get_vmcs_field(addr, name, exists()); }

    inline auto get_if_exists(bool verbose = false)
    { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }

    inline void set(value_type val)
    { set_vmcs_field(val, addr, name, exists()); }

    inline void set_if_exists(value_type val, bool verbose = false)
    { set_vmcs_field_if_exists(val, addr, name, verbose, exists()); }

    namespace rpl
    {
        constexpr const auto mask = 0x00000003ULL;
        constexpr const auto from = 0ULL;
        constexpr const auto name = "rpl";

        inline auto get()
        { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

        inline auto get(value_type field)
        { return get_bits(field, mask) >> from; }

        inline auto get_if_exists(bool verbose = false)
        { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }

        inline void set(value_type val)
        { set_vmcs_field_bits(val, addr, mask, from, name, exists()); }

        inline void set(value_type &field, value_type val)
        { field = set_bits(field, mask, (val << from)); }

        inline void set_if_exists(value_type val, bool verbose = false)
        { set_vmcs_field_bits_if_exists(val, addr, mask, from, name, verbose, exists()); }

        inline void dump(int level, std::string *msg = nullptr)
        { dump_vmcs_subnhex(level, msg); }
    }

    namespace ti
    {
        constexpr const auto mask = 0x00000004ULL;
        constexpr const auto from = 2ULL;
        constexpr const auto name = "ti";

        inline auto is_enabled()
        { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_enabled(value_type field)
        { return is_bit_set(field, from); }

        inline auto is_enabled_if_exists(bool verbose = false)
        { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_disabled()
        { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_disabled(value_type field)
        { return is_bit_cleared(field, from); }

        inline auto is_disabled_if_exists(bool verbose = false)
        { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline void enable()
        { set_vmcs_field_bit(addr, from, name, exists()); }

        inline void enable(value_type &field)
        { field = set_bit(field, from); }

        inline void enable_if_exists(bool verbose = false)
        { set_vmcs_field_bit_if_exists(addr, from, name, verbose, exists()); }

        inline void disable()
        { clear_vmcs_field_bit(addr, from, name, exists()); }

        inline void disable(value_type &field)
        { field = clear_bit(field, from); }

        inline void disable_if_exists(bool verbose = false)
        { clear_vmcs_field_bit_if_exists(addr, from, name, verbose, exists()); }

        inline void set(bool val)
        { val ? enable() : disable(); }

        inline void set(value_type &field, bool val)
        { val ? enable(field) : disable(field); }

        inline void set_if_exists(bool val, bool verbose = false)
        { val ? enable_if_exists(verbose) : disable_if_exists(verbose); }

        inline void dump(int level, std::string *msg = nullptr)
        { dump_vmcs_subbool(level, msg); }
    }

    namespace index
    {
        constexpr const auto mask = 0x0000FFF8ULL;
        constexpr const auto from = 3ULL;
        constexpr const auto name = "index";

        inline auto get()
        { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

        inline auto get(value_type field)
        { return get_bits(field, mask) >> from; }

        inline auto get_if_exists(bool verbose = false)
        { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }

        inline void set(value_type val)
        { set_vmcs_field_bits(val, addr, mask, from, name, exists()); }

        inline void set(value_type &field, value_type val)
        { field = set_bits(field, mask, (val << from)); }

        inline void set_if_exists(value_type val, bool verbose = false)
        { set_vmcs_field_bits_if_exists(val, addr, mask, from, name, verbose, exists()); }

        inline void dump(int level, std::string *msg = nullptr)
        { dump_vmcs_subnhex(level, msg); }
    }

    inline void dump(int level, std::string *msg = nullptr)
    {
        dump_vmcs_nhex(level, msg);
        rpl::dump(level, msg);
        ti::dump(level, msg);
        index::dump(level, msg);
    }
}

namespace host_ds_selector
{
    constexpr const auto addr = 0x0000000000000C06ULL;
    constexpr const auto name = "host_ds_selector";

    inline bool exists()
    { return true; }

    inline auto get()
    { return get_vmcs_field(addr, name, exists()); }

    inline auto get_if_exists(bool verbose = false)
    { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }

    inline void set(value_type val)
    { set_vmcs_field(val, addr, name, exists()); }

    inline void set_if_exists(value_type val, bool verbose = false)
    { set_vmcs_field_if_exists(val, addr, name, verbose, exists()); }

    namespace rpl
    {
        constexpr const auto mask = 0x00000003ULL;
        constexpr const auto from = 0ULL;
        constexpr const auto name = "rpl";

        inline auto get()
        { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

        inline auto get(value_type field)
        { return get_bits(field, mask) >> from; }

        inline auto get_if_exists(bool verbose = false)
        { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }

        inline void set(value_type val)
        { set_vmcs_field_bits(val, addr, mask, from, name, exists()); }

        inline void set(value_type &field, value_type val)
        { field = set_bits(field, mask, (val << from)); }

        inline void set_if_exists(value_type val, bool verbose = false)
        { set_vmcs_field_bits_if_exists(val, addr, mask, from, name, verbose, exists()); }

        inline void dump(int level, std::string *msg = nullptr)
        { dump_vmcs_subnhex(level, msg); }
    }

    namespace ti
    {
        constexpr const auto mask = 0x00000004ULL;
        constexpr const auto from = 2ULL;
        constexpr const auto name = "ti";

        inline auto is_enabled()
        { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_enabled(value_type field)
        { return is_bit_set(field, from); }

        inline auto is_enabled_if_exists(bool verbose = false)
        { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_disabled()
        { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_disabled(value_type field)
        { return is_bit_cleared(field, from); }

        inline auto is_disabled_if_exists(bool verbose = false)
        { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline void enable()
        { set_vmcs_field_bit(addr, from, name, exists()); }

        inline void enable(value_type &field)
        { field = set_bit(field, from); }

        inline void enable_if_exists(bool verbose = false)
        { set_vmcs_field_bit_if_exists(addr, from, name, verbose, exists()); }

        inline void disable()
        { clear_vmcs_field_bit(addr, from, name, exists()); }

        inline void disable(value_type &field)
        { field = clear_bit(field, from); }

        inline void disable_if_exists(bool verbose = false)
        { clear_vmcs_field_bit_if_exists(addr, from, name, verbose, exists()); }

        inline void set(bool val)
        { val ? enable() : disable(); }

        inline void set(value_type &field, bool val)
        { val ? enable(field) : disable(field); }

        inline void set_if_exists(bool val, bool verbose = false)
        { val ? enable_if_exists(verbose) : disable_if_exists(verbose); }

        inline void dump(int level, std::string *msg = nullptr)
        { dump_vmcs_subbool(level, msg); }
    }

    namespace index
    {
        constexpr const auto mask = 0x0000FFF8ULL;
        constexpr const auto from = 3ULL;
        constexpr const auto name = "index";

        inline auto get()
        { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

        inline auto get(value_type field)
        { return get_bits(field, mask) >> from; }

        inline auto get_if_exists(bool verbose = false)
        { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }

        inline void set(value_type val)
        { set_vmcs_field_bits(val, addr, mask, from, name, exists()); }

        inline void set(value_type &field, value_type val)
        { field = set_bits(field, mask, (val << from)); }

        inline void set_if_exists(value_type val, bool verbose = false)
        { set_vmcs_field_bits_if_exists(val, addr, mask, from, name, verbose, exists()); }

        inline void dump(int level, std::string *msg = nullptr)
        { dump_vmcs_subnhex(level, msg); }
    }

    inline void dump(int level, std::string *msg = nullptr)
    {
        dump_vmcs_nhex(level, msg);
        rpl::dump(level, msg);
        ti::dump(level, msg);
        index::dump(level, msg);
    }
}

namespace host_fs_selector
{
    constexpr const auto addr = 0x0000000000000C08ULL;
    constexpr const auto name = "host_fs_selector";

    inline bool exists()
    { return true; }

    inline auto get()
    { return get_vmcs_field(addr, name, exists()); }

    inline auto get_if_exists(bool verbose = false)
    { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }

    inline void set(value_type val)
    { set_vmcs_field(val, addr, name, exists()); }

    inline void set_if_exists(value_type val, bool verbose = false)
    { set_vmcs_field_if_exists(val, addr, name, verbose, exists()); }

    namespace rpl
    {
        constexpr const auto mask = 0x00000003ULL;
        constexpr const auto from = 0ULL;
        constexpr const auto name = "rpl";

        inline auto get()
        { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

        inline auto get(value_type field)
        { return get_bits(field, mask) >> from; }

        inline auto get_if_exists(bool verbose = false)
        { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }

        inline void set(value_type val)
        { set_vmcs_field_bits(val, addr, mask, from, name, exists()); }

        inline void set(value_type &field, value_type val)
        { field = set_bits(field, mask, (val << from)); }

        inline void set_if_exists(value_type val, bool verbose = false)
        { set_vmcs_field_bits_if_exists(val, addr, mask, from, name, verbose, exists()); }

        inline void dump(int level, std::string *msg = nullptr)
        { dump_vmcs_subnhex(level, msg); }
    }

    namespace ti
    {
        constexpr const auto mask = 0x00000004ULL;
        constexpr const auto from = 2ULL;
        constexpr const auto name = "ti";

        inline auto is_enabled()
        { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_enabled(value_type field)
        { return is_bit_set(field, from); }

        inline auto is_enabled_if_exists(bool verbose = false)
        { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_disabled()
        { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_disabled(value_type field)
        { return is_bit_cleared(field, from); }

        inline auto is_disabled_if_exists(bool verbose = false)
        { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline void enable()
        { set_vmcs_field_bit(addr, from, name, exists()); }

        inline void enable(value_type &field)
        { field = set_bit(field, from); }

        inline void enable_if_exists(bool verbose = false)
        { set_vmcs_field_bit_if_exists(addr, from, name, verbose, exists()); }

        inline void disable()
        { clear_vmcs_field_bit(addr, from, name, exists()); }

        inline void disable(value_type &field)
        { field = clear_bit(field, from); }

        inline void disable_if_exists(bool verbose = false)
        { clear_vmcs_field_bit_if_exists(addr, from, name, verbose, exists()); }

        inline void set(bool val)
        { val ? enable() : disable(); }

        inline void set(value_type &field, bool val)
        { val ? enable(field) : disable(field); }

        inline void set_if_exists(bool val, bool verbose = false)
        { val ? enable_if_exists(verbose) : disable_if_exists(verbose); }

        inline void dump(int level, std::string *msg = nullptr)
        { dump_vmcs_subbool(level, msg); }
    }

    namespace index
    {
        constexpr const auto mask = 0x0000FFF8ULL;
        constexpr const auto from = 3ULL;
        constexpr const auto name = "index";

        inline auto get()
        { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

        inline auto get(value_type field)
        { return get_bits(field, mask) >> from; }

        inline auto get_if_exists(bool verbose = false)
        { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }

        inline void set(value_type val)
        { set_vmcs_field_bits(val, addr, mask, from, name, exists()); }

        inline void set(value_type &field, value_type val)
        { field = set_bits(field, mask, (val << from)); }

        inline void set_if_exists(value_type val, bool verbose = false)
        { set_vmcs_field_bits_if_exists(val, addr, mask, from, name, verbose, exists()); }

        inline void dump(int level, std::string *msg = nullptr)
        { dump_vmcs_subnhex(level, msg); }
    }

    inline void dump(int level, std::string *msg = nullptr)
    {
        dump_vmcs_nhex(level, msg);
        rpl::dump(level, msg);
        ti::dump(level, msg);
        index::dump(level, msg);
    }
}

namespace host_gs_selector
{
    constexpr const auto addr = 0x0000000000000C0AULL;
    constexpr const auto name = "host_gs_selector";

    inline bool exists()
    { return true; }

    inline auto get()
    { return get_vmcs_field(addr, name, exists()); }

    inline auto get_if_exists(bool verbose = false)
    { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }

    inline void set(value_type val)
    { set_vmcs_field(val, addr, name, exists()); }

    inline void set_if_exists(value_type val, bool verbose = false)
    { set_vmcs_field_if_exists(val, addr, name, verbose, exists()); }

    namespace rpl
    {
        constexpr const auto mask = 0x00000003ULL;
        constexpr const auto from = 0ULL;
        constexpr const auto name = "rpl";

        inline auto get()
        { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

        inline auto get(value_type field)
        { return get_bits(field, mask) >> from; }

        inline auto get_if_exists(bool verbose = false)
        { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }

        inline void set(value_type val)
        { set_vmcs_field_bits(val, addr, mask, from, name, exists()); }

        inline void set(value_type &field, value_type val)
        { field = set_bits(field, mask, (val << from)); }

        inline void set_if_exists(value_type val, bool verbose = false)
        { set_vmcs_field_bits_if_exists(val, addr, mask, from, name, verbose, exists()); }

        inline void dump(int level, std::string *msg = nullptr)
        { dump_vmcs_subnhex(level, msg); }
    }

    namespace ti
    {
        constexpr const auto mask = 0x00000004ULL;
        constexpr const auto from = 2ULL;
        constexpr const auto name = "ti";

        inline auto is_enabled()
        { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_enabled(value_type field)
        { return is_bit_set(field, from); }

        inline auto is_enabled_if_exists(bool verbose = false)
        { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_disabled()
        { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_disabled(value_type field)
        { return is_bit_cleared(field, from); }

        inline auto is_disabled_if_exists(bool verbose = false)
        { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline void enable()
        { set_vmcs_field_bit(addr, from, name, exists()); }

        inline void enable(value_type &field)
        { field = set_bit(field, from); }

        inline void enable_if_exists(bool verbose = false)
        { set_vmcs_field_bit_if_exists(addr, from, name, verbose, exists()); }

        inline void disable()
        { clear_vmcs_field_bit(addr, from, name, exists()); }

        inline void disable(value_type &field)
        { field = clear_bit(field, from); }

        inline void disable_if_exists(bool verbose = false)
        { clear_vmcs_field_bit_if_exists(addr, from, name, verbose, exists()); }

        inline void set(bool val)
        { val ? enable() : disable(); }

        inline void set(value_type &field, bool val)
        { val ? enable(field) : disable(field); }

        inline void set_if_exists(bool val, bool verbose = false)
        { val ? enable_if_exists(verbose) : disable_if_exists(verbose); }

        inline void dump(int level, std::string *msg = nullptr)
        { dump_vmcs_subbool(level, msg); }
    }

    namespace index
    {
        constexpr const auto mask = 0x0000FFF8ULL;
        constexpr const auto from = 3ULL;
        constexpr const auto name = "index";

        inline auto get()
        { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

        inline auto get(value_type field)
        { return get_bits(field, mask) >> from; }

        inline auto get_if_exists(bool verbose = false)
        { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }

        inline void set(value_type val)
        { set_vmcs_field_bits(val, addr, mask, from, name, exists()); }

        inline void set(value_type &field, value_type val)
        { field = set_bits(field, mask, (val << from)); }

        inline void set_if_exists(value_type val, bool verbose = false)
        { set_vmcs_field_bits_if_exists(val, addr, mask, from, name, verbose, exists()); }

        inline void dump(int level, std::string *msg = nullptr)
        { dump_vmcs_subnhex(level, msg); }
    }

    inline void dump(int level, std::string *msg = nullptr)
    {
        dump_vmcs_nhex(level, msg);
        rpl::dump(level, msg);
        ti::dump(level, msg);
        index::dump(level, msg);
    }
}

namespace host_tr_selector
{
    constexpr const auto addr = 0x0000000000000C0CULL;
    constexpr const auto name = "host_tr_selector";

    inline bool exists()
    { return true; }

    inline auto get()
    { return get_vmcs_field(addr, name, exists()); }

    inline auto get_if_exists(bool verbose = false)
    { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }

    inline void set(value_type val)
    { set_vmcs_field(val, addr, name, exists()); }

    inline void set_if_exists(value_type val, bool verbose = false)
    { set_vmcs_field_if_exists(val, addr, name, verbose, exists()); }

    namespace rpl
    {
        constexpr const auto mask = 0x00000003ULL;
        constexpr const auto from = 0ULL;
        constexpr const auto name = "rpl";

        inline auto get()
        { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

        inline auto get(value_type field)
        { return get_bits(field, mask) >> from; }

        inline auto get_if_exists(bool verbose = false)
        { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }

        inline void set(value_type val)
        { set_vmcs_field_bits(val, addr, mask, from, name, exists()); }

        inline void set(value_type &field, value_type val)
        { field = set_bits(field, mask, (val << from)); }

        inline void set_if_exists(value_type val, bool verbose = false)
        { set_vmcs_field_bits_if_exists(val, addr, mask, from, name, verbose, exists()); }

        inline void dump(int level, std::string *msg = nullptr)
        { dump_vmcs_subnhex(level, msg); }
    }

    namespace ti
    {
        constexpr const auto mask = 0x00000004ULL;
        constexpr const auto from = 2ULL;
        constexpr const auto name = "ti";

        inline auto is_enabled()
        { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_enabled(value_type field)
        { return is_bit_set(field, from); }

        inline auto is_enabled_if_exists(bool verbose = false)
        { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_disabled()
        { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_disabled(value_type field)
        { return is_bit_cleared(field, from); }

        inline auto is_disabled_if_exists(bool verbose = false)
        { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline void enable()
        { set_vmcs_field_bit(addr, from, name, exists()); }

        inline void enable(value_type &field)
        { field = set_bit(field, from); }

        inline void enable_if_exists(bool verbose = false)
        { set_vmcs_field_bit_if_exists(addr, from, name, verbose, exists()); }

        inline void disable()
        { clear_vmcs_field_bit(addr, from, name, exists()); }

        inline void disable(value_type &field)
        { field = clear_bit(field, from); }

        inline void disable_if_exists(bool verbose = false)
        { clear_vmcs_field_bit_if_exists(addr, from, name, verbose, exists()); }

        inline void set(bool val)
        { val ? enable() : disable(); }

        inline void set(value_type &field, bool val)
        { val ? enable(field) : disable(field); }

        inline void set_if_exists(bool val, bool verbose = false)
        { val ? enable_if_exists(verbose) : disable_if_exists(verbose); }

        inline void dump(int level, std::string *msg = nullptr)
        { dump_vmcs_subbool(level, msg); }
    }

    namespace index
    {
        constexpr const auto mask = 0x0000FFF8ULL;
        constexpr const auto from = 3ULL;
        constexpr const auto name = "index";

        inline auto get()
        { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

        inline auto get(value_type field)
        { return get_bits(field, mask) >> from; }

        inline auto get_if_exists(bool verbose = false)
        { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }

        inline void set(value_type val)
        { set_vmcs_field_bits(val, addr, mask, from, name, exists()); }

        inline void set(value_type &field, value_type val)
        { field = set_bits(field, mask, (val << from)); }

        inline void set_if_exists(value_type val, bool verbose = false)
        { set_vmcs_field_bits_if_exists(val, addr, mask, from, name, verbose, exists()); }

        inline void dump(int level, std::string *msg = nullptr)
        { dump_vmcs_subnhex(level, msg); }
    }

    inline void dump(int level, std::string *msg = nullptr)
    {
        dump_vmcs_nhex(level, msg);
        rpl::dump(level, msg);
        ti::dump(level, msg);
        index::dump(level, msg);
    }
}

}
}

// *INDENT-ON*

#endif
