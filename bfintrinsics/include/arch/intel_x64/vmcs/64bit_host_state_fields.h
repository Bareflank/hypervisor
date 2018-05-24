//
// Bareflank Hypervisor
// Copyright (C) 2015 Assured Information Security, Inc.
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

#ifndef VMCS_INTEL_X64_64BIT_HOST_STATE_FIELDS_H
#define VMCS_INTEL_X64_64BIT_HOST_STATE_FIELDS_H

#include <arch/intel_x64/vmcs/helpers.h>

/// Intel x86_64 VMCS 64-bit Host-State Fields
///
/// The following provides the interface for the 64-bit host-state VMCS
/// fields as defined in Appendix B.2.4, Vol. 3 of the Intel Software Developer's
/// Manual.
///

// *INDENT-OFF*

namespace intel_x64
{
namespace vmcs
{

namespace host_ia32_pat
{
    constexpr const auto addr = 0x0000000000002C00ULL;
    constexpr const auto name = "host_ia32_pat";

    inline auto exists()
    { return msrs::ia32_vmx_true_exit_ctls::load_ia32_pat::is_allowed1(); }

    inline auto get()
    { return get_vmcs_field(addr, name, exists()); }

    inline auto get_if_exists(bool verbose = false)
    { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }

    inline void set(value_type val)
    { set_vmcs_field(val, addr, name, exists()); }

    inline void set_if_exists(value_type val, bool verbose = false)
    { set_vmcs_field_if_exists(val, addr, name, verbose, exists()); }

    namespace pa0
    {
        constexpr const auto mask = 0x00000000000000FFULL;
        constexpr const auto from = 0ULL;
        constexpr const auto name = "pa0";

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

        namespace memory_type
        {
            constexpr const auto mask = 0x0000000000000007ULL;
            constexpr const auto from = 0ULL;
            constexpr const auto name = "memory_type";

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

        namespace reserved
        {
            constexpr const auto mask = 0x00000000000000F8ULL;
            constexpr const auto from = 3ULL;
            constexpr const auto name = "reserved";

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
            memory_type::dump(level, msg);
            reserved::dump(level, msg);
        }
    }

    namespace pa1
    {
        constexpr const auto mask = 0x000000000000FF00ULL;
        constexpr const auto from = 8ULL;
        constexpr const auto name = "pa1";

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

        namespace memory_type
        {
            constexpr const auto mask = 0x0000000000000700ULL;
            constexpr const auto from = 8ULL;
            constexpr const auto name = "memory_type";

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

        namespace reserved
        {
            constexpr const auto mask = 0x000000000000F800ULL;
            constexpr const auto from = 11ULL;
            constexpr const auto name = "reserved";

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
            memory_type::dump(level, msg);
            reserved::dump(level, msg);
        }
    }

    namespace pa2
    {
        constexpr const auto mask = 0x0000000000FF0000ULL;
        constexpr const auto from = 16ULL;
        constexpr const auto name = "pa2";

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

        namespace memory_type
        {
            constexpr const auto mask = 0x0000000000070000ULL;
            constexpr const auto from = 16ULL;
            constexpr const auto name = "memory_type";

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

        namespace reserved
        {
            constexpr const auto mask = 0x0000000000F80000ULL;
            constexpr const auto from = 19ULL;
            constexpr const auto name = "reserved";

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
            memory_type::dump(level, msg);
            reserved::dump(level, msg);
        }
    }

    namespace pa3
    {
        constexpr const auto mask = 0x00000000FF000000ULL;
        constexpr const auto from = 24ULL;
        constexpr const auto name = "pa3";

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

        namespace memory_type
        {
            constexpr const auto mask = 0x0000000007000000ULL;
            constexpr const auto from = 24ULL;
            constexpr const auto name = "memory_type";

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

        namespace reserved
        {
            constexpr const auto mask = 0x00000000F8000000ULL;
            constexpr const auto from = 27ULL;
            constexpr const auto name = "reserved";

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
            memory_type::dump(level, msg);
            reserved::dump(level, msg);
        }
    }

    namespace pa4
    {
        constexpr const auto mask = 0x000000FF00000000ULL;
        constexpr const auto from = 32ULL;
        constexpr const auto name = "pa4";

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

        namespace memory_type
        {
            constexpr const auto mask = 0x0000000700000000ULL;
            constexpr const auto from = 32ULL;
            constexpr const auto name = "memory_type";

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

        namespace reserved
        {
            constexpr const auto mask = 0x000000F800000000ULL;
            constexpr const auto from = 35ULL;
            constexpr const auto name = "reserved";

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
            memory_type::dump(level, msg);
            reserved::dump(level, msg);
        }
    }

    namespace pa5
    {
        constexpr const auto mask = 0x0000FF0000000000ULL;
        constexpr const auto from = 40ULL;
        constexpr const auto name = "pa5";

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

        namespace memory_type
        {
            constexpr const auto mask = 0x0000070000000000ULL;
            constexpr const auto from = 40ULL;
            constexpr const auto name = "memory_type";

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

        namespace reserved
        {
            constexpr const auto mask = 0x0000F80000000000ULL;
            constexpr const auto from = 43ULL;
            constexpr const auto name = "reserved";

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
            memory_type::dump(level, msg);
            reserved::dump(level, msg);
        }
    }

    namespace pa6
    {
        constexpr const auto mask = 0x00FF000000000000ULL;
        constexpr const auto from = 48ULL;
        constexpr const auto name = "pa6";

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

        namespace memory_type
        {
            constexpr const auto mask = 0x0007000000000000ULL;
            constexpr const auto from = 48ULL;
            constexpr const auto name = "memory_type";

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

        namespace reserved
        {
            constexpr const auto mask = 0x00F8000000000000ULL;
            constexpr const auto from = 51ULL;
            constexpr const auto name = "reserved";

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
            memory_type::dump(level, msg);
            reserved::dump(level, msg);
        }
    }

    namespace pa7
    {
        constexpr const auto mask = 0xFF00000000000000ULL;
        constexpr const auto from = 56ULL;
        constexpr const auto name = "pa7";

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

        namespace memory_type
        {
            constexpr const auto mask = 0x0700000000000000ULL;
            constexpr const auto from = 56ULL;
            constexpr const auto name = "memory_type";

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

        namespace reserved
        {
            constexpr const auto mask = 0xF800000000000000ULL;
            constexpr const auto from = 59ULL;
            constexpr const auto name = "reserved";

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
            memory_type::dump(level, msg);
            reserved::dump(level, msg);
        }
    }

    inline void dump(int level, std::string *msg = nullptr)
    {
        dump_vmcs_nhex(level, msg);
        pa0::dump(level, msg);
        pa1::dump(level, msg);
        pa2::dump(level, msg);
        pa3::dump(level, msg);
        pa4::dump(level, msg);
        pa5::dump(level, msg);
        pa6::dump(level, msg);
        pa7::dump(level, msg);
    }
}

namespace host_ia32_efer
{
    constexpr const auto addr = 0x0000000000002C02ULL;
    constexpr const auto name = "host_ia32_efer";

    inline auto exists()
    { return msrs::ia32_vmx_true_exit_ctls::load_ia32_efer::is_allowed1(); }

    inline auto get()
    { return get_vmcs_field(addr, name, exists()); }

    inline auto get_if_exists(bool verbose = false)
    { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }

    inline void set(value_type val)
    { set_vmcs_field(val, addr, name, exists()); }

    inline void set_if_exists(value_type val, bool verbose = false)
    { set_vmcs_field_if_exists(val, addr, name, verbose, exists()); }

    namespace sce
    {
        constexpr const auto mask = 0x0000000000000001ULL;
        constexpr const auto from = 0ULL;
        constexpr const auto name = "sce";

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

    namespace lme
    {
        constexpr const auto mask = 0x0000000000000100ULL;
        constexpr const auto from = 8ULL;
        constexpr const auto name = "lme";

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

    namespace lma
    {
        constexpr const auto mask = 0x0000000000000400ULL;
        constexpr const auto from = 10ULL;
        constexpr const auto name = "lma";

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

    namespace nxe
    {
        constexpr const auto mask = 0x0000000000000800ULL;
        constexpr const auto from = 11ULL;
        constexpr const auto name = "nxe";

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

    namespace reserved
    {
        constexpr const auto mask = 0xFFFFFFFFFFFFF2FEULL;
        constexpr const auto from = 0ULL;
        constexpr const auto name = "reserved";

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
        sce::dump(level, msg);
        lme::dump(level, msg);
        lma::dump(level, msg);
        nxe::dump(level, msg);
        reserved::dump(level, msg);
    }
}

namespace host_ia32_perf_global_ctrl
{
    constexpr const auto addr = 0x0000000000002C04ULL;
    constexpr const auto name = "host_ia32_perf_global_ctrl";

    inline auto exists()
    { return msrs::ia32_vmx_true_exit_ctls::load_ia32_perf_global_ctrl::is_allowed1(); }

    inline auto get()
    { return get_vmcs_field(addr, name, exists()); }

    inline auto get_if_exists(bool verbose = false)
    { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }

    inline void set(value_type val)
    { set_vmcs_field(val, addr, name, exists()); }

    inline void set_if_exists(value_type val, bool verbose = false)
    { set_vmcs_field_if_exists(val, addr, name, verbose, exists()); }

    namespace reserved
    {
        constexpr const auto mask = 0xFFFFFFF8FFFFFFFCULL;
        constexpr const auto from = 0ULL;

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
        reserved::dump(level, msg);
    }
}

}
}

// *INDENT-ON*

#endif
