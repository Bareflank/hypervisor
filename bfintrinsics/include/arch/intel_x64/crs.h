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

#ifndef CRS_INTEL_X64_H
#define CRS_INTEL_X64_H

#include <bfdebug.h>
#include <bfbitmanip.h>

// -----------------------------------------------------------------------------
// Exports
// -----------------------------------------------------------------------------

#include <bfexports.h>

#ifndef STATIC_INTRINSICS
#ifdef SHARED_INTRINSICS
#define EXPORT_INTRINSICS EXPORT_SYM
#else
#define EXPORT_INTRINSICS IMPORT_SYM
#endif
#else
#define EXPORT_INTRINSICS
#endif

// -----------------------------------------------------------------------------
// Definitions
// -----------------------------------------------------------------------------

extern "C" uint64_t _read_cr0(void) noexcept;
extern "C" void _write_cr0(uint64_t val) noexcept;

extern "C" uint64_t _read_cr2(void) noexcept;
extern "C" void _write_cr2(uint64_t val) noexcept;

extern "C" uint64_t _read_cr3(void) noexcept;
extern "C" void _write_cr3(uint64_t val) noexcept;

extern "C" uint64_t _read_cr4(void) noexcept;
extern "C" void _write_cr4(uint64_t val) noexcept;

extern "C" uint64_t _read_cr8(void) noexcept;
extern "C" void _write_cr8(uint64_t val) noexcept;

extern "C" void _write_xcr0(uint64_t val) noexcept;

// *INDENT-OFF*

namespace intel_x64
{
namespace cr0
{
    constexpr const auto name = "cr0";

    using value_type = uint64_t;

    inline auto get() noexcept
    { return _read_cr0(); }

    inline void set(value_type val) noexcept
    { _write_cr0(val); }

    namespace protection_enable
    {
        constexpr const auto mask = 0x0000000000000001ULL;
        constexpr const auto from = 0ULL;
        constexpr const auto name = "protection_enable";

        inline auto is_enabled()
        { return is_bit_set(_read_cr0(), from); }

        inline auto is_enabled(value_type cr)
        { return is_bit_set(cr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_cr0(), from); }

        inline auto is_disabled(value_type cr)
        { return is_bit_cleared(cr, from); }

        inline void enable()
        { _write_cr0(set_bit(_read_cr0(), from)); }

        inline void enable(value_type &cr)
        { _write_cr0(set_bit(cr, from)); }

        inline void disable()
        { _write_cr0(clear_bit(_read_cr0(), from)); }

        inline void disable(value_type &cr)
        { _write_cr0(clear_bit(cr, from)); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }

    }

    namespace monitor_coprocessor
    {
        constexpr const auto mask = 0x0000000000000002ULL;
        constexpr const auto from = 1ULL;
        constexpr const auto name = "monitor_coprocessor";

        inline auto is_enabled()
        { return is_bit_set(_read_cr0(), from); }

        inline auto is_enabled(value_type cr)
        { return is_bit_set(cr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_cr0(), from); }

        inline auto is_disabled(value_type cr)
        { return is_bit_cleared(cr, from); }

        inline void enable()
        { _write_cr0(set_bit(_read_cr0(), from)); }

        inline void enable(value_type &cr)
        { _write_cr0(set_bit(cr, from)); }

        inline void disable()
        { _write_cr0(clear_bit(_read_cr0(), from)); }

        inline void disable(value_type &cr)
        { _write_cr0(clear_bit(cr, from)); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace emulation
    {
        constexpr const auto mask = 0x0000000000000004ULL;
        constexpr const auto from = 2ULL;
        constexpr const auto name = "emulation";

        inline auto is_enabled()
        { return is_bit_set(_read_cr0(), from); }

        inline auto is_enabled(value_type cr)
        { return is_bit_set(cr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_cr0(), from); }

        inline auto is_disabled(value_type cr)
        { return is_bit_cleared(cr, from); }

        inline void enable()
        { _write_cr0(set_bit(_read_cr0(), from)); }

        inline void enable(value_type &cr)
        { _write_cr0(set_bit(cr, from)); }

        inline void disable()
        { _write_cr0(clear_bit(_read_cr0(), from)); }

        inline void disable(value_type &cr)
        { _write_cr0(clear_bit(cr, from)); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace task_switched
    {
        constexpr const auto mask = 0x0000000000000008ULL;
        constexpr const auto from = 3ULL;
        constexpr const auto name = "task_switched";

        inline auto is_enabled()
        { return is_bit_set(_read_cr0(), from); }

        inline auto is_enabled(value_type cr)
        { return is_bit_set(cr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_cr0(), from); }

        inline auto is_disabled(value_type cr)
        { return is_bit_cleared(cr, from); }

        inline void enable()
        { _write_cr0(set_bit(_read_cr0(), from)); }

        inline void enable(value_type &cr)
        { _write_cr0(set_bit(cr, from)); }

        inline void disable()
        { _write_cr0(clear_bit(_read_cr0(), from)); }

        inline void disable(value_type &cr)
        { _write_cr0(clear_bit(cr, from)); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace extension_type
    {
        constexpr const auto mask = 0x0000000000000010ULL;
        constexpr const auto from = 4ULL;
        constexpr const auto name = "extension_type";

        inline auto is_enabled()
        { return is_bit_set(_read_cr0(), from); }

        inline auto is_enabled(value_type cr)
        { return is_bit_set(cr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_cr0(), from); }

        inline auto is_disabled(value_type cr)
        { return is_bit_cleared(cr, from); }

        inline void enable()
        { _write_cr0(set_bit(_read_cr0(), from)); }

        inline void enable(value_type &cr)
        { _write_cr0(set_bit(cr, from)); }

        inline void disable()
        { _write_cr0(clear_bit(_read_cr0(), from)); }

        inline void disable(value_type &cr)
        { _write_cr0(clear_bit(cr, from)); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace numeric_error
    {
        constexpr const auto mask = 0x0000000000000020ULL;
        constexpr const auto from = 5ULL;
        constexpr const auto name = "numeric_error";

        inline auto is_enabled()
        { return is_bit_set(_read_cr0(), from); }

        inline auto is_enabled(value_type cr)
        { return is_bit_set(cr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_cr0(), from); }

        inline auto is_disabled(value_type cr)
        { return is_bit_cleared(cr, from); }

        inline void enable()
        { _write_cr0(set_bit(_read_cr0(), from)); }

        inline void enable(value_type &cr)
        { _write_cr0(set_bit(cr, from)); }

        inline void disable()
        { _write_cr0(clear_bit(_read_cr0(), from)); }

        inline void disable(value_type &cr)
        { _write_cr0(clear_bit(cr, from)); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace write_protect
    {
        constexpr const auto mask = 0x0000000000010000ULL;
        constexpr const auto from = 16ULL;
        constexpr const auto name = "write_protect";

        inline auto is_enabled()
        { return is_bit_set(_read_cr0(), from); }

        inline auto is_enabled(value_type cr)
        { return is_bit_set(cr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_cr0(), from); }

        inline auto is_disabled(value_type cr)
        { return is_bit_cleared(cr, from); }

        inline void enable()
        { _write_cr0(set_bit(_read_cr0(), from)); }

        inline void enable(value_type &cr)
        { _write_cr0(set_bit(cr, from)); }

        inline void disable()
        { _write_cr0(clear_bit(_read_cr0(), from)); }

        inline void disable(value_type &cr)
        { _write_cr0(clear_bit(cr, from)); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace alignment_mask
    {
        constexpr const auto mask = 0x0000000000040000ULL;
        constexpr const auto from = 18ULL;
        constexpr const auto name = "alignment_mask";

        inline auto is_enabled()
        { return is_bit_set(_read_cr0(), from); }

        inline auto is_enabled(value_type cr)
        { return is_bit_set(cr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_cr0(), from); }

        inline auto is_disabled(value_type cr)
        { return is_bit_cleared(cr, from); }

        inline void enable()
        { _write_cr0(set_bit(_read_cr0(), from)); }

        inline void enable(value_type &cr)
        { _write_cr0(set_bit(cr, from)); }

        inline void disable()
        { _write_cr0(clear_bit(_read_cr0(), from)); }

        inline void disable(value_type &cr)
        { _write_cr0(clear_bit(cr, from)); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace not_write_through
    {
        constexpr const auto mask = 0x0000000020000000ULL;
        constexpr const auto from = 29ULL;
        constexpr const auto name = "not_write_through";

        inline auto is_enabled()
        { return is_bit_set(_read_cr0(), from); }

        inline auto is_enabled(value_type cr)
        { return is_bit_set(cr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_cr0(), from); }

        inline auto is_disabled(value_type cr)
        { return is_bit_cleared(cr, from); }

        inline void enable()
        { _write_cr0(set_bit(_read_cr0(), from)); }

        inline void enable(value_type &cr)
        { _write_cr0(set_bit(cr, from)); }

        inline void disable()
        { _write_cr0(clear_bit(_read_cr0(), from)); }

        inline void disable(value_type &cr)
        { _write_cr0(clear_bit(cr, from)); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace cache_disable
    {
        constexpr const auto mask = 0x0000000040000000ULL;
        constexpr const auto from = 30ULL;
        constexpr const auto name = "cache_disable";

        inline auto is_enabled()
        { return is_bit_set(_read_cr0(), from); }

        inline auto is_enabled(value_type cr)
        { return is_bit_set(cr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_cr0(), from); }

        inline auto is_disabled(value_type cr)
        { return is_bit_cleared(cr, from); }

        inline void enable()
        { _write_cr0(set_bit(_read_cr0(), from)); }

        inline void enable(value_type &cr)
        { _write_cr0(set_bit(cr, from)); }

        inline void disable()
        { _write_cr0(clear_bit(_read_cr0(), from)); }

        inline void disable(value_type &cr)
        { _write_cr0(clear_bit(cr, from)); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace paging
    {
        constexpr const auto mask = 0x0000000080000000ULL;
        constexpr const auto from = 31ULL;
        constexpr const auto name = "paging";

        inline auto is_enabled()
        { return is_bit_set(_read_cr0(), from); }

        inline auto is_enabled(value_type cr)
        { return is_bit_set(cr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_cr0(), from); }

        inline auto is_disabled(value_type cr)
        { return is_bit_cleared(cr, from); }

        inline void enable()
        { _write_cr0(set_bit(_read_cr0(), from)); }

        inline void enable(value_type &cr)
        { _write_cr0(set_bit(cr, from)); }

        inline void disable()
        { _write_cr0(clear_bit(_read_cr0(), from)); }

        inline void disable(value_type &cr)
        { _write_cr0(clear_bit(cr, from)); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    inline void dump(int level, std::string *msg = nullptr)
    {
        bfdebug_nhex(level, name, get(), msg);
        protection_enable::dump(level, msg);
        monitor_coprocessor::dump(level, msg);
        emulation::dump(level, msg);
        task_switched::dump(level, msg);
        extension_type::dump(level, msg);
        numeric_error::dump(level, msg);
        write_protect::dump(level, msg);
        alignment_mask::dump(level, msg);
        not_write_through::dump(level, msg);
        cache_disable::dump(level, msg);
        paging::dump(level, msg);
    }
}

namespace cr2
{
    constexpr const auto name = "cr2";

    using value_type = uint64_t;

    inline auto get() noexcept
    { return _read_cr2(); }

    inline void set(value_type val) noexcept
    { _write_cr2(val); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace cr3
{
    constexpr const auto name = "cr3";

    using value_type = uint64_t;

    inline auto get() noexcept
    { return _read_cr3(); }

    inline void set(value_type val) noexcept
    { _write_cr3(val); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace cr4
{
    constexpr const auto name = "cr4";

    using value_type = uint64_t;

    inline auto get() noexcept
    { return _read_cr4(); }

    inline void set(value_type val) noexcept
    { _write_cr4(val); }

    namespace v8086_mode_extensions
    {
        constexpr const auto mask = 0x0000000000000001ULL;
        constexpr const auto from = 0ULL;
        constexpr const auto name = "v8086_mode_extensions";

        inline auto is_enabled()
        { return is_bit_set(_read_cr4(), from); }

        inline auto is_enabled(value_type cr)
        { return is_bit_set(cr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_cr4(), from); }

        inline auto is_disabled(value_type cr)
        { return is_bit_cleared(cr, from); }

        inline void enable()
        { _write_cr4(set_bit(_read_cr4(), from)); }

        inline void enable(value_type &cr)
        { _write_cr4(set_bit(cr, from)); }

        inline void disable()
        { _write_cr4(clear_bit(_read_cr4(), from)); }

        inline void disable(value_type &cr)
        { _write_cr4(clear_bit(cr, from)); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace protected_mode_virtual_interrupts
    {
        constexpr const auto mask = 0x0000000000000002ULL;
        constexpr const auto from = 1ULL;
        constexpr const auto name = "protected_mode_virtual_interrupts";

        inline auto is_enabled()
        { return is_bit_set(_read_cr4(), from); }

        inline auto is_enabled(value_type cr)
        { return is_bit_set(cr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_cr4(), from); }

        inline auto is_disabled(value_type cr)
        { return is_bit_cleared(cr, from); }

        inline void enable()
        { _write_cr4(set_bit(_read_cr4(), from)); }

        inline void enable(value_type &cr)
        { _write_cr4(set_bit(cr, from)); }

        inline void disable()
        { _write_cr4(clear_bit(_read_cr4(), from)); }

        inline void disable(value_type &cr)
        { _write_cr4(clear_bit(cr, from)); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace time_stamp_disable
    {
        constexpr const auto mask = 0x0000000000000004ULL;
        constexpr const auto from = 2ULL;
        constexpr const auto name = "time_stamp_disable";

        inline auto is_enabled()
        { return is_bit_set(_read_cr4(), from); }

        inline auto is_enabled(value_type cr)
        { return is_bit_set(cr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_cr4(), from); }

        inline auto is_disabled(value_type cr)
        { return is_bit_cleared(cr, from); }

        inline void enable()
        { _write_cr4(set_bit(_read_cr4(), from)); }

        inline void enable(value_type &cr)
        { _write_cr4(set_bit(cr, from)); }

        inline void disable()
        { _write_cr4(clear_bit(_read_cr4(), from)); }

        inline void disable(value_type &cr)
        { _write_cr4(clear_bit(cr, from)); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace debugging_extensions
    {
        constexpr const auto mask = 0x0000000000000008ULL;
        constexpr const auto from = 3ULL;
        constexpr const auto name = "debugging_extensions";

        inline auto is_enabled()
        { return is_bit_set(_read_cr4(), from); }

        inline auto is_enabled(value_type cr)
        { return is_bit_set(cr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_cr4(), from); }

        inline auto is_disabled(value_type cr)
        { return is_bit_cleared(cr, from); }

        inline void enable()
        { _write_cr4(set_bit(_read_cr4(), from)); }

        inline void enable(value_type &cr)
        { _write_cr4(set_bit(cr, from)); }

        inline void disable()
        { _write_cr4(clear_bit(_read_cr4(), from)); }

        inline void disable(value_type &cr)
        { _write_cr4(clear_bit(cr, from)); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace page_size_extensions
    {
        constexpr const auto mask = 0x0000000000000010ULL;
        constexpr const auto from = 4ULL;
        constexpr const auto name = "page_size_extensions";

        inline auto is_enabled()
        { return is_bit_set(_read_cr4(), from); }

        inline auto is_enabled(value_type cr)
        { return is_bit_set(cr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_cr4(), from); }

        inline auto is_disabled(value_type cr)
        { return is_bit_cleared(cr, from); }

        inline void enable()
        { _write_cr4(set_bit(_read_cr4(), from)); }

        inline void enable(value_type &cr)
        { _write_cr4(set_bit(cr, from)); }

        inline void disable()
        { _write_cr4(clear_bit(_read_cr4(), from)); }

        inline void disable(value_type &cr)
        { _write_cr4(clear_bit(cr, from)); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace physical_address_extensions
    {
        constexpr const auto mask = 0x0000000000000020ULL;
        constexpr const auto from = 5ULL;
        constexpr const auto name = "physical_address_extensions";

        inline auto is_enabled()
        { return is_bit_set(_read_cr4(), from); }

        inline auto is_enabled(value_type cr)
        { return is_bit_set(cr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_cr4(), from); }

        inline auto is_disabled(value_type cr)
        { return is_bit_cleared(cr, from); }

        inline void enable()
        { _write_cr4(set_bit(_read_cr4(), from)); }

        inline void enable(value_type &cr)
        { _write_cr4(set_bit(cr, from)); }

        inline void disable()
        { _write_cr4(clear_bit(_read_cr4(), from)); }

        inline void disable(value_type &cr)
        { _write_cr4(clear_bit(cr, from)); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace machine_check_enable
    {
        constexpr const auto mask = 0x0000000000000040ULL;
        constexpr const auto from = 6ULL;
        constexpr const auto name = "machine_check_enable";

        inline auto is_enabled()
        { return is_bit_set(_read_cr4(), from); }

        inline auto is_enabled(value_type cr)
        { return is_bit_set(cr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_cr4(), from); }

        inline auto is_disabled(value_type cr)
        { return is_bit_cleared(cr, from); }

        inline void enable()
        { _write_cr4(set_bit(_read_cr4(), from)); }

        inline void enable(value_type &cr)
        { _write_cr4(set_bit(cr, from)); }

        inline void disable()
        { _write_cr4(clear_bit(_read_cr4(), from)); }

        inline void disable(value_type &cr)
        { _write_cr4(clear_bit(cr, from)); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace page_global_enable
    {
        constexpr const auto mask = 0x0000000000000080ULL;
        constexpr const auto from = 7ULL;
        constexpr const auto name = "page_global_enable";

        inline auto is_enabled()
        { return is_bit_set(_read_cr4(), from); }

        inline auto is_enabled(value_type cr)
        { return is_bit_set(cr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_cr4(), from); }

        inline auto is_disabled(value_type cr)
        { return is_bit_cleared(cr, from); }

        inline void enable()
        { _write_cr4(set_bit(_read_cr4(), from)); }

        inline void enable(value_type &cr)
        { _write_cr4(set_bit(cr, from)); }

        inline void disable()
        { _write_cr4(clear_bit(_read_cr4(), from)); }

        inline void disable(value_type &cr)
        { _write_cr4(clear_bit(cr, from)); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace performance_monitor_counter_enable
    {
        constexpr const auto mask = 0x0000000000000100ULL;
        constexpr const auto from = 8ULL;
        constexpr const auto name = "performance_monitor_counter_enable";

        inline auto is_enabled()
        { return is_bit_set(_read_cr4(), from); }

        inline auto is_enabled(value_type cr)
        { return is_bit_set(cr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_cr4(), from); }

        inline auto is_disabled(value_type cr)
        { return is_bit_cleared(cr, from); }

        inline void enable()
        { _write_cr4(set_bit(_read_cr4(), from)); }

        inline void enable(value_type &cr)
        { _write_cr4(set_bit(cr, from)); }

        inline void disable()
        { _write_cr4(clear_bit(_read_cr4(), from)); }

        inline void disable(value_type &cr)
        { _write_cr4(clear_bit(cr, from)); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace osfxsr
    {
        constexpr const auto mask = 0x0000000000000200ULL;
        constexpr const auto from = 9ULL;
        constexpr const auto name = "osfxsr";

        inline auto is_enabled()
        { return is_bit_set(_read_cr4(), from); }

        inline auto is_enabled(value_type cr)
        { return is_bit_set(cr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_cr4(), from); }

        inline auto is_disabled(value_type cr)
        { return is_bit_cleared(cr, from); }

        inline void enable()
        { _write_cr4(set_bit(_read_cr4(), from)); }

        inline void enable(value_type &cr)
        { _write_cr4(set_bit(cr, from)); }

        inline void disable()
        { _write_cr4(clear_bit(_read_cr4(), from)); }

        inline void disable(value_type &cr)
        { _write_cr4(clear_bit(cr, from)); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace osxmmexcpt
    {
        constexpr const auto mask = 0x0000000000000400ULL;
        constexpr const auto from = 10ULL;
        constexpr const auto name = "osxmmexcpt";

        inline auto is_enabled()
        { return is_bit_set(_read_cr4(), from); }

        inline auto is_enabled(value_type cr)
        { return is_bit_set(cr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_cr4(), from); }

        inline auto is_disabled(value_type cr)
        { return is_bit_cleared(cr, from); }

        inline void enable()
        { _write_cr4(set_bit(_read_cr4(), from)); }

        inline void enable(value_type &cr)
        { _write_cr4(set_bit(cr, from)); }

        inline void disable()
        { _write_cr4(clear_bit(_read_cr4(), from)); }

        inline void disable(value_type &cr)
        { _write_cr4(clear_bit(cr, from)); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace vmx_enable_bit
    {
        constexpr const auto mask = 0x0000000000002000ULL;
        constexpr const auto from = 13ULL;
        constexpr const auto name = "vmx_enable_bit";

        inline auto is_enabled()
        { return is_bit_set(_read_cr4(), from); }

        inline auto is_enabled(value_type cr)
        { return is_bit_set(cr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_cr4(), from); }

        inline auto is_disabled(value_type cr)
        { return is_bit_cleared(cr, from); }

        inline void enable()
        { _write_cr4(set_bit(_read_cr4(), from)); }

        inline void enable(value_type &cr)
        { _write_cr4(set_bit(cr, from)); }

        inline void disable()
        { _write_cr4(clear_bit(_read_cr4(), from)); }

        inline void disable(value_type &cr)
        { _write_cr4(clear_bit(cr, from)); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace smx_enable_bit
    {
        constexpr const auto mask = 0x0000000000004000ULL;
        constexpr const auto from = 14ULL;
        constexpr const auto name = "smx_enable_bit";

        inline auto is_enabled()
        { return is_bit_set(_read_cr4(), from); }

        inline auto is_enabled(value_type cr)
        { return is_bit_set(cr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_cr4(), from); }

        inline auto is_disabled(value_type cr)
        { return is_bit_cleared(cr, from); }

        inline void enable()
        { _write_cr4(set_bit(_read_cr4(), from)); }

        inline void enable(value_type &cr)
        { _write_cr4(set_bit(cr, from)); }

        inline void disable()
        { _write_cr4(clear_bit(_read_cr4(), from)); }

        inline void disable(value_type &cr)
        { _write_cr4(clear_bit(cr, from)); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace fsgsbase_enable_bit
    {
        constexpr const auto mask = 0x0000000000010000ULL;
        constexpr const auto from = 16ULL;
        constexpr const auto name = "fsgsbase_enable_bit";

        inline auto is_enabled()
        { return is_bit_set(_read_cr4(), from); }

        inline auto is_enabled(value_type cr)
        { return is_bit_set(cr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_cr4(), from); }

        inline auto is_disabled(value_type cr)
        { return is_bit_cleared(cr, from); }

        inline void enable()
        { _write_cr4(set_bit(_read_cr4(), from)); }

        inline void enable(value_type &cr)
        { _write_cr4(set_bit(cr, from)); }

        inline void disable()
        { _write_cr4(clear_bit(_read_cr4(), from)); }

        inline void disable(value_type &cr)
        { _write_cr4(clear_bit(cr, from)); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace pcid_enable_bit
    {
        constexpr const auto mask = 0x0000000000020000ULL;
        constexpr const auto from = 17ULL;
        constexpr const auto name = "pcid_enable_bit";

        inline auto is_enabled()
        { return is_bit_set(_read_cr4(), from); }

        inline auto is_enabled(value_type cr)
        { return is_bit_set(cr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_cr4(), from); }

        inline auto is_disabled(value_type cr)
        { return is_bit_cleared(cr, from); }

        inline void enable()
        { _write_cr4(set_bit(_read_cr4(), from)); }

        inline void enable(value_type &cr)
        { _write_cr4(set_bit(cr, from)); }

        inline void disable()
        { _write_cr4(clear_bit(_read_cr4(), from)); }

        inline void disable(value_type &cr)
        { _write_cr4(clear_bit(cr, from)); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace osxsave
    {
        constexpr const auto mask = 0x0000000000040000ULL;
        constexpr const auto from = 18ULL;
        constexpr const auto name = "osxsave";

        inline auto is_enabled()
        { return is_bit_set(_read_cr4(), from); }

        inline auto is_enabled(value_type cr)
        { return is_bit_set(cr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_cr4(), from); }

        inline auto is_disabled(value_type cr)
        { return is_bit_cleared(cr, from); }

        inline void enable()
        { _write_cr4(set_bit(_read_cr4(), from)); }

        inline void enable(value_type &cr)
        { _write_cr4(set_bit(cr, from)); }

        inline void disable()
        { _write_cr4(clear_bit(_read_cr4(), from)); }

        inline void disable(value_type &cr)
        { _write_cr4(clear_bit(cr, from)); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace smep_enable_bit
    {
        constexpr const auto mask = 0x0000000000100000ULL;
        constexpr const auto from = 20ULL;
        constexpr const auto name = "smep_enable_bit";

        inline auto is_enabled()
        { return is_bit_set(_read_cr4(), from); }

        inline auto is_enabled(value_type cr)
        { return is_bit_set(cr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_cr4(), from); }

        inline auto is_disabled(value_type cr)
        { return is_bit_cleared(cr, from); }

        inline void enable()
        { _write_cr4(set_bit(_read_cr4(), from)); }

        inline void enable(value_type &cr)
        { _write_cr4(set_bit(cr, from)); }

        inline void disable()
        { _write_cr4(clear_bit(_read_cr4(), from)); }

        inline void disable(value_type &cr)
        { _write_cr4(clear_bit(cr, from)); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace smap_enable_bit
    {
        constexpr const auto mask = 0x0000000000200000ULL;
        constexpr const auto from = 21ULL;
        constexpr const auto name = "smap_enable_bit";

        inline auto is_enabled()
        { return is_bit_set(_read_cr4(), from); }

        inline auto is_enabled(value_type cr)
        { return is_bit_set(cr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_cr4(), from); }

        inline auto is_disabled(value_type cr)
        { return is_bit_cleared(cr, from); }

        inline void enable()
        { _write_cr4(set_bit(_read_cr4(), from)); }

        inline void enable(value_type &cr)
        { _write_cr4(set_bit(cr, from)); }

        inline void disable()
        { _write_cr4(clear_bit(_read_cr4(), from)); }

        inline void disable(value_type &cr)
        { _write_cr4(clear_bit(cr, from)); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace protection_key_enable_bit
    {
        constexpr const auto mask = 0x0000000000400000ULL;
        constexpr const auto from = 22ULL;
        constexpr const auto name = "protection_key_enable_bit";

        inline auto is_enabled()
        { return is_bit_set(_read_cr4(), from); }

        inline auto is_enabled(value_type cr)
        { return is_bit_set(cr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_cr4(), from); }

        inline auto is_disabled(value_type cr)
        { return is_bit_cleared(cr, from); }

        inline void enable()
        { _write_cr4(set_bit(_read_cr4(), from)); }

        inline void enable(value_type &cr)
        { _write_cr4(set_bit(cr, from)); }

        inline void disable()
        { _write_cr4(clear_bit(_read_cr4(), from)); }

        inline void disable(value_type &cr)
        { _write_cr4(clear_bit(cr, from)); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    inline void dump(int level, std::string *msg = nullptr)
    {
        bfdebug_nhex(level, name, get(), msg);
        v8086_mode_extensions::dump(level, msg);
        protected_mode_virtual_interrupts::dump(level, msg);
        time_stamp_disable::dump(level, msg);
        debugging_extensions::dump(level, msg);
        page_size_extensions::dump(level, msg);
        physical_address_extensions::dump(level, msg);
        machine_check_enable::dump(level, msg);
        page_global_enable::dump(level, msg);
        performance_monitor_counter_enable::dump(level, msg);
        osfxsr::dump(level, msg);
        osxmmexcpt::dump(level, msg);
        vmx_enable_bit::dump(level, msg);
        smx_enable_bit::dump(level, msg);
        fsgsbase_enable_bit::dump(level, msg);
        pcid_enable_bit::dump(level, msg);
        osxsave::dump(level, msg);
        smep_enable_bit::dump(level, msg);
        smap_enable_bit::dump(level, msg);
        protection_key_enable_bit::dump(level, msg);
    }
}

namespace cr8
{
    constexpr const auto name = "cr8";

    using value_type = uint64_t;

    inline auto get() noexcept
    { return _read_cr8(); }

    inline void set(value_type val) noexcept
    { _write_cr8(val); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace xcr0
{
    constexpr const auto name = "xcr0";

    using value_type = uint64_t;

    inline void set(value_type val) noexcept
    { _write_xcr0(val); }
}


}

// *INDENT-ON*

#endif
