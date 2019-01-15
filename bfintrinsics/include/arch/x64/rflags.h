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

#ifndef RFLAGS_X64_H
#define RFLAGS_X64_H

#include <bfdebug.h>
#include <bfbitmanip.h>

// -----------------------------------------------------------------------------
// Definitions
// -----------------------------------------------------------------------------

extern "C" uint64_t _read_rflags(void) noexcept;
extern "C" void _write_rflags(uint64_t val) noexcept;

// *INDENT-OFF*

namespace x64
{
namespace rflags
{

using value_type = uint64_t;

constexpr const auto name = "rflags";

inline auto get() noexcept
{ return _read_rflags(); }

inline void set(value_type rflags) noexcept
{ _write_rflags(rflags); }

namespace carry_flag
{
    constexpr const auto mask = 0x0000000000000001ULL;
    constexpr const auto from = 0ULL;
    constexpr const auto name = "carry_flag";

    inline auto is_enabled()
    { return is_bit_set(_read_rflags(), from); }

    inline auto is_enabled(value_type rflags)
    { return is_bit_set(rflags, from); }

    inline auto is_disabled()
    { return is_bit_cleared(_read_rflags(), from); }

    inline auto is_disabled(value_type rflags)
    { return is_bit_cleared(rflags, from); }

    inline void enable()
    { _write_rflags(set_bit(_read_rflags(), from)); }

    inline void enable(value_type &rflags)
    { rflags = set_bit(rflags, from); }

    inline void disable()
    { _write_rflags(clear_bit(_read_rflags(), from)); }

    inline void disable(value_type &rflags)
    { rflags = clear_bit(rflags, from); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_subbool(level, name, is_enabled(), msg); }
}

namespace parity_flag
{
    constexpr const auto mask = 0x0000000000000004ULL;
    constexpr const auto from = 2ULL;
    constexpr const auto name = "parity_flag";

    inline auto is_enabled()
    { return is_bit_set(_read_rflags(), from); }

    inline auto is_enabled(value_type rflags)
    { return is_bit_set(rflags, from); }

    inline auto is_disabled()
    { return is_bit_cleared(_read_rflags(), from); }

    inline auto is_disabled(value_type rflags)
    { return is_bit_cleared(rflags, from); }

    inline void enable()
    { _write_rflags(set_bit(_read_rflags(), from)); }

    inline void enable(value_type &rflags)
    { rflags = set_bit(rflags, from); }

    inline void disable()
    { _write_rflags(clear_bit(_read_rflags(), from)); }

    inline void disable(value_type &rflags)
    { rflags = clear_bit(rflags, from); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_subbool(level, name, is_enabled(), msg); }
}

namespace auxiliary_carry_flag
{
    constexpr const auto mask = 0x0000000000000010ULL;
    constexpr const auto from = 4ULL;
    constexpr const auto name = "auxiliary_carry_flag";

    inline auto is_enabled()
    { return is_bit_set(_read_rflags(), from); }

    inline auto is_enabled(value_type rflags)
    { return is_bit_set(rflags, from); }

    inline auto is_disabled()
    { return is_bit_cleared(_read_rflags(), from); }

    inline auto is_disabled(value_type rflags)
    { return is_bit_cleared(rflags, from); }

    inline void enable()
    { _write_rflags(set_bit(_read_rflags(), from)); }

    inline void enable(value_type &rflags)
    { rflags = set_bit(rflags, from); }

    inline void disable()
    { _write_rflags(clear_bit(_read_rflags(), from)); }

    inline void disable(value_type &rflags)
    { rflags = clear_bit(rflags, from); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_subbool(level, name, is_enabled(), msg); }
}

namespace zero_flag
{
    constexpr const auto mask = 0x0000000000000040ULL;
    constexpr const auto from = 6ULL;
    constexpr const auto name = "zero_flag";

    inline auto is_enabled()
    { return is_bit_set(_read_rflags(), from); }

    inline auto is_enabled(value_type rflags)
    { return is_bit_set(rflags, from); }

    inline auto is_disabled()
    { return is_bit_cleared(_read_rflags(), from); }

    inline auto is_disabled(value_type rflags)
    { return is_bit_cleared(rflags, from); }

    inline void enable()
    { _write_rflags(set_bit(_read_rflags(), from)); }

    inline void enable(value_type &rflags)
    { rflags = set_bit(rflags, from); }

    inline void disable()
    { _write_rflags(clear_bit(_read_rflags(), from)); }

    inline void disable(value_type &rflags)
    { rflags = clear_bit(rflags, from); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_subbool(level, name, is_enabled(), msg); }
}

namespace sign_flag
{
    constexpr const auto mask = 0x0000000000000080ULL;
    constexpr const auto from = 7ULL;
    constexpr const auto name = "sign_flag";

    inline auto is_enabled()
    { return is_bit_set(_read_rflags(), from); }

    inline auto is_enabled(value_type rflags)
    { return is_bit_set(rflags, from); }

    inline auto is_disabled()
    { return is_bit_cleared(_read_rflags(), from); }

    inline auto is_disabled(value_type rflags)
    { return is_bit_cleared(rflags, from); }

    inline void enable()
    { _write_rflags(set_bit(_read_rflags(), from)); }

    inline void enable(value_type &rflags)
    { rflags = set_bit(rflags, from); }

    inline void disable()
    { _write_rflags(clear_bit(_read_rflags(), from)); }

    inline void disable(value_type &rflags)
    { rflags = clear_bit(rflags, from); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_subbool(level, name, is_enabled(), msg); }
}

namespace trap_flag
{
    constexpr const auto mask = 0x0000000000000100ULL;
    constexpr const auto from = 8ULL;
    constexpr const auto name = "trap_flag";

    inline auto is_enabled()
    { return is_bit_set(_read_rflags(), from); }

    inline auto is_enabled(value_type rflags)
    { return is_bit_set(rflags, from); }

    inline auto is_disabled()
    { return is_bit_cleared(_read_rflags(), from); }

    inline auto is_disabled(value_type rflags)
    { return is_bit_cleared(rflags, from); }

    inline void enable()
    { _write_rflags(set_bit(_read_rflags(), from)); }

    inline void enable(value_type &rflags)
    { rflags = set_bit(rflags, from); }

    inline void disable()
    { _write_rflags(clear_bit(_read_rflags(), from)); }

    inline void disable(value_type &rflags)
    { rflags = clear_bit(rflags, from); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_subbool(level, name, is_enabled(), msg); }
}

namespace interrupt_enable_flag
{
    constexpr const auto mask = 0x0000000000000200ULL;
    constexpr const auto from = 9ULL;
    constexpr const auto name = "interrupt_enable_flag";

    inline auto is_enabled()
    { return is_bit_set(_read_rflags(), from); }

    inline auto is_enabled(value_type rflags)
    { return is_bit_set(rflags, from); }

    inline auto is_disabled()
    { return is_bit_cleared(_read_rflags(), from); }

    inline auto is_disabled(value_type rflags)
    { return is_bit_cleared(rflags, from); }

    inline void enable()
    { _write_rflags(set_bit(_read_rflags(), from)); }

    inline void enable(value_type &rflags)
    { rflags = set_bit(rflags, from); }

    inline void disable()
    { _write_rflags(clear_bit(_read_rflags(), from)); }

    inline void disable(value_type &rflags)
    { rflags = clear_bit(rflags, from); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_subbool(level, name, is_enabled(), msg); }
}

namespace direction_flag
{
    constexpr const auto mask = 0x0000000000000400ULL;
    constexpr const auto from = 10ULL;
    constexpr const auto name = "direction_flag";

    inline auto is_enabled()
    { return is_bit_set(_read_rflags(), from); }

    inline auto is_enabled(value_type rflags)
    { return is_bit_set(rflags, from); }

    inline auto is_disabled()
    { return is_bit_cleared(_read_rflags(), from); }

    inline auto is_disabled(value_type rflags)
    { return is_bit_cleared(rflags, from); }

    inline void enable()
    { _write_rflags(set_bit(_read_rflags(), from)); }

    inline void enable(value_type &rflags)
    { rflags = set_bit(rflags, from); }

    inline void disable()
    { _write_rflags(clear_bit(_read_rflags(), from)); }

    inline void disable(value_type &rflags)
    { rflags = clear_bit(rflags, from); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_subbool(level, name, is_enabled(), msg); }
}

namespace overflow_flag
{
    constexpr const auto mask = 0x0000000000000800ULL;
    constexpr const auto from = 11ULL;
    constexpr const auto name = "overflow_flag";

    inline auto is_enabled()
    { return is_bit_set(_read_rflags(), from); }

    inline auto is_enabled(value_type rflags)
    { return is_bit_set(rflags, from); }

    inline auto is_disabled()
    { return is_bit_cleared(_read_rflags(), from); }

    inline auto is_disabled(value_type rflags)
    { return is_bit_cleared(rflags, from); }

    inline void enable()
    { _write_rflags(set_bit(_read_rflags(), from)); }

    inline void enable(value_type &rflags)
    { rflags = set_bit(rflags, from); }

    inline void disable()
    { _write_rflags(clear_bit(_read_rflags(), from)); }

    inline void disable(value_type &rflags)
    { rflags = clear_bit(rflags, from); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_subbool(level, name, is_enabled(), msg); }
}

namespace privilege_level
{
    constexpr const auto mask = 0x0000000000003000ULL;
    constexpr const auto from = 12ULL;
    constexpr const auto name = "privilege_level";

    inline auto get() noexcept
    { return get_bits(_read_rflags(), mask) >> from; }

    inline auto get(value_type rflags) noexcept
    { return get_bits(rflags, mask) >> from; }

    inline void set(value_type val) noexcept
    { _write_rflags(set_bits(_read_rflags(), mask, val << from)); }

    inline void set(value_type &rflags, value_type val) noexcept
    { rflags = set_bits(rflags, mask, val << from); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_subnhex(level, name, get(), msg); }
}

namespace nested_task
{
    constexpr const auto mask = 0x0000000000004000ULL;
    constexpr const auto from = 14ULL;
    constexpr const auto name = "nested_task";

    inline auto is_enabled()
    { return is_bit_set(_read_rflags(), from); }

    inline auto is_enabled(value_type rflags)
    { return is_bit_set(rflags, from); }

    inline auto is_disabled()
    { return is_bit_cleared(_read_rflags(), from); }

    inline auto is_disabled(value_type rflags)
    { return is_bit_cleared(rflags, from); }

    inline void enable()
    { _write_rflags(set_bit(_read_rflags(), from)); }

    inline void enable(value_type &rflags)
    { rflags = set_bit(rflags, from); }

    inline void disable()
    { _write_rflags(clear_bit(_read_rflags(), from)); }

    inline void disable(value_type &rflags)
    { rflags = clear_bit(rflags, from); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_subbool(level, name, is_enabled(), msg); }
}

namespace resume_flag
{
    constexpr const auto mask = 0x0000000000010000ULL;
    constexpr const auto from = 16ULL;
    constexpr const auto name = "resume_flag";

    inline auto is_enabled()
    { return is_bit_set(_read_rflags(), from); }

    inline auto is_enabled(value_type rflags)
    { return is_bit_set(rflags, from); }

    inline auto is_disabled()
    { return is_bit_cleared(_read_rflags(), from); }

    inline auto is_disabled(value_type rflags)
    { return is_bit_cleared(rflags, from); }

    inline void enable()
    { _write_rflags(set_bit(_read_rflags(), from)); }

    inline void enable(value_type &rflags)
    { rflags = set_bit(rflags, from); }

    inline void disable()
    { _write_rflags(clear_bit(_read_rflags(), from)); }

    inline void disable(value_type &rflags)
    { rflags = clear_bit(rflags, from); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_subbool(level, name, is_enabled(), msg); }
}

namespace virtual_8086_mode
{
    constexpr const auto mask = 0x0000000000020000ULL;
    constexpr const auto from = 17ULL;
    constexpr const auto name = "virtual_8086_mode";

    inline auto is_enabled()
    { return is_bit_set(_read_rflags(), from); }

    inline auto is_enabled(value_type rflags)
    { return is_bit_set(rflags, from); }

    inline auto is_disabled()
    { return is_bit_cleared(_read_rflags(), from); }

    inline auto is_disabled(value_type rflags)
    { return is_bit_cleared(rflags, from); }

    inline void enable()
    { _write_rflags(set_bit(_read_rflags(), from)); }

    inline void enable(value_type &rflags)
    { rflags = set_bit(rflags, from); }

    inline void disable()
    { _write_rflags(clear_bit(_read_rflags(), from)); }

    inline void disable(value_type &rflags)
    { rflags = clear_bit(rflags, from); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_subbool(level, name, is_enabled(), msg); }
}

namespace alignment_check_access_control
{
    constexpr const auto mask = 0x0000000000040000ULL;
    constexpr const auto from = 18ULL;
    constexpr const auto name = "alignment_check_access_control";

    inline auto is_enabled()
    { return is_bit_set(_read_rflags(), from); }

    inline auto is_enabled(value_type rflags)
    { return is_bit_set(rflags, from); }

    inline auto is_disabled()
    { return is_bit_cleared(_read_rflags(), from); }

    inline auto is_disabled(value_type rflags)
    { return is_bit_cleared(rflags, from); }

    inline void enable()
    { _write_rflags(set_bit(_read_rflags(), from)); }

    inline void enable(value_type &rflags)
    { rflags = set_bit(rflags, from); }

    inline void disable()
    { _write_rflags(clear_bit(_read_rflags(), from)); }

    inline void disable(value_type &rflags)
    { rflags = clear_bit(rflags, from); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_subbool(level, name, is_enabled(), msg); }
}

namespace virtual_interupt_flag
{
    constexpr const auto mask = 0x0000000000080000ULL;
    constexpr const auto from = 19ULL;
    constexpr const auto name = "virtual_interupt_flag";

    inline auto is_enabled()
    { return is_bit_set(_read_rflags(), from); }

    inline auto is_enabled(value_type rflags)
    { return is_bit_set(rflags, from); }

    inline auto is_disabled()
    { return is_bit_cleared(_read_rflags(), from); }

    inline auto is_disabled(value_type rflags)
    { return is_bit_cleared(rflags, from); }

    inline void enable()
    { _write_rflags(set_bit(_read_rflags(), from)); }

    inline void enable(value_type &rflags)
    { rflags = set_bit(rflags, from); }

    inline void disable()
    { _write_rflags(clear_bit(_read_rflags(), from)); }

    inline void disable(value_type &rflags)
    { rflags = clear_bit(rflags, from); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_subbool(level, name, is_enabled(), msg); }
}

namespace virtual_interupt_pending
{
    constexpr const auto mask = 0x0000000000100000ULL;
    constexpr const auto from = 20ULL;
    constexpr const auto name = "virtual_interupt_pending";

    inline auto is_enabled()
    { return is_bit_set(_read_rflags(), from); }

    inline auto is_enabled(value_type rflags)
    { return is_bit_set(rflags, from); }

    inline auto is_disabled()
    { return is_bit_cleared(_read_rflags(), from); }

    inline auto is_disabled(value_type rflags)
    { return is_bit_cleared(rflags, from); }

    inline void enable()
    { _write_rflags(set_bit(_read_rflags(), from)); }

    inline void enable(value_type &rflags)
    { rflags = set_bit(rflags, from); }

    inline void disable()
    { _write_rflags(clear_bit(_read_rflags(), from)); }

    inline void disable(value_type &rflags)
    { rflags = clear_bit(rflags, from); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_subbool(level, name, is_enabled(), msg); }
}

namespace id_flag
{
    constexpr const auto mask = 0x0000000000200000ULL;
    constexpr const auto from = 21ULL;
    constexpr const auto name = "id_flag";

    inline auto is_enabled()
    { return is_bit_set(_read_rflags(), from); }

    inline auto is_enabled(value_type rflags)
    { return is_bit_set(rflags, from); }

    inline auto is_disabled()
    { return is_bit_cleared(_read_rflags(), from); }

    inline auto is_disabled(value_type rflags)
    { return is_bit_cleared(rflags, from); }

    inline void enable()
    { _write_rflags(set_bit(_read_rflags(), from)); }

    inline void enable(value_type &rflags)
    { rflags = set_bit(rflags, from); }

    inline void disable()
    { _write_rflags(clear_bit(_read_rflags(), from)); }

    inline void disable(value_type &rflags)
    { rflags = clear_bit(rflags, from); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_subbool(level, name, is_enabled(), msg); }
}

inline void dump(int level, std::string *msg = nullptr)
{
    bfdebug_nhex(level, name, get(), msg);
    carry_flag::dump(level, msg);
    parity_flag::dump(level, msg);
    auxiliary_carry_flag::dump(level, msg);
    zero_flag::dump(level, msg);
    sign_flag::dump(level, msg);
    trap_flag::dump(level, msg);
    interrupt_enable_flag::dump(level, msg);
    direction_flag::dump(level, msg);
    overflow_flag::dump(level, msg);
    privilege_level::dump(level, msg);
    nested_task::dump(level, msg);
    resume_flag::dump(level, msg);
    virtual_8086_mode::dump(level, msg);
    alignment_check_access_control::dump(level, msg);
    virtual_interupt_flag::dump(level, msg);
    virtual_interupt_pending::dump(level, msg);
    id_flag::dump(level, msg);
}

}
}

// *INDENT-ON*

#endif
