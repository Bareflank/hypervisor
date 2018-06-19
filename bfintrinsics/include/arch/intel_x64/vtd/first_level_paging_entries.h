//
// Bareflank Hypervisor
// Copyright (C) 2018 Assured Information Security, Inc.
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
//

#ifndef VTD_FIRST_LEVEL_PAGING_ENTRIES_H
#define VTD_FIRST_LEVEL_PAGING_ENTRIES_H

#include <stdint.h>
#include <bfgsl.h>
#include <bfbitmanip.h>
#include <bfdebug.h>

// *INDENT-OFF*

namespace intel_x64
{
namespace vtd
{
namespace first_level_paging_entries
{

namespace pml5e
{
	constexpr const auto name = "pml5e";

	using value_type = uint64_t;

	namespace present
	{
		constexpr const auto mask = 0x1ULL;
		constexpr const auto from = 0ULL;
		constexpr const auto name = "present";

		inline auto is_enabled(const value_type &pml5e) noexcept
		{ return is_bit_set(pml5e, from); }

		inline auto is_disabled(const value_type &pml5e) noexcept
		{ return !is_bit_set(pml5e, from); }

		inline void enable(value_type &pml5e) noexcept
		{ pml5e = set_bit(pml5e, from); }

		inline void disable(value_type &pml5e) noexcept
		{ pml5e = clear_bit(pml5e, from); }

		inline void dump(int level, const value_type &pml5e, std::string *msg = nullptr)
		{ bfdebug_subbool(level, name, is_enabled(pml5e), msg); }
	}

	namespace write_enable
	{
		constexpr const auto mask = 0x2ULL;
		constexpr const auto from = 1ULL;
		constexpr const auto name = "write_enable";

		inline auto is_enabled(const value_type &pml5e) noexcept
		{ return is_bit_set(pml5e, from); }

		inline auto is_disabled(const value_type &pml5e) noexcept
		{ return !is_bit_set(pml5e, from); }

		inline void enable(value_type &pml5e) noexcept
		{ pml5e = set_bit(pml5e, from); }

		inline void disable(value_type &pml5e) noexcept
		{ pml5e = clear_bit(pml5e, from); }

		inline void dump(int level, const value_type &pml5e, std::string *msg = nullptr)
		{ bfdebug_subbool(level, name, is_enabled(pml5e), msg); }
	}

	namespace user_access
	{
		constexpr const auto mask = 0x4ULL;
		constexpr const auto from = 2ULL;
		constexpr const auto name = "user_access";

		inline auto is_enabled(const value_type &pml5e) noexcept
		{ return is_bit_set(pml5e, from); }

		inline auto is_disabled(const value_type &pml5e) noexcept
		{ return !is_bit_set(pml5e, from); }

		inline void enable(value_type &pml5e) noexcept
		{ pml5e = set_bit(pml5e, from); }

		inline void disable(value_type &pml5e) noexcept
		{ pml5e = clear_bit(pml5e, from); }

		inline void dump(int level, const value_type &pml5e, std::string *msg = nullptr)
		{ bfdebug_subbool(level, name, is_enabled(pml5e), msg); }
	}

	namespace page_level_write_through
	{
		constexpr const auto mask = 0x8ULL;
		constexpr const auto from = 3ULL;
		constexpr const auto name = "page_level_write_through";

		inline auto is_enabled(const value_type &pml5e) noexcept
		{ return is_bit_set(pml5e, from); }

		inline auto is_disabled(const value_type &pml5e) noexcept
		{ return !is_bit_set(pml5e, from); }

		inline void enable(value_type &pml5e) noexcept
		{ pml5e = set_bit(pml5e, from); }

		inline void disable(value_type &pml5e) noexcept
		{ pml5e = clear_bit(pml5e, from); }

		inline void dump(int level, const value_type &pml5e, std::string *msg = nullptr)
		{ bfdebug_subbool(level, name, is_enabled(pml5e), msg); }
	}

	namespace page_level_cache_disable
	{
		constexpr const auto mask = 0x10ULL;
		constexpr const auto from = 4ULL;
		constexpr const auto name = "page_level_cache_disable";

		inline auto is_enabled(const value_type &pml5e) noexcept
		{ return is_bit_set(pml5e, from); }

		inline auto is_disabled(const value_type &pml5e) noexcept
		{ return !is_bit_set(pml5e, from); }

		inline void enable(value_type &pml5e) noexcept
		{ pml5e = set_bit(pml5e, from); }

		inline void disable(value_type &pml5e) noexcept
		{ pml5e = clear_bit(pml5e, from); }

		inline void dump(int level, const value_type &pml5e, std::string *msg = nullptr)
		{ bfdebug_subbool(level, name, is_enabled(pml5e), msg); }
	}

	namespace accessed_flag
	{
		constexpr const auto mask = 0x20ULL;
		constexpr const auto from = 5ULL;
		constexpr const auto name = "accessed_flag";

		inline auto is_enabled(const value_type &pml5e) noexcept
		{ return is_bit_set(pml5e, from); }

		inline auto is_disabled(const value_type &pml5e) noexcept
		{ return !is_bit_set(pml5e, from); }

		inline void enable(value_type &pml5e) noexcept
		{ pml5e = set_bit(pml5e, from); }

		inline void disable(value_type &pml5e) noexcept
		{ pml5e = clear_bit(pml5e, from); }

		inline void dump(int level, const value_type &pml5e, std::string *msg = nullptr)
		{ bfdebug_subbool(level, name, is_enabled(pml5e), msg); }
	}

	namespace extended_access
	{
		constexpr const auto mask = 0x400ULL;
		constexpr const auto from = 10ULL;
		constexpr const auto name = "extended_access";

		inline auto is_enabled(const value_type &pml5e) noexcept
		{ return is_bit_set(pml5e, from); }

		inline auto is_disabled(const value_type &pml5e) noexcept
		{ return !is_bit_set(pml5e, from); }

		inline void enable(value_type &pml5e) noexcept
		{ pml5e = set_bit(pml5e, from); }

		inline void disable(value_type &pml5e) noexcept
		{ pml5e = clear_bit(pml5e, from); }

		inline void dump(int level, const value_type &pml5e, std::string *msg = nullptr)
		{ bfdebug_subbool(level, name, is_enabled(pml5e), msg); }
	}

	namespace phys_addr_bits
	{
		constexpr const auto mask = 0xFFFFFFFFF000ULL;
		constexpr const auto from = 12ULL;
		constexpr const auto name = "phys_addr_bits";

		inline auto get(const value_type &pml5e) noexcept
		{ return get_bits(pml5e, mask) >> from; }

		inline void set(value_type &pml5e, uint64_t val) noexcept
		{ pml5e = set_bits(pml5e, mask, val << from); }

		inline void dump(int level, const value_type &pml5e, std::string *msg = nullptr)
		{ bfdebug_subnhex(level, name, get(pml5e), msg); }
	}

	namespace execute_disable
	{
		constexpr const auto mask = 0x8000000000000000ULL;
		constexpr const auto from = 63ULL;
		constexpr const auto name = "execute_disable";

		inline auto is_enabled(const value_type &pml5e) noexcept
		{ return is_bit_set(pml5e, from); }

		inline auto is_disabled(const value_type &pml5e) noexcept
		{ return !is_bit_set(pml5e, from); }

		inline void enable(value_type &pml5e) noexcept
		{ pml5e = set_bit(pml5e, from); }

		inline void disable(value_type &pml5e) noexcept
		{ pml5e = clear_bit(pml5e, from); }

		inline void dump(int level, const value_type &pml5e, std::string *msg = nullptr)
		{ bfdebug_subbool(level, name, is_enabled(pml5e), msg); }
	}

	inline void dump(int level, const value_type &pml5e, std::string *msg = nullptr)
	{
		bfdebug_nhex(level, "pml5e", pml5e, msg);

		present::dump(level, pml5e, msg);
		write_enable::dump(level, pml5e, msg);
		user_access::dump(level, pml5e, msg);
		page_level_write_through::dump(level, pml5e, msg);
		page_level_cache_disable::dump(level, pml5e, msg);
		accessed_flag::dump(level, pml5e, msg);
		extended_access::dump(level, pml5e, msg);
		phys_addr_bits::dump(level, pml5e, msg);
		execute_disable::dump(level, pml5e, msg);
	}
}

namespace pml4e
{
	constexpr const auto name = "pml4e";

	using value_type = uint64_t;

	namespace present
	{
		constexpr const auto mask = 0x1ULL;
		constexpr const auto from = 0ULL;
		constexpr const auto name = "present";

		inline auto is_enabled(const value_type &pml4e) noexcept
		{ return is_bit_set(pml4e, from); }

		inline auto is_disabled(const value_type &pml4e) noexcept
		{ return !is_bit_set(pml4e, from); }

		inline void enable(value_type &pml4e) noexcept
		{ pml4e = set_bit(pml4e, from); }

		inline void disable(value_type &pml4e) noexcept
		{ pml4e = clear_bit(pml4e, from); }

		inline void dump(int level, const value_type &pml4e, std::string *msg = nullptr)
		{ bfdebug_subbool(level, name, is_enabled(pml4e), msg); }
	}

	namespace write_enable
	{
		constexpr const auto mask = 0x2ULL;
		constexpr const auto from = 1ULL;
		constexpr const auto name = "write_enable";

		inline auto is_enabled(const value_type &pml4e) noexcept
		{ return is_bit_set(pml4e, from); }

		inline auto is_disabled(const value_type &pml4e) noexcept
		{ return !is_bit_set(pml4e, from); }

		inline void enable(value_type &pml4e) noexcept
		{ pml4e = set_bit(pml4e, from); }

		inline void disable(value_type &pml4e) noexcept
		{ pml4e = clear_bit(pml4e, from); }

		inline void dump(int level, const value_type &pml4e, std::string *msg = nullptr)
		{ bfdebug_subbool(level, name, is_enabled(pml4e), msg); }
	}

	namespace user_access
	{
		constexpr const auto mask = 0x4ULL;
		constexpr const auto from = 2ULL;
		constexpr const auto name = "user_access";

		inline auto is_enabled(const value_type &pml4e) noexcept
		{ return is_bit_set(pml4e, from); }

		inline auto is_disabled(const value_type &pml4e) noexcept
		{ return !is_bit_set(pml4e, from); }

		inline void enable(value_type &pml4e) noexcept
		{ pml4e = set_bit(pml4e, from); }

		inline void disable(value_type &pml4e) noexcept
		{ pml4e = clear_bit(pml4e, from); }

		inline void dump(int level, const value_type &pml4e, std::string *msg = nullptr)
		{ bfdebug_subbool(level, name, is_enabled(pml4e), msg); }
	}

	namespace page_level_write_through
	{
		constexpr const auto mask = 0x8ULL;
		constexpr const auto from = 3ULL;
		constexpr const auto name = "page_level_write_through";

		inline auto is_enabled(const value_type &pml4e) noexcept
		{ return is_bit_set(pml4e, from); }

		inline auto is_disabled(const value_type &pml4e) noexcept
		{ return !is_bit_set(pml4e, from); }

		inline void enable(value_type &pml4e) noexcept
		{ pml4e = set_bit(pml4e, from); }

		inline void disable(value_type &pml4e) noexcept
		{ pml4e = clear_bit(pml4e, from); }

		inline void dump(int level, const value_type &pml4e, std::string *msg = nullptr)
		{ bfdebug_subbool(level, name, is_enabled(pml4e), msg); }
	}

	namespace page_level_cache_disable
	{
		constexpr const auto mask = 0x10ULL;
		constexpr const auto from = 4ULL;
		constexpr const auto name = "page_level_cache_disable";

		inline auto is_enabled(const value_type &pml4e) noexcept
		{ return is_bit_set(pml4e, from); }

		inline auto is_disabled(const value_type &pml4e) noexcept
		{ return !is_bit_set(pml4e, from); }

		inline void enable(value_type &pml4e) noexcept
		{ pml4e = set_bit(pml4e, from); }

		inline void disable(value_type &pml4e) noexcept
		{ pml4e = clear_bit(pml4e, from); }

		inline void dump(int level, const value_type &pml4e, std::string *msg = nullptr)
		{ bfdebug_subbool(level, name, is_enabled(pml4e), msg); }
	}

	namespace accessed_flag
	{
		constexpr const auto mask = 0x20ULL;
		constexpr const auto from = 5ULL;
		constexpr const auto name = "accessed_flag";

		inline auto is_enabled(const value_type &pml4e) noexcept
		{ return is_bit_set(pml4e, from); }

		inline auto is_disabled(const value_type &pml4e) noexcept
		{ return !is_bit_set(pml4e, from); }

		inline void enable(value_type &pml4e) noexcept
		{ pml4e = set_bit(pml4e, from); }

		inline void disable(value_type &pml4e) noexcept
		{ pml4e = clear_bit(pml4e, from); }

		inline void dump(int level, const value_type &pml4e, std::string *msg = nullptr)
		{ bfdebug_subbool(level, name, is_enabled(pml4e), msg); }
	}

	namespace extended_access
	{
		constexpr const auto mask = 0x400ULL;
		constexpr const auto from = 10ULL;
		constexpr const auto name = "extended_access";

		inline auto is_enabled(const value_type &pml4e) noexcept
		{ return is_bit_set(pml4e, from); }

		inline auto is_disabled(const value_type &pml4e) noexcept
		{ return !is_bit_set(pml4e, from); }

		inline void enable(value_type &pml4e) noexcept
		{ pml4e = set_bit(pml4e, from); }

		inline void disable(value_type &pml4e) noexcept
		{ pml4e = clear_bit(pml4e, from); }

		inline void dump(int level, const value_type &pml4e, std::string *msg = nullptr)
		{ bfdebug_subbool(level, name, is_enabled(pml4e), msg); }
	}

	namespace phys_addr_bits
	{
		constexpr const auto mask = 0xFFFFFFFFF000ULL;
		constexpr const auto from = 12ULL;
		constexpr const auto name = "phys_addr_bits";

		inline auto get(const value_type &pml4e) noexcept
		{ return get_bits(pml4e, mask) >> from; }

		inline void set(value_type &pml4e, uint64_t val) noexcept
		{ pml4e = set_bits(pml4e, mask, val << from); }

		inline void dump(int level, const value_type &pml4e, std::string *msg = nullptr)
		{ bfdebug_subnhex(level, name, get(pml4e), msg); }
	}

	namespace execute_disable
	{
		constexpr const auto mask = 0x8000000000000000ULL;
		constexpr const auto from = 63ULL;
		constexpr const auto name = "execute_disable";

		inline auto is_enabled(const value_type &pml4e) noexcept
		{ return is_bit_set(pml4e, from); }

		inline auto is_disabled(const value_type &pml4e) noexcept
		{ return !is_bit_set(pml4e, from); }

		inline void enable(value_type &pml4e) noexcept
		{ pml4e = set_bit(pml4e, from); }

		inline void disable(value_type &pml4e) noexcept
		{ pml4e = clear_bit(pml4e, from); }

		inline void dump(int level, const value_type &pml4e, std::string *msg = nullptr)
		{ bfdebug_subbool(level, name, is_enabled(pml4e), msg); }
	}

	inline void dump(int level, const value_type &pml4e, std::string *msg = nullptr)
	{
		bfdebug_nhex(level, "pml4e", pml4e, msg);

		present::dump(level, pml4e, msg);
		write_enable::dump(level, pml4e, msg);
		user_access::dump(level, pml4e, msg);
		page_level_write_through::dump(level, pml4e, msg);
		page_level_cache_disable::dump(level, pml4e, msg);
		accessed_flag::dump(level, pml4e, msg);
		extended_access::dump(level, pml4e, msg);
		phys_addr_bits::dump(level, pml4e, msg);
		execute_disable::dump(level, pml4e, msg);
	}
}

namespace pdpte
{
	constexpr const auto name = "pdpte";

	using value_type = uint64_t;

	namespace present
	{
		constexpr const auto mask = 0x1ULL;
		constexpr const auto from = 0ULL;
		constexpr const auto name = "present";

		inline auto is_enabled(const value_type &pdpte) noexcept
		{ return is_bit_set(pdpte, from); }

		inline auto is_disabled(const value_type &pdpte) noexcept
		{ return !is_bit_set(pdpte, from); }

		inline void enable(value_type &pdpte) noexcept
		{ pdpte = set_bit(pdpte, from); }

		inline void disable(value_type &pdpte) noexcept
		{ pdpte = clear_bit(pdpte, from); }

		inline void dump(int level, const value_type &pdpte, std::string *msg = nullptr)
		{ bfdebug_subbool(level, name, is_enabled(pdpte), msg); }
	}

	namespace write_enable
	{
		constexpr const auto mask = 0x2ULL;
		constexpr const auto from = 1ULL;
		constexpr const auto name = "write_enable";

		inline auto is_enabled(const value_type &pdpte) noexcept
		{ return is_bit_set(pdpte, from); }

		inline auto is_disabled(const value_type &pdpte) noexcept
		{ return !is_bit_set(pdpte, from); }

		inline void enable(value_type &pdpte) noexcept
		{ pdpte = set_bit(pdpte, from); }

		inline void disable(value_type &pdpte) noexcept
		{ pdpte = clear_bit(pdpte, from); }

		inline void dump(int level, const value_type &pdpte, std::string *msg = nullptr)
		{ bfdebug_subbool(level, name, is_enabled(pdpte), msg); }
	}

	namespace user_access
	{
		constexpr const auto mask = 0x4ULL;
		constexpr const auto from = 2ULL;
		constexpr const auto name = "user_access";

		inline auto is_enabled(const value_type &pdpte) noexcept
		{ return is_bit_set(pdpte, from); }

		inline auto is_disabled(const value_type &pdpte) noexcept
		{ return !is_bit_set(pdpte, from); }

		inline void enable(value_type &pdpte) noexcept
		{ pdpte = set_bit(pdpte, from); }

		inline void disable(value_type &pdpte) noexcept
		{ pdpte = clear_bit(pdpte, from); }

		inline void dump(int level, const value_type &pdpte, std::string *msg = nullptr)
		{ bfdebug_subbool(level, name, is_enabled(pdpte), msg); }
	}

	namespace page_level_write_through
	{
		constexpr const auto mask = 0x8ULL;
		constexpr const auto from = 3ULL;
		constexpr const auto name = "page_level_write_through";

		inline auto is_enabled(const value_type &pdpte) noexcept
		{ return is_bit_set(pdpte, from); }

		inline auto is_disabled(const value_type &pdpte) noexcept
		{ return !is_bit_set(pdpte, from); }

		inline void enable(value_type &pdpte) noexcept
		{ pdpte = set_bit(pdpte, from); }

		inline void disable(value_type &pdpte) noexcept
		{ pdpte = clear_bit(pdpte, from); }

		inline void dump(int level, const value_type &pdpte, std::string *msg = nullptr)
		{ bfdebug_subbool(level, name, is_enabled(pdpte), msg); }
	}

	namespace page_level_cache_disable
	{
		constexpr const auto mask = 0x10ULL;
		constexpr const auto from = 4ULL;
		constexpr const auto name = "page_level_cache_disable";

		inline auto is_enabled(const value_type &pdpte) noexcept
		{ return is_bit_set(pdpte, from); }

		inline auto is_disabled(const value_type &pdpte) noexcept
		{ return !is_bit_set(pdpte, from); }

		inline void enable(value_type &pdpte) noexcept
		{ pdpte = set_bit(pdpte, from); }

		inline void disable(value_type &pdpte) noexcept
		{ pdpte = clear_bit(pdpte, from); }

		inline void dump(int level, const value_type &pdpte, std::string *msg = nullptr)
		{ bfdebug_subbool(level, name, is_enabled(pdpte), msg); }
	}

	namespace accessed_flag
	{
		constexpr const auto mask = 0x20ULL;
		constexpr const auto from = 5ULL;
		constexpr const auto name = "accessed_flag";

		inline auto is_enabled(const value_type &pdpte) noexcept
		{ return is_bit_set(pdpte, from); }

		inline auto is_disabled(const value_type &pdpte) noexcept
		{ return !is_bit_set(pdpte, from); }

		inline void enable(value_type &pdpte) noexcept
		{ pdpte = set_bit(pdpte, from); }

		inline void disable(value_type &pdpte) noexcept
		{ pdpte = clear_bit(pdpte, from); }

		inline void dump(int level, const value_type &pdpte, std::string *msg = nullptr)
		{ bfdebug_subbool(level, name, is_enabled(pdpte), msg); }
	}

	namespace dirty_flag
	{
		constexpr const auto mask = 0x40ULL;
		constexpr const auto from = 6ULL;
		constexpr const auto name = "dirty_flag";

		inline auto is_enabled(const value_type &pdpte) noexcept
		{ return is_bit_set(pdpte, from); }

		inline auto is_disabled(const value_type &pdpte) noexcept
		{ return !is_bit_set(pdpte, from); }

		inline void enable(value_type &pdpte) noexcept
		{ pdpte = set_bit(pdpte, from); }

		inline void disable(value_type &pdpte) noexcept
		{ pdpte = clear_bit(pdpte, from); }

		inline void dump(int level, const value_type &pdpte, std::string *msg = nullptr)
		{ bfdebug_subbool(level, name, is_enabled(pdpte), msg); }
	}

	namespace entry_type
	{
		constexpr const auto mask = 0x80ULL;
		constexpr const auto from = 7ULL;
		constexpr const auto name = "entry_type";

		inline auto is_enabled(const value_type &pdpte) noexcept
		{ return is_bit_set(pdpte, from); }

		inline auto is_disabled(const value_type &pdpte) noexcept
		{ return !is_bit_set(pdpte, from); }

		inline void enable(value_type &pdpte) noexcept
		{ pdpte = set_bit(pdpte, from); }

		inline void disable(value_type &pdpte) noexcept
		{ pdpte = clear_bit(pdpte, from); }

		inline void dump(int level, const value_type &pdpte, std::string *msg = nullptr)
		{ bfdebug_subbool(level, name, is_enabled(pdpte), msg); }
	}

	namespace global_enable
	{
		constexpr const auto mask = 0x100ULL;
		constexpr const auto from = 8ULL;
		constexpr const auto name = "global_enable";

		inline auto is_enabled(const value_type &pdpte) noexcept
		{ return is_bit_set(pdpte, from); }

		inline auto is_disabled(const value_type &pdpte) noexcept
		{ return !is_bit_set(pdpte, from); }

		inline void enable(value_type &pdpte) noexcept
		{ pdpte = set_bit(pdpte, from); }

		inline void disable(value_type &pdpte) noexcept
		{ pdpte = clear_bit(pdpte, from); }

		inline void dump(int level, const value_type &pdpte, std::string *msg = nullptr)
		{ bfdebug_subbool(level, name, is_enabled(pdpte), msg); }
	}

	namespace extended_access
	{
		constexpr const auto mask = 0x400ULL;
		constexpr const auto from = 10ULL;
		constexpr const auto name = "extended_access";

		inline auto is_enabled(const value_type &pdpte) noexcept
		{ return is_bit_set(pdpte, from); }

		inline auto is_disabled(const value_type &pdpte) noexcept
		{ return !is_bit_set(pdpte, from); }

		inline void enable(value_type &pdpte) noexcept
		{ pdpte = set_bit(pdpte, from); }

		inline void disable(value_type &pdpte) noexcept
		{ pdpte = clear_bit(pdpte, from); }

		inline void dump(int level, const value_type &pdpte, std::string *msg = nullptr)
		{ bfdebug_subbool(level, name, is_enabled(pdpte), msg); }
	}

	namespace pat
	{
		constexpr const auto mask = 0x1000ULL;
		constexpr const auto from = 12ULL;
		constexpr const auto name = "pat";

		inline auto is_enabled(const value_type &pdpte) noexcept
		{ return is_bit_set(pdpte, from); }

		inline auto is_disabled(const value_type &pdpte) noexcept
		{ return !is_bit_set(pdpte, from); }

		inline void enable(value_type &pdpte) noexcept
		{ pdpte = set_bit(pdpte, from); }

		inline void disable(value_type &pdpte) noexcept
		{ pdpte = clear_bit(pdpte, from); }

		inline void dump(int level, const value_type &pdpte, std::string *msg = nullptr)
		{ bfdebug_subbool(level, name, is_enabled(pdpte), msg); }
	}

	namespace phys_addr_bits
	{
		constexpr const auto mask = 0xFFFFFFFFF000ULL;
		constexpr const auto from = 12ULL;
		constexpr const auto name = "phys_addr_bits";

		inline auto get(const value_type &pdpte) noexcept
		{ return get_bits(pdpte, mask) >> from; }

		inline void set(value_type &pdpte, uint64_t val) noexcept
		{ pdpte = set_bits(pdpte, mask, val << from); }

		inline void dump(int level, const value_type &pdpte, std::string *msg = nullptr)
		{ bfdebug_subnhex(level, name, get(pdpte), msg); }
	}

	namespace execute_disable
	{
		constexpr const auto mask = 0x8000000000000000ULL;
		constexpr const auto from = 63ULL;
		constexpr const auto name = "execute_disable";

		inline auto is_enabled(const value_type &pdpte) noexcept
		{ return is_bit_set(pdpte, from); }

		inline auto is_disabled(const value_type &pdpte) noexcept
		{ return !is_bit_set(pdpte, from); }

		inline void enable(value_type &pdpte) noexcept
		{ pdpte = set_bit(pdpte, from); }

		inline void disable(value_type &pdpte) noexcept
		{ pdpte = clear_bit(pdpte, from); }

		inline void dump(int level, const value_type &pdpte, std::string *msg = nullptr)
		{ bfdebug_subbool(level, name, is_enabled(pdpte), msg); }
	}

	inline void dump(int level, const value_type &pdpte, std::string *msg = nullptr)
	{
		bfdebug_nhex(level, "pdpte", pdpte, msg);

		present::dump(level, pdpte, msg);
		write_enable::dump(level, pdpte, msg);
		user_access::dump(level, pdpte, msg);
		page_level_write_through::dump(level, pdpte, msg);
		page_level_cache_disable::dump(level, pdpte, msg);
		accessed_flag::dump(level, pdpte, msg);
		dirty_flag::dump(level, pdpte, msg);
		entry_type::dump(level, pdpte, msg);
		global_enable::dump(level, pdpte, msg);
		extended_access::dump(level, pdpte, msg);
		pat::dump(level, pdpte, msg);
		phys_addr_bits::dump(level, pdpte, msg);
		execute_disable::dump(level, pdpte, msg);
	}
}

namespace pde
{
	constexpr const auto name = "pde";

	using value_type = uint64_t;

	namespace present
	{
		constexpr const auto mask = 0x1ULL;
		constexpr const auto from = 0ULL;
		constexpr const auto name = "present";

		inline auto is_enabled(const value_type &pde) noexcept
		{ return is_bit_set(pde, from); }

		inline auto is_disabled(const value_type &pde) noexcept
		{ return !is_bit_set(pde, from); }

		inline void enable(value_type &pde) noexcept
		{ pde = set_bit(pde, from); }

		inline void disable(value_type &pde) noexcept
		{ pde = clear_bit(pde, from); }

		inline void dump(int level, const value_type &pde, std::string *msg = nullptr)
		{ bfdebug_subbool(level, name, is_enabled(pde), msg); }
	}

	namespace write_enable
	{
		constexpr const auto mask = 0x2ULL;
		constexpr const auto from = 1ULL;
		constexpr const auto name = "write_enable";

		inline auto is_enabled(const value_type &pde) noexcept
		{ return is_bit_set(pde, from); }

		inline auto is_disabled(const value_type &pde) noexcept
		{ return !is_bit_set(pde, from); }

		inline void enable(value_type &pde) noexcept
		{ pde = set_bit(pde, from); }

		inline void disable(value_type &pde) noexcept
		{ pde = clear_bit(pde, from); }

		inline void dump(int level, const value_type &pde, std::string *msg = nullptr)
		{ bfdebug_subbool(level, name, is_enabled(pde), msg); }
	}

	namespace user_access
	{
		constexpr const auto mask = 0x4ULL;
		constexpr const auto from = 2ULL;
		constexpr const auto name = "user_access";

		inline auto is_enabled(const value_type &pde) noexcept
		{ return is_bit_set(pde, from); }

		inline auto is_disabled(const value_type &pde) noexcept
		{ return !is_bit_set(pde, from); }

		inline void enable(value_type &pde) noexcept
		{ pde = set_bit(pde, from); }

		inline void disable(value_type &pde) noexcept
		{ pde = clear_bit(pde, from); }

		inline void dump(int level, const value_type &pde, std::string *msg = nullptr)
		{ bfdebug_subbool(level, name, is_enabled(pde), msg); }
	}

	namespace page_level_write_through
	{
		constexpr const auto mask = 0x8ULL;
		constexpr const auto from = 3ULL;
		constexpr const auto name = "page_level_write_through";

		inline auto is_enabled(const value_type &pde) noexcept
		{ return is_bit_set(pde, from); }

		inline auto is_disabled(const value_type &pde) noexcept
		{ return !is_bit_set(pde, from); }

		inline void enable(value_type &pde) noexcept
		{ pde = set_bit(pde, from); }

		inline void disable(value_type &pde) noexcept
		{ pde = clear_bit(pde, from); }

		inline void dump(int level, const value_type &pde, std::string *msg = nullptr)
		{ bfdebug_subbool(level, name, is_enabled(pde), msg); }
	}

	namespace page_level_cache_disable
	{
		constexpr const auto mask = 0x10ULL;
		constexpr const auto from = 4ULL;
		constexpr const auto name = "page_level_cache_disable";

		inline auto is_enabled(const value_type &pde) noexcept
		{ return is_bit_set(pde, from); }

		inline auto is_disabled(const value_type &pde) noexcept
		{ return !is_bit_set(pde, from); }

		inline void enable(value_type &pde) noexcept
		{ pde = set_bit(pde, from); }

		inline void disable(value_type &pde) noexcept
		{ pde = clear_bit(pde, from); }

		inline void dump(int level, const value_type &pde, std::string *msg = nullptr)
		{ bfdebug_subbool(level, name, is_enabled(pde), msg); }
	}

	namespace accessed_flag
	{
		constexpr const auto mask = 0x20ULL;
		constexpr const auto from = 5ULL;
		constexpr const auto name = "accessed_flag";

		inline auto is_enabled(const value_type &pde) noexcept
		{ return is_bit_set(pde, from); }

		inline auto is_disabled(const value_type &pde) noexcept
		{ return !is_bit_set(pde, from); }

		inline void enable(value_type &pde) noexcept
		{ pde = set_bit(pde, from); }

		inline void disable(value_type &pde) noexcept
		{ pde = clear_bit(pde, from); }

		inline void dump(int level, const value_type &pde, std::string *msg = nullptr)
		{ bfdebug_subbool(level, name, is_enabled(pde), msg); }
	}

	namespace dirty_flag
	{
		constexpr const auto mask = 0x40ULL;
		constexpr const auto from = 6ULL;
		constexpr const auto name = "dirty_flag";

		inline auto is_enabled(const value_type &pde) noexcept
		{ return is_bit_set(pde, from); }

		inline auto is_disabled(const value_type &pde) noexcept
		{ return !is_bit_set(pde, from); }

		inline void enable(value_type &pde) noexcept
		{ pde = set_bit(pde, from); }

		inline void disable(value_type &pde) noexcept
		{ pde = clear_bit(pde, from); }

		inline void dump(int level, const value_type &pde, std::string *msg = nullptr)
		{ bfdebug_subbool(level, name, is_enabled(pde), msg); }
	}

	namespace entry_type
	{
		constexpr const auto mask = 0x80ULL;
		constexpr const auto from = 7ULL;
		constexpr const auto name = "entry_type";

		inline auto is_enabled(const value_type &pde) noexcept
		{ return is_bit_set(pde, from); }

		inline auto is_disabled(const value_type &pde) noexcept
		{ return !is_bit_set(pde, from); }

		inline void enable(value_type &pde) noexcept
		{ pde = set_bit(pde, from); }

		inline void disable(value_type &pde) noexcept
		{ pde = clear_bit(pde, from); }

		inline void dump(int level, const value_type &pde, std::string *msg = nullptr)
		{ bfdebug_subbool(level, name, is_enabled(pde), msg); }
	}

	namespace global_enable
	{
		constexpr const auto mask = 0x100ULL;
		constexpr const auto from = 8ULL;
		constexpr const auto name = "global_enable";

		inline auto is_enabled(const value_type &pde) noexcept
		{ return is_bit_set(pde, from); }

		inline auto is_disabled(const value_type &pde) noexcept
		{ return !is_bit_set(pde, from); }

		inline void enable(value_type &pde) noexcept
		{ pde = set_bit(pde, from); }

		inline void disable(value_type &pde) noexcept
		{ pde = clear_bit(pde, from); }

		inline void dump(int level, const value_type &pde, std::string *msg = nullptr)
		{ bfdebug_subbool(level, name, is_enabled(pde), msg); }
	}

	namespace extended_access
	{
		constexpr const auto mask = 0x400ULL;
		constexpr const auto from = 10ULL;
		constexpr const auto name = "extended_access";

		inline auto is_enabled(const value_type &pde) noexcept
		{ return is_bit_set(pde, from); }

		inline auto is_disabled(const value_type &pde) noexcept
		{ return !is_bit_set(pde, from); }

		inline void enable(value_type &pde) noexcept
		{ pde = set_bit(pde, from); }

		inline void disable(value_type &pde) noexcept
		{ pde = clear_bit(pde, from); }

		inline void dump(int level, const value_type &pde, std::string *msg = nullptr)
		{ bfdebug_subbool(level, name, is_enabled(pde), msg); }
	}

	namespace pat
	{
		constexpr const auto mask = 0x1000ULL;
		constexpr const auto from = 12ULL;
		constexpr const auto name = "pat";

		inline auto is_enabled(const value_type &pde) noexcept
		{ return is_bit_set(pde, from); }

		inline auto is_disabled(const value_type &pde) noexcept
		{ return !is_bit_set(pde, from); }

		inline void enable(value_type &pde) noexcept
		{ pde = set_bit(pde, from); }

		inline void disable(value_type &pde) noexcept
		{ pde = clear_bit(pde, from); }

		inline void dump(int level, const value_type &pde, std::string *msg = nullptr)
		{ bfdebug_subbool(level, name, is_enabled(pde), msg); }
	}

	namespace phys_addr_bits
	{
		constexpr const auto mask = 0xFFFFFFFFF000ULL;
		constexpr const auto from = 12ULL;
		constexpr const auto name = "phys_addr_bits";

		inline auto get(const value_type &pde) noexcept
		{ return get_bits(pde, mask) >> from; }

		inline void set(value_type &pde, uint64_t val) noexcept
		{ pde = set_bits(pde, mask, val << from); }

		inline void dump(int level, const value_type &pde, std::string *msg = nullptr)
		{ bfdebug_subnhex(level, name, get(pde), msg); }
	}

	namespace execute_disable
	{
		constexpr const auto mask = 0x8000000000000000ULL;
		constexpr const auto from = 63ULL;
		constexpr const auto name = "execute_disable";

		inline auto is_enabled(const value_type &pde) noexcept
		{ return is_bit_set(pde, from); }

		inline auto is_disabled(const value_type &pde) noexcept
		{ return !is_bit_set(pde, from); }

		inline void enable(value_type &pde) noexcept
		{ pde = set_bit(pde, from); }

		inline void disable(value_type &pde) noexcept
		{ pde = clear_bit(pde, from); }

		inline void dump(int level, const value_type &pde, std::string *msg = nullptr)
		{ bfdebug_subbool(level, name, is_enabled(pde), msg); }
	}

	inline void dump(int level, const value_type &pde, std::string *msg = nullptr)
	{
		bfdebug_nhex(level, "pde", pde, msg);

		present::dump(level, pde, msg);
		write_enable::dump(level, pde, msg);
		user_access::dump(level, pde, msg);
		page_level_write_through::dump(level, pde, msg);
		page_level_cache_disable::dump(level, pde, msg);
		accessed_flag::dump(level, pde, msg);
		dirty_flag::dump(level, pde, msg);
		entry_type::dump(level, pde, msg);
		global_enable::dump(level, pde, msg);
		extended_access::dump(level, pde, msg);
		pat::dump(level, pde, msg);
		phys_addr_bits::dump(level, pde, msg);
		execute_disable::dump(level, pde, msg);
	}
}

namespace pte
{
	constexpr const auto name = "pte";

	using value_type = uint64_t;

	namespace present
	{
		constexpr const auto mask = 0x1ULL;
		constexpr const auto from = 0ULL;
		constexpr const auto name = "present";

		inline auto is_enabled(const value_type &pte) noexcept
		{ return is_bit_set(pte, from); }

		inline auto is_disabled(const value_type &pte) noexcept
		{ return !is_bit_set(pte, from); }

		inline void enable(value_type &pte) noexcept
		{ pte = set_bit(pte, from); }

		inline void disable(value_type &pte) noexcept
		{ pte = clear_bit(pte, from); }

		inline void dump(int level, const value_type &pte, std::string *msg = nullptr)
		{ bfdebug_subbool(level, name, is_enabled(pte), msg); }
	}

	namespace write_enable
	{
		constexpr const auto mask = 0x2ULL;
		constexpr const auto from = 1ULL;
		constexpr const auto name = "write_enable";

		inline auto is_enabled(const value_type &pte) noexcept
		{ return is_bit_set(pte, from); }

		inline auto is_disabled(const value_type &pte) noexcept
		{ return !is_bit_set(pte, from); }

		inline void enable(value_type &pte) noexcept
		{ pte = set_bit(pte, from); }

		inline void disable(value_type &pte) noexcept
		{ pte = clear_bit(pte, from); }

		inline void dump(int level, const value_type &pte, std::string *msg = nullptr)
		{ bfdebug_subbool(level, name, is_enabled(pte), msg); }
	}

	namespace user_access
	{
		constexpr const auto mask = 0x4ULL;
		constexpr const auto from = 2ULL;
		constexpr const auto name = "user_access";

		inline auto is_enabled(const value_type &pte) noexcept
		{ return is_bit_set(pte, from); }

		inline auto is_disabled(const value_type &pte) noexcept
		{ return !is_bit_set(pte, from); }

		inline void enable(value_type &pte) noexcept
		{ pte = set_bit(pte, from); }

		inline void disable(value_type &pte) noexcept
		{ pte = clear_bit(pte, from); }

		inline void dump(int level, const value_type &pte, std::string *msg = nullptr)
		{ bfdebug_subbool(level, name, is_enabled(pte), msg); }
	}

	namespace page_level_write_through
	{
		constexpr const auto mask = 0x8ULL;
		constexpr const auto from = 3ULL;
		constexpr const auto name = "page_level_write_through";

		inline auto is_enabled(const value_type &pte) noexcept
		{ return is_bit_set(pte, from); }

		inline auto is_disabled(const value_type &pte) noexcept
		{ return !is_bit_set(pte, from); }

		inline void enable(value_type &pte) noexcept
		{ pte = set_bit(pte, from); }

		inline void disable(value_type &pte) noexcept
		{ pte = clear_bit(pte, from); }

		inline void dump(int level, const value_type &pte, std::string *msg = nullptr)
		{ bfdebug_subbool(level, name, is_enabled(pte), msg); }
	}

	namespace page_level_cache_disable
	{
		constexpr const auto mask = 0x10ULL;
		constexpr const auto from = 4ULL;
		constexpr const auto name = "page_level_cache_disable";

		inline auto is_enabled(const value_type &pte) noexcept
		{ return is_bit_set(pte, from); }

		inline auto is_disabled(const value_type &pte) noexcept
		{ return !is_bit_set(pte, from); }

		inline void enable(value_type &pte) noexcept
		{ pte = set_bit(pte, from); }

		inline void disable(value_type &pte) noexcept
		{ pte = clear_bit(pte, from); }

		inline void dump(int level, const value_type &pte, std::string *msg = nullptr)
		{ bfdebug_subbool(level, name, is_enabled(pte), msg); }
	}

	namespace accessed_flag
	{
		constexpr const auto mask = 0x20ULL;
		constexpr const auto from = 5ULL;
		constexpr const auto name = "accessed_flag";

		inline auto is_enabled(const value_type &pte) noexcept
		{ return is_bit_set(pte, from); }

		inline auto is_disabled(const value_type &pte) noexcept
		{ return !is_bit_set(pte, from); }

		inline void enable(value_type &pte) noexcept
		{ pte = set_bit(pte, from); }

		inline void disable(value_type &pte) noexcept
		{ pte = clear_bit(pte, from); }

		inline void dump(int level, const value_type &pte, std::string *msg = nullptr)
		{ bfdebug_subbool(level, name, is_enabled(pte), msg); }
	}

	namespace dirty_flag
	{
		constexpr const auto mask = 0x40ULL;
		constexpr const auto from = 6ULL;
		constexpr const auto name = "dirty_flag";

		inline auto is_enabled(const value_type &pte) noexcept
		{ return is_bit_set(pte, from); }

		inline auto is_disabled(const value_type &pte) noexcept
		{ return !is_bit_set(pte, from); }

		inline void enable(value_type &pte) noexcept
		{ pte = set_bit(pte, from); }

		inline void disable(value_type &pte) noexcept
		{ pte = clear_bit(pte, from); }

		inline void dump(int level, const value_type &pte, std::string *msg = nullptr)
		{ bfdebug_subbool(level, name, is_enabled(pte), msg); }
	}

	namespace pat
	{
		constexpr const auto mask = 0x80ULL;
		constexpr const auto from = 7ULL;
		constexpr const auto name = "pat";

		inline auto is_enabled(const value_type &pte) noexcept
		{ return is_bit_set(pte, from); }

		inline auto is_disabled(const value_type &pte) noexcept
		{ return !is_bit_set(pte, from); }

		inline void enable(value_type &pte) noexcept
		{ pte = set_bit(pte, from); }

		inline void disable(value_type &pte) noexcept
		{ pte = clear_bit(pte, from); }

		inline void dump(int level, const value_type &pte, std::string *msg = nullptr)
		{ bfdebug_subbool(level, name, is_enabled(pte), msg); }
	}

	namespace global_enable
	{
		constexpr const auto mask = 0x100ULL;
		constexpr const auto from = 8ULL;
		constexpr const auto name = "global_enable";

		inline auto is_enabled(const value_type &pte) noexcept
		{ return is_bit_set(pte, from); }

		inline auto is_disabled(const value_type &pte) noexcept
		{ return !is_bit_set(pte, from); }

		inline void enable(value_type &pte) noexcept
		{ pte = set_bit(pte, from); }

		inline void disable(value_type &pte) noexcept
		{ pte = clear_bit(pte, from); }

		inline void dump(int level, const value_type &pte, std::string *msg = nullptr)
		{ bfdebug_subbool(level, name, is_enabled(pte), msg); }
	}

	namespace extended_access
	{
		constexpr const auto mask = 0x400ULL;
		constexpr const auto from = 10ULL;
		constexpr const auto name = "extended_access";

		inline auto is_enabled(const value_type &pte) noexcept
		{ return is_bit_set(pte, from); }

		inline auto is_disabled(const value_type &pte) noexcept
		{ return !is_bit_set(pte, from); }

		inline void enable(value_type &pte) noexcept
		{ pte = set_bit(pte, from); }

		inline void disable(value_type &pte) noexcept
		{ pte = clear_bit(pte, from); }

		inline void dump(int level, const value_type &pte, std::string *msg = nullptr)
		{ bfdebug_subbool(level, name, is_enabled(pte), msg); }
	}

	namespace phys_addr_bits
	{
		constexpr const auto mask = 0xFFFFFFFFF000ULL;
		constexpr const auto from = 12ULL;
		constexpr const auto name = "phys_addr_bits";

		inline auto get(const value_type &pte) noexcept
		{ return get_bits(pte, mask) >> from; }

		inline void set(value_type &pte, uint64_t val) noexcept
		{ pte = set_bits(pte, mask, val << from); }

		inline void dump(int level, const value_type &pte, std::string *msg = nullptr)
		{ bfdebug_subnhex(level, name, get(pte), msg); }
	}

	namespace execute_disable
	{
		constexpr const auto mask = 0x8000000000000000ULL;
		constexpr const auto from = 63ULL;
		constexpr const auto name = "execute_disable";

		inline auto is_enabled(const value_type &pte) noexcept
		{ return is_bit_set(pte, from); }

		inline auto is_disabled(const value_type &pte) noexcept
		{ return !is_bit_set(pte, from); }

		inline void enable(value_type &pte) noexcept
		{ pte = set_bit(pte, from); }

		inline void disable(value_type &pte) noexcept
		{ pte = clear_bit(pte, from); }

		inline void dump(int level, const value_type &pte, std::string *msg = nullptr)
		{ bfdebug_subbool(level, name, is_enabled(pte), msg); }
	}

	inline void dump(int level, const value_type &pte, std::string *msg = nullptr)
	{
		bfdebug_nhex(level, "pte", pte, msg);

		present::dump(level, pte, msg);
		write_enable::dump(level, pte, msg);
		user_access::dump(level, pte, msg);
		page_level_write_through::dump(level, pte, msg);
		page_level_cache_disable::dump(level, pte, msg);
		accessed_flag::dump(level, pte, msg);
		dirty_flag::dump(level, pte, msg);
		pat::dump(level, pte, msg);
		global_enable::dump(level, pte, msg);
		extended_access::dump(level, pte, msg);
		phys_addr_bits::dump(level, pte, msg);
		execute_disable::dump(level, pte, msg);
	}
}

}
}
}

// *INDENT-ON*

#endif
