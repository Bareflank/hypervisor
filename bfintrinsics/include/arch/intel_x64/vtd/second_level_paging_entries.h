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

#ifndef VTD_SECOND_LEVEL_PAGING_ENTRIES_H
#define VTD_SECOND_LEVEL_PAGING_ENTRIES_H

#include <stdint.h>
#include <bfgsl.h>
#include <bfbitmanip.h>
#include <bfdebug.h>

// *INDENT-OFF*

namespace intel_x64
{
namespace vtd
{
namespace second_level_paging_entries
{

namespace pml5e
{
	constexpr const auto name = "pml5e";

	using value_type = uint64_t;

	namespace read_access
	{
		constexpr const auto mask = 0x1ULL;
		constexpr const auto from = 0ULL;
		constexpr const auto name = "read_access";

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

	namespace write_access
	{
		constexpr const auto mask = 0x2ULL;
		constexpr const auto from = 1ULL;
		constexpr const auto name = "write_access";

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

	namespace execute_access
	{
		constexpr const auto mask = 0x4ULL;
		constexpr const auto from = 2ULL;
		constexpr const auto name = "execute_access";

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

	inline void dump(int level, const value_type &pml5e, std::string *msg = nullptr)
	{
		bfdebug_nhex(level, "pml5e", pml5e, msg);

		read_access::dump(level, pml5e, msg);
		write_access::dump(level, pml5e, msg);
		execute_access::dump(level, pml5e, msg);
		phys_addr_bits::dump(level, pml5e, msg);
	}
}

namespace pml4e
{
	constexpr const auto name = "pml4e";

	using value_type = uint64_t;

	namespace read_access
	{
		constexpr const auto mask = 0x1ULL;
		constexpr const auto from = 0ULL;
		constexpr const auto name = "read_access";

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

	namespace write_access
	{
		constexpr const auto mask = 0x2ULL;
		constexpr const auto from = 1ULL;
		constexpr const auto name = "write_access";

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

	namespace execute_access
	{
		constexpr const auto mask = 0x4ULL;
		constexpr const auto from = 2ULL;
		constexpr const auto name = "execute_access";

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

	inline void dump(int level, const value_type &pml4e, std::string *msg = nullptr)
	{
		bfdebug_nhex(level, "pml4e", pml4e, msg);

		read_access::dump(level, pml4e, msg);
		write_access::dump(level, pml4e, msg);
		execute_access::dump(level, pml4e, msg);
		phys_addr_bits::dump(level, pml4e, msg);
	}
}

namespace pdpte
{
	constexpr const auto name = "pdpte";

	using value_type = uint64_t;

	namespace read_access
	{
		constexpr const auto mask = 0x1ULL;
		constexpr const auto from = 0ULL;
		constexpr const auto name = "read_access";

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

	namespace write_access
	{
		constexpr const auto mask = 0x2ULL;
		constexpr const auto from = 1ULL;
		constexpr const auto name = "write_access";

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

	namespace execute_access
	{
		constexpr const auto mask = 0x4ULL;
		constexpr const auto from = 2ULL;
		constexpr const auto name = "execute_access";

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

	namespace extended_memory_type
	{
		constexpr const auto mask = 0x38ULL;
		constexpr const auto from = 3ULL;
		constexpr const auto name = "extended_memory_type";

		inline auto get(const value_type &pdpte) noexcept
		{ return get_bits(pdpte, mask) >> from; }

		inline void set(value_type &pdpte, uint64_t val) noexcept
		{ pdpte = set_bits(pdpte, mask, val << from); }

		inline void dump(int level, const value_type &pdpte, std::string *msg = nullptr)
		{ bfdebug_subnhex(level, name, get(pdpte), msg); }
	}

	namespace ignore_pat
	{
		constexpr const auto mask = 0x40ULL;
		constexpr const auto from = 6ULL;
		constexpr const auto name = "ignore_pat";

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

	namespace snoop
	{
		constexpr const auto mask = 0x800ULL;
		constexpr const auto from = 11ULL;
		constexpr const auto name = "snoop";

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

	namespace transient_mapping
	{
		constexpr const auto mask = 0x4000000000000000ULL;
		constexpr const auto from = 62ULL;
		constexpr const auto name = "transient_mapping";

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

		read_access::dump(level, pdpte, msg);
		write_access::dump(level, pdpte, msg);
		execute_access::dump(level, pdpte, msg);
		extended_memory_type::dump(level, pdpte, msg);
		ignore_pat::dump(level, pdpte, msg);
		entry_type::dump(level, pdpte, msg);
		snoop::dump(level, pdpte, msg);
		phys_addr_bits::dump(level, pdpte, msg);
		transient_mapping::dump(level, pdpte, msg);
	}
}

namespace pde
{
	constexpr const auto name = "pde";

	using value_type = uint64_t;

	namespace read_access
	{
		constexpr const auto mask = 0x1ULL;
		constexpr const auto from = 0ULL;
		constexpr const auto name = "read_access";

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

	namespace write_access
	{
		constexpr const auto mask = 0x2ULL;
		constexpr const auto from = 1ULL;
		constexpr const auto name = "write_access";

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

	namespace execute_access
	{
		constexpr const auto mask = 0x4ULL;
		constexpr const auto from = 2ULL;
		constexpr const auto name = "execute_access";

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

	namespace extended_memory_type
	{
		constexpr const auto mask = 0x38ULL;
		constexpr const auto from = 3ULL;
		constexpr const auto name = "extended_memory_type";

		inline auto get(const value_type &pde) noexcept
		{ return get_bits(pde, mask) >> from; }

		inline void set(value_type &pde, uint64_t val) noexcept
		{ pde = set_bits(pde, mask, val << from); }

		inline void dump(int level, const value_type &pde, std::string *msg = nullptr)
		{ bfdebug_subnhex(level, name, get(pde), msg); }
	}

	namespace ignore_pat
	{
		constexpr const auto mask = 0x40ULL;
		constexpr const auto from = 6ULL;
		constexpr const auto name = "ignore_pat";

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

	namespace snoop
	{
		constexpr const auto mask = 0x800ULL;
		constexpr const auto from = 11ULL;
		constexpr const auto name = "snoop";

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

	namespace transient_mapping
	{
		constexpr const auto mask = 0x4000000000000000ULL;
		constexpr const auto from = 62ULL;
		constexpr const auto name = "transient_mapping";

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

		read_access::dump(level, pde, msg);
		write_access::dump(level, pde, msg);
		execute_access::dump(level, pde, msg);
		extended_memory_type::dump(level, pde, msg);
		ignore_pat::dump(level, pde, msg);
		entry_type::dump(level, pde, msg);
		snoop::dump(level, pde, msg);
		phys_addr_bits::dump(level, pde, msg);
		transient_mapping::dump(level, pde, msg);
	}
}

namespace pte
{
	constexpr const auto name = "pte";

	using value_type = uint64_t;

	namespace read_access
	{
		constexpr const auto mask = 0x1ULL;
		constexpr const auto from = 0ULL;
		constexpr const auto name = "read_access";

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

	namespace write_access
	{
		constexpr const auto mask = 0x2ULL;
		constexpr const auto from = 1ULL;
		constexpr const auto name = "write_access";

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

	namespace execute_access
	{
		constexpr const auto mask = 0x4ULL;
		constexpr const auto from = 2ULL;
		constexpr const auto name = "execute_access";

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

	namespace extended_memory_type
	{
		constexpr const auto mask = 0x38ULL;
		constexpr const auto from = 3ULL;
		constexpr const auto name = "extended_memory_type";

		inline auto get(const value_type &pte) noexcept
		{ return get_bits(pte, mask) >> from; }

		inline void set(value_type &pte, uint64_t val) noexcept
		{ pte = set_bits(pte, mask, val << from); }

		inline void dump(int level, const value_type &pte, std::string *msg = nullptr)
		{ bfdebug_subnhex(level, name, get(pte), msg); }
	}

	namespace ignore_pat
	{
		constexpr const auto mask = 0x40ULL;
		constexpr const auto from = 6ULL;
		constexpr const auto name = "ignore_pat";

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

	namespace entry_type
	{
		constexpr const auto mask = 0x80ULL;
		constexpr const auto from = 7ULL;
		constexpr const auto name = "entry_type";

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

	namespace snoop
	{
		constexpr const auto mask = 0x800ULL;
		constexpr const auto from = 11ULL;
		constexpr const auto name = "snoop";

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

	namespace transient_mapping
	{
		constexpr const auto mask = 0x4000000000000000ULL;
		constexpr const auto from = 62ULL;
		constexpr const auto name = "transient_mapping";

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

		read_access::dump(level, pte, msg);
		write_access::dump(level, pte, msg);
		execute_access::dump(level, pte, msg);
		extended_memory_type::dump(level, pte, msg);
		ignore_pat::dump(level, pte, msg);
		entry_type::dump(level, pte, msg);
		snoop::dump(level, pte, msg);
		phys_addr_bits::dump(level, pte, msg);
		transient_mapping::dump(level, pte, msg);
	}
}

}
}
}

// *INDENT-ON*

#endif
