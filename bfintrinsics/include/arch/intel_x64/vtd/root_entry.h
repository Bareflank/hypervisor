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

#ifndef VTD_ROOT_TABLE_ENTRY_H
#define VTD_ROOT_TABLE_ENTRY_H

#include <stdint.h>
#include <bfgsl.h>
#include <bfbitmanip.h>
#include <bfdebug.h>

// *INDENT-OFF*

namespace intel_x64
{
namespace vtd
{

namespace rte
{
	constexpr const auto name = "rte";

	using value_type = uint64_t;

	namespace present
	{
		constexpr const auto mask = 0x1ULL;
		constexpr const auto from = 0ULL;
		constexpr const auto name = "present";

		inline auto is_enabled(const value_type &rte) noexcept
		{ return is_bit_set(rte, from); }

		inline auto is_disabled(const value_type &rte) noexcept
		{ return !is_bit_set(rte, from); }

		inline void enable(value_type &rte) noexcept
		{ rte = set_bit(rte, from); }

		inline void disable(value_type &rte) noexcept
		{ rte = clear_bit(rte, from); }

		inline void dump(int level, const value_type &rte, std::string *msg = nullptr)
		{ bfdebug_subbool(level, name, is_enabled(rte), msg); }
	}

	namespace context_table_pointer
	{
		constexpr const auto mask = 0xFFFFFFFFF000ULL;
		constexpr const auto from = 12ULL;
		constexpr const auto name = "context_table_pointer";

		inline auto get(const value_type &rte) noexcept
		{ return get_bits(rte, mask) >> from; }

		inline void set(value_type &rte, uint64_t val) noexcept
		{ rte = set_bits(rte, mask, val << from); }

		inline void dump(int level, const value_type &rte, std::string *msg = nullptr)
		{ bfdebug_subnhex(level, name, get(rte), msg); }
	}

	inline void dump(int level, const value_type &rte, std::string *msg = nullptr)
	{
		bfdebug_nhex(level, "rte", rte, msg);

		present::dump(level, rte, msg);
		context_table_pointer::dump(level, rte, msg);
	}
}

}
}

// *INDENT-ON*

#endif
