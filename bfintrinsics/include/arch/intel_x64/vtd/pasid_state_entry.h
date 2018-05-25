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

#ifndef VTD_PASID_STATE_ENTRY_H
#define VTD_PASID_STATE_ENTRY_H

#include <stdint.h>
#include <bfgsl.h>
#include <bfbitmanip.h>
#include <bfdebug.h>

// *INDENT-OFF*

namespace intel_x64
{
namespace vtd
{

namespace pasid_state_entry
{
	constexpr const auto name = "pasid_state_entry";

	using value_type = uint64_t;

	namespace arefcnt
	{
		constexpr const auto mask = 0xFFFF00000000ULL;
		constexpr const auto from = 32ULL;
		constexpr const auto name = "active_reference_count";

		inline auto get(const value_type &pasid_state_entry) noexcept
		{ return get_bits(pasid_state_entry, mask) >> from; }

		inline void set(value_type &pasid_state_entry, uint64_t val) noexcept
		{ pasid_state_entry = set_bits(pasid_state_entry, mask, val << from); }

		inline void dump(int level, const value_type &pasid_state_entry, std::string *msg = nullptr)
		{ bfdebug_subnhex(level, name, get(pasid_state_entry), msg); }
	}

	namespace dinv
	{
		constexpr const auto mask = 0x8000000000000000ULL;
		constexpr const auto from = 63ULL;
		constexpr const auto name = "deferred_invalidate";

		inline auto is_enabled(const value_type &pasid_state_entry) noexcept
		{ return is_bit_set(pasid_state_entry, from); }

		inline auto is_disabled(const value_type &pasid_state_entry) noexcept
		{ return !is_bit_set(pasid_state_entry, from); }

		inline void enable(value_type &pasid_state_entry) noexcept
		{ pasid_state_entry = set_bit(pasid_state_entry, from); }

		inline void disable(value_type &pasid_state_entry) noexcept
		{ pasid_state_entry = clear_bit(pasid_state_entry, from); }

		inline void dump(int level, const value_type &pasid_state_entry, std::string *msg = nullptr)
		{ bfdebug_subbool(level, name, is_enabled(pasid_state_entry), msg); }
	}

	inline void dump(int level, const value_type &pasid_state_entry, std::string *msg = nullptr)
	{
		bfdebug_nhex(level, "pasid_state_entry", pasid_state_entry, msg);

		arefcnt::dump(level, pasid_state_entry, msg);
		dinv::dump(level, pasid_state_entry, msg);
	}
}

}
}

// *INDENT-ON*

#endif
