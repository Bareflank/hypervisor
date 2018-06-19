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

#ifndef VTD_PASID_ENTRY_H
#define VTD_PASID_ENTRY_H

#include <stdint.h>
#include <bfgsl.h>
#include <bfbitmanip.h>
#include <bfdebug.h>

// *INDENT-OFF*

namespace intel_x64
{
namespace vtd
{

namespace pasid_entry
{
	constexpr const auto name = "pasid_entry";

	using value_type = uint64_t;

	namespace p
	{
		constexpr const auto mask = 0x1ULL;
		constexpr const auto from = 0ULL;
		constexpr const auto name = "present";

		inline auto is_enabled(const value_type &pasid_entry) noexcept
		{ return is_bit_set(pasid_entry, from); }

		inline auto is_disabled(const value_type &pasid_entry) noexcept
		{ return !is_bit_set(pasid_entry, from); }

		inline void enable(value_type &pasid_entry) noexcept
		{ pasid_entry = set_bit(pasid_entry, from); }

		inline void disable(value_type &pasid_entry) noexcept
		{ pasid_entry = clear_bit(pasid_entry, from); }

		inline void dump(int level, const value_type &pasid_entry, std::string *msg = nullptr)
		{ bfdebug_subbool(level, name, is_enabled(pasid_entry), msg); }
	}

	namespace pwt
	{
		constexpr const auto mask = 0x8ULL;
		constexpr const auto from = 3ULL;
		constexpr const auto name = "page_level_write_through";

		inline auto is_enabled(const value_type &pasid_entry) noexcept
		{ return is_bit_set(pasid_entry, from); }

		inline auto is_disabled(const value_type &pasid_entry) noexcept
		{ return !is_bit_set(pasid_entry, from); }

		inline void enable(value_type &pasid_entry) noexcept
		{ pasid_entry = set_bit(pasid_entry, from); }

		inline void disable(value_type &pasid_entry) noexcept
		{ pasid_entry = clear_bit(pasid_entry, from); }

		inline void dump(int level, const value_type &pasid_entry, std::string *msg = nullptr)
		{ bfdebug_subbool(level, name, is_enabled(pasid_entry), msg); }
	}

	namespace pcd
	{
		constexpr const auto mask = 0x10ULL;
		constexpr const auto from = 4ULL;
		constexpr const auto name = "page_level_cache_disable";

		inline auto is_enabled(const value_type &pasid_entry) noexcept
		{ return is_bit_set(pasid_entry, from); }

		inline auto is_disabled(const value_type &pasid_entry) noexcept
		{ return !is_bit_set(pasid_entry, from); }

		inline void enable(value_type &pasid_entry) noexcept
		{ pasid_entry = set_bit(pasid_entry, from); }

		inline void disable(value_type &pasid_entry) noexcept
		{ pasid_entry = clear_bit(pasid_entry, from); }

		inline void dump(int level, const value_type &pasid_entry, std::string *msg = nullptr)
		{ bfdebug_subbool(level, name, is_enabled(pasid_entry), msg); }
	}

	namespace flpm
	{
		constexpr const auto mask = 0x600ULL;
		constexpr const auto from = 9ULL;
		constexpr const auto name = "first_level_paging_mode";

		inline auto get(const value_type &pasid_entry) noexcept
		{ return get_bits(pasid_entry, mask) >> from; }

		inline void set(value_type &pasid_entry, uint64_t val) noexcept
		{ pasid_entry = set_bits(pasid_entry, mask, val << from); }

		inline void dump(int level, const value_type &pasid_entry, std::string *msg = nullptr)
		{ bfdebug_subnhex(level, name, get(pasid_entry), msg); }
	}

	namespace sre
	{
		constexpr const auto mask = 0x800ULL;
		constexpr const auto from = 11ULL;
		constexpr const auto name = "supervisor_request_enable";

		inline auto is_enabled(const value_type &pasid_entry) noexcept
		{ return is_bit_set(pasid_entry, from); }

		inline auto is_disabled(const value_type &pasid_entry) noexcept
		{ return !is_bit_set(pasid_entry, from); }

		inline void enable(value_type &pasid_entry) noexcept
		{ pasid_entry = set_bit(pasid_entry, from); }

		inline void disable(value_type &pasid_entry) noexcept
		{ pasid_entry = clear_bit(pasid_entry, from); }

		inline void dump(int level, const value_type &pasid_entry, std::string *msg = nullptr)
		{ bfdebug_subbool(level, name, is_enabled(pasid_entry), msg); }
	}

	namespace flptptr
	{
		constexpr const auto mask = 0xFFFFFFFFF000ULL;
		constexpr const auto from = 12ULL;
		constexpr const auto name = "first_level_page_table_translation_pointer";

		inline auto get(const value_type &pasid_entry) noexcept
		{ return get_bits(pasid_entry, mask) >> from; }

		inline void set(value_type &pasid_entry, uint64_t val) noexcept
		{ pasid_entry = set_bits(pasid_entry, mask, val << from); }

		inline void dump(int level, const value_type &pasid_entry, std::string *msg = nullptr)
		{ bfdebug_subnhex(level, name, get(pasid_entry), msg); }
	}

	inline void dump(int level, const value_type &pasid_entry, std::string *msg = nullptr)
	{
		bfdebug_nhex(level, "pasid_entry", pasid_entry, msg);

		p::dump(level, pasid_entry, msg);
		pwt::dump(level, pasid_entry, msg);
		pcd::dump(level, pasid_entry, msg);
		flpm::dump(level, pasid_entry, msg);
		sre::dump(level, pasid_entry, msg);
		flptptr::dump(level, pasid_entry, msg);
	}
}

}
}

// *INDENT-ON*

#endif
