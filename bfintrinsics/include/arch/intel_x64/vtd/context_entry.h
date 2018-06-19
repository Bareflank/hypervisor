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

#ifndef VTD_CONTEXT_ENTRY_H
#define VTD_CONTEXT_ENTRY_H

#include <stdint.h>
#include <bfgsl.h>
#include <bfbitmanip.h>
#include <bfdebug.h>

// *INDENT-OFF*

namespace intel_x64
{
namespace vtd
{

namespace context_entry
{
	constexpr const auto name = "context_entry";

	using value_type = struct value_type { uint64_t data[2]{0}; };

	namespace p
	{
		constexpr const auto mask = 0x1ULL;
		constexpr const auto index = 0ULL;
		constexpr const auto from = 0ULL;
		constexpr const auto name = "present";

		inline auto is_enabled(const value_type &context_entry) noexcept
		{ return is_bit_set(context_entry.data[index], from); }

		inline auto is_disabled(const value_type &context_entry) noexcept
		{ return !is_bit_set(context_entry.data[index], from); }

		inline void enable(value_type &context_entry) noexcept
		{ context_entry.data[index] = set_bit(context_entry.data[index], from); }

		inline void disable(value_type &context_entry) noexcept
		{ context_entry.data[index] = clear_bit(context_entry.data[index], from); }

		inline void dump(int level, const value_type &context_entry, std::string *msg = nullptr)
		{ bfdebug_subbool(level, name, is_enabled(context_entry), msg); }
	}

	namespace fpd
	{
		constexpr const auto mask = 0x2ULL;
		constexpr const auto index = 0ULL;
		constexpr const auto from = 1ULL;
		constexpr const auto name = "fault_processing_disable";

		inline auto is_enabled(const value_type &context_entry) noexcept
		{ return is_bit_set(context_entry.data[index], from); }

		inline auto is_disabled(const value_type &context_entry) noexcept
		{ return !is_bit_set(context_entry.data[index], from); }

		inline void enable(value_type &context_entry) noexcept
		{ context_entry.data[index] = set_bit(context_entry.data[index], from); }

		inline void disable(value_type &context_entry) noexcept
		{ context_entry.data[index] = clear_bit(context_entry.data[index], from); }

		inline void dump(int level, const value_type &context_entry, std::string *msg = nullptr)
		{ bfdebug_subbool(level, name, is_enabled(context_entry), msg); }
	}

	namespace t
	{
		constexpr const auto mask = 0xCULL;
		constexpr const auto index = 0ULL;
		constexpr const auto from = 2ULL;
		constexpr const auto name = "translation_type";

		inline auto get(const value_type &context_entry) noexcept
		{ return get_bits(context_entry.data[index], mask) >> from; }

		inline void set(value_type &context_entry, uint64_t val) noexcept
		{ context_entry.data[index] = set_bits(context_entry.data[index], mask, val << from); }

		inline void dump(int level, const value_type &context_entry, std::string *msg = nullptr)
		{ bfdebug_subnhex(level, name, get(context_entry), msg); }
	}

	namespace slptptr
	{
		constexpr const auto mask = 0xFFFFFFFFF000ULL;
		constexpr const auto index = 0ULL;
		constexpr const auto from = 12ULL;
		constexpr const auto name = "second_level_page_translation_pointer";

		inline auto get(const value_type &context_entry) noexcept
		{ return get_bits(context_entry.data[index], mask) >> from; }

		inline void set(value_type &context_entry, uint64_t val) noexcept
		{ context_entry.data[index] = set_bits(context_entry.data[index], mask, val << from); }

		inline void dump(int level, const value_type &context_entry, std::string *msg = nullptr)
		{ bfdebug_subnhex(level, name, get(context_entry), msg); }
	}

	namespace aw
	{
		constexpr const auto mask = 0x7ULL;
		constexpr const auto index = 1ULL;
		constexpr const auto from = 0ULL;
		constexpr const auto name = "address_width";

		inline auto get(const value_type &context_entry) noexcept
		{ return get_bits(context_entry.data[index], mask) >> from; }

		inline void set(value_type &context_entry, uint64_t val) noexcept
		{ context_entry.data[index] = set_bits(context_entry.data[index], mask, val << from); }

		inline void dump(int level, const value_type &context_entry, std::string *msg = nullptr)
		{ bfdebug_subnhex(level, name, get(context_entry), msg); }
	}

	namespace did
	{
		constexpr const auto mask = 0xFFFF00ULL;
		constexpr const auto index = 1ULL;
		constexpr const auto from = 8ULL;
		constexpr const auto name = "domain_identifier";

		inline auto get(const value_type &context_entry) noexcept
		{ return get_bits(context_entry.data[index], mask) >> from; }

		inline void set(value_type &context_entry, uint64_t val) noexcept
		{ context_entry.data[index] = set_bits(context_entry.data[index], mask, val << from); }

		inline void dump(int level, const value_type &context_entry, std::string *msg = nullptr)
		{ bfdebug_subnhex(level, name, get(context_entry), msg); }
	}

	inline void dump(int level, const value_type &context_entry, std::string *msg = nullptr)
	{
		bfdebug_nhex(level, "context_entry[63:0]", context_entry.data[0], msg);
		bfdebug_nhex(level, "context_entry[127:64]", context_entry.data[1], msg);

		p::dump(level, context_entry, msg);
		fpd::dump(level, context_entry, msg);
		t::dump(level, context_entry, msg);
		slptptr::dump(level, context_entry, msg);
		aw::dump(level, context_entry, msg);
		did::dump(level, context_entry, msg);
	}
}

}
}

// *INDENT-ON*

#endif
