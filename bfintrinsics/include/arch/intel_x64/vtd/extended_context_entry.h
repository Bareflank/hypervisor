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

#ifndef VTD_EXTENDED_CONTEXT_ENTRY_H
#define VTD_EXTENDED_CONTEXT_ENTRY_H

#include <stdint.h>
#include <bfgsl.h>
#include <bfbitmanip.h>
#include <bfdebug.h>

// *INDENT-OFF*

namespace intel_x64
{
namespace vtd
{

namespace extended_context_entry
{
	constexpr const auto name = "extended_context_entry";

	using value_type = struct value_type { uint64_t data[4]{0}; };

	namespace p
	{
		constexpr const auto mask = 0x1ULL;
		constexpr const auto index = 0ULL;
		constexpr const auto from = 0ULL;
		constexpr const auto name = "present";

		inline auto is_enabled(const value_type &extended_context_entry) noexcept
		{ return is_bit_set(extended_context_entry.data[index], from); }

		inline auto is_disabled(const value_type &extended_context_entry) noexcept
		{ return !is_bit_set(extended_context_entry.data[index], from); }

		inline void enable(value_type &extended_context_entry) noexcept
		{ extended_context_entry.data[index] = set_bit(extended_context_entry.data[index], from); }

		inline void disable(value_type &extended_context_entry) noexcept
		{ extended_context_entry.data[index] = clear_bit(extended_context_entry.data[index], from); }

		inline void dump(int level, const value_type &extended_context_entry, std::string *msg = nullptr)
		{ bfdebug_subbool(level, name, is_enabled(extended_context_entry), msg); }
	}

	namespace fpd
	{
		constexpr const auto mask = 0x2ULL;
		constexpr const auto index = 0ULL;
		constexpr const auto from = 1ULL;
		constexpr const auto name = "fault_processing_disable";

		inline auto is_enabled(const value_type &extended_context_entry) noexcept
		{ return is_bit_set(extended_context_entry.data[index], from); }

		inline auto is_disabled(const value_type &extended_context_entry) noexcept
		{ return !is_bit_set(extended_context_entry.data[index], from); }

		inline void enable(value_type &extended_context_entry) noexcept
		{ extended_context_entry.data[index] = set_bit(extended_context_entry.data[index], from); }

		inline void disable(value_type &extended_context_entry) noexcept
		{ extended_context_entry.data[index] = clear_bit(extended_context_entry.data[index], from); }

		inline void dump(int level, const value_type &extended_context_entry, std::string *msg = nullptr)
		{ bfdebug_subbool(level, name, is_enabled(extended_context_entry), msg); }
	}

	namespace t
	{
		constexpr const auto mask = 0x1CULL;
		constexpr const auto index = 0ULL;
		constexpr const auto from = 2ULL;
		constexpr const auto name = "translation_type";

		inline auto get(const value_type &extended_context_entry) noexcept
		{ return get_bits(extended_context_entry.data[index], mask) >> from; }

		inline void set(value_type &extended_context_entry, uint64_t val) noexcept
		{ extended_context_entry.data[index] = set_bits(extended_context_entry.data[index], mask, val << from); }

		inline void dump(int level, const value_type &extended_context_entry, std::string *msg = nullptr)
		{ bfdebug_subnhex(level, name, get(extended_context_entry), msg); }
	}

	namespace emt
	{
		constexpr const auto mask = 0xE0ULL;
		constexpr const auto index = 0ULL;
		constexpr const auto from = 5ULL;
		constexpr const auto name = "extended_memory_type";

		inline auto get(const value_type &extended_context_entry) noexcept
		{ return get_bits(extended_context_entry.data[index], mask) >> from; }

		inline void set(value_type &extended_context_entry, uint64_t val) noexcept
		{ extended_context_entry.data[index] = set_bits(extended_context_entry.data[index], mask, val << from); }

		inline void dump(int level, const value_type &extended_context_entry, std::string *msg = nullptr)
		{ bfdebug_subnhex(level, name, get(extended_context_entry), msg); }
	}

	namespace dinve
	{
		constexpr const auto mask = 0x100ULL;
		constexpr const auto index = 0ULL;
		constexpr const auto from = 8ULL;
		constexpr const auto name = "deferred_invalidate_enable";

		inline auto is_enabled(const value_type &extended_context_entry) noexcept
		{ return is_bit_set(extended_context_entry.data[index], from); }

		inline auto is_disabled(const value_type &extended_context_entry) noexcept
		{ return !is_bit_set(extended_context_entry.data[index], from); }

		inline void enable(value_type &extended_context_entry) noexcept
		{ extended_context_entry.data[index] = set_bit(extended_context_entry.data[index], from); }

		inline void disable(value_type &extended_context_entry) noexcept
		{ extended_context_entry.data[index] = clear_bit(extended_context_entry.data[index], from); }

		inline void dump(int level, const value_type &extended_context_entry, std::string *msg = nullptr)
		{ bfdebug_subbool(level, name, is_enabled(extended_context_entry), msg); }
	}

	namespace pre
	{
		constexpr const auto mask = 0x200ULL;
		constexpr const auto index = 0ULL;
		constexpr const auto from = 9ULL;
		constexpr const auto name = "page_request_enable";

		inline auto is_enabled(const value_type &extended_context_entry) noexcept
		{ return is_bit_set(extended_context_entry.data[index], from); }

		inline auto is_disabled(const value_type &extended_context_entry) noexcept
		{ return !is_bit_set(extended_context_entry.data[index], from); }

		inline void enable(value_type &extended_context_entry) noexcept
		{ extended_context_entry.data[index] = set_bit(extended_context_entry.data[index], from); }

		inline void disable(value_type &extended_context_entry) noexcept
		{ extended_context_entry.data[index] = clear_bit(extended_context_entry.data[index], from); }

		inline void dump(int level, const value_type &extended_context_entry, std::string *msg = nullptr)
		{ bfdebug_subbool(level, name, is_enabled(extended_context_entry), msg); }
	}

	namespace neste
	{
		constexpr const auto mask = 0x400ULL;
		constexpr const auto index = 0ULL;
		constexpr const auto from = 10ULL;
		constexpr const auto name = "nested_translation_enable";

		inline auto is_enabled(const value_type &extended_context_entry) noexcept
		{ return is_bit_set(extended_context_entry.data[index], from); }

		inline auto is_disabled(const value_type &extended_context_entry) noexcept
		{ return !is_bit_set(extended_context_entry.data[index], from); }

		inline void enable(value_type &extended_context_entry) noexcept
		{ extended_context_entry.data[index] = set_bit(extended_context_entry.data[index], from); }

		inline void disable(value_type &extended_context_entry) noexcept
		{ extended_context_entry.data[index] = clear_bit(extended_context_entry.data[index], from); }

		inline void dump(int level, const value_type &extended_context_entry, std::string *msg = nullptr)
		{ bfdebug_subbool(level, name, is_enabled(extended_context_entry), msg); }
	}

	namespace paside
	{
		constexpr const auto mask = 0x800ULL;
		constexpr const auto index = 0ULL;
		constexpr const auto from = 11ULL;
		constexpr const auto name = "pasid_enable";

		inline auto is_enabled(const value_type &extended_context_entry) noexcept
		{ return is_bit_set(extended_context_entry.data[index], from); }

		inline auto is_disabled(const value_type &extended_context_entry) noexcept
		{ return !is_bit_set(extended_context_entry.data[index], from); }

		inline void enable(value_type &extended_context_entry) noexcept
		{ extended_context_entry.data[index] = set_bit(extended_context_entry.data[index], from); }

		inline void disable(value_type &extended_context_entry) noexcept
		{ extended_context_entry.data[index] = clear_bit(extended_context_entry.data[index], from); }

		inline void dump(int level, const value_type &extended_context_entry, std::string *msg = nullptr)
		{ bfdebug_subbool(level, name, is_enabled(extended_context_entry), msg); }
	}

	namespace slptptr
	{
		constexpr const auto mask = 0xFFFFFFFFF000ULL;
		constexpr const auto index = 0ULL;
		constexpr const auto from = 12ULL;
		constexpr const auto name = "second_level_page_translation_pointer";

		inline auto get(const value_type &extended_context_entry) noexcept
		{ return get_bits(extended_context_entry.data[index], mask) >> from; }

		inline void set(value_type &extended_context_entry, uint64_t val) noexcept
		{ extended_context_entry.data[index] = set_bits(extended_context_entry.data[index], mask, val << from); }

		inline void dump(int level, const value_type &extended_context_entry, std::string *msg = nullptr)
		{ bfdebug_subnhex(level, name, get(extended_context_entry), msg); }
	}

	namespace aw
	{
		constexpr const auto mask = 0x7ULL;
		constexpr const auto index = 1ULL;
		constexpr const auto from = 0ULL;
		constexpr const auto name = "address_width";

		inline auto get(const value_type &extended_context_entry) noexcept
		{ return get_bits(extended_context_entry.data[index], mask) >> from; }

		inline void set(value_type &extended_context_entry, uint64_t val) noexcept
		{ extended_context_entry.data[index] = set_bits(extended_context_entry.data[index], mask, val << from); }

		inline void dump(int level, const value_type &extended_context_entry, std::string *msg = nullptr)
		{ bfdebug_subnhex(level, name, get(extended_context_entry), msg); }
	}

	namespace pge
	{
		constexpr const auto mask = 0x8ULL;
		constexpr const auto index = 1ULL;
		constexpr const auto from = 3ULL;
		constexpr const auto name = "page_global_enable";

		inline auto is_enabled(const value_type &extended_context_entry) noexcept
		{ return is_bit_set(extended_context_entry.data[index], from); }

		inline auto is_disabled(const value_type &extended_context_entry) noexcept
		{ return !is_bit_set(extended_context_entry.data[index], from); }

		inline void enable(value_type &extended_context_entry) noexcept
		{ extended_context_entry.data[index] = set_bit(extended_context_entry.data[index], from); }

		inline void disable(value_type &extended_context_entry) noexcept
		{ extended_context_entry.data[index] = clear_bit(extended_context_entry.data[index], from); }

		inline void dump(int level, const value_type &extended_context_entry, std::string *msg = nullptr)
		{ bfdebug_subbool(level, name, is_enabled(extended_context_entry), msg); }
	}

	namespace nxe
	{
		constexpr const auto mask = 0x10ULL;
		constexpr const auto index = 1ULL;
		constexpr const auto from = 4ULL;
		constexpr const auto name = "no_execute_enable";

		inline auto is_enabled(const value_type &extended_context_entry) noexcept
		{ return is_bit_set(extended_context_entry.data[index], from); }

		inline auto is_disabled(const value_type &extended_context_entry) noexcept
		{ return !is_bit_set(extended_context_entry.data[index], from); }

		inline void enable(value_type &extended_context_entry) noexcept
		{ extended_context_entry.data[index] = set_bit(extended_context_entry.data[index], from); }

		inline void disable(value_type &extended_context_entry) noexcept
		{ extended_context_entry.data[index] = clear_bit(extended_context_entry.data[index], from); }

		inline void dump(int level, const value_type &extended_context_entry, std::string *msg = nullptr)
		{ bfdebug_subbool(level, name, is_enabled(extended_context_entry), msg); }
	}

	namespace wpe
	{
		constexpr const auto mask = 0x20ULL;
		constexpr const auto index = 1ULL;
		constexpr const auto from = 5ULL;
		constexpr const auto name = "write_protect_enable";

		inline auto is_enabled(const value_type &extended_context_entry) noexcept
		{ return is_bit_set(extended_context_entry.data[index], from); }

		inline auto is_disabled(const value_type &extended_context_entry) noexcept
		{ return !is_bit_set(extended_context_entry.data[index], from); }

		inline void enable(value_type &extended_context_entry) noexcept
		{ extended_context_entry.data[index] = set_bit(extended_context_entry.data[index], from); }

		inline void disable(value_type &extended_context_entry) noexcept
		{ extended_context_entry.data[index] = clear_bit(extended_context_entry.data[index], from); }

		inline void dump(int level, const value_type &extended_context_entry, std::string *msg = nullptr)
		{ bfdebug_subbool(level, name, is_enabled(extended_context_entry), msg); }
	}

	namespace cd
	{
		constexpr const auto mask = 0x40ULL;
		constexpr const auto index = 1ULL;
		constexpr const auto from = 6ULL;
		constexpr const auto name = "cache_disable";

		inline auto is_enabled(const value_type &extended_context_entry) noexcept
		{ return is_bit_set(extended_context_entry.data[index], from); }

		inline auto is_disabled(const value_type &extended_context_entry) noexcept
		{ return !is_bit_set(extended_context_entry.data[index], from); }

		inline void enable(value_type &extended_context_entry) noexcept
		{ extended_context_entry.data[index] = set_bit(extended_context_entry.data[index], from); }

		inline void disable(value_type &extended_context_entry) noexcept
		{ extended_context_entry.data[index] = clear_bit(extended_context_entry.data[index], from); }

		inline void dump(int level, const value_type &extended_context_entry, std::string *msg = nullptr)
		{ bfdebug_subbool(level, name, is_enabled(extended_context_entry), msg); }
	}

	namespace emte
	{
		constexpr const auto mask = 0x80ULL;
		constexpr const auto index = 1ULL;
		constexpr const auto from = 7ULL;
		constexpr const auto name = "extended_memory_type_enable";

		inline auto is_enabled(const value_type &extended_context_entry) noexcept
		{ return is_bit_set(extended_context_entry.data[index], from); }

		inline auto is_disabled(const value_type &extended_context_entry) noexcept
		{ return !is_bit_set(extended_context_entry.data[index], from); }

		inline void enable(value_type &extended_context_entry) noexcept
		{ extended_context_entry.data[index] = set_bit(extended_context_entry.data[index], from); }

		inline void disable(value_type &extended_context_entry) noexcept
		{ extended_context_entry.data[index] = clear_bit(extended_context_entry.data[index], from); }

		inline void dump(int level, const value_type &extended_context_entry, std::string *msg = nullptr)
		{ bfdebug_subbool(level, name, is_enabled(extended_context_entry), msg); }
	}

	namespace did
	{
		constexpr const auto mask = 0xFFFF00ULL;
		constexpr const auto index = 1ULL;
		constexpr const auto from = 8ULL;
		constexpr const auto name = "domain_identifier";

		inline auto get(const value_type &extended_context_entry) noexcept
		{ return get_bits(extended_context_entry.data[index], mask) >> from; }

		inline void set(value_type &extended_context_entry, uint64_t val) noexcept
		{ extended_context_entry.data[index] = set_bits(extended_context_entry.data[index], mask, val << from); }

		inline void dump(int level, const value_type &extended_context_entry, std::string *msg = nullptr)
		{ bfdebug_subnhex(level, name, get(extended_context_entry), msg); }
	}

	namespace smep
	{
		constexpr const auto mask = 0x1000000ULL;
		constexpr const auto index = 1ULL;
		constexpr const auto from = 24ULL;
		constexpr const auto name = "supervisor_mode_execute_protection";

		inline auto is_enabled(const value_type &extended_context_entry) noexcept
		{ return is_bit_set(extended_context_entry.data[index], from); }

		inline auto is_disabled(const value_type &extended_context_entry) noexcept
		{ return !is_bit_set(extended_context_entry.data[index], from); }

		inline void enable(value_type &extended_context_entry) noexcept
		{ extended_context_entry.data[index] = set_bit(extended_context_entry.data[index], from); }

		inline void disable(value_type &extended_context_entry) noexcept
		{ extended_context_entry.data[index] = clear_bit(extended_context_entry.data[index], from); }

		inline void dump(int level, const value_type &extended_context_entry, std::string *msg = nullptr)
		{ bfdebug_subbool(level, name, is_enabled(extended_context_entry), msg); }
	}

	namespace eafe
	{
		constexpr const auto mask = 0x2000000ULL;
		constexpr const auto index = 1ULL;
		constexpr const auto from = 25ULL;
		constexpr const auto name = "extended_access_flag_enable";

		inline auto is_enabled(const value_type &extended_context_entry) noexcept
		{ return is_bit_set(extended_context_entry.data[index], from); }

		inline auto is_disabled(const value_type &extended_context_entry) noexcept
		{ return !is_bit_set(extended_context_entry.data[index], from); }

		inline void enable(value_type &extended_context_entry) noexcept
		{ extended_context_entry.data[index] = set_bit(extended_context_entry.data[index], from); }

		inline void disable(value_type &extended_context_entry) noexcept
		{ extended_context_entry.data[index] = clear_bit(extended_context_entry.data[index], from); }

		inline void dump(int level, const value_type &extended_context_entry, std::string *msg = nullptr)
		{ bfdebug_subbool(level, name, is_enabled(extended_context_entry), msg); }
	}

	namespace ere
	{
		constexpr const auto mask = 0x4000000ULL;
		constexpr const auto index = 1ULL;
		constexpr const auto from = 26ULL;
		constexpr const auto name = "execute_requests_enable";

		inline auto is_enabled(const value_type &extended_context_entry) noexcept
		{ return is_bit_set(extended_context_entry.data[index], from); }

		inline auto is_disabled(const value_type &extended_context_entry) noexcept
		{ return !is_bit_set(extended_context_entry.data[index], from); }

		inline void enable(value_type &extended_context_entry) noexcept
		{ extended_context_entry.data[index] = set_bit(extended_context_entry.data[index], from); }

		inline void disable(value_type &extended_context_entry) noexcept
		{ extended_context_entry.data[index] = clear_bit(extended_context_entry.data[index], from); }

		inline void dump(int level, const value_type &extended_context_entry, std::string *msg = nullptr)
		{ bfdebug_subbool(level, name, is_enabled(extended_context_entry), msg); }
	}

	namespace slee
	{
		constexpr const auto mask = 0x8000000ULL;
		constexpr const auto index = 1ULL;
		constexpr const auto from = 27ULL;
		constexpr const auto name = "second_level_execute_enable";

		inline auto is_enabled(const value_type &extended_context_entry) noexcept
		{ return is_bit_set(extended_context_entry.data[index], from); }

		inline auto is_disabled(const value_type &extended_context_entry) noexcept
		{ return !is_bit_set(extended_context_entry.data[index], from); }

		inline void enable(value_type &extended_context_entry) noexcept
		{ extended_context_entry.data[index] = set_bit(extended_context_entry.data[index], from); }

		inline void disable(value_type &extended_context_entry) noexcept
		{ extended_context_entry.data[index] = clear_bit(extended_context_entry.data[index], from); }

		inline void dump(int level, const value_type &extended_context_entry, std::string *msg = nullptr)
		{ bfdebug_subbool(level, name, is_enabled(extended_context_entry), msg); }
	}

	namespace pat
	{
		constexpr const auto mask = 0xFFFFFFFF00000000ULL;
		constexpr const auto index = 1ULL;
		constexpr const auto from = 32ULL;
		constexpr const auto name = "page_attribute_table";

		inline auto get(const value_type &extended_context_entry) noexcept
		{ return get_bits(extended_context_entry.data[index], mask) >> from; }

		inline void set(value_type &extended_context_entry, uint64_t val) noexcept
		{ extended_context_entry.data[index] = set_bits(extended_context_entry.data[index], mask, val << from); }

		inline void dump(int level, const value_type &extended_context_entry, std::string *msg = nullptr)
		{ bfdebug_subnhex(level, name, get(extended_context_entry), msg); }
	}

	namespace pts
	{
		constexpr const auto mask = 0xFULL;
		constexpr const auto index = 2ULL;
		constexpr const auto from = 0ULL;
		constexpr const auto name = "pasid_table_size";

		inline auto get(const value_type &extended_context_entry) noexcept
		{ return get_bits(extended_context_entry.data[index], mask) >> from; }

		inline void set(value_type &extended_context_entry, uint64_t val) noexcept
		{ extended_context_entry.data[index] = set_bits(extended_context_entry.data[index], mask, val << from); }

		inline void dump(int level, const value_type &extended_context_entry, std::string *msg = nullptr)
		{ bfdebug_subnhex(level, name, get(extended_context_entry), msg); }
	}

	namespace pasidptr
	{
		constexpr const auto mask = 0xFFFFFFFFF000ULL;
		constexpr const auto index = 2ULL;
		constexpr const auto from = 12ULL;
		constexpr const auto name = "pasid_table_pointer";

		inline auto get(const value_type &extended_context_entry) noexcept
		{ return get_bits(extended_context_entry.data[index], mask) >> from; }

		inline void set(value_type &extended_context_entry, uint64_t val) noexcept
		{ extended_context_entry.data[index] = set_bits(extended_context_entry.data[index], mask, val << from); }

		inline void dump(int level, const value_type &extended_context_entry, std::string *msg = nullptr)
		{ bfdebug_subnhex(level, name, get(extended_context_entry), msg); }
	}

	namespace pasidstptr
	{
		constexpr const auto mask = 0xFFFFFFFFF000ULL;
		constexpr const auto index = 3ULL;
		constexpr const auto from = 12ULL;
		constexpr const auto name = "pasid_state_table_pointer";

		inline auto get(const value_type &extended_context_entry) noexcept
		{ return get_bits(extended_context_entry.data[index], mask) >> from; }

		inline void set(value_type &extended_context_entry, uint64_t val) noexcept
		{ extended_context_entry.data[index] = set_bits(extended_context_entry.data[index], mask, val << from); }

		inline void dump(int level, const value_type &extended_context_entry, std::string *msg = nullptr)
		{ bfdebug_subnhex(level, name, get(extended_context_entry), msg); }
	}

	inline void dump(int level, const value_type &extended_context_entry, std::string *msg = nullptr)
	{
		bfdebug_nhex(level, "extended_context_entry[63:0]", extended_context_entry.data[0], msg);
		bfdebug_nhex(level, "extended_context_entry[127:64]", extended_context_entry.data[1], msg);
		bfdebug_nhex(level, "extended_context_entry[191:128]", extended_context_entry.data[2], msg);
		bfdebug_nhex(level, "extended_context_entry[255:192]", extended_context_entry.data[3], msg);

		p::dump(level, extended_context_entry, msg);
		fpd::dump(level, extended_context_entry, msg);
		t::dump(level, extended_context_entry, msg);
		emt::dump(level, extended_context_entry, msg);
		dinve::dump(level, extended_context_entry, msg);
		pre::dump(level, extended_context_entry, msg);
		neste::dump(level, extended_context_entry, msg);
		paside::dump(level, extended_context_entry, msg);
		slptptr::dump(level, extended_context_entry, msg);
		aw::dump(level, extended_context_entry, msg);
		pge::dump(level, extended_context_entry, msg);
		nxe::dump(level, extended_context_entry, msg);
		wpe::dump(level, extended_context_entry, msg);
		cd::dump(level, extended_context_entry, msg);
		emte::dump(level, extended_context_entry, msg);
		did::dump(level, extended_context_entry, msg);
		smep::dump(level, extended_context_entry, msg);
		eafe::dump(level, extended_context_entry, msg);
		ere::dump(level, extended_context_entry, msg);
		slee::dump(level, extended_context_entry, msg);
		pat::dump(level, extended_context_entry, msg);
		pts::dump(level, extended_context_entry, msg);
		pasidptr::dump(level, extended_context_entry, msg);
		pasidstptr::dump(level, extended_context_entry, msg);
	}
}

}
}

// *INDENT-ON*

#endif
