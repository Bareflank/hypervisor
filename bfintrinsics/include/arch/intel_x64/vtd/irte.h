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

#ifndef VTD_IRTE_H
#define VTD_IRTE_H

#include <stdint.h>
#include <bfgsl.h>
#include <bfbitmanip.h>
#include <bfdebug.h>

// *INDENT-OFF*

namespace intel_x64
{
namespace vtd
{

namespace irte
{
	constexpr const auto name = "irte";

	using value_type = struct value_type { uint64_t data[2]{0}; };

	namespace p
	{
		constexpr const auto mask = 0x1ULL;
		constexpr const auto index = 0ULL;
		constexpr const auto from = 0ULL;
		constexpr const auto name = "present";

		inline auto is_enabled(const value_type &irte) noexcept
		{ return is_bit_set(irte.data[index], from); }

		inline auto is_disabled(const value_type &irte) noexcept
		{ return !is_bit_set(irte.data[index], from); }

		inline void enable(value_type &irte) noexcept
		{ irte.data[index] = set_bit(irte.data[index], from); }

		inline void disable(value_type &irte) noexcept
		{ irte.data[index] = clear_bit(irte.data[index], from); }

		inline void dump(int level, const value_type &irte, std::string *msg = nullptr)
		{ bfdebug_subbool(level, name, is_enabled(irte), msg); }
	}

	namespace fpd
	{
		constexpr const auto mask = 0x2ULL;
		constexpr const auto index = 0ULL;
		constexpr const auto from = 1ULL;
		constexpr const auto name = "fault_processing_disable";

		inline auto is_enabled(const value_type &irte) noexcept
		{ return is_bit_set(irte.data[index], from); }

		inline auto is_disabled(const value_type &irte) noexcept
		{ return !is_bit_set(irte.data[index], from); }

		inline void enable(value_type &irte) noexcept
		{ irte.data[index] = set_bit(irte.data[index], from); }

		inline void disable(value_type &irte) noexcept
		{ irte.data[index] = clear_bit(irte.data[index], from); }

		inline void dump(int level, const value_type &irte, std::string *msg = nullptr)
		{ bfdebug_subbool(level, name, is_enabled(irte), msg); }
	}

	namespace dm
	{
		constexpr const auto mask = 0x4ULL;
		constexpr const auto index = 0ULL;
		constexpr const auto from = 2ULL;
		constexpr const auto name = "destination_mode";

		inline auto is_enabled(const value_type &irte) noexcept
		{ return is_bit_set(irte.data[index], from); }

		inline auto is_disabled(const value_type &irte) noexcept
		{ return !is_bit_set(irte.data[index], from); }

		inline void enable(value_type &irte) noexcept
		{ irte.data[index] = set_bit(irte.data[index], from); }

		inline void disable(value_type &irte) noexcept
		{ irte.data[index] = clear_bit(irte.data[index], from); }

		inline void dump(int level, const value_type &irte, std::string *msg = nullptr)
		{ bfdebug_subbool(level, name, is_enabled(irte), msg); }
	}

	namespace rh
	{
		constexpr const auto mask = 0x8ULL;
		constexpr const auto index = 0ULL;
		constexpr const auto from = 3ULL;
		constexpr const auto name = "redirection_hint";

		inline auto is_enabled(const value_type &irte) noexcept
		{ return is_bit_set(irte.data[index], from); }

		inline auto is_disabled(const value_type &irte) noexcept
		{ return !is_bit_set(irte.data[index], from); }

		inline void enable(value_type &irte) noexcept
		{ irte.data[index] = set_bit(irte.data[index], from); }

		inline void disable(value_type &irte) noexcept
		{ irte.data[index] = clear_bit(irte.data[index], from); }

		inline void dump(int level, const value_type &irte, std::string *msg = nullptr)
		{ bfdebug_subbool(level, name, is_enabled(irte), msg); }
	}

	namespace tm
	{
		constexpr const auto mask = 0x10ULL;
		constexpr const auto index = 0ULL;
		constexpr const auto from = 4ULL;
		constexpr const auto name = "trigger_mode";

		inline auto is_enabled(const value_type &irte) noexcept
		{ return is_bit_set(irte.data[index], from); }

		inline auto is_disabled(const value_type &irte) noexcept
		{ return !is_bit_set(irte.data[index], from); }

		inline void enable(value_type &irte) noexcept
		{ irte.data[index] = set_bit(irte.data[index], from); }

		inline void disable(value_type &irte) noexcept
		{ irte.data[index] = clear_bit(irte.data[index], from); }

		inline void dump(int level, const value_type &irte, std::string *msg = nullptr)
		{ bfdebug_subbool(level, name, is_enabled(irte), msg); }
	}

	namespace dlm
	{
		constexpr const auto mask = 0xE0ULL;
		constexpr const auto index = 0ULL;
		constexpr const auto from = 5ULL;
		constexpr const auto name = "delivery_mode";

		inline auto get(const value_type &irte) noexcept
		{ return get_bits(irte.data[index], mask) >> from; }

		inline void set(value_type &irte, uint64_t val) noexcept
		{ irte.data[index] = set_bits(irte.data[index], mask, val << from); }

		inline void dump(int level, const value_type &irte, std::string *msg = nullptr)
		{ bfdebug_subnhex(level, name, get(irte), msg); }
	}

	namespace avail
	{
		constexpr const auto mask = 0xF00ULL;
		constexpr const auto index = 0ULL;
		constexpr const auto from = 8ULL;
		constexpr const auto name = "available";

		inline auto get(const value_type &irte) noexcept
		{ return get_bits(irte.data[index], mask) >> from; }

		inline void set(value_type &irte, uint64_t val) noexcept
		{ irte.data[index] = set_bits(irte.data[index], mask, val << from); }

		inline void dump(int level, const value_type &irte, std::string *msg = nullptr)
		{ bfdebug_subnhex(level, name, get(irte), msg); }
	}

	namespace urg
	{
		constexpr const auto mask = 0x4000ULL;
		constexpr const auto index = 0ULL;
		constexpr const auto from = 14ULL;
		constexpr const auto name = "urgent";

		inline auto is_enabled(const value_type &irte) noexcept
		{ return is_bit_set(irte.data[index], from); }

		inline auto is_disabled(const value_type &irte) noexcept
		{ return !is_bit_set(irte.data[index], from); }

		inline void enable(value_type &irte) noexcept
		{ irte.data[index] = set_bit(irte.data[index], from); }

		inline void disable(value_type &irte) noexcept
		{ irte.data[index] = clear_bit(irte.data[index], from); }

		inline void dump(int level, const value_type &irte, std::string *msg = nullptr)
		{ bfdebug_subbool(level, name, is_enabled(irte), msg); }
	}

	namespace im
	{
		constexpr const auto mask = 0x8000ULL;
		constexpr const auto index = 0ULL;
		constexpr const auto from = 15ULL;
		constexpr const auto name = "irte_mode";

		inline auto is_enabled(const value_type &irte) noexcept
		{ return is_bit_set(irte.data[index], from); }

		inline auto is_disabled(const value_type &irte) noexcept
		{ return !is_bit_set(irte.data[index], from); }

		inline void enable(value_type &irte) noexcept
		{ irte.data[index] = set_bit(irte.data[index], from); }

		inline void disable(value_type &irte) noexcept
		{ irte.data[index] = clear_bit(irte.data[index], from); }

		inline void dump(int level, const value_type &irte, std::string *msg = nullptr)
		{ bfdebug_subbool(level, name, is_enabled(irte), msg); }
	}

	namespace v
	{
		constexpr const auto mask = 0xFF0000ULL;
		constexpr const auto index = 0ULL;
		constexpr const auto from = 16ULL;
		constexpr const auto name = "vector";

		inline auto get(const value_type &irte) noexcept
		{ return get_bits(irte.data[index], mask) >> from; }

		inline void set(value_type &irte, uint64_t val) noexcept
		{ irte.data[index] = set_bits(irte.data[index], mask, val << from); }

		inline void dump(int level, const value_type &irte, std::string *msg = nullptr)
		{ bfdebug_subnhex(level, name, get(irte), msg); }
	}

	namespace vv
	{
		constexpr const auto mask = 0xFF0000ULL;
		constexpr const auto index = 0ULL;
		constexpr const auto from = 16ULL;
		constexpr const auto name = "virtual_vector";

		inline auto get(const value_type &irte) noexcept
		{ return get_bits(irte.data[index], mask) >> from; }

		inline void set(value_type &irte, uint64_t val) noexcept
		{ irte.data[index] = set_bits(irte.data[index], mask, val << from); }

		inline void dump(int level, const value_type &irte, std::string *msg = nullptr)
		{ bfdebug_subnhex(level, name, get(irte), msg); }
	}

	namespace dst
	{
		constexpr const auto mask = 0xFFFFFFFF00000000ULL;
		constexpr const auto index = 0ULL;
		constexpr const auto from = 32ULL;
		constexpr const auto name = "destination_id";

		inline auto get(const value_type &irte) noexcept
		{ return get_bits(irte.data[index], mask) >> from; }

		inline void set(value_type &irte, uint64_t val) noexcept
		{ irte.data[index] = set_bits(irte.data[index], mask, val << from); }

		inline void dump(int level, const value_type &irte, std::string *msg = nullptr)
		{ bfdebug_subnhex(level, name, get(irte), msg); }
	}

	namespace pdal
	{
		constexpr const auto mask = 0xFFFFFFC000000000ULL;
		constexpr const auto index = 0ULL;
		constexpr const auto from = 38ULL;
		constexpr const auto name = "posted_descriptor_address_low";

		inline auto get(const value_type &irte) noexcept
		{ return get_bits(irte.data[index], mask) >> from; }

		inline void set(value_type &irte, uint64_t val) noexcept
		{ irte.data[index] = set_bits(irte.data[index], mask, val << from); }

		inline void dump(int level, const value_type &irte, std::string *msg = nullptr)
		{ bfdebug_subnhex(level, name, get(irte), msg); }
	}

	namespace sid
	{
		constexpr const auto mask = 0xFFFFULL;
		constexpr const auto index = 1ULL;
		constexpr const auto from = 0ULL;
		constexpr const auto name = "source_identifier";

		inline auto get(const value_type &irte) noexcept
		{ return get_bits(irte.data[index], mask) >> from; }

		inline void set(value_type &irte, uint64_t val) noexcept
		{ irte.data[index] = set_bits(irte.data[index], mask, val << from); }

		inline void dump(int level, const value_type &irte, std::string *msg = nullptr)
		{ bfdebug_subnhex(level, name, get(irte), msg); }
	}

	namespace sq
	{
		constexpr const auto mask = 0x30000ULL;
		constexpr const auto index = 1ULL;
		constexpr const auto from = 16ULL;
		constexpr const auto name = "source_id_qualifier";

		inline auto get(const value_type &irte) noexcept
		{ return get_bits(irte.data[index], mask) >> from; }

		inline void set(value_type &irte, uint64_t val) noexcept
		{ irte.data[index] = set_bits(irte.data[index], mask, val << from); }

		inline void dump(int level, const value_type &irte, std::string *msg = nullptr)
		{ bfdebug_subnhex(level, name, get(irte), msg); }
	}

	namespace svt
	{
		constexpr const auto mask = 0xC0000ULL;
		constexpr const auto index = 1ULL;
		constexpr const auto from = 18ULL;
		constexpr const auto name = "source_validation_type";

		inline auto get(const value_type &irte) noexcept
		{ return get_bits(irte.data[index], mask) >> from; }

		inline void set(value_type &irte, uint64_t val) noexcept
		{ irte.data[index] = set_bits(irte.data[index], mask, val << from); }

		inline void dump(int level, const value_type &irte, std::string *msg = nullptr)
		{ bfdebug_subnhex(level, name, get(irte), msg); }
	}

	namespace pdah
	{
		constexpr const auto mask = 0xFFFFFFFF00000000ULL;
		constexpr const auto index = 1ULL;
		constexpr const auto from = 32ULL;
		constexpr const auto name = "posted_descriptor_address_high";

		inline auto get(const value_type &irte) noexcept
		{ return get_bits(irte.data[index], mask) >> from; }

		inline void set(value_type &irte, uint64_t val) noexcept
		{ irte.data[index] = set_bits(irte.data[index], mask, val << from); }

		inline void dump(int level, const value_type &irte, std::string *msg = nullptr)
		{ bfdebug_subnhex(level, name, get(irte), msg); }
	}

	inline void dump(int level, const value_type &irte, std::string *msg = nullptr)
	{
		bfdebug_nhex(level, "irte[63:0]", irte.data[0], msg);
		bfdebug_nhex(level, "irte[127:64]", irte.data[1], msg);

		p::dump(level, irte, msg);
		fpd::dump(level, irte, msg);
		dm::dump(level, irte, msg);
		rh::dump(level, irte, msg);
		tm::dump(level, irte, msg);
		dlm::dump(level, irte, msg);
		avail::dump(level, irte, msg);
		urg::dump(level, irte, msg);
		im::dump(level, irte, msg);
		v::dump(level, irte, msg);
		vv::dump(level, irte, msg);
		dst::dump(level, irte, msg);
		pdal::dump(level, irte, msg);
		sid::dump(level, irte, msg);
		sq::dump(level, irte, msg);
		svt::dump(level, irte, msg);
		pdah::dump(level, irte, msg);
	}
}

}
}

// *INDENT-ON*

#endif
