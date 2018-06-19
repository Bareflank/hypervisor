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

#ifndef VTD_FAULT_RECORD_H
#define VTD_FAULT_RECORD_H

#include <stdint.h>
#include <bfgsl.h>
#include <bfbitmanip.h>
#include <bfdebug.h>

// *INDENT-OFF*

namespace intel_x64
{
namespace vtd
{

namespace fault_record
{
	constexpr const auto name = "fault_record";

	using value_type = struct value_type { uint64_t data[2]{0}; };

	namespace fi
	{
		constexpr const auto mask = 0xFFFFFFFFFFFFF000ULL;
		constexpr const auto index = 0ULL;
		constexpr const auto from = 12ULL;
		constexpr const auto name = "fault_information";

		inline auto get(const value_type &fault_record) noexcept
		{ return get_bits(fault_record.data[index], mask) >> from; }

		inline void set(value_type &fault_record, uint64_t val) noexcept
		{ fault_record.data[index] = set_bits(fault_record.data[index], mask, val << from); }

		inline void dump(int level, const value_type &fault_record, std::string *msg = nullptr)
		{ bfdebug_subnhex(level, name, get(fault_record), msg); }
	}

	namespace sid
	{
		constexpr const auto mask = 0xFFFFULL;
		constexpr const auto index = 1ULL;
		constexpr const auto from = 0ULL;
		constexpr const auto name = "source_identifier";

		inline auto get(const value_type &fault_record) noexcept
		{ return get_bits(fault_record.data[index], mask) >> from; }

		inline void set(value_type &fault_record, uint64_t val) noexcept
		{ fault_record.data[index] = set_bits(fault_record.data[index], mask, val << from); }

		inline void dump(int level, const value_type &fault_record, std::string *msg = nullptr)
		{ bfdebug_subnhex(level, name, get(fault_record), msg); }
	}

	namespace priv
	{
		constexpr const auto mask = 0x20000000ULL;
		constexpr const auto index = 1ULL;
		constexpr const auto from = 29ULL;
		constexpr const auto name = "priviledge_mode_requested";

		inline auto is_enabled(const value_type &fault_record) noexcept
		{ return is_bit_set(fault_record.data[index], from); }

		inline auto is_disabled(const value_type &fault_record) noexcept
		{ return !is_bit_set(fault_record.data[index], from); }

		inline void enable(value_type &fault_record) noexcept
		{ fault_record.data[index] = set_bit(fault_record.data[index], from); }

		inline void disable(value_type &fault_record) noexcept
		{ fault_record.data[index] = clear_bit(fault_record.data[index], from); }

		inline void dump(int level, const value_type &fault_record, std::string *msg = nullptr)
		{ bfdebug_subbool(level, name, is_enabled(fault_record), msg); }
	}

	namespace exe
	{
		constexpr const auto mask = 0x40000000ULL;
		constexpr const auto index = 1ULL;
		constexpr const auto from = 30ULL;
		constexpr const auto name = "execute_permission_requested";

		inline auto is_enabled(const value_type &fault_record) noexcept
		{ return is_bit_set(fault_record.data[index], from); }

		inline auto is_disabled(const value_type &fault_record) noexcept
		{ return !is_bit_set(fault_record.data[index], from); }

		inline void enable(value_type &fault_record) noexcept
		{ fault_record.data[index] = set_bit(fault_record.data[index], from); }

		inline void disable(value_type &fault_record) noexcept
		{ fault_record.data[index] = clear_bit(fault_record.data[index], from); }

		inline void dump(int level, const value_type &fault_record, std::string *msg = nullptr)
		{ bfdebug_subbool(level, name, is_enabled(fault_record), msg); }
	}

	namespace pp
	{
		constexpr const auto mask = 0x80000000ULL;
		constexpr const auto index = 1ULL;
		constexpr const auto from = 31ULL;
		constexpr const auto name = "pasid_present";

		inline auto is_enabled(const value_type &fault_record) noexcept
		{ return is_bit_set(fault_record.data[index], from); }

		inline auto is_disabled(const value_type &fault_record) noexcept
		{ return !is_bit_set(fault_record.data[index], from); }

		inline void enable(value_type &fault_record) noexcept
		{ fault_record.data[index] = set_bit(fault_record.data[index], from); }

		inline void disable(value_type &fault_record) noexcept
		{ fault_record.data[index] = clear_bit(fault_record.data[index], from); }

		inline void dump(int level, const value_type &fault_record, std::string *msg = nullptr)
		{ bfdebug_subbool(level, name, is_enabled(fault_record), msg); }
	}

	namespace fr
	{
		constexpr const auto mask = 0xFF00000000ULL;
		constexpr const auto index = 1ULL;
		constexpr const auto from = 32ULL;
		constexpr const auto name = "fault_reason";

		inline auto get(const value_type &fault_record) noexcept
		{ return get_bits(fault_record.data[index], mask) >> from; }

		inline void set(value_type &fault_record, uint64_t val) noexcept
		{ fault_record.data[index] = set_bits(fault_record.data[index], mask, val << from); }

		inline void dump(int level, const value_type &fault_record, std::string *msg = nullptr)
		{ bfdebug_subnhex(level, name, get(fault_record), msg); }
	}

	namespace pv
	{
		constexpr const auto mask = 0xFFFFF0000000000ULL;
		constexpr const auto index = 1ULL;
		constexpr const auto from = 40ULL;
		constexpr const auto name = "pasid_value";

		inline auto get(const value_type &fault_record) noexcept
		{ return get_bits(fault_record.data[index], mask) >> from; }

		inline void set(value_type &fault_record, uint64_t val) noexcept
		{ fault_record.data[index] = set_bits(fault_record.data[index], mask, val << from); }

		inline void dump(int level, const value_type &fault_record, std::string *msg = nullptr)
		{ bfdebug_subnhex(level, name, get(fault_record), msg); }
	}

	namespace at
	{
		constexpr const auto mask = 0x3000000000000000ULL;
		constexpr const auto index = 1ULL;
		constexpr const auto from = 60ULL;
		constexpr const auto name = "address_type";

		inline auto get(const value_type &fault_record) noexcept
		{ return get_bits(fault_record.data[index], mask) >> from; }

		inline void set(value_type &fault_record, uint64_t val) noexcept
		{ fault_record.data[index] = set_bits(fault_record.data[index], mask, val << from); }

		inline void dump(int level, const value_type &fault_record, std::string *msg = nullptr)
		{ bfdebug_subnhex(level, name, get(fault_record), msg); }
	}

	namespace t
	{
		constexpr const auto mask = 0x4000000000000000ULL;
		constexpr const auto index = 1ULL;
		constexpr const auto from = 62ULL;
		constexpr const auto name = "type";

		inline auto is_enabled(const value_type &fault_record) noexcept
		{ return is_bit_set(fault_record.data[index], from); }

		inline auto is_disabled(const value_type &fault_record) noexcept
		{ return !is_bit_set(fault_record.data[index], from); }

		inline void enable(value_type &fault_record) noexcept
		{ fault_record.data[index] = set_bit(fault_record.data[index], from); }

		inline void disable(value_type &fault_record) noexcept
		{ fault_record.data[index] = clear_bit(fault_record.data[index], from); }

		inline void dump(int level, const value_type &fault_record, std::string *msg = nullptr)
		{ bfdebug_subbool(level, name, is_enabled(fault_record), msg); }
	}

	inline void dump(int level, const value_type &fault_record, std::string *msg = nullptr)
	{
		bfdebug_nhex(level, "fault_record[63:0]", fault_record.data[0], msg);
		bfdebug_nhex(level, "fault_record[127:64]", fault_record.data[1], msg);

		fi::dump(level, fault_record, msg);
		sid::dump(level, fault_record, msg);
		priv::dump(level, fault_record, msg);
		exe::dump(level, fault_record, msg);
		pp::dump(level, fault_record, msg);
		fr::dump(level, fault_record, msg);
		pv::dump(level, fault_record, msg);
		at::dump(level, fault_record, msg);
		t::dump(level, fault_record, msg);
	}
}

}
}

// *INDENT-ON*

#endif
