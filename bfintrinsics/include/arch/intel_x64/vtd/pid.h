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

#ifndef VTD_POSTED_INTERRUPT_DESCRIPTOR_H
#define VTD_POSTED_INTERRUPT_DESCRIPTOR_H

#include <stdint.h>
#include <bfgsl.h>
#include <bfbitmanip.h>
#include <bfdebug.h>

// *INDENT-OFF*

namespace intel_x64
{
namespace vtd
{

namespace pid
{
	constexpr const auto name = "pid";

	using value_type = struct value_type { uint64_t data[8]{0}; };

	namespace pir
	{
		constexpr const auto mask = 0xFFFFFFFFFFFFFFFFULL;
		constexpr const auto index = 0ULL;
		constexpr const auto from = 0ULL;
		constexpr const auto name = "posted_interrupt_requests";

		inline auto get(const value_type &pid) noexcept
		{ return get_bits(pid.data[index], mask) >> from; }

		inline void set(value_type &pid, uint64_t val) noexcept
		{ pid.data[index] = set_bits(pid.data[index], mask, val << from); }

		inline void dump(int level, const value_type &pid, std::string *msg = nullptr)
		{ bfdebug_subnhex(level, name, get(pid), msg); }
	}

	namespace on
	{
		constexpr const auto mask = 0x1ULL;
		constexpr const auto index = 4ULL;
		constexpr const auto from = 0ULL;
		constexpr const auto name = "outstanding_notification";

		inline auto is_enabled(const value_type &pid) noexcept
		{ return is_bit_set(pid.data[index], from); }

		inline auto is_disabled(const value_type &pid) noexcept
		{ return !is_bit_set(pid.data[index], from); }

		inline void enable(value_type &pid) noexcept
		{ pid.data[index] = set_bit(pid.data[index], from); }

		inline void disable(value_type &pid) noexcept
		{ pid.data[index] = clear_bit(pid.data[index], from); }

		inline void dump(int level, const value_type &pid, std::string *msg = nullptr)
		{ bfdebug_subbool(level, name, is_enabled(pid), msg); }
	}

	namespace sn
	{
		constexpr const auto mask = 0x2ULL;
		constexpr const auto index = 4ULL;
		constexpr const auto from = 1ULL;
		constexpr const auto name = "supress_notification";

		inline auto is_enabled(const value_type &pid) noexcept
		{ return is_bit_set(pid.data[index], from); }

		inline auto is_disabled(const value_type &pid) noexcept
		{ return !is_bit_set(pid.data[index], from); }

		inline void enable(value_type &pid) noexcept
		{ pid.data[index] = set_bit(pid.data[index], from); }

		inline void disable(value_type &pid) noexcept
		{ pid.data[index] = clear_bit(pid.data[index], from); }

		inline void dump(int level, const value_type &pid, std::string *msg = nullptr)
		{ bfdebug_subbool(level, name, is_enabled(pid), msg); }
	}

	namespace nv
	{
		constexpr const auto mask = 0xFF0000ULL;
		constexpr const auto index = 4ULL;
		constexpr const auto from = 16ULL;
		constexpr const auto name = "notification_vector";

		inline auto get(const value_type &pid) noexcept
		{ return get_bits(pid.data[index], mask) >> from; }

		inline void set(value_type &pid, uint64_t val) noexcept
		{ pid.data[index] = set_bits(pid.data[index], mask, val << from); }

		inline void dump(int level, const value_type &pid, std::string *msg = nullptr)
		{ bfdebug_subnhex(level, name, get(pid), msg); }
	}

	namespace ndst
	{
		constexpr const auto mask = 0xFFFFFFFF00000000ULL;
		constexpr const auto index = 4ULL;
		constexpr const auto from = 32ULL;
		constexpr const auto name = "notification_destination";

		inline auto get(const value_type &pid) noexcept
		{ return get_bits(pid.data[index], mask) >> from; }

		inline void set(value_type &pid, uint64_t val) noexcept
		{ pid.data[index] = set_bits(pid.data[index], mask, val << from); }

		inline void dump(int level, const value_type &pid, std::string *msg = nullptr)
		{ bfdebug_subnhex(level, name, get(pid), msg); }
	}

	inline void dump(int level, const value_type &pid, std::string *msg = nullptr)
	{
		bfdebug_nhex(level, "pid[63:0]", pid.data[0], msg);
		bfdebug_nhex(level, "pid[127:64]", pid.data[1], msg);
		bfdebug_nhex(level, "pid[191:128]", pid.data[2], msg);
		bfdebug_nhex(level, "pid[255:192]", pid.data[3], msg);
		bfdebug_nhex(level, "pid[319:256]", pid.data[4], msg);
		bfdebug_nhex(level, "pid[383:320]", pid.data[5], msg);
		bfdebug_nhex(level, "pid[447:384]", pid.data[6], msg);
		bfdebug_nhex(level, "pid[511:448]", pid.data[7], msg);

		pir::dump(level, pid, msg);
		on::dump(level, pid, msg);
		sn::dump(level, pid, msg);
		nv::dump(level, pid, msg);
		ndst::dump(level, pid, msg);
	}
}

}
}

// *INDENT-ON*

#endif
