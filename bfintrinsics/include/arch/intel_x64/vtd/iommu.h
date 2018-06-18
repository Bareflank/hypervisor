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

#ifndef IOMMU_INTEL_X64_H
#define IOMMU_INTEL_X64_H

#include <stdint.h>
#include <bfgsl.h>
#include <bfbitmanip.h>
#include <bfdebug.h>
#include "../../../../../bfvmm/include/hve/arch/intel_x64/vtd/phys_iommu.h"

// *INDENT-OFF*

namespace intel_x64
{
namespace vtd
{

namespace iommu
{

namespace ver_reg
{
	constexpr const auto name = "version_register";
	constexpr const auto offset = 0x000;

	using value_type = uint32_t;

	inline auto get(const gsl::not_null<phys_iommu *> iommu) noexcept
	{ return iommu->read_32(offset); }

	namespace min
	{
		constexpr const auto mask = 0xFULL;
		constexpr const auto from = 0ULL;
		constexpr const auto name = "minor_version_number";

		inline auto get(const gsl::not_null<phys_iommu *> iommu) noexcept
		{ return get_bits(iommu->read_32(offset), mask) >> from; }

		inline auto get(const value_type &ver_reg) noexcept
		{ return get_bits(ver_reg, mask) >> from; }

		inline void dump(int level, const value_type &ver_reg, std::string *msg = nullptr)
		{ bfdebug_subnhex(level, name, get(ver_reg), msg); }
	}

	namespace max
	{
		constexpr const auto mask = 0xF0ULL;
		constexpr const auto from = 4ULL;
		constexpr const auto name = "major_version_number";

		inline auto get(const gsl::not_null<phys_iommu *> iommu) noexcept
		{ return get_bits(iommu->read_32(offset), mask) >> from; }

		inline auto get(const value_type &ver_reg) noexcept
		{ return get_bits(ver_reg, mask) >> from; }

		inline void dump(int level, const value_type &ver_reg, std::string *msg = nullptr)
		{ bfdebug_subnhex(level, name, get(ver_reg), msg); }
	}

	inline void dump(int level, const value_type &ver_reg, std::string *msg = nullptr)
	{
		bfdebug_nhex(level, name, ver_reg, msg);

		min::dump(level, ver_reg, msg);
		max::dump(level, ver_reg, msg);
	}

	inline void dump(int level, const gsl::not_null<phys_iommu *> iommu, std::string *msg = nullptr)
	{
		auto reg_val = get(iommu);
		dump(level, reg_val, msg);
	}
}

namespace cap_reg
{
	constexpr const auto name = "capability_register";
	constexpr const auto offset = 0x008;

	using value_type = uint64_t;

	inline auto get(const gsl::not_null<phys_iommu *> iommu) noexcept
	{ return iommu->read_64(offset); }

	namespace nd
	{
		constexpr const auto mask = 0x7ULL;
		constexpr const auto from = 0ULL;
		constexpr const auto name = "number_of_domains_supported";

		inline auto get(const gsl::not_null<phys_iommu *> iommu) noexcept
		{ return get_bits(iommu->read_64(offset), mask) >> from; }

		inline auto get(const value_type &cap_reg) noexcept
		{ return get_bits(cap_reg, mask) >> from; }

		inline void dump(int level, const value_type &cap_reg, std::string *msg = nullptr)
		{ bfdebug_subnhex(level, name, get(cap_reg), msg); }
	}

	namespace afl
	{
		constexpr const auto mask = 0x8ULL;
		constexpr const auto from = 3ULL;
		constexpr const auto name = "advanced_fault_logging";

		inline auto is_enabled(const gsl::not_null<phys_iommu *> iommu) noexcept
		{ return is_bit_set(get(iommu), from); }

		inline auto is_enabled(const value_type &cap_reg) noexcept
		{ return is_bit_set(cap_reg, from); }

		inline auto is_disabled(const gsl::not_null<phys_iommu *> iommu) noexcept
		{ return !is_bit_set(get(iommu), from); }

		inline auto is_disabled(const value_type &cap_reg) noexcept
		{ return !is_bit_set(cap_reg, from); }

		inline void dump(int level, const value_type &cap_reg, std::string *msg = nullptr)
		{ bfdebug_subbool(level, name, is_enabled(cap_reg), msg); }
	}

	namespace rwbf
	{
		constexpr const auto mask = 0x10ULL;
		constexpr const auto from = 4ULL;
		constexpr const auto name = "required_write_buffer_flushing";

		inline auto is_enabled(const gsl::not_null<phys_iommu *> iommu) noexcept
		{ return is_bit_set(get(iommu), from); }

		inline auto is_enabled(const value_type &cap_reg) noexcept
		{ return is_bit_set(cap_reg, from); }

		inline auto is_disabled(const gsl::not_null<phys_iommu *> iommu) noexcept
		{ return !is_bit_set(get(iommu), from); }

		inline auto is_disabled(const value_type &cap_reg) noexcept
		{ return !is_bit_set(cap_reg, from); }

		inline void dump(int level, const value_type &cap_reg, std::string *msg = nullptr)
		{ bfdebug_subbool(level, name, is_enabled(cap_reg), msg); }
	}

	namespace plmr
	{
		constexpr const auto mask = 0x20ULL;
		constexpr const auto from = 5ULL;
		constexpr const auto name = "protected_low_memory_region";

		inline auto is_enabled(const gsl::not_null<phys_iommu *> iommu) noexcept
		{ return is_bit_set(get(iommu), from); }

		inline auto is_enabled(const value_type &cap_reg) noexcept
		{ return is_bit_set(cap_reg, from); }

		inline auto is_disabled(const gsl::not_null<phys_iommu *> iommu) noexcept
		{ return !is_bit_set(get(iommu), from); }

		inline auto is_disabled(const value_type &cap_reg) noexcept
		{ return !is_bit_set(cap_reg, from); }

		inline void dump(int level, const value_type &cap_reg, std::string *msg = nullptr)
		{ bfdebug_subbool(level, name, is_enabled(cap_reg), msg); }
	}

	namespace phmr
	{
		constexpr const auto mask = 0x40ULL;
		constexpr const auto from = 6ULL;
		constexpr const auto name = "protected_high_memory_region";

		inline auto is_enabled(const gsl::not_null<phys_iommu *> iommu) noexcept
		{ return is_bit_set(get(iommu), from); }

		inline auto is_enabled(const value_type &cap_reg) noexcept
		{ return is_bit_set(cap_reg, from); }

		inline auto is_disabled(const gsl::not_null<phys_iommu *> iommu) noexcept
		{ return !is_bit_set(get(iommu), from); }

		inline auto is_disabled(const value_type &cap_reg) noexcept
		{ return !is_bit_set(cap_reg, from); }

		inline void dump(int level, const value_type &cap_reg, std::string *msg = nullptr)
		{ bfdebug_subbool(level, name, is_enabled(cap_reg), msg); }
	}

	namespace cm
	{
		constexpr const auto mask = 0x80ULL;
		constexpr const auto from = 7ULL;
		constexpr const auto name = "caching_mode";

		inline auto is_enabled(const gsl::not_null<phys_iommu *> iommu) noexcept
		{ return is_bit_set(get(iommu), from); }

		inline auto is_enabled(const value_type &cap_reg) noexcept
		{ return is_bit_set(cap_reg, from); }

		inline auto is_disabled(const gsl::not_null<phys_iommu *> iommu) noexcept
		{ return !is_bit_set(get(iommu), from); }

		inline auto is_disabled(const value_type &cap_reg) noexcept
		{ return !is_bit_set(cap_reg, from); }

		inline void dump(int level, const value_type &cap_reg, std::string *msg = nullptr)
		{ bfdebug_subbool(level, name, is_enabled(cap_reg), msg); }
	}

	namespace sagaw
	{
		constexpr const auto mask = 0x1F00ULL;
		constexpr const auto from = 8ULL;
		constexpr const auto name = "supported_adjusted_guest_address_widths";

		inline auto get(const gsl::not_null<phys_iommu *> iommu) noexcept
		{ return get_bits(iommu->read_64(offset), mask) >> from; }

		inline auto get(const value_type &cap_reg) noexcept
		{ return get_bits(cap_reg, mask) >> from; }

		inline void dump(int level, const value_type &cap_reg, std::string *msg = nullptr)
		{ bfdebug_subnhex(level, name, get(cap_reg), msg); }
	}

	namespace mgaw
	{
		constexpr const auto mask = 0x3F0000ULL;
		constexpr const auto from = 16ULL;
		constexpr const auto name = "maximum_guest_address_width";

		inline auto get(const gsl::not_null<phys_iommu *> iommu) noexcept
		{ return get_bits(iommu->read_64(offset), mask) >> from; }

		inline auto get(const value_type &cap_reg) noexcept
		{ return get_bits(cap_reg, mask) >> from; }

		inline void dump(int level, const value_type &cap_reg, std::string *msg = nullptr)
		{ bfdebug_subnhex(level, name, get(cap_reg), msg); }
	}

	namespace zlr
	{
		constexpr const auto mask = 0x400000ULL;
		constexpr const auto from = 22ULL;
		constexpr const auto name = "zero_length_read";

		inline auto is_enabled(const gsl::not_null<phys_iommu *> iommu) noexcept
		{ return is_bit_set(get(iommu), from); }

		inline auto is_enabled(const value_type &cap_reg) noexcept
		{ return is_bit_set(cap_reg, from); }

		inline auto is_disabled(const gsl::not_null<phys_iommu *> iommu) noexcept
		{ return !is_bit_set(get(iommu), from); }

		inline auto is_disabled(const value_type &cap_reg) noexcept
		{ return !is_bit_set(cap_reg, from); }

		inline void dump(int level, const value_type &cap_reg, std::string *msg = nullptr)
		{ bfdebug_subbool(level, name, is_enabled(cap_reg), msg); }
	}

	namespace fro
	{
		constexpr const auto mask = 0x3FF000000ULL;
		constexpr const auto from = 24ULL;
		constexpr const auto name = "fault_recording_register_offset";

		inline auto get(const gsl::not_null<phys_iommu *> iommu) noexcept
		{ return get_bits(iommu->read_64(offset), mask) >> from; }

		inline auto get(const value_type &cap_reg) noexcept
		{ return get_bits(cap_reg, mask) >> from; }

		inline void dump(int level, const value_type &cap_reg, std::string *msg = nullptr)
		{ bfdebug_subnhex(level, name, get(cap_reg), msg); }
	}

	namespace sllps
	{
		constexpr const auto mask = 0x3C00000000ULL;
		constexpr const auto from = 34ULL;
		constexpr const auto name = "second_level_large_page_support";

		inline auto get(const gsl::not_null<phys_iommu *> iommu) noexcept
		{ return get_bits(iommu->read_64(offset), mask) >> from; }

		inline auto get(const value_type &cap_reg) noexcept
		{ return get_bits(cap_reg, mask) >> from; }

		inline void dump(int level, const value_type &cap_reg, std::string *msg = nullptr)
		{ bfdebug_subnhex(level, name, get(cap_reg), msg); }
	}

	namespace psi
	{
		constexpr const auto mask = 0x8000000000ULL;
		constexpr const auto from = 39ULL;
		constexpr const auto name = "page_selective_invalidation";

		inline auto is_enabled(const gsl::not_null<phys_iommu *> iommu) noexcept
		{ return is_bit_set(get(iommu), from); }

		inline auto is_enabled(const value_type &cap_reg) noexcept
		{ return is_bit_set(cap_reg, from); }

		inline auto is_disabled(const gsl::not_null<phys_iommu *> iommu) noexcept
		{ return !is_bit_set(get(iommu), from); }

		inline auto is_disabled(const value_type &cap_reg) noexcept
		{ return !is_bit_set(cap_reg, from); }

		inline void dump(int level, const value_type &cap_reg, std::string *msg = nullptr)
		{ bfdebug_subbool(level, name, is_enabled(cap_reg), msg); }
	}

	namespace nfr
	{
		constexpr const auto mask = 0xFF0000000000ULL;
		constexpr const auto from = 40ULL;
		constexpr const auto name = "number_of_fault_recording_registers";

		inline auto get(const gsl::not_null<phys_iommu *> iommu) noexcept
		{ return get_bits(iommu->read_64(offset), mask) >> from; }

		inline auto get(const value_type &cap_reg) noexcept
		{ return get_bits(cap_reg, mask) >> from; }

		inline void dump(int level, const value_type &cap_reg, std::string *msg = nullptr)
		{ bfdebug_subnhex(level, name, get(cap_reg), msg); }
	}

	namespace mamv
	{
		constexpr const auto mask = 0x3F000000000000ULL;
		constexpr const auto from = 48ULL;
		constexpr const auto name = "maximum_address_value_mask";

		inline auto get(const gsl::not_null<phys_iommu *> iommu) noexcept
		{ return get_bits(iommu->read_64(offset), mask) >> from; }

		inline auto get(const value_type &cap_reg) noexcept
		{ return get_bits(cap_reg, mask) >> from; }

		inline void dump(int level, const value_type &cap_reg, std::string *msg = nullptr)
		{ bfdebug_subnhex(level, name, get(cap_reg), msg); }
	}

	namespace dwd
	{
		constexpr const auto mask = 0x40000000000000ULL;
		constexpr const auto from = 54ULL;
		constexpr const auto name = "write_draining";

		inline auto is_enabled(const gsl::not_null<phys_iommu *> iommu) noexcept
		{ return is_bit_set(get(iommu), from); }

		inline auto is_enabled(const value_type &cap_reg) noexcept
		{ return is_bit_set(cap_reg, from); }

		inline auto is_disabled(const gsl::not_null<phys_iommu *> iommu) noexcept
		{ return !is_bit_set(get(iommu), from); }

		inline auto is_disabled(const value_type &cap_reg) noexcept
		{ return !is_bit_set(cap_reg, from); }

		inline void dump(int level, const value_type &cap_reg, std::string *msg = nullptr)
		{ bfdebug_subbool(level, name, is_enabled(cap_reg), msg); }
	}

	namespace drd
	{
		constexpr const auto mask = 0x80000000000000ULL;
		constexpr const auto from = 55ULL;
		constexpr const auto name = "read_draining";

		inline auto is_enabled(const gsl::not_null<phys_iommu *> iommu) noexcept
		{ return is_bit_set(get(iommu), from); }

		inline auto is_enabled(const value_type &cap_reg) noexcept
		{ return is_bit_set(cap_reg, from); }

		inline auto is_disabled(const gsl::not_null<phys_iommu *> iommu) noexcept
		{ return !is_bit_set(get(iommu), from); }

		inline auto is_disabled(const value_type &cap_reg) noexcept
		{ return !is_bit_set(cap_reg, from); }

		inline void dump(int level, const value_type &cap_reg, std::string *msg = nullptr)
		{ bfdebug_subbool(level, name, is_enabled(cap_reg), msg); }
	}

	namespace fl1gp
	{
		constexpr const auto mask = 0x100000000000000ULL;
		constexpr const auto from = 56ULL;
		constexpr const auto name = "first_level_1_gbyte_page_support";

		inline auto is_enabled(const gsl::not_null<phys_iommu *> iommu) noexcept
		{ return is_bit_set(get(iommu), from); }

		inline auto is_enabled(const value_type &cap_reg) noexcept
		{ return is_bit_set(cap_reg, from); }

		inline auto is_disabled(const gsl::not_null<phys_iommu *> iommu) noexcept
		{ return !is_bit_set(get(iommu), from); }

		inline auto is_disabled(const value_type &cap_reg) noexcept
		{ return !is_bit_set(cap_reg, from); }

		inline void dump(int level, const value_type &cap_reg, std::string *msg = nullptr)
		{ bfdebug_subbool(level, name, is_enabled(cap_reg), msg); }
	}

	namespace pi
	{
		constexpr const auto mask = 0x800000000000000ULL;
		constexpr const auto from = 59ULL;
		constexpr const auto name = "posted_interrupts_support";

		inline auto is_enabled(const gsl::not_null<phys_iommu *> iommu) noexcept
		{ return is_bit_set(get(iommu), from); }

		inline auto is_enabled(const value_type &cap_reg) noexcept
		{ return is_bit_set(cap_reg, from); }

		inline auto is_disabled(const gsl::not_null<phys_iommu *> iommu) noexcept
		{ return !is_bit_set(get(iommu), from); }

		inline auto is_disabled(const value_type &cap_reg) noexcept
		{ return !is_bit_set(cap_reg, from); }

		inline void dump(int level, const value_type &cap_reg, std::string *msg = nullptr)
		{ bfdebug_subbool(level, name, is_enabled(cap_reg), msg); }
	}

	namespace l5p
	{
		constexpr const auto mask = 0x1000000000000000ULL;
		constexpr const auto from = 60ULL;
		constexpr const auto name = "level_5_paging_support";

		inline auto is_enabled(const gsl::not_null<phys_iommu *> iommu) noexcept
		{ return is_bit_set(get(iommu), from); }

		inline auto is_enabled(const value_type &cap_reg) noexcept
		{ return is_bit_set(cap_reg, from); }

		inline auto is_disabled(const gsl::not_null<phys_iommu *> iommu) noexcept
		{ return !is_bit_set(get(iommu), from); }

		inline auto is_disabled(const value_type &cap_reg) noexcept
		{ return !is_bit_set(cap_reg, from); }

		inline void dump(int level, const value_type &cap_reg, std::string *msg = nullptr)
		{ bfdebug_subbool(level, name, is_enabled(cap_reg), msg); }
	}

	inline void dump(int level, const value_type &cap_reg, std::string *msg = nullptr)
	{
		bfdebug_nhex(level, name, cap_reg, msg);

		nd::dump(level, cap_reg, msg);
		afl::dump(level, cap_reg, msg);
		rwbf::dump(level, cap_reg, msg);
		plmr::dump(level, cap_reg, msg);
		phmr::dump(level, cap_reg, msg);
		cm::dump(level, cap_reg, msg);
		sagaw::dump(level, cap_reg, msg);
		mgaw::dump(level, cap_reg, msg);
		zlr::dump(level, cap_reg, msg);
		fro::dump(level, cap_reg, msg);
		sllps::dump(level, cap_reg, msg);
		psi::dump(level, cap_reg, msg);
		nfr::dump(level, cap_reg, msg);
		mamv::dump(level, cap_reg, msg);
		dwd::dump(level, cap_reg, msg);
		drd::dump(level, cap_reg, msg);
		fl1gp::dump(level, cap_reg, msg);
		pi::dump(level, cap_reg, msg);
		l5p::dump(level, cap_reg, msg);
	}

	inline void dump(int level, const gsl::not_null<phys_iommu *> iommu, std::string *msg = nullptr)
	{
		auto reg_val = get(iommu);
		dump(level, reg_val, msg);
	}
}

namespace ecap_reg
{
	constexpr const auto name = "extended_capability_register";
	constexpr const auto offset = 0x010;

	using value_type = uint64_t;

	inline auto get(const gsl::not_null<phys_iommu *> iommu) noexcept
	{ return iommu->read_64(offset); }

	namespace c
	{
		constexpr const auto mask = 0x1ULL;
		constexpr const auto from = 0ULL;
		constexpr const auto name = "page_walk_coherency";

		inline auto is_enabled(const gsl::not_null<phys_iommu *> iommu) noexcept
		{ return is_bit_set(get(iommu), from); }

		inline auto is_enabled(const value_type &ecap_reg) noexcept
		{ return is_bit_set(ecap_reg, from); }

		inline auto is_disabled(const gsl::not_null<phys_iommu *> iommu) noexcept
		{ return !is_bit_set(get(iommu), from); }

		inline auto is_disabled(const value_type &ecap_reg) noexcept
		{ return !is_bit_set(ecap_reg, from); }

		inline void dump(int level, const value_type &ecap_reg, std::string *msg = nullptr)
		{ bfdebug_subbool(level, name, is_enabled(ecap_reg), msg); }
	}

	namespace qi
	{
		constexpr const auto mask = 0x2ULL;
		constexpr const auto from = 1ULL;
		constexpr const auto name = "queued_invalidation_support";

		inline auto is_enabled(const gsl::not_null<phys_iommu *> iommu) noexcept
		{ return is_bit_set(get(iommu), from); }

		inline auto is_enabled(const value_type &ecap_reg) noexcept
		{ return is_bit_set(ecap_reg, from); }

		inline auto is_disabled(const gsl::not_null<phys_iommu *> iommu) noexcept
		{ return !is_bit_set(get(iommu), from); }

		inline auto is_disabled(const value_type &ecap_reg) noexcept
		{ return !is_bit_set(ecap_reg, from); }

		inline void dump(int level, const value_type &ecap_reg, std::string *msg = nullptr)
		{ bfdebug_subbool(level, name, is_enabled(ecap_reg), msg); }
	}

	namespace dt
	{
		constexpr const auto mask = 0x4ULL;
		constexpr const auto from = 2ULL;
		constexpr const auto name = "device_tlb_support";

		inline auto is_enabled(const gsl::not_null<phys_iommu *> iommu) noexcept
		{ return is_bit_set(get(iommu), from); }

		inline auto is_enabled(const value_type &ecap_reg) noexcept
		{ return is_bit_set(ecap_reg, from); }

		inline auto is_disabled(const gsl::not_null<phys_iommu *> iommu) noexcept
		{ return !is_bit_set(get(iommu), from); }

		inline auto is_disabled(const value_type &ecap_reg) noexcept
		{ return !is_bit_set(ecap_reg, from); }

		inline void dump(int level, const value_type &ecap_reg, std::string *msg = nullptr)
		{ bfdebug_subbool(level, name, is_enabled(ecap_reg), msg); }
	}

	namespace ir
	{
		constexpr const auto mask = 0x8ULL;
		constexpr const auto from = 3ULL;
		constexpr const auto name = "interrupt_remapping_support";

		inline auto is_enabled(const gsl::not_null<phys_iommu *> iommu) noexcept
		{ return is_bit_set(get(iommu), from); }

		inline auto is_enabled(const value_type &ecap_reg) noexcept
		{ return is_bit_set(ecap_reg, from); }

		inline auto is_disabled(const gsl::not_null<phys_iommu *> iommu) noexcept
		{ return !is_bit_set(get(iommu), from); }

		inline auto is_disabled(const value_type &ecap_reg) noexcept
		{ return !is_bit_set(ecap_reg, from); }

		inline void dump(int level, const value_type &ecap_reg, std::string *msg = nullptr)
		{ bfdebug_subbool(level, name, is_enabled(ecap_reg), msg); }
	}

	namespace eim
	{
		constexpr const auto mask = 0x10ULL;
		constexpr const auto from = 4ULL;
		constexpr const auto name = "extended_interrupt_mode";

		inline auto is_enabled(const gsl::not_null<phys_iommu *> iommu) noexcept
		{ return is_bit_set(get(iommu), from); }

		inline auto is_enabled(const value_type &ecap_reg) noexcept
		{ return is_bit_set(ecap_reg, from); }

		inline auto is_disabled(const gsl::not_null<phys_iommu *> iommu) noexcept
		{ return !is_bit_set(get(iommu), from); }

		inline auto is_disabled(const value_type &ecap_reg) noexcept
		{ return !is_bit_set(ecap_reg, from); }

		inline void dump(int level, const value_type &ecap_reg, std::string *msg = nullptr)
		{ bfdebug_subbool(level, name, is_enabled(ecap_reg), msg); }
	}

	namespace pt
	{
		constexpr const auto mask = 0x40ULL;
		constexpr const auto from = 6ULL;
		constexpr const auto name = "pass_through";

		inline auto is_enabled(const gsl::not_null<phys_iommu *> iommu) noexcept
		{ return is_bit_set(get(iommu), from); }

		inline auto is_enabled(const value_type &ecap_reg) noexcept
		{ return is_bit_set(ecap_reg, from); }

		inline auto is_disabled(const gsl::not_null<phys_iommu *> iommu) noexcept
		{ return !is_bit_set(get(iommu), from); }

		inline auto is_disabled(const value_type &ecap_reg) noexcept
		{ return !is_bit_set(ecap_reg, from); }

		inline void dump(int level, const value_type &ecap_reg, std::string *msg = nullptr)
		{ bfdebug_subbool(level, name, is_enabled(ecap_reg), msg); }
	}

	namespace sc
	{
		constexpr const auto mask = 0x80ULL;
		constexpr const auto from = 7ULL;
		constexpr const auto name = "snoop_control";

		inline auto is_enabled(const gsl::not_null<phys_iommu *> iommu) noexcept
		{ return is_bit_set(get(iommu), from); }

		inline auto is_enabled(const value_type &ecap_reg) noexcept
		{ return is_bit_set(ecap_reg, from); }

		inline auto is_disabled(const gsl::not_null<phys_iommu *> iommu) noexcept
		{ return !is_bit_set(get(iommu), from); }

		inline auto is_disabled(const value_type &ecap_reg) noexcept
		{ return !is_bit_set(ecap_reg, from); }

		inline void dump(int level, const value_type &ecap_reg, std::string *msg = nullptr)
		{ bfdebug_subbool(level, name, is_enabled(ecap_reg), msg); }
	}

	namespace iro
	{
		constexpr const auto mask = 0x3FF00ULL;
		constexpr const auto from = 8ULL;
		constexpr const auto name = "iotlb_register_offset";

		inline auto get(const gsl::not_null<phys_iommu *> iommu) noexcept
		{ return get_bits(iommu->read_64(offset), mask) >> from; }

		inline auto get(const value_type &ecap_reg) noexcept
		{ return get_bits(ecap_reg, mask) >> from; }

		inline void dump(int level, const value_type &ecap_reg, std::string *msg = nullptr)
		{ bfdebug_subnhex(level, name, get(ecap_reg), msg); }
	}

	namespace mhmv
	{
		constexpr const auto mask = 0xF00000ULL;
		constexpr const auto from = 20ULL;
		constexpr const auto name = "maximum_handle_mask_value";

		inline auto get(const gsl::not_null<phys_iommu *> iommu) noexcept
		{ return get_bits(iommu->read_64(offset), mask) >> from; }

		inline auto get(const value_type &ecap_reg) noexcept
		{ return get_bits(ecap_reg, mask) >> from; }

		inline void dump(int level, const value_type &ecap_reg, std::string *msg = nullptr)
		{ bfdebug_subnhex(level, name, get(ecap_reg), msg); }
	}

	namespace ecs
	{
		constexpr const auto mask = 0x1000000ULL;
		constexpr const auto from = 24ULL;
		constexpr const auto name = "extended_context_support";

		inline auto is_enabled(const gsl::not_null<phys_iommu *> iommu) noexcept
		{ return is_bit_set(get(iommu), from); }

		inline auto is_enabled(const value_type &ecap_reg) noexcept
		{ return is_bit_set(ecap_reg, from); }

		inline auto is_disabled(const gsl::not_null<phys_iommu *> iommu) noexcept
		{ return !is_bit_set(get(iommu), from); }

		inline auto is_disabled(const value_type &ecap_reg) noexcept
		{ return !is_bit_set(ecap_reg, from); }

		inline void dump(int level, const value_type &ecap_reg, std::string *msg = nullptr)
		{ bfdebug_subbool(level, name, is_enabled(ecap_reg), msg); }
	}

	namespace mts
	{
		constexpr const auto mask = 0x2000000ULL;
		constexpr const auto from = 25ULL;
		constexpr const auto name = "memory_type_support";

		inline auto is_enabled(const gsl::not_null<phys_iommu *> iommu) noexcept
		{ return is_bit_set(get(iommu), from); }

		inline auto is_enabled(const value_type &ecap_reg) noexcept
		{ return is_bit_set(ecap_reg, from); }

		inline auto is_disabled(const gsl::not_null<phys_iommu *> iommu) noexcept
		{ return !is_bit_set(get(iommu), from); }

		inline auto is_disabled(const value_type &ecap_reg) noexcept
		{ return !is_bit_set(ecap_reg, from); }

		inline void dump(int level, const value_type &ecap_reg, std::string *msg = nullptr)
		{ bfdebug_subbool(level, name, is_enabled(ecap_reg), msg); }
	}

	namespace nest
	{
		constexpr const auto mask = 0x4000000ULL;
		constexpr const auto from = 26ULL;
		constexpr const auto name = "nested_translation_support";

		inline auto is_enabled(const gsl::not_null<phys_iommu *> iommu) noexcept
		{ return is_bit_set(get(iommu), from); }

		inline auto is_enabled(const value_type &ecap_reg) noexcept
		{ return is_bit_set(ecap_reg, from); }

		inline auto is_disabled(const gsl::not_null<phys_iommu *> iommu) noexcept
		{ return !is_bit_set(get(iommu), from); }

		inline auto is_disabled(const value_type &ecap_reg) noexcept
		{ return !is_bit_set(ecap_reg, from); }

		inline void dump(int level, const value_type &ecap_reg, std::string *msg = nullptr)
		{ bfdebug_subbool(level, name, is_enabled(ecap_reg), msg); }
	}

	namespace dis
	{
		constexpr const auto mask = 0x8000000ULL;
		constexpr const auto from = 27ULL;
		constexpr const auto name = "deferred_invalidate_support";

		inline auto is_enabled(const gsl::not_null<phys_iommu *> iommu) noexcept
		{ return is_bit_set(get(iommu), from); }

		inline auto is_enabled(const value_type &ecap_reg) noexcept
		{ return is_bit_set(ecap_reg, from); }

		inline auto is_disabled(const gsl::not_null<phys_iommu *> iommu) noexcept
		{ return !is_bit_set(get(iommu), from); }

		inline auto is_disabled(const value_type &ecap_reg) noexcept
		{ return !is_bit_set(ecap_reg, from); }

		inline void dump(int level, const value_type &ecap_reg, std::string *msg = nullptr)
		{ bfdebug_subbool(level, name, is_enabled(ecap_reg), msg); }
	}

	namespace prs
	{
		constexpr const auto mask = 0x20000000ULL;
		constexpr const auto from = 29ULL;
		constexpr const auto name = "page_request_support";

		inline auto is_enabled(const gsl::not_null<phys_iommu *> iommu) noexcept
		{ return is_bit_set(get(iommu), from); }

		inline auto is_enabled(const value_type &ecap_reg) noexcept
		{ return is_bit_set(ecap_reg, from); }

		inline auto is_disabled(const gsl::not_null<phys_iommu *> iommu) noexcept
		{ return !is_bit_set(get(iommu), from); }

		inline auto is_disabled(const value_type &ecap_reg) noexcept
		{ return !is_bit_set(ecap_reg, from); }

		inline void dump(int level, const value_type &ecap_reg, std::string *msg = nullptr)
		{ bfdebug_subbool(level, name, is_enabled(ecap_reg), msg); }
	}

	namespace ers
	{
		constexpr const auto mask = 0x40000000ULL;
		constexpr const auto from = 30ULL;
		constexpr const auto name = "execute_request_support";

		inline auto is_enabled(const gsl::not_null<phys_iommu *> iommu) noexcept
		{ return is_bit_set(get(iommu), from); }

		inline auto is_enabled(const value_type &ecap_reg) noexcept
		{ return is_bit_set(ecap_reg, from); }

		inline auto is_disabled(const gsl::not_null<phys_iommu *> iommu) noexcept
		{ return !is_bit_set(get(iommu), from); }

		inline auto is_disabled(const value_type &ecap_reg) noexcept
		{ return !is_bit_set(ecap_reg, from); }

		inline void dump(int level, const value_type &ecap_reg, std::string *msg = nullptr)
		{ bfdebug_subbool(level, name, is_enabled(ecap_reg), msg); }
	}

	namespace srs
	{
		constexpr const auto mask = 0x80000000ULL;
		constexpr const auto from = 31ULL;
		constexpr const auto name = "supervisor_request_support";

		inline auto is_enabled(const gsl::not_null<phys_iommu *> iommu) noexcept
		{ return is_bit_set(get(iommu), from); }

		inline auto is_enabled(const value_type &ecap_reg) noexcept
		{ return is_bit_set(ecap_reg, from); }

		inline auto is_disabled(const gsl::not_null<phys_iommu *> iommu) noexcept
		{ return !is_bit_set(get(iommu), from); }

		inline auto is_disabled(const value_type &ecap_reg) noexcept
		{ return !is_bit_set(ecap_reg, from); }

		inline void dump(int level, const value_type &ecap_reg, std::string *msg = nullptr)
		{ bfdebug_subbool(level, name, is_enabled(ecap_reg), msg); }
	}

	namespace nwfs
	{
		constexpr const auto mask = 0x200000000ULL;
		constexpr const auto from = 33ULL;
		constexpr const auto name = "no_write_flag_support";

		inline auto is_enabled(const gsl::not_null<phys_iommu *> iommu) noexcept
		{ return is_bit_set(get(iommu), from); }

		inline auto is_enabled(const value_type &ecap_reg) noexcept
		{ return is_bit_set(ecap_reg, from); }

		inline auto is_disabled(const gsl::not_null<phys_iommu *> iommu) noexcept
		{ return !is_bit_set(get(iommu), from); }

		inline auto is_disabled(const value_type &ecap_reg) noexcept
		{ return !is_bit_set(ecap_reg, from); }

		inline void dump(int level, const value_type &ecap_reg, std::string *msg = nullptr)
		{ bfdebug_subbool(level, name, is_enabled(ecap_reg), msg); }
	}

	namespace eafs
	{
		constexpr const auto mask = 0x400000000ULL;
		constexpr const auto from = 34ULL;
		constexpr const auto name = "extended_accessed_flag_support";

		inline auto is_enabled(const gsl::not_null<phys_iommu *> iommu) noexcept
		{ return is_bit_set(get(iommu), from); }

		inline auto is_enabled(const value_type &ecap_reg) noexcept
		{ return is_bit_set(ecap_reg, from); }

		inline auto is_disabled(const gsl::not_null<phys_iommu *> iommu) noexcept
		{ return !is_bit_set(get(iommu), from); }

		inline auto is_disabled(const value_type &ecap_reg) noexcept
		{ return !is_bit_set(ecap_reg, from); }

		inline void dump(int level, const value_type &ecap_reg, std::string *msg = nullptr)
		{ bfdebug_subbool(level, name, is_enabled(ecap_reg), msg); }
	}

	namespace pss
	{
		constexpr const auto mask = 0xF800000000ULL;
		constexpr const auto from = 35ULL;
		constexpr const auto name = "pasid_size_supported";

		inline auto get(const gsl::not_null<phys_iommu *> iommu) noexcept
		{ return get_bits(iommu->read_64(offset), mask) >> from; }

		inline auto get(const value_type &ecap_reg) noexcept
		{ return get_bits(ecap_reg, mask) >> from; }

		inline void dump(int level, const value_type &ecap_reg, std::string *msg = nullptr)
		{ bfdebug_subnhex(level, name, get(ecap_reg), msg); }
	}

	namespace pasid
	{
		constexpr const auto mask = 0x10000000000ULL;
		constexpr const auto from = 40ULL;
		constexpr const auto name = "process_address_space_id_support";

		inline auto is_enabled(const gsl::not_null<phys_iommu *> iommu) noexcept
		{ return is_bit_set(get(iommu), from); }

		inline auto is_enabled(const value_type &ecap_reg) noexcept
		{ return is_bit_set(ecap_reg, from); }

		inline auto is_disabled(const gsl::not_null<phys_iommu *> iommu) noexcept
		{ return !is_bit_set(get(iommu), from); }

		inline auto is_disabled(const value_type &ecap_reg) noexcept
		{ return !is_bit_set(ecap_reg, from); }

		inline void dump(int level, const value_type &ecap_reg, std::string *msg = nullptr)
		{ bfdebug_subbool(level, name, is_enabled(ecap_reg), msg); }
	}

	namespace dit
	{
		constexpr const auto mask = 0x20000000000ULL;
		constexpr const auto from = 41ULL;
		constexpr const auto name = "device_tlb_invalidation_throttle";

		inline auto is_enabled(const gsl::not_null<phys_iommu *> iommu) noexcept
		{ return is_bit_set(get(iommu), from); }

		inline auto is_enabled(const value_type &ecap_reg) noexcept
		{ return is_bit_set(ecap_reg, from); }

		inline auto is_disabled(const gsl::not_null<phys_iommu *> iommu) noexcept
		{ return !is_bit_set(get(iommu), from); }

		inline auto is_disabled(const value_type &ecap_reg) noexcept
		{ return !is_bit_set(ecap_reg, from); }

		inline void dump(int level, const value_type &ecap_reg, std::string *msg = nullptr)
		{ bfdebug_subbool(level, name, is_enabled(ecap_reg), msg); }
	}

	namespace pds
	{
		constexpr const auto mask = 0x40000000000ULL;
		constexpr const auto from = 42ULL;
		constexpr const auto name = "page_request_drain_support";

		inline auto is_enabled(const gsl::not_null<phys_iommu *> iommu) noexcept
		{ return is_bit_set(get(iommu), from); }

		inline auto is_enabled(const value_type &ecap_reg) noexcept
		{ return is_bit_set(ecap_reg, from); }

		inline auto is_disabled(const gsl::not_null<phys_iommu *> iommu) noexcept
		{ return !is_bit_set(get(iommu), from); }

		inline auto is_disabled(const value_type &ecap_reg) noexcept
		{ return !is_bit_set(ecap_reg, from); }

		inline void dump(int level, const value_type &ecap_reg, std::string *msg = nullptr)
		{ bfdebug_subbool(level, name, is_enabled(ecap_reg), msg); }
	}

	inline void dump(int level, const value_type &ecap_reg, std::string *msg = nullptr)
	{
		bfdebug_nhex(level, name, ecap_reg, msg);

		c::dump(level, ecap_reg, msg);
		qi::dump(level, ecap_reg, msg);
		dt::dump(level, ecap_reg, msg);
		ir::dump(level, ecap_reg, msg);
		eim::dump(level, ecap_reg, msg);
		pt::dump(level, ecap_reg, msg);
		sc::dump(level, ecap_reg, msg);
		iro::dump(level, ecap_reg, msg);
		mhmv::dump(level, ecap_reg, msg);
		ecs::dump(level, ecap_reg, msg);
		mts::dump(level, ecap_reg, msg);
		nest::dump(level, ecap_reg, msg);
		dis::dump(level, ecap_reg, msg);
		prs::dump(level, ecap_reg, msg);
		ers::dump(level, ecap_reg, msg);
		srs::dump(level, ecap_reg, msg);
		nwfs::dump(level, ecap_reg, msg);
		eafs::dump(level, ecap_reg, msg);
		pss::dump(level, ecap_reg, msg);
		pasid::dump(level, ecap_reg, msg);
		dit::dump(level, ecap_reg, msg);
		pds::dump(level, ecap_reg, msg);
	}

	inline void dump(int level, const gsl::not_null<phys_iommu *> iommu, std::string *msg = nullptr)
	{
		auto reg_val = get(iommu);
		dump(level, reg_val, msg);
	}
}

namespace gcmd_reg
{
	constexpr const auto name = "global_command_register";
	constexpr const auto offset = 0x018;

	using value_type = uint32_t;

	inline auto set(const gsl::not_null<phys_iommu *> iommu, value_type val) noexcept
	{ return iommu->write_32(offset, val); }

	namespace cfi
	{
		constexpr const auto mask = 0x800000ULL;
		constexpr const auto from = 23ULL;
		constexpr const auto name = "compatibility_format_interrupt";

		inline void enable(value_type &gcmd_reg) noexcept
		{ gcmd_reg = set_bit(gcmd_reg, from); }

		inline void disable(value_type &gcmd_reg) noexcept
		{ gcmd_reg = clear_bit(gcmd_reg, from); }

	}

	namespace sirtp
	{
		constexpr const auto mask = 0x1000000ULL;
		constexpr const auto from = 24ULL;
		constexpr const auto name = "set_interrupt_remap_table_pointer";

		inline void enable(value_type &gcmd_reg) noexcept
		{ gcmd_reg = set_bit(gcmd_reg, from); }

		inline void disable(value_type &gcmd_reg) noexcept
		{ gcmd_reg = clear_bit(gcmd_reg, from); }

	}

	namespace ire
	{
		constexpr const auto mask = 0x2000000ULL;
		constexpr const auto from = 25ULL;
		constexpr const auto name = "interrupt_remapping_enable";

		inline void enable(value_type &gcmd_reg) noexcept
		{ gcmd_reg = set_bit(gcmd_reg, from); }

		inline void disable(value_type &gcmd_reg) noexcept
		{ gcmd_reg = clear_bit(gcmd_reg, from); }

	}

	namespace qie
	{
		constexpr const auto mask = 0x4000000ULL;
		constexpr const auto from = 26ULL;
		constexpr const auto name = "queued_invalidation_enable";

		inline void enable(value_type &gcmd_reg) noexcept
		{ gcmd_reg = set_bit(gcmd_reg, from); }

		inline void disable(value_type &gcmd_reg) noexcept
		{ gcmd_reg = clear_bit(gcmd_reg, from); }

	}

	namespace wbf
	{
		constexpr const auto mask = 0x8000000ULL;
		constexpr const auto from = 27ULL;
		constexpr const auto name = "write_buffer_flush";

		inline void enable(value_type &gcmd_reg) noexcept
		{ gcmd_reg = set_bit(gcmd_reg, from); }

		inline void disable(value_type &gcmd_reg) noexcept
		{ gcmd_reg = clear_bit(gcmd_reg, from); }

	}

	namespace eafl
	{
		constexpr const auto mask = 0x10000000ULL;
		constexpr const auto from = 28ULL;
		constexpr const auto name = "enable_advanced_fault_logging";

		inline void enable(value_type &gcmd_reg) noexcept
		{ gcmd_reg = set_bit(gcmd_reg, from); }

		inline void disable(value_type &gcmd_reg) noexcept
		{ gcmd_reg = clear_bit(gcmd_reg, from); }

	}

	namespace sfl
	{
		constexpr const auto mask = 0x20000000ULL;
		constexpr const auto from = 29ULL;
		constexpr const auto name = "set_fault_log";

		inline void enable(value_type &gcmd_reg) noexcept
		{ gcmd_reg = set_bit(gcmd_reg, from); }

		inline void disable(value_type &gcmd_reg) noexcept
		{ gcmd_reg = clear_bit(gcmd_reg, from); }

	}

	namespace srtp
	{
		constexpr const auto mask = 0x40000000ULL;
		constexpr const auto from = 30ULL;
		constexpr const auto name = "set_root_table_pointer";

		inline void enable(value_type &gcmd_reg) noexcept
		{ gcmd_reg = set_bit(gcmd_reg, from); }

		inline void disable(value_type &gcmd_reg) noexcept
		{ gcmd_reg = clear_bit(gcmd_reg, from); }

	}

	namespace te
	{
		constexpr const auto mask = 0x80000000ULL;
		constexpr const auto from = 31ULL;
		constexpr const auto name = "translation_enable";

		inline void enable(value_type &gcmd_reg) noexcept
		{ gcmd_reg = set_bit(gcmd_reg, from); }

		inline void disable(value_type &gcmd_reg) noexcept
		{ gcmd_reg = clear_bit(gcmd_reg, from); }

	}
}

namespace gsts_reg
{
	constexpr const auto name = "global_status_register";
	constexpr const auto offset = 0x01c;

	using value_type = uint32_t;

	inline auto get(const gsl::not_null<phys_iommu *> iommu) noexcept
	{ return iommu->read_32(offset); }

	namespace cfis
	{
		constexpr const auto mask = 0x800000ULL;
		constexpr const auto from = 23ULL;
		constexpr const auto name = "compatibility_format_interrupt_status";

		inline auto is_enabled(const gsl::not_null<phys_iommu *> iommu) noexcept
		{ return is_bit_set(get(iommu), from); }

		inline auto is_enabled(const value_type &gsts_reg) noexcept
		{ return is_bit_set(gsts_reg, from); }

		inline auto is_disabled(const gsl::not_null<phys_iommu *> iommu) noexcept
		{ return !is_bit_set(get(iommu), from); }

		inline auto is_disabled(const value_type &gsts_reg) noexcept
		{ return !is_bit_set(gsts_reg, from); }

		inline void dump(int level, const value_type &gsts_reg, std::string *msg = nullptr)
		{ bfdebug_subbool(level, name, is_enabled(gsts_reg), msg); }
	}

	namespace irtps
	{
		constexpr const auto mask = 0x1000000ULL;
		constexpr const auto from = 24ULL;
		constexpr const auto name = "interrupt_remapping_table_pointer_status";

		inline auto is_enabled(const gsl::not_null<phys_iommu *> iommu) noexcept
		{ return is_bit_set(get(iommu), from); }

		inline auto is_enabled(const value_type &gsts_reg) noexcept
		{ return is_bit_set(gsts_reg, from); }

		inline auto is_disabled(const gsl::not_null<phys_iommu *> iommu) noexcept
		{ return !is_bit_set(get(iommu), from); }

		inline auto is_disabled(const value_type &gsts_reg) noexcept
		{ return !is_bit_set(gsts_reg, from); }

		inline void dump(int level, const value_type &gsts_reg, std::string *msg = nullptr)
		{ bfdebug_subbool(level, name, is_enabled(gsts_reg), msg); }
	}

	namespace ires
	{
		constexpr const auto mask = 0x2000000ULL;
		constexpr const auto from = 25ULL;
		constexpr const auto name = "interrupt_remapping_enable_status";

		inline auto is_enabled(const gsl::not_null<phys_iommu *> iommu) noexcept
		{ return is_bit_set(get(iommu), from); }

		inline auto is_enabled(const value_type &gsts_reg) noexcept
		{ return is_bit_set(gsts_reg, from); }

		inline auto is_disabled(const gsl::not_null<phys_iommu *> iommu) noexcept
		{ return !is_bit_set(get(iommu), from); }

		inline auto is_disabled(const value_type &gsts_reg) noexcept
		{ return !is_bit_set(gsts_reg, from); }

		inline void dump(int level, const value_type &gsts_reg, std::string *msg = nullptr)
		{ bfdebug_subbool(level, name, is_enabled(gsts_reg), msg); }
	}

	namespace qies
	{
		constexpr const auto mask = 0x4000000ULL;
		constexpr const auto from = 26ULL;
		constexpr const auto name = "queued_invalidation_enable_status";

		inline auto is_enabled(const gsl::not_null<phys_iommu *> iommu) noexcept
		{ return is_bit_set(get(iommu), from); }

		inline auto is_enabled(const value_type &gsts_reg) noexcept
		{ return is_bit_set(gsts_reg, from); }

		inline auto is_disabled(const gsl::not_null<phys_iommu *> iommu) noexcept
		{ return !is_bit_set(get(iommu), from); }

		inline auto is_disabled(const value_type &gsts_reg) noexcept
		{ return !is_bit_set(gsts_reg, from); }

		inline void dump(int level, const value_type &gsts_reg, std::string *msg = nullptr)
		{ bfdebug_subbool(level, name, is_enabled(gsts_reg), msg); }
	}

	namespace wbfs
	{
		constexpr const auto mask = 0x8000000ULL;
		constexpr const auto from = 27ULL;
		constexpr const auto name = "write_buffer_flush_status";

		inline auto is_enabled(const gsl::not_null<phys_iommu *> iommu) noexcept
		{ return is_bit_set(get(iommu), from); }

		inline auto is_enabled(const value_type &gsts_reg) noexcept
		{ return is_bit_set(gsts_reg, from); }

		inline auto is_disabled(const gsl::not_null<phys_iommu *> iommu) noexcept
		{ return !is_bit_set(get(iommu), from); }

		inline auto is_disabled(const value_type &gsts_reg) noexcept
		{ return !is_bit_set(gsts_reg, from); }

		inline void dump(int level, const value_type &gsts_reg, std::string *msg = nullptr)
		{ bfdebug_subbool(level, name, is_enabled(gsts_reg), msg); }
	}

	namespace afls
	{
		constexpr const auto mask = 0x10000000ULL;
		constexpr const auto from = 28ULL;
		constexpr const auto name = "advanced_fault_logging_status";

		inline auto is_enabled(const gsl::not_null<phys_iommu *> iommu) noexcept
		{ return is_bit_set(get(iommu), from); }

		inline auto is_enabled(const value_type &gsts_reg) noexcept
		{ return is_bit_set(gsts_reg, from); }

		inline auto is_disabled(const gsl::not_null<phys_iommu *> iommu) noexcept
		{ return !is_bit_set(get(iommu), from); }

		inline auto is_disabled(const value_type &gsts_reg) noexcept
		{ return !is_bit_set(gsts_reg, from); }

		inline void dump(int level, const value_type &gsts_reg, std::string *msg = nullptr)
		{ bfdebug_subbool(level, name, is_enabled(gsts_reg), msg); }
	}

	namespace fls
	{
		constexpr const auto mask = 0x20000000ULL;
		constexpr const auto from = 29ULL;
		constexpr const auto name = "fault_log_status";

		inline auto is_enabled(const gsl::not_null<phys_iommu *> iommu) noexcept
		{ return is_bit_set(get(iommu), from); }

		inline auto is_enabled(const value_type &gsts_reg) noexcept
		{ return is_bit_set(gsts_reg, from); }

		inline auto is_disabled(const gsl::not_null<phys_iommu *> iommu) noexcept
		{ return !is_bit_set(get(iommu), from); }

		inline auto is_disabled(const value_type &gsts_reg) noexcept
		{ return !is_bit_set(gsts_reg, from); }

		inline void dump(int level, const value_type &gsts_reg, std::string *msg = nullptr)
		{ bfdebug_subbool(level, name, is_enabled(gsts_reg), msg); }
	}

	namespace rtps
	{
		constexpr const auto mask = 0x40000000ULL;
		constexpr const auto from = 30ULL;
		constexpr const auto name = "root_table_pointer_status";

		inline auto is_enabled(const gsl::not_null<phys_iommu *> iommu) noexcept
		{ return is_bit_set(get(iommu), from); }

		inline auto is_enabled(const value_type &gsts_reg) noexcept
		{ return is_bit_set(gsts_reg, from); }

		inline auto is_disabled(const gsl::not_null<phys_iommu *> iommu) noexcept
		{ return !is_bit_set(get(iommu), from); }

		inline auto is_disabled(const value_type &gsts_reg) noexcept
		{ return !is_bit_set(gsts_reg, from); }

		inline void dump(int level, const value_type &gsts_reg, std::string *msg = nullptr)
		{ bfdebug_subbool(level, name, is_enabled(gsts_reg), msg); }
	}

	namespace tes
	{
		constexpr const auto mask = 0x80000000ULL;
		constexpr const auto from = 31ULL;
		constexpr const auto name = "translation_enable_status";

		inline auto is_enabled(const gsl::not_null<phys_iommu *> iommu) noexcept
		{ return is_bit_set(get(iommu), from); }

		inline auto is_enabled(const value_type &gsts_reg) noexcept
		{ return is_bit_set(gsts_reg, from); }

		inline auto is_disabled(const gsl::not_null<phys_iommu *> iommu) noexcept
		{ return !is_bit_set(get(iommu), from); }

		inline auto is_disabled(const value_type &gsts_reg) noexcept
		{ return !is_bit_set(gsts_reg, from); }

		inline void dump(int level, const value_type &gsts_reg, std::string *msg = nullptr)
		{ bfdebug_subbool(level, name, is_enabled(gsts_reg), msg); }
	}

	inline void dump(int level, const value_type &gsts_reg, std::string *msg = nullptr)
	{
		bfdebug_nhex(level, name, gsts_reg, msg);

		cfis::dump(level, gsts_reg, msg);
		irtps::dump(level, gsts_reg, msg);
		ires::dump(level, gsts_reg, msg);
		qies::dump(level, gsts_reg, msg);
		wbfs::dump(level, gsts_reg, msg);
		afls::dump(level, gsts_reg, msg);
		fls::dump(level, gsts_reg, msg);
		rtps::dump(level, gsts_reg, msg);
		tes::dump(level, gsts_reg, msg);
	}

	inline void dump(int level, const gsl::not_null<phys_iommu *> iommu, std::string *msg = nullptr)
	{
		auto reg_val = get(iommu);
		dump(level, reg_val, msg);
	}
}

namespace rtaddr_reg
{
	constexpr const auto name = "root_table_address_register";
	constexpr const auto offset = 0x020;

	using value_type = uint64_t;

	inline auto get(const gsl::not_null<phys_iommu *> iommu) noexcept
	{ return iommu->read_64(offset); }

	inline auto set(const gsl::not_null<phys_iommu *> iommu, value_type val) noexcept
	{ return iommu->write_64(offset, val); }

	namespace rtt
	{
		constexpr const auto mask = 0x800ULL;
		constexpr const auto from = 11ULL;
		constexpr const auto name = "root_table_type";

		inline auto is_enabled(const gsl::not_null<phys_iommu *> iommu) noexcept
		{ return is_bit_set(get(iommu), from); }

		inline auto is_enabled(const value_type &rtaddr_reg) noexcept
		{ return is_bit_set(rtaddr_reg, from); }

		inline auto is_disabled(const gsl::not_null<phys_iommu *> iommu) noexcept
		{ return !is_bit_set(get(iommu), from); }

		inline auto is_disabled(const value_type &rtaddr_reg) noexcept
		{ return !is_bit_set(rtaddr_reg, from); }

		inline void enable(const gsl::not_null<phys_iommu *> iommu) noexcept
		{ set(iommu, set_bit(get(iommu), from)); }

		inline void enable(value_type &rtaddr_reg) noexcept
		{ rtaddr_reg = set_bit(rtaddr_reg, from); }

		inline void disable(const gsl::not_null<phys_iommu *> iommu) noexcept
		{ set(iommu, clear_bit(get(iommu), from)); }

		inline void disable(value_type &rtaddr_reg) noexcept
		{ rtaddr_reg = clear_bit(rtaddr_reg, from); }

		inline void dump(int level, const value_type &rtaddr_reg, std::string *msg = nullptr)
		{ bfdebug_subbool(level, name, is_enabled(rtaddr_reg), msg); }
	}

	namespace rta
	{
		constexpr const auto mask = 0xFFFFFFFFFFFFF000ULL;
		constexpr const auto from = 12ULL;
		constexpr const auto name = "root_table_address";

		inline auto get(const gsl::not_null<phys_iommu *> iommu) noexcept
		{ return get_bits(iommu->read_64(offset), mask) >> from; }

		inline auto get(const value_type &rtaddr_reg) noexcept
		{ return get_bits(rtaddr_reg, mask) >> from; }

		inline void set(const gsl::not_null<phys_iommu *> iommu, uint64_t val) noexcept
		{ set(iommu, set_bits(iommu->read_64(offset), mask, val << from)); }

		inline void set(value_type &rtaddr_reg, uint64_t val) noexcept
		{ rtaddr_reg = set_bits(rtaddr_reg, mask, val << from); }

		inline void dump(int level, const value_type &rtaddr_reg, std::string *msg = nullptr)
		{ bfdebug_subnhex(level, name, get(rtaddr_reg), msg); }
	}

	inline void dump(int level, const value_type &rtaddr_reg, std::string *msg = nullptr)
	{
		bfdebug_nhex(level, name, rtaddr_reg, msg);

		rtt::dump(level, rtaddr_reg, msg);
		rta::dump(level, rtaddr_reg, msg);
	}

	inline void dump(int level, const gsl::not_null<phys_iommu *> iommu, std::string *msg = nullptr)
	{
		auto reg_val = get(iommu);
		dump(level, reg_val, msg);
	}
}

namespace ccmd_reg
{
	constexpr const auto name = "context_command_register";
	constexpr const auto offset = 0x028;

	using value_type = uint64_t;

	inline auto get(const gsl::not_null<phys_iommu *> iommu) noexcept
	{ return iommu->read_64(offset); }

	inline auto set(const gsl::not_null<phys_iommu *> iommu, value_type val) noexcept
	{ return iommu->write_64(offset, val); }

	namespace did
	{
		constexpr const auto mask = 0xFFFFULL;
		constexpr const auto from = 0ULL;
		constexpr const auto name = "domain_id";

		inline auto get(const gsl::not_null<phys_iommu *> iommu) noexcept
		{ return get_bits(iommu->read_64(offset), mask) >> from; }

		inline auto get(const value_type &ccmd_reg) noexcept
		{ return get_bits(ccmd_reg, mask) >> from; }

		inline void set(const gsl::not_null<phys_iommu *> iommu, uint64_t val) noexcept
		{ set(iommu, set_bits(iommu->read_64(offset), mask, val << from)); }

		inline void set(value_type &ccmd_reg, uint64_t val) noexcept
		{ ccmd_reg = set_bits(ccmd_reg, mask, val << from); }

		inline void dump(int level, const value_type &ccmd_reg, std::string *msg = nullptr)
		{ bfdebug_subnhex(level, name, get(ccmd_reg), msg); }
	}

	namespace sid
	{
		constexpr const auto mask = 0xFFFF0000ULL;
		constexpr const auto from = 16ULL;
		constexpr const auto name = "source_id";

		inline void set(value_type &ccmd_reg, uint64_t val) noexcept
		{ ccmd_reg = set_bits(ccmd_reg, mask, val << from); }

	}

	namespace fm
	{
		constexpr const auto mask = 0x300000000ULL;
		constexpr const auto from = 32ULL;
		constexpr const auto name = "function_mask";

		inline void set(value_type &ccmd_reg, uint64_t val) noexcept
		{ ccmd_reg = set_bits(ccmd_reg, mask, val << from); }

	}

	namespace caig
	{
		constexpr const auto mask = 0x1800000000000000ULL;
		constexpr const auto from = 59ULL;
		constexpr const auto name = "context_actual_invalidation_granularity";

		inline auto get(const gsl::not_null<phys_iommu *> iommu) noexcept
		{ return get_bits(iommu->read_64(offset), mask) >> from; }

		inline auto get(const value_type &ccmd_reg) noexcept
		{ return get_bits(ccmd_reg, mask) >> from; }

		inline void dump(int level, const value_type &ccmd_reg, std::string *msg = nullptr)
		{ bfdebug_subnhex(level, name, get(ccmd_reg), msg); }
	}

	namespace cirg
	{
		constexpr const auto mask = 0x6000000000000000ULL;
		constexpr const auto from = 61ULL;
		constexpr const auto name = "context_invalidation_request_granularity";

		inline auto get(const gsl::not_null<phys_iommu *> iommu) noexcept
		{ return get_bits(iommu->read_64(offset), mask) >> from; }

		inline auto get(const value_type &ccmd_reg) noexcept
		{ return get_bits(ccmd_reg, mask) >> from; }

		inline void set(const gsl::not_null<phys_iommu *> iommu, uint64_t val) noexcept
		{ set(iommu, set_bits(iommu->read_64(offset), mask, val << from)); }

		inline void set(value_type &ccmd_reg, uint64_t val) noexcept
		{ ccmd_reg = set_bits(ccmd_reg, mask, val << from); }

		inline void dump(int level, const value_type &ccmd_reg, std::string *msg = nullptr)
		{ bfdebug_subnhex(level, name, get(ccmd_reg), msg); }
	}

	namespace icc
	{
		constexpr const auto mask = 0x8000000000000000ULL;
		constexpr const auto from = 63ULL;
		constexpr const auto name = "invalidate_context_cache";

		inline auto is_enabled(const gsl::not_null<phys_iommu *> iommu) noexcept
		{ return is_bit_set(get(iommu), from); }

		inline auto is_enabled(const value_type &ccmd_reg) noexcept
		{ return is_bit_set(ccmd_reg, from); }

		inline auto is_disabled(const gsl::not_null<phys_iommu *> iommu) noexcept
		{ return !is_bit_set(get(iommu), from); }

		inline auto is_disabled(const value_type &ccmd_reg) noexcept
		{ return !is_bit_set(ccmd_reg, from); }

		inline void enable(const gsl::not_null<phys_iommu *> iommu) noexcept
		{ set(iommu, set_bit(get(iommu), from)); }

		inline void enable(value_type &ccmd_reg) noexcept
		{ ccmd_reg = set_bit(ccmd_reg, from); }

		inline void disable(const gsl::not_null<phys_iommu *> iommu) noexcept
		{ set(iommu, clear_bit(get(iommu), from)); }

		inline void disable(value_type &ccmd_reg) noexcept
		{ ccmd_reg = clear_bit(ccmd_reg, from); }

		inline void dump(int level, const value_type &ccmd_reg, std::string *msg = nullptr)
		{ bfdebug_subbool(level, name, is_enabled(ccmd_reg), msg); }
	}

	inline void dump(int level, const value_type &ccmd_reg, std::string *msg = nullptr)
	{
		bfdebug_nhex(level, name, ccmd_reg, msg);

		did::dump(level, ccmd_reg, msg);
		caig::dump(level, ccmd_reg, msg);
		cirg::dump(level, ccmd_reg, msg);
		icc::dump(level, ccmd_reg, msg);
	}

	inline void dump(int level, const gsl::not_null<phys_iommu *> iommu, std::string *msg = nullptr)
	{
		auto reg_val = get(iommu);
		dump(level, reg_val, msg);
	}
}

namespace fsts_reg
{
	constexpr const auto name = "fault_status_register";
	constexpr const auto offset = 0x034;

	using value_type = uint32_t;

	inline auto get(const gsl::not_null<phys_iommu *> iommu) noexcept
	{ return iommu->read_32(offset); }

	inline auto set(const gsl::not_null<phys_iommu *> iommu, value_type val) noexcept
	{ return iommu->write_32(offset, val); }

	namespace pfo
	{
		constexpr const auto mask = 0x1ULL;
		constexpr const auto from = 0ULL;
		constexpr const auto name = "primary_fault_overflow";

		inline auto is_enabled(const gsl::not_null<phys_iommu *> iommu) noexcept
		{ return is_bit_set(get(iommu), from); }

		inline auto is_enabled(const value_type &fsts_reg) noexcept
		{ return is_bit_set(fsts_reg, from); }

		inline auto is_disabled(const gsl::not_null<phys_iommu *> iommu) noexcept
		{ return !is_bit_set(get(iommu), from); }

		inline auto is_disabled(const value_type &fsts_reg) noexcept
		{ return !is_bit_set(fsts_reg, from); }

		inline void enable(const gsl::not_null<phys_iommu *> iommu) noexcept
		{ set(iommu, set_bit(get(iommu), from)); }

		inline void enable(value_type &fsts_reg) noexcept
		{ fsts_reg = set_bit(fsts_reg, from); }

		inline void dump(int level, const value_type &fsts_reg, std::string *msg = nullptr)
		{ bfdebug_subbool(level, name, is_enabled(fsts_reg), msg); }
	}

	namespace ppf
	{
		constexpr const auto mask = 0x2ULL;
		constexpr const auto from = 1ULL;
		constexpr const auto name = "primary_pending_fault";

		inline auto is_enabled(const gsl::not_null<phys_iommu *> iommu) noexcept
		{ return is_bit_set(get(iommu), from); }

		inline auto is_enabled(const value_type &fsts_reg) noexcept
		{ return is_bit_set(fsts_reg, from); }

		inline auto is_disabled(const gsl::not_null<phys_iommu *> iommu) noexcept
		{ return !is_bit_set(get(iommu), from); }

		inline auto is_disabled(const value_type &fsts_reg) noexcept
		{ return !is_bit_set(fsts_reg, from); }

		inline void dump(int level, const value_type &fsts_reg, std::string *msg = nullptr)
		{ bfdebug_subbool(level, name, is_enabled(fsts_reg), msg); }
	}

	namespace afo
	{
		constexpr const auto mask = 0x4ULL;
		constexpr const auto from = 2ULL;
		constexpr const auto name = "advanced_fault_overflow";

		inline auto is_enabled(const gsl::not_null<phys_iommu *> iommu) noexcept
		{ return is_bit_set(get(iommu), from); }

		inline auto is_enabled(const value_type &fsts_reg) noexcept
		{ return is_bit_set(fsts_reg, from); }

		inline auto is_disabled(const gsl::not_null<phys_iommu *> iommu) noexcept
		{ return !is_bit_set(get(iommu), from); }

		inline auto is_disabled(const value_type &fsts_reg) noexcept
		{ return !is_bit_set(fsts_reg, from); }

		inline void enable(const gsl::not_null<phys_iommu *> iommu) noexcept
		{ set(iommu, set_bit(get(iommu), from)); }

		inline void enable(value_type &fsts_reg) noexcept
		{ fsts_reg = set_bit(fsts_reg, from); }

		inline void dump(int level, const value_type &fsts_reg, std::string *msg = nullptr)
		{ bfdebug_subbool(level, name, is_enabled(fsts_reg), msg); }
	}

	namespace apf
	{
		constexpr const auto mask = 0x8ULL;
		constexpr const auto from = 3ULL;
		constexpr const auto name = "advanced_pending_fault";

		inline auto is_enabled(const gsl::not_null<phys_iommu *> iommu) noexcept
		{ return is_bit_set(get(iommu), from); }

		inline auto is_enabled(const value_type &fsts_reg) noexcept
		{ return is_bit_set(fsts_reg, from); }

		inline auto is_disabled(const gsl::not_null<phys_iommu *> iommu) noexcept
		{ return !is_bit_set(get(iommu), from); }

		inline auto is_disabled(const value_type &fsts_reg) noexcept
		{ return !is_bit_set(fsts_reg, from); }

		inline void enable(const gsl::not_null<phys_iommu *> iommu) noexcept
		{ set(iommu, set_bit(get(iommu), from)); }

		inline void enable(value_type &fsts_reg) noexcept
		{ fsts_reg = set_bit(fsts_reg, from); }

		inline void dump(int level, const value_type &fsts_reg, std::string *msg = nullptr)
		{ bfdebug_subbool(level, name, is_enabled(fsts_reg), msg); }
	}

	namespace iqe
	{
		constexpr const auto mask = 0x10ULL;
		constexpr const auto from = 4ULL;
		constexpr const auto name = "invalidation_queue_error";

		inline auto is_enabled(const gsl::not_null<phys_iommu *> iommu) noexcept
		{ return is_bit_set(get(iommu), from); }

		inline auto is_enabled(const value_type &fsts_reg) noexcept
		{ return is_bit_set(fsts_reg, from); }

		inline auto is_disabled(const gsl::not_null<phys_iommu *> iommu) noexcept
		{ return !is_bit_set(get(iommu), from); }

		inline auto is_disabled(const value_type &fsts_reg) noexcept
		{ return !is_bit_set(fsts_reg, from); }

		inline void enable(const gsl::not_null<phys_iommu *> iommu) noexcept
		{ set(iommu, set_bit(get(iommu), from)); }

		inline void enable(value_type &fsts_reg) noexcept
		{ fsts_reg = set_bit(fsts_reg, from); }

		inline void dump(int level, const value_type &fsts_reg, std::string *msg = nullptr)
		{ bfdebug_subbool(level, name, is_enabled(fsts_reg), msg); }
	}

	namespace ice
	{
		constexpr const auto mask = 0x20ULL;
		constexpr const auto from = 5ULL;
		constexpr const auto name = "invalidation_completion_error";

		inline auto is_enabled(const gsl::not_null<phys_iommu *> iommu) noexcept
		{ return is_bit_set(get(iommu), from); }

		inline auto is_enabled(const value_type &fsts_reg) noexcept
		{ return is_bit_set(fsts_reg, from); }

		inline auto is_disabled(const gsl::not_null<phys_iommu *> iommu) noexcept
		{ return !is_bit_set(get(iommu), from); }

		inline auto is_disabled(const value_type &fsts_reg) noexcept
		{ return !is_bit_set(fsts_reg, from); }

		inline void enable(const gsl::not_null<phys_iommu *> iommu) noexcept
		{ set(iommu, set_bit(get(iommu), from)); }

		inline void enable(value_type &fsts_reg) noexcept
		{ fsts_reg = set_bit(fsts_reg, from); }

		inline void dump(int level, const value_type &fsts_reg, std::string *msg = nullptr)
		{ bfdebug_subbool(level, name, is_enabled(fsts_reg), msg); }
	}

	namespace ite
	{
		constexpr const auto mask = 0x40ULL;
		constexpr const auto from = 6ULL;
		constexpr const auto name = "invalidation_time_out_error";

		inline auto is_enabled(const gsl::not_null<phys_iommu *> iommu) noexcept
		{ return is_bit_set(get(iommu), from); }

		inline auto is_enabled(const value_type &fsts_reg) noexcept
		{ return is_bit_set(fsts_reg, from); }

		inline auto is_disabled(const gsl::not_null<phys_iommu *> iommu) noexcept
		{ return !is_bit_set(get(iommu), from); }

		inline auto is_disabled(const value_type &fsts_reg) noexcept
		{ return !is_bit_set(fsts_reg, from); }

		inline void enable(const gsl::not_null<phys_iommu *> iommu) noexcept
		{ set(iommu, set_bit(get(iommu), from)); }

		inline void enable(value_type &fsts_reg) noexcept
		{ fsts_reg = set_bit(fsts_reg, from); }

		inline void dump(int level, const value_type &fsts_reg, std::string *msg = nullptr)
		{ bfdebug_subbool(level, name, is_enabled(fsts_reg), msg); }
	}

	namespace pro
	{
		constexpr const auto mask = 0x80ULL;
		constexpr const auto from = 7ULL;
		constexpr const auto name = "page_request_overflow";

		inline auto is_enabled(const gsl::not_null<phys_iommu *> iommu) noexcept
		{ return is_bit_set(get(iommu), from); }

		inline auto is_enabled(const value_type &fsts_reg) noexcept
		{ return is_bit_set(fsts_reg, from); }

		inline auto is_disabled(const gsl::not_null<phys_iommu *> iommu) noexcept
		{ return !is_bit_set(get(iommu), from); }

		inline auto is_disabled(const value_type &fsts_reg) noexcept
		{ return !is_bit_set(fsts_reg, from); }

		inline void enable(const gsl::not_null<phys_iommu *> iommu) noexcept
		{ set(iommu, set_bit(get(iommu), from)); }

		inline void enable(value_type &fsts_reg) noexcept
		{ fsts_reg = set_bit(fsts_reg, from); }

		inline void dump(int level, const value_type &fsts_reg, std::string *msg = nullptr)
		{ bfdebug_subbool(level, name, is_enabled(fsts_reg), msg); }
	}

	namespace fri
	{
		constexpr const auto mask = 0xFF00ULL;
		constexpr const auto from = 8ULL;
		constexpr const auto name = "fault_record_index";

		inline auto get(const gsl::not_null<phys_iommu *> iommu) noexcept
		{ return get_bits(iommu->read_32(offset), mask) >> from; }

		inline auto get(const value_type &fsts_reg) noexcept
		{ return get_bits(fsts_reg, mask) >> from; }

		inline void dump(int level, const value_type &fsts_reg, std::string *msg = nullptr)
		{ bfdebug_subnhex(level, name, get(fsts_reg), msg); }
	}

	inline void dump(int level, const value_type &fsts_reg, std::string *msg = nullptr)
	{
		bfdebug_nhex(level, name, fsts_reg, msg);

		pfo::dump(level, fsts_reg, msg);
		ppf::dump(level, fsts_reg, msg);
		afo::dump(level, fsts_reg, msg);
		apf::dump(level, fsts_reg, msg);
		iqe::dump(level, fsts_reg, msg);
		ice::dump(level, fsts_reg, msg);
		ite::dump(level, fsts_reg, msg);
		pro::dump(level, fsts_reg, msg);
		fri::dump(level, fsts_reg, msg);
	}

	inline void dump(int level, const gsl::not_null<phys_iommu *> iommu, std::string *msg = nullptr)
	{
		auto reg_val = get(iommu);
		dump(level, reg_val, msg);
	}
}

namespace fectl_reg
{
	constexpr const auto name = "fault_event_control_register";
	constexpr const auto preserved_mask = 0x3FFFFFFF;
	constexpr const auto offset = 0x038;

	using value_type = uint32_t;

	inline auto get(const gsl::not_null<phys_iommu *> iommu) noexcept
	{ return iommu->read_32(offset); }

	inline auto set(const gsl::not_null<phys_iommu *> iommu, value_type val) noexcept
	{ return iommu->write_32_preserved(offset, val, preserved_mask); }

	namespace ip
	{
		constexpr const auto mask = 0x40000000ULL;
		constexpr const auto from = 30ULL;
		constexpr const auto name = "interrupt_pending";

		inline auto is_enabled(const gsl::not_null<phys_iommu *> iommu) noexcept
		{ return is_bit_set(get(iommu), from); }

		inline auto is_enabled(const value_type &fectl_reg) noexcept
		{ return is_bit_set(fectl_reg, from); }

		inline auto is_disabled(const gsl::not_null<phys_iommu *> iommu) noexcept
		{ return !is_bit_set(get(iommu), from); }

		inline auto is_disabled(const value_type &fectl_reg) noexcept
		{ return !is_bit_set(fectl_reg, from); }

		inline void dump(int level, const value_type &fectl_reg, std::string *msg = nullptr)
		{ bfdebug_subbool(level, name, is_enabled(fectl_reg), msg); }
	}

	namespace im
	{
		constexpr const auto mask = 0x80000000ULL;
		constexpr const auto from = 31ULL;
		constexpr const auto name = "interrupt_mask";

		inline auto is_enabled(const gsl::not_null<phys_iommu *> iommu) noexcept
		{ return is_bit_set(get(iommu), from); }

		inline auto is_enabled(const value_type &fectl_reg) noexcept
		{ return is_bit_set(fectl_reg, from); }

		inline auto is_disabled(const gsl::not_null<phys_iommu *> iommu) noexcept
		{ return !is_bit_set(get(iommu), from); }

		inline auto is_disabled(const value_type &fectl_reg) noexcept
		{ return !is_bit_set(fectl_reg, from); }

		inline void enable(const gsl::not_null<phys_iommu *> iommu) noexcept
		{ set(iommu, set_bit(get(iommu), from)); }

		inline void enable(value_type &fectl_reg) noexcept
		{ fectl_reg = set_bit(fectl_reg, from); }

		inline void disable(const gsl::not_null<phys_iommu *> iommu) noexcept
		{ set(iommu, clear_bit(get(iommu), from)); }

		inline void disable(value_type &fectl_reg) noexcept
		{ fectl_reg = clear_bit(fectl_reg, from); }

		inline void dump(int level, const value_type &fectl_reg, std::string *msg = nullptr)
		{ bfdebug_subbool(level, name, is_enabled(fectl_reg), msg); }
	}

	inline void dump(int level, const value_type &fectl_reg, std::string *msg = nullptr)
	{
		bfdebug_nhex(level, name, fectl_reg, msg);

		ip::dump(level, fectl_reg, msg);
		im::dump(level, fectl_reg, msg);
	}

	inline void dump(int level, const gsl::not_null<phys_iommu *> iommu, std::string *msg = nullptr)
	{
		auto reg_val = get(iommu);
		dump(level, reg_val, msg);
	}
}

namespace fedata_reg
{
	constexpr const auto name = "fault_event_data_register";
	constexpr const auto offset = 0x03c;

	using value_type = uint32_t;

	inline auto get(const gsl::not_null<phys_iommu *> iommu) noexcept
	{ return iommu->read_32(offset); }

	inline auto set(const gsl::not_null<phys_iommu *> iommu, value_type val) noexcept
	{ return iommu->write_32(offset, val); }

	namespace imd
	{
		constexpr const auto mask = 0xFFFFULL;
		constexpr const auto from = 0ULL;
		constexpr const auto name = "interrupt_message_data";

		inline auto get(const gsl::not_null<phys_iommu *> iommu) noexcept
		{ return get_bits(iommu->read_32(offset), mask) >> from; }

		inline auto get(const value_type &fedata_reg) noexcept
		{ return get_bits(fedata_reg, mask) >> from; }

		inline void set(const gsl::not_null<phys_iommu *> iommu, uint64_t val) noexcept
		{ set(iommu, set_bits(iommu->read_32(offset), mask, val << from)); }

		inline void set(value_type &fedata_reg, uint64_t val) noexcept
		{ fedata_reg = set_bits(fedata_reg, mask, val << from); }

		inline void dump(int level, const value_type &fedata_reg, std::string *msg = nullptr)
		{ bfdebug_subnhex(level, name, get(fedata_reg), msg); }
	}

	namespace eimd
	{
		constexpr const auto mask = 0xFFFF0000ULL;
		constexpr const auto from = 16ULL;
		constexpr const auto name = "extended_interrupt_message_data";

		inline auto get(const gsl::not_null<phys_iommu *> iommu) noexcept
		{ return get_bits(iommu->read_32(offset), mask) >> from; }

		inline auto get(const value_type &fedata_reg) noexcept
		{ return get_bits(fedata_reg, mask) >> from; }

		inline void set(const gsl::not_null<phys_iommu *> iommu, uint64_t val) noexcept
		{ set(iommu, set_bits(iommu->read_32(offset), mask, val << from)); }

		inline void set(value_type &fedata_reg, uint64_t val) noexcept
		{ fedata_reg = set_bits(fedata_reg, mask, val << from); }

		inline void dump(int level, const value_type &fedata_reg, std::string *msg = nullptr)
		{ bfdebug_subnhex(level, name, get(fedata_reg), msg); }
	}

	inline void dump(int level, const value_type &fedata_reg, std::string *msg = nullptr)
	{
		bfdebug_nhex(level, name, fedata_reg, msg);

		imd::dump(level, fedata_reg, msg);
		eimd::dump(level, fedata_reg, msg);
	}

	inline void dump(int level, const gsl::not_null<phys_iommu *> iommu, std::string *msg = nullptr)
	{
		auto reg_val = get(iommu);
		dump(level, reg_val, msg);
	}
}

namespace feaddr_reg
{
	constexpr const auto name = "fault_event_address_register";
	constexpr const auto offset = 0x040;

	using value_type = uint32_t;

	inline auto get(const gsl::not_null<phys_iommu *> iommu) noexcept
	{ return iommu->read_32(offset); }

	inline auto set(const gsl::not_null<phys_iommu *> iommu, value_type val) noexcept
	{ return iommu->write_32(offset, val); }

	namespace ma
	{
		constexpr const auto mask = 0xFFFFFFFCULL;
		constexpr const auto from = 2ULL;
		constexpr const auto name = "message_address";

		inline auto get(const gsl::not_null<phys_iommu *> iommu) noexcept
		{ return get_bits(iommu->read_32(offset), mask) >> from; }

		inline auto get(const value_type &feaddr_reg) noexcept
		{ return get_bits(feaddr_reg, mask) >> from; }

		inline void set(const gsl::not_null<phys_iommu *> iommu, uint64_t val) noexcept
		{ set(iommu, set_bits(iommu->read_32(offset), mask, val << from)); }

		inline void set(value_type &feaddr_reg, uint64_t val) noexcept
		{ feaddr_reg = set_bits(feaddr_reg, mask, val << from); }

		inline void dump(int level, const value_type &feaddr_reg, std::string *msg = nullptr)
		{ bfdebug_subnhex(level, name, get(feaddr_reg), msg); }
	}

	inline void dump(int level, const value_type &feaddr_reg, std::string *msg = nullptr)
	{
		bfdebug_nhex(level, name, feaddr_reg, msg);

		ma::dump(level, feaddr_reg, msg);
	}

	inline void dump(int level, const gsl::not_null<phys_iommu *> iommu, std::string *msg = nullptr)
	{
		auto reg_val = get(iommu);
		dump(level, reg_val, msg);
	}
}

namespace feuaddr_reg
{
	constexpr const auto name = "fault_event_upper_address_register";
	constexpr const auto offset = 0x044;

	using value_type = uint32_t;

	inline auto get(const gsl::not_null<phys_iommu *> iommu) noexcept
	{ return iommu->read_32(offset); }

	inline auto set(const gsl::not_null<phys_iommu *> iommu, value_type val) noexcept
	{ return iommu->write_32(offset, val); }

	namespace mua
	{
		constexpr const auto mask = 0xFFFFFFFFULL;
		constexpr const auto from = 0ULL;
		constexpr const auto name = "message_upper_address";

		inline auto get(const gsl::not_null<phys_iommu *> iommu) noexcept
		{ return get_bits(iommu->read_32(offset), mask) >> from; }

		inline auto get(const value_type &feuaddr_reg) noexcept
		{ return get_bits(feuaddr_reg, mask) >> from; }

		inline void set(const gsl::not_null<phys_iommu *> iommu, uint64_t val) noexcept
		{ set(iommu, set_bits(iommu->read_32(offset), mask, val << from)); }

		inline void set(value_type &feuaddr_reg, uint64_t val) noexcept
		{ feuaddr_reg = set_bits(feuaddr_reg, mask, val << from); }

		inline void dump(int level, const value_type &feuaddr_reg, std::string *msg = nullptr)
		{ bfdebug_subnhex(level, name, get(feuaddr_reg), msg); }
	}

	inline void dump(int level, const value_type &feuaddr_reg, std::string *msg = nullptr)
	{
		bfdebug_nhex(level, name, feuaddr_reg, msg);

		mua::dump(level, feuaddr_reg, msg);
	}

	inline void dump(int level, const gsl::not_null<phys_iommu *> iommu, std::string *msg = nullptr)
	{
		auto reg_val = get(iommu);
		dump(level, reg_val, msg);
	}
}

namespace aflog_reg
{
	constexpr const auto name = "advanced_fault_log_register";
	constexpr const auto offset = 0x058;

	using value_type = uint64_t;

	inline auto get(const gsl::not_null<phys_iommu *> iommu) noexcept
	{ return iommu->read_64(offset); }

	inline auto set(const gsl::not_null<phys_iommu *> iommu, value_type val) noexcept
	{ return iommu->write_64(offset, val); }

	namespace fls
	{
		constexpr const auto mask = 0xE00ULL;
		constexpr const auto from = 9ULL;
		constexpr const auto name = "fault_log_size";

		inline auto get(const gsl::not_null<phys_iommu *> iommu) noexcept
		{ return get_bits(iommu->read_64(offset), mask) >> from; }

		inline auto get(const value_type &aflog_reg) noexcept
		{ return get_bits(aflog_reg, mask) >> from; }

		inline void set(const gsl::not_null<phys_iommu *> iommu, uint64_t val) noexcept
		{ set(iommu, set_bits(iommu->read_64(offset), mask, val << from)); }

		inline void set(value_type &aflog_reg, uint64_t val) noexcept
		{ aflog_reg = set_bits(aflog_reg, mask, val << from); }

		inline void dump(int level, const value_type &aflog_reg, std::string *msg = nullptr)
		{ bfdebug_subnhex(level, name, get(aflog_reg), msg); }
	}

	namespace fla
	{
		constexpr const auto mask = 0xFFFFFFFFFFFFF000ULL;
		constexpr const auto from = 12ULL;
		constexpr const auto name = "fault_log_address";

		inline auto get(const gsl::not_null<phys_iommu *> iommu) noexcept
		{ return get_bits(iommu->read_64(offset), mask) >> from; }

		inline auto get(const value_type &aflog_reg) noexcept
		{ return get_bits(aflog_reg, mask) >> from; }

		inline void set(const gsl::not_null<phys_iommu *> iommu, uint64_t val) noexcept
		{ set(iommu, set_bits(iommu->read_64(offset), mask, val << from)); }

		inline void set(value_type &aflog_reg, uint64_t val) noexcept
		{ aflog_reg = set_bits(aflog_reg, mask, val << from); }

		inline void dump(int level, const value_type &aflog_reg, std::string *msg = nullptr)
		{ bfdebug_subnhex(level, name, get(aflog_reg), msg); }
	}

	inline void dump(int level, const value_type &aflog_reg, std::string *msg = nullptr)
	{
		bfdebug_nhex(level, name, aflog_reg, msg);

		fls::dump(level, aflog_reg, msg);
		fla::dump(level, aflog_reg, msg);
	}

	inline void dump(int level, const gsl::not_null<phys_iommu *> iommu, std::string *msg = nullptr)
	{
		auto reg_val = get(iommu);
		dump(level, reg_val, msg);
	}
}

namespace pmen_reg
{
	constexpr const auto name = "protected_memory_enable_register";
	constexpr const auto preserved_mask = 0x7FFFFFFE;
	constexpr const auto offset = 0x064;

	using value_type = uint32_t;

	inline auto get(const gsl::not_null<phys_iommu *> iommu) noexcept
	{ return iommu->read_32(offset); }

	inline auto set(const gsl::not_null<phys_iommu *> iommu, value_type val) noexcept
	{ return iommu->write_32_preserved(offset, val, preserved_mask); }

	namespace prs
	{
		constexpr const auto mask = 0x1ULL;
		constexpr const auto from = 0ULL;
		constexpr const auto name = "protected_region_status";

		inline auto is_enabled(const gsl::not_null<phys_iommu *> iommu) noexcept
		{ return is_bit_set(get(iommu), from); }

		inline auto is_enabled(const value_type &pmen_reg) noexcept
		{ return is_bit_set(pmen_reg, from); }

		inline auto is_disabled(const gsl::not_null<phys_iommu *> iommu) noexcept
		{ return !is_bit_set(get(iommu), from); }

		inline auto is_disabled(const value_type &pmen_reg) noexcept
		{ return !is_bit_set(pmen_reg, from); }

		inline void dump(int level, const value_type &pmen_reg, std::string *msg = nullptr)
		{ bfdebug_subbool(level, name, is_enabled(pmen_reg), msg); }
	}

	namespace epm
	{
		constexpr const auto mask = 0x80000000ULL;
		constexpr const auto from = 31ULL;
		constexpr const auto name = "enable_protected_memory";

		inline auto is_enabled(const gsl::not_null<phys_iommu *> iommu) noexcept
		{ return is_bit_set(get(iommu), from); }

		inline auto is_enabled(const value_type &pmen_reg) noexcept
		{ return is_bit_set(pmen_reg, from); }

		inline auto is_disabled(const gsl::not_null<phys_iommu *> iommu) noexcept
		{ return !is_bit_set(get(iommu), from); }

		inline auto is_disabled(const value_type &pmen_reg) noexcept
		{ return !is_bit_set(pmen_reg, from); }

		inline void enable(const gsl::not_null<phys_iommu *> iommu) noexcept
		{ set(iommu, set_bit(get(iommu), from)); }

		inline void enable(value_type &pmen_reg) noexcept
		{ pmen_reg = set_bit(pmen_reg, from); }

		inline void disable(const gsl::not_null<phys_iommu *> iommu) noexcept
		{ set(iommu, clear_bit(get(iommu), from)); }

		inline void disable(value_type &pmen_reg) noexcept
		{ pmen_reg = clear_bit(pmen_reg, from); }

		inline void dump(int level, const value_type &pmen_reg, std::string *msg = nullptr)
		{ bfdebug_subbool(level, name, is_enabled(pmen_reg), msg); }
	}

	inline void dump(int level, const value_type &pmen_reg, std::string *msg = nullptr)
	{
		bfdebug_nhex(level, name, pmen_reg, msg);

		prs::dump(level, pmen_reg, msg);
		epm::dump(level, pmen_reg, msg);
	}

	inline void dump(int level, const gsl::not_null<phys_iommu *> iommu, std::string *msg = nullptr)
	{
		auto reg_val = get(iommu);
		dump(level, reg_val, msg);
	}
}

namespace plmbase_reg
{
	constexpr const auto name = "protected_low_memory_base_register";
	constexpr const auto offset = 0x068;

	using value_type = uint32_t;

	inline auto get(const gsl::not_null<phys_iommu *> iommu) noexcept
	{ return iommu->read_32(offset); }

	inline auto set(const gsl::not_null<phys_iommu *> iommu, value_type val) noexcept
	{ return iommu->write_32(offset, val); }

	namespace plmb
	{
		constexpr const auto mask = 0xFFFFFFFFULL;
		constexpr const auto from = 0ULL;
		constexpr const auto name = "protected_low_memory_base";

		inline auto get(const gsl::not_null<phys_iommu *> iommu) noexcept
		{ return get_bits(iommu->read_32(offset), mask) >> from; }

		inline auto get(const value_type &plmbase_reg) noexcept
		{ return get_bits(plmbase_reg, mask) >> from; }

		inline void set(const gsl::not_null<phys_iommu *> iommu, uint64_t val) noexcept
		{ set(iommu, set_bits(iommu->read_32(offset), mask, val << from)); }

		inline void set(value_type &plmbase_reg, uint64_t val) noexcept
		{ plmbase_reg = set_bits(plmbase_reg, mask, val << from); }

		inline void dump(int level, const value_type &plmbase_reg, std::string *msg = nullptr)
		{ bfdebug_subnhex(level, name, get(plmbase_reg), msg); }
	}

	inline void dump(int level, const value_type &plmbase_reg, std::string *msg = nullptr)
	{
		bfdebug_nhex(level, name, plmbase_reg, msg);

		plmb::dump(level, plmbase_reg, msg);
	}

	inline void dump(int level, const gsl::not_null<phys_iommu *> iommu, std::string *msg = nullptr)
	{
		auto reg_val = get(iommu);
		dump(level, reg_val, msg);
	}
}

namespace plmlimit_reg
{
	constexpr const auto name = "protected_low_memory_limit_register";
	constexpr const auto offset = 0x06c;

	using value_type = uint32_t;

	inline auto get(const gsl::not_null<phys_iommu *> iommu) noexcept
	{ return iommu->read_32(offset); }

	inline auto set(const gsl::not_null<phys_iommu *> iommu, value_type val) noexcept
	{ return iommu->write_32(offset, val); }

	namespace plml
	{
		constexpr const auto mask = 0xFFFFFFFFULL;
		constexpr const auto from = 0ULL;
		constexpr const auto name = "protected_low_memory_limit";

		inline auto get(const gsl::not_null<phys_iommu *> iommu) noexcept
		{ return get_bits(iommu->read_32(offset), mask) >> from; }

		inline auto get(const value_type &plmlimit_reg) noexcept
		{ return get_bits(plmlimit_reg, mask) >> from; }

		inline void set(const gsl::not_null<phys_iommu *> iommu, uint64_t val) noexcept
		{ set(iommu, set_bits(iommu->read_32(offset), mask, val << from)); }

		inline void set(value_type &plmlimit_reg, uint64_t val) noexcept
		{ plmlimit_reg = set_bits(plmlimit_reg, mask, val << from); }

		inline void dump(int level, const value_type &plmlimit_reg, std::string *msg = nullptr)
		{ bfdebug_subnhex(level, name, get(plmlimit_reg), msg); }
	}

	inline void dump(int level, const value_type &plmlimit_reg, std::string *msg = nullptr)
	{
		bfdebug_nhex(level, name, plmlimit_reg, msg);

		plml::dump(level, plmlimit_reg, msg);
	}

	inline void dump(int level, const gsl::not_null<phys_iommu *> iommu, std::string *msg = nullptr)
	{
		auto reg_val = get(iommu);
		dump(level, reg_val, msg);
	}
}

namespace pmhbase_reg
{
	constexpr const auto name = "protected_high_memory_base_register";
	constexpr const auto offset = 0x070;

	using value_type = uint64_t;

	inline auto get(const gsl::not_null<phys_iommu *> iommu) noexcept
	{ return iommu->read_64(offset); }

	inline auto set(const gsl::not_null<phys_iommu *> iommu, value_type val) noexcept
	{ return iommu->write_64(offset, val); }

	namespace phmb
	{
		constexpr const auto mask = 0xFFFFFFFFFFFFFFFFULL;
		constexpr const auto from = 0ULL;
		constexpr const auto name = "protected_high_memory_base";

		inline auto get(const gsl::not_null<phys_iommu *> iommu) noexcept
		{ return get_bits(iommu->read_64(offset), mask) >> from; }

		inline auto get(const value_type &pmhbase_reg) noexcept
		{ return get_bits(pmhbase_reg, mask) >> from; }

		inline void set(const gsl::not_null<phys_iommu *> iommu, uint64_t val) noexcept
		{ set(iommu, set_bits(iommu->read_64(offset), mask, val << from)); }

		inline void set(value_type &pmhbase_reg, uint64_t val) noexcept
		{ pmhbase_reg = set_bits(pmhbase_reg, mask, val << from); }

		inline void dump(int level, const value_type &pmhbase_reg, std::string *msg = nullptr)
		{ bfdebug_subnhex(level, name, get(pmhbase_reg), msg); }
	}

	inline void dump(int level, const value_type &pmhbase_reg, std::string *msg = nullptr)
	{
		bfdebug_nhex(level, name, pmhbase_reg, msg);

		phmb::dump(level, pmhbase_reg, msg);
	}

	inline void dump(int level, const gsl::not_null<phys_iommu *> iommu, std::string *msg = nullptr)
	{
		auto reg_val = get(iommu);
		dump(level, reg_val, msg);
	}
}

namespace phmlimit_reg
{
	constexpr const auto name = "protected_high_memory_limit_register";
	constexpr const auto offset = 0x078;

	using value_type = uint64_t;

	inline auto get(const gsl::not_null<phys_iommu *> iommu) noexcept
	{ return iommu->read_64(offset); }

	inline auto set(const gsl::not_null<phys_iommu *> iommu, value_type val) noexcept
	{ return iommu->write_64(offset, val); }

	namespace phml
	{
		constexpr const auto mask = 0xFFFFFFFFFFFFFFFFULL;
		constexpr const auto from = 0ULL;
		constexpr const auto name = "protected_high_memory_limit";

		inline auto get(const gsl::not_null<phys_iommu *> iommu) noexcept
		{ return get_bits(iommu->read_64(offset), mask) >> from; }

		inline auto get(const value_type &phmlimit_reg) noexcept
		{ return get_bits(phmlimit_reg, mask) >> from; }

		inline void set(const gsl::not_null<phys_iommu *> iommu, uint64_t val) noexcept
		{ set(iommu, set_bits(iommu->read_64(offset), mask, val << from)); }

		inline void set(value_type &phmlimit_reg, uint64_t val) noexcept
		{ phmlimit_reg = set_bits(phmlimit_reg, mask, val << from); }

		inline void dump(int level, const value_type &phmlimit_reg, std::string *msg = nullptr)
		{ bfdebug_subnhex(level, name, get(phmlimit_reg), msg); }
	}

	inline void dump(int level, const value_type &phmlimit_reg, std::string *msg = nullptr)
	{
		bfdebug_nhex(level, name, phmlimit_reg, msg);

		phml::dump(level, phmlimit_reg, msg);
	}

	inline void dump(int level, const gsl::not_null<phys_iommu *> iommu, std::string *msg = nullptr)
	{
		auto reg_val = get(iommu);
		dump(level, reg_val, msg);
	}
}

namespace iqh_reg
{
	constexpr const auto name = "invalidation_queue_head_register";
	constexpr const auto offset = 0x080;

	using value_type = uint64_t;

	inline auto get(const gsl::not_null<phys_iommu *> iommu) noexcept
	{ return iommu->read_64(offset); }

	namespace qh
	{
		constexpr const auto mask = 0x7FFF0ULL;
		constexpr const auto from = 4ULL;
		constexpr const auto name = "queue_head";

		inline auto get(const gsl::not_null<phys_iommu *> iommu) noexcept
		{ return get_bits(iommu->read_64(offset), mask) >> from; }

		inline auto get(const value_type &iqh_reg) noexcept
		{ return get_bits(iqh_reg, mask) >> from; }

		inline void dump(int level, const value_type &iqh_reg, std::string *msg = nullptr)
		{ bfdebug_subnhex(level, name, get(iqh_reg), msg); }
	}

	inline void dump(int level, const value_type &iqh_reg, std::string *msg = nullptr)
	{
		bfdebug_nhex(level, name, iqh_reg, msg);

		qh::dump(level, iqh_reg, msg);
	}

	inline void dump(int level, const gsl::not_null<phys_iommu *> iommu, std::string *msg = nullptr)
	{
		auto reg_val = get(iommu);
		dump(level, reg_val, msg);
	}
}

namespace iqt_reg
{
	constexpr const auto name = "invalidation_queue_tail_register";
	constexpr const auto offset = 0x088;

	using value_type = uint64_t;

	inline auto get(const gsl::not_null<phys_iommu *> iommu) noexcept
	{ return iommu->read_64(offset); }

	namespace qt
	{
		constexpr const auto mask = 0x7FFF0ULL;
		constexpr const auto from = 4ULL;
		constexpr const auto name = "queue_tail";

		inline auto get(const gsl::not_null<phys_iommu *> iommu) noexcept
		{ return get_bits(iommu->read_64(offset), mask) >> from; }

		inline auto get(const value_type &iqt_reg) noexcept
		{ return get_bits(iqt_reg, mask) >> from; }

		inline void dump(int level, const value_type &iqt_reg, std::string *msg = nullptr)
		{ bfdebug_subnhex(level, name, get(iqt_reg), msg); }
	}

	inline void dump(int level, const value_type &iqt_reg, std::string *msg = nullptr)
	{
		bfdebug_nhex(level, name, iqt_reg, msg);

		qt::dump(level, iqt_reg, msg);
	}

	inline void dump(int level, const gsl::not_null<phys_iommu *> iommu, std::string *msg = nullptr)
	{
		auto reg_val = get(iommu);
		dump(level, reg_val, msg);
	}
}

namespace iqa_reg
{
	constexpr const auto name = "invalidation_queue_address_register";
	constexpr const auto offset = 0x090;

	using value_type = uint64_t;

	inline auto get(const gsl::not_null<phys_iommu *> iommu) noexcept
	{ return iommu->read_64(offset); }

	inline auto set(const gsl::not_null<phys_iommu *> iommu, value_type val) noexcept
	{ return iommu->write_64(offset, val); }

	namespace qs
	{
		constexpr const auto mask = 0x7ULL;
		constexpr const auto from = 0ULL;
		constexpr const auto name = "queue_size";

		inline auto get(const gsl::not_null<phys_iommu *> iommu) noexcept
		{ return get_bits(iommu->read_64(offset), mask) >> from; }

		inline auto get(const value_type &iqa_reg) noexcept
		{ return get_bits(iqa_reg, mask) >> from; }

		inline void set(const gsl::not_null<phys_iommu *> iommu, uint64_t val) noexcept
		{ set(iommu, set_bits(iommu->read_64(offset), mask, val << from)); }

		inline void set(value_type &iqa_reg, uint64_t val) noexcept
		{ iqa_reg = set_bits(iqa_reg, mask, val << from); }

		inline void dump(int level, const value_type &iqa_reg, std::string *msg = nullptr)
		{ bfdebug_subnhex(level, name, get(iqa_reg), msg); }
	}

	namespace iqa
	{
		constexpr const auto mask = 0xFFFFFFFFFFFFF000ULL;
		constexpr const auto from = 12ULL;
		constexpr const auto name = "invalidation_queue_base_address";

		inline auto get(const gsl::not_null<phys_iommu *> iommu) noexcept
		{ return get_bits(iommu->read_64(offset), mask) >> from; }

		inline auto get(const value_type &iqa_reg) noexcept
		{ return get_bits(iqa_reg, mask) >> from; }

		inline void set(const gsl::not_null<phys_iommu *> iommu, uint64_t val) noexcept
		{ set(iommu, set_bits(iommu->read_64(offset), mask, val << from)); }

		inline void set(value_type &iqa_reg, uint64_t val) noexcept
		{ iqa_reg = set_bits(iqa_reg, mask, val << from); }

		inline void dump(int level, const value_type &iqa_reg, std::string *msg = nullptr)
		{ bfdebug_subnhex(level, name, get(iqa_reg), msg); }
	}

	inline void dump(int level, const value_type &iqa_reg, std::string *msg = nullptr)
	{
		bfdebug_nhex(level, name, iqa_reg, msg);

		qs::dump(level, iqa_reg, msg);
		iqa::dump(level, iqa_reg, msg);
	}

	inline void dump(int level, const gsl::not_null<phys_iommu *> iommu, std::string *msg = nullptr)
	{
		auto reg_val = get(iommu);
		dump(level, reg_val, msg);
	}
}

namespace ics_reg
{
	constexpr const auto name = "invalidation_completion_status_register";
	constexpr const auto offset = 0x09c;

	using value_type = uint32_t;

	inline auto get(const gsl::not_null<phys_iommu *> iommu) noexcept
	{ return iommu->read_32(offset); }

	inline auto set(const gsl::not_null<phys_iommu *> iommu, value_type val) noexcept
	{ return iommu->write_32(offset, val); }

	namespace iwc
	{
		constexpr const auto mask = 0x1ULL;
		constexpr const auto from = 0ULL;
		constexpr const auto name = "invalidation_wait_descriptor_complete";

		inline auto is_enabled(const gsl::not_null<phys_iommu *> iommu) noexcept
		{ return is_bit_set(get(iommu), from); }

		inline auto is_enabled(const value_type &ics_reg) noexcept
		{ return is_bit_set(ics_reg, from); }

		inline auto is_disabled(const gsl::not_null<phys_iommu *> iommu) noexcept
		{ return !is_bit_set(get(iommu), from); }

		inline auto is_disabled(const value_type &ics_reg) noexcept
		{ return !is_bit_set(ics_reg, from); }

		inline void enable(const gsl::not_null<phys_iommu *> iommu) noexcept
		{ set(iommu, set_bit(get(iommu), from)); }

		inline void enable(value_type &ics_reg) noexcept
		{ ics_reg = set_bit(ics_reg, from); }

		inline void dump(int level, const value_type &ics_reg, std::string *msg = nullptr)
		{ bfdebug_subbool(level, name, is_enabled(ics_reg), msg); }
	}

	inline void dump(int level, const value_type &ics_reg, std::string *msg = nullptr)
	{
		bfdebug_nhex(level, name, ics_reg, msg);

		iwc::dump(level, ics_reg, msg);
	}

	inline void dump(int level, const gsl::not_null<phys_iommu *> iommu, std::string *msg = nullptr)
	{
		auto reg_val = get(iommu);
		dump(level, reg_val, msg);
	}
}

namespace iectl_reg
{
	constexpr const auto name = "invalidation_event_control_register";
	constexpr const auto preserved_mask = 0x3FFFFFFF;
	constexpr const auto offset = 0x0a0;

	using value_type = uint32_t;

	inline auto get(const gsl::not_null<phys_iommu *> iommu) noexcept
	{ return iommu->read_32(offset); }

	inline auto set(const gsl::not_null<phys_iommu *> iommu, value_type val) noexcept
	{ return iommu->write_32_preserved(offset, val, preserved_mask); }

	namespace ip
	{
		constexpr const auto mask = 0x40000000ULL;
		constexpr const auto from = 30ULL;
		constexpr const auto name = "interrupt_pending";

		inline auto is_enabled(const gsl::not_null<phys_iommu *> iommu) noexcept
		{ return is_bit_set(get(iommu), from); }

		inline auto is_enabled(const value_type &iectl_reg) noexcept
		{ return is_bit_set(iectl_reg, from); }

		inline auto is_disabled(const gsl::not_null<phys_iommu *> iommu) noexcept
		{ return !is_bit_set(get(iommu), from); }

		inline auto is_disabled(const value_type &iectl_reg) noexcept
		{ return !is_bit_set(iectl_reg, from); }

		inline void dump(int level, const value_type &iectl_reg, std::string *msg = nullptr)
		{ bfdebug_subbool(level, name, is_enabled(iectl_reg), msg); }
	}

	namespace im
	{
		constexpr const auto mask = 0x80000000ULL;
		constexpr const auto from = 31ULL;
		constexpr const auto name = "interrupt_mask";

		inline auto is_enabled(const gsl::not_null<phys_iommu *> iommu) noexcept
		{ return is_bit_set(get(iommu), from); }

		inline auto is_enabled(const value_type &iectl_reg) noexcept
		{ return is_bit_set(iectl_reg, from); }

		inline auto is_disabled(const gsl::not_null<phys_iommu *> iommu) noexcept
		{ return !is_bit_set(get(iommu), from); }

		inline auto is_disabled(const value_type &iectl_reg) noexcept
		{ return !is_bit_set(iectl_reg, from); }

		inline void enable(const gsl::not_null<phys_iommu *> iommu) noexcept
		{ set(iommu, set_bit(get(iommu), from)); }

		inline void enable(value_type &iectl_reg) noexcept
		{ iectl_reg = set_bit(iectl_reg, from); }

		inline void disable(const gsl::not_null<phys_iommu *> iommu) noexcept
		{ set(iommu, clear_bit(get(iommu), from)); }

		inline void disable(value_type &iectl_reg) noexcept
		{ iectl_reg = clear_bit(iectl_reg, from); }

		inline void dump(int level, const value_type &iectl_reg, std::string *msg = nullptr)
		{ bfdebug_subbool(level, name, is_enabled(iectl_reg), msg); }
	}

	inline void dump(int level, const value_type &iectl_reg, std::string *msg = nullptr)
	{
		bfdebug_nhex(level, name, iectl_reg, msg);

		ip::dump(level, iectl_reg, msg);
		im::dump(level, iectl_reg, msg);
	}

	inline void dump(int level, const gsl::not_null<phys_iommu *> iommu, std::string *msg = nullptr)
	{
		auto reg_val = get(iommu);
		dump(level, reg_val, msg);
	}
}

namespace iedata_reg
{
	constexpr const auto name = "invalidation_event_data_register";
	constexpr const auto offset = 0x0a4;

	using value_type = uint32_t;

	inline auto get(const gsl::not_null<phys_iommu *> iommu) noexcept
	{ return iommu->read_32(offset); }

	inline auto set(const gsl::not_null<phys_iommu *> iommu, value_type val) noexcept
	{ return iommu->write_32(offset, val); }

	namespace imd
	{
		constexpr const auto mask = 0xFFFFULL;
		constexpr const auto from = 0ULL;
		constexpr const auto name = "interrupt_message_data";

		inline auto get(const gsl::not_null<phys_iommu *> iommu) noexcept
		{ return get_bits(iommu->read_32(offset), mask) >> from; }

		inline auto get(const value_type &iedata_reg) noexcept
		{ return get_bits(iedata_reg, mask) >> from; }

		inline void set(const gsl::not_null<phys_iommu *> iommu, uint64_t val) noexcept
		{ set(iommu, set_bits(iommu->read_32(offset), mask, val << from)); }

		inline void set(value_type &iedata_reg, uint64_t val) noexcept
		{ iedata_reg = set_bits(iedata_reg, mask, val << from); }

		inline void dump(int level, const value_type &iedata_reg, std::string *msg = nullptr)
		{ bfdebug_subnhex(level, name, get(iedata_reg), msg); }
	}

	namespace eimd
	{
		constexpr const auto mask = 0xFFFF0000ULL;
		constexpr const auto from = 16ULL;
		constexpr const auto name = "extended_interrupt_message_data";

		inline auto get(const gsl::not_null<phys_iommu *> iommu) noexcept
		{ return get_bits(iommu->read_32(offset), mask) >> from; }

		inline auto get(const value_type &iedata_reg) noexcept
		{ return get_bits(iedata_reg, mask) >> from; }

		inline void set(const gsl::not_null<phys_iommu *> iommu, uint64_t val) noexcept
		{ set(iommu, set_bits(iommu->read_32(offset), mask, val << from)); }

		inline void set(value_type &iedata_reg, uint64_t val) noexcept
		{ iedata_reg = set_bits(iedata_reg, mask, val << from); }

		inline void dump(int level, const value_type &iedata_reg, std::string *msg = nullptr)
		{ bfdebug_subnhex(level, name, get(iedata_reg), msg); }
	}

	inline void dump(int level, const value_type &iedata_reg, std::string *msg = nullptr)
	{
		bfdebug_nhex(level, name, iedata_reg, msg);

		imd::dump(level, iedata_reg, msg);
		eimd::dump(level, iedata_reg, msg);
	}

	inline void dump(int level, const gsl::not_null<phys_iommu *> iommu, std::string *msg = nullptr)
	{
		auto reg_val = get(iommu);
		dump(level, reg_val, msg);
	}
}

namespace ieaddr_reg
{
	constexpr const auto name = "invalidation_event_address_register";
	constexpr const auto offset = 0x0a8;

	using value_type = uint32_t;

	inline auto get(const gsl::not_null<phys_iommu *> iommu) noexcept
	{ return iommu->read_32(offset); }

	inline auto set(const gsl::not_null<phys_iommu *> iommu, value_type val) noexcept
	{ return iommu->write_32(offset, val); }

	namespace ma
	{
		constexpr const auto mask = 0xFFFFFFFCULL;
		constexpr const auto from = 2ULL;
		constexpr const auto name = "message_address";

		inline auto get(const gsl::not_null<phys_iommu *> iommu) noexcept
		{ return get_bits(iommu->read_32(offset), mask) >> from; }

		inline auto get(const value_type &ieaddr_reg) noexcept
		{ return get_bits(ieaddr_reg, mask) >> from; }

		inline void set(const gsl::not_null<phys_iommu *> iommu, uint64_t val) noexcept
		{ set(iommu, set_bits(iommu->read_32(offset), mask, val << from)); }

		inline void set(value_type &ieaddr_reg, uint64_t val) noexcept
		{ ieaddr_reg = set_bits(ieaddr_reg, mask, val << from); }

		inline void dump(int level, const value_type &ieaddr_reg, std::string *msg = nullptr)
		{ bfdebug_subnhex(level, name, get(ieaddr_reg), msg); }
	}

	inline void dump(int level, const value_type &ieaddr_reg, std::string *msg = nullptr)
	{
		bfdebug_nhex(level, name, ieaddr_reg, msg);

		ma::dump(level, ieaddr_reg, msg);
	}

	inline void dump(int level, const gsl::not_null<phys_iommu *> iommu, std::string *msg = nullptr)
	{
		auto reg_val = get(iommu);
		dump(level, reg_val, msg);
	}
}

namespace ieuaddr_reg
{
	constexpr const auto name = "invalidation_event_upper_address_register";
	constexpr const auto offset = 0x0ac;

	using value_type = uint32_t;

	inline auto get(const gsl::not_null<phys_iommu *> iommu) noexcept
	{ return iommu->read_32(offset); }

	inline auto set(const gsl::not_null<phys_iommu *> iommu, value_type val) noexcept
	{ return iommu->write_32(offset, val); }

	namespace mua
	{
		constexpr const auto mask = 0xFFFFFFFFULL;
		constexpr const auto from = 0ULL;
		constexpr const auto name = "message_upper_address";

		inline auto get(const gsl::not_null<phys_iommu *> iommu) noexcept
		{ return get_bits(iommu->read_32(offset), mask) >> from; }

		inline auto get(const value_type &ieuaddr_reg) noexcept
		{ return get_bits(ieuaddr_reg, mask) >> from; }

		inline void set(const gsl::not_null<phys_iommu *> iommu, uint64_t val) noexcept
		{ set(iommu, set_bits(iommu->read_32(offset), mask, val << from)); }

		inline void set(value_type &ieuaddr_reg, uint64_t val) noexcept
		{ ieuaddr_reg = set_bits(ieuaddr_reg, mask, val << from); }

		inline void dump(int level, const value_type &ieuaddr_reg, std::string *msg = nullptr)
		{ bfdebug_subnhex(level, name, get(ieuaddr_reg), msg); }
	}

	inline void dump(int level, const value_type &ieuaddr_reg, std::string *msg = nullptr)
	{
		bfdebug_nhex(level, name, ieuaddr_reg, msg);

		mua::dump(level, ieuaddr_reg, msg);
	}

	inline void dump(int level, const gsl::not_null<phys_iommu *> iommu, std::string *msg = nullptr)
	{
		auto reg_val = get(iommu);
		dump(level, reg_val, msg);
	}
}

namespace irta_reg
{
	constexpr const auto name = "interrupt_remapping_table_address_register";
	constexpr const auto offset = 0x0b8;

	using value_type = uint64_t;

	inline auto get(const gsl::not_null<phys_iommu *> iommu) noexcept
	{ return iommu->read_64(offset); }

	inline auto set(const gsl::not_null<phys_iommu *> iommu, value_type val) noexcept
	{ return iommu->write_64(offset, val); }

	namespace s
	{
		constexpr const auto mask = 0xFULL;
		constexpr const auto from = 0ULL;
		constexpr const auto name = "size";

		inline auto get(const gsl::not_null<phys_iommu *> iommu) noexcept
		{ return get_bits(iommu->read_64(offset), mask) >> from; }

		inline auto get(const value_type &irta_reg) noexcept
		{ return get_bits(irta_reg, mask) >> from; }

		inline void set(const gsl::not_null<phys_iommu *> iommu, uint64_t val) noexcept
		{ set(iommu, set_bits(iommu->read_64(offset), mask, val << from)); }

		inline void set(value_type &irta_reg, uint64_t val) noexcept
		{ irta_reg = set_bits(irta_reg, mask, val << from); }

		inline void dump(int level, const value_type &irta_reg, std::string *msg = nullptr)
		{ bfdebug_subnhex(level, name, get(irta_reg), msg); }
	}

	namespace eime
	{
		constexpr const auto mask = 0x800ULL;
		constexpr const auto from = 11ULL;
		constexpr const auto name = "extended_interrupt_mode_enable";

		inline auto is_enabled(const gsl::not_null<phys_iommu *> iommu) noexcept
		{ return is_bit_set(get(iommu), from); }

		inline auto is_enabled(const value_type &irta_reg) noexcept
		{ return is_bit_set(irta_reg, from); }

		inline auto is_disabled(const gsl::not_null<phys_iommu *> iommu) noexcept
		{ return !is_bit_set(get(iommu), from); }

		inline auto is_disabled(const value_type &irta_reg) noexcept
		{ return !is_bit_set(irta_reg, from); }

		inline void enable(const gsl::not_null<phys_iommu *> iommu) noexcept
		{ set(iommu, set_bit(get(iommu), from)); }

		inline void enable(value_type &irta_reg) noexcept
		{ irta_reg = set_bit(irta_reg, from); }

		inline void disable(const gsl::not_null<phys_iommu *> iommu) noexcept
		{ set(iommu, clear_bit(get(iommu), from)); }

		inline void disable(value_type &irta_reg) noexcept
		{ irta_reg = clear_bit(irta_reg, from); }

		inline void dump(int level, const value_type &irta_reg, std::string *msg = nullptr)
		{ bfdebug_subbool(level, name, is_enabled(irta_reg), msg); }
	}

	namespace irta
	{
		constexpr const auto mask = 0xFFFFFFFFFFFFF000ULL;
		constexpr const auto from = 12ULL;
		constexpr const auto name = "interrupt_remapping_table_address";

		inline auto get(const gsl::not_null<phys_iommu *> iommu) noexcept
		{ return get_bits(iommu->read_64(offset), mask) >> from; }

		inline auto get(const value_type &irta_reg) noexcept
		{ return get_bits(irta_reg, mask) >> from; }

		inline void set(const gsl::not_null<phys_iommu *> iommu, uint64_t val) noexcept
		{ set(iommu, set_bits(iommu->read_64(offset), mask, val << from)); }

		inline void set(value_type &irta_reg, uint64_t val) noexcept
		{ irta_reg = set_bits(irta_reg, mask, val << from); }

		inline void dump(int level, const value_type &irta_reg, std::string *msg = nullptr)
		{ bfdebug_subnhex(level, name, get(irta_reg), msg); }
	}

	inline void dump(int level, const value_type &irta_reg, std::string *msg = nullptr)
	{
		bfdebug_nhex(level, name, irta_reg, msg);

		s::dump(level, irta_reg, msg);
		eime::dump(level, irta_reg, msg);
		irta::dump(level, irta_reg, msg);
	}

	inline void dump(int level, const gsl::not_null<phys_iommu *> iommu, std::string *msg = nullptr)
	{
		auto reg_val = get(iommu);
		dump(level, reg_val, msg);
	}
}

namespace pqh_reg
{
	constexpr const auto name = "page_request_queue_head_register";
	constexpr const auto offset = 0x0c0;

	using value_type = uint64_t;

	inline auto get(const gsl::not_null<phys_iommu *> iommu) noexcept
	{ return iommu->read_64(offset); }

	inline auto set(const gsl::not_null<phys_iommu *> iommu, value_type val) noexcept
	{ return iommu->write_64(offset, val); }

	namespace pqh
	{
		constexpr const auto mask = 0x7FFF0ULL;
		constexpr const auto from = 4ULL;
		constexpr const auto name = "page_queue_head";

		inline auto get(const gsl::not_null<phys_iommu *> iommu) noexcept
		{ return get_bits(iommu->read_64(offset), mask) >> from; }

		inline auto get(const value_type &pqh_reg) noexcept
		{ return get_bits(pqh_reg, mask) >> from; }

		inline void set(const gsl::not_null<phys_iommu *> iommu, uint64_t val) noexcept
		{ set(iommu, set_bits(iommu->read_64(offset), mask, val << from)); }

		inline void set(value_type &pqh_reg, uint64_t val) noexcept
		{ pqh_reg = set_bits(pqh_reg, mask, val << from); }

		inline void dump(int level, const value_type &pqh_reg, std::string *msg = nullptr)
		{ bfdebug_subnhex(level, name, get(pqh_reg), msg); }
	}

	inline void dump(int level, const value_type &pqh_reg, std::string *msg = nullptr)
	{
		bfdebug_nhex(level, name, pqh_reg, msg);

		pqh::dump(level, pqh_reg, msg);
	}

	inline void dump(int level, const gsl::not_null<phys_iommu *> iommu, std::string *msg = nullptr)
	{
		auto reg_val = get(iommu);
		dump(level, reg_val, msg);
	}
}

namespace pqt_reg
{
	constexpr const auto name = "page_request_queue_tail_register";
	constexpr const auto offset = 0x0c8;

	using value_type = uint64_t;

	inline auto get(const gsl::not_null<phys_iommu *> iommu) noexcept
	{ return iommu->read_64(offset); }

	inline auto set(const gsl::not_null<phys_iommu *> iommu, value_type val) noexcept
	{ return iommu->write_64(offset, val); }

	namespace pqt
	{
		constexpr const auto mask = 0x7FFF0ULL;
		constexpr const auto from = 4ULL;
		constexpr const auto name = "page_queue_tail";

		inline auto get(const gsl::not_null<phys_iommu *> iommu) noexcept
		{ return get_bits(iommu->read_64(offset), mask) >> from; }

		inline auto get(const value_type &pqt_reg) noexcept
		{ return get_bits(pqt_reg, mask) >> from; }

		inline void set(const gsl::not_null<phys_iommu *> iommu, uint64_t val) noexcept
		{ set(iommu, set_bits(iommu->read_64(offset), mask, val << from)); }

		inline void set(value_type &pqt_reg, uint64_t val) noexcept
		{ pqt_reg = set_bits(pqt_reg, mask, val << from); }

		inline void dump(int level, const value_type &pqt_reg, std::string *msg = nullptr)
		{ bfdebug_subnhex(level, name, get(pqt_reg), msg); }
	}

	inline void dump(int level, const value_type &pqt_reg, std::string *msg = nullptr)
	{
		bfdebug_nhex(level, name, pqt_reg, msg);

		pqt::dump(level, pqt_reg, msg);
	}

	inline void dump(int level, const gsl::not_null<phys_iommu *> iommu, std::string *msg = nullptr)
	{
		auto reg_val = get(iommu);
		dump(level, reg_val, msg);
	}
}

namespace pqa_reg
{
	constexpr const auto name = "page_request_queue_address_register";
	constexpr const auto offset = 0x0d0;

	using value_type = uint64_t;

	inline auto get(const gsl::not_null<phys_iommu *> iommu) noexcept
	{ return iommu->read_64(offset); }

	inline auto set(const gsl::not_null<phys_iommu *> iommu, value_type val) noexcept
	{ return iommu->write_64(offset, val); }

	namespace pqs
	{
		constexpr const auto mask = 0x7ULL;
		constexpr const auto from = 0ULL;
		constexpr const auto name = "page_queue_size";

		inline auto get(const gsl::not_null<phys_iommu *> iommu) noexcept
		{ return get_bits(iommu->read_64(offset), mask) >> from; }

		inline auto get(const value_type &pqa_reg) noexcept
		{ return get_bits(pqa_reg, mask) >> from; }

		inline void set(const gsl::not_null<phys_iommu *> iommu, uint64_t val) noexcept
		{ set(iommu, set_bits(iommu->read_64(offset), mask, val << from)); }

		inline void set(value_type &pqa_reg, uint64_t val) noexcept
		{ pqa_reg = set_bits(pqa_reg, mask, val << from); }

		inline void dump(int level, const value_type &pqa_reg, std::string *msg = nullptr)
		{ bfdebug_subnhex(level, name, get(pqa_reg), msg); }
	}

	namespace pqa
	{
		constexpr const auto mask = 0xFFFFFFFFFFFFF000ULL;
		constexpr const auto from = 12ULL;
		constexpr const auto name = "page_request_queue_base_address";

		inline auto get(const gsl::not_null<phys_iommu *> iommu) noexcept
		{ return get_bits(iommu->read_64(offset), mask) >> from; }

		inline auto get(const value_type &pqa_reg) noexcept
		{ return get_bits(pqa_reg, mask) >> from; }

		inline void set(const gsl::not_null<phys_iommu *> iommu, uint64_t val) noexcept
		{ set(iommu, set_bits(iommu->read_64(offset), mask, val << from)); }

		inline void set(value_type &pqa_reg, uint64_t val) noexcept
		{ pqa_reg = set_bits(pqa_reg, mask, val << from); }

		inline void dump(int level, const value_type &pqa_reg, std::string *msg = nullptr)
		{ bfdebug_subnhex(level, name, get(pqa_reg), msg); }
	}

	inline void dump(int level, const value_type &pqa_reg, std::string *msg = nullptr)
	{
		bfdebug_nhex(level, name, pqa_reg, msg);

		pqs::dump(level, pqa_reg, msg);
		pqa::dump(level, pqa_reg, msg);
	}

	inline void dump(int level, const gsl::not_null<phys_iommu *> iommu, std::string *msg = nullptr)
	{
		auto reg_val = get(iommu);
		dump(level, reg_val, msg);
	}
}

namespace prs_reg
{
	constexpr const auto name = "page_request_status_register";
	constexpr const auto offset = 0x0dc;

	using value_type = uint32_t;

	inline auto get(const gsl::not_null<phys_iommu *> iommu) noexcept
	{ return iommu->read_32(offset); }

	inline auto set(const gsl::not_null<phys_iommu *> iommu, value_type val) noexcept
	{ return iommu->write_32(offset, val); }

	namespace ppr
	{
		constexpr const auto mask = 0x1ULL;
		constexpr const auto from = 0ULL;
		constexpr const auto name = "pending_page_request";

		inline auto is_enabled(const gsl::not_null<phys_iommu *> iommu) noexcept
		{ return is_bit_set(get(iommu), from); }

		inline auto is_enabled(const value_type &prs_reg) noexcept
		{ return is_bit_set(prs_reg, from); }

		inline auto is_disabled(const gsl::not_null<phys_iommu *> iommu) noexcept
		{ return !is_bit_set(get(iommu), from); }

		inline auto is_disabled(const value_type &prs_reg) noexcept
		{ return !is_bit_set(prs_reg, from); }

		inline void enable(const gsl::not_null<phys_iommu *> iommu) noexcept
		{ set(iommu, set_bit(get(iommu), from)); }

		inline void enable(value_type &prs_reg) noexcept
		{ prs_reg = set_bit(prs_reg, from); }

		inline void dump(int level, const value_type &prs_reg, std::string *msg = nullptr)
		{ bfdebug_subbool(level, name, is_enabled(prs_reg), msg); }
	}

	inline void dump(int level, const value_type &prs_reg, std::string *msg = nullptr)
	{
		bfdebug_nhex(level, name, prs_reg, msg);

		ppr::dump(level, prs_reg, msg);
	}

	inline void dump(int level, const gsl::not_null<phys_iommu *> iommu, std::string *msg = nullptr)
	{
		auto reg_val = get(iommu);
		dump(level, reg_val, msg);
	}
}

namespace pectl_reg
{
	constexpr const auto name = "page_request_event_control_register";
	constexpr const auto preserved_mask = 0x3FFFFFFF;
	constexpr const auto offset = 0x0e0;

	using value_type = uint32_t;

	inline auto get(const gsl::not_null<phys_iommu *> iommu) noexcept
	{ return iommu->read_32(offset); }

	inline auto set(const gsl::not_null<phys_iommu *> iommu, value_type val) noexcept
	{ return iommu->write_32_preserved(offset, val, preserved_mask); }

	namespace ip
	{
		constexpr const auto mask = 0x40000000ULL;
		constexpr const auto from = 30ULL;
		constexpr const auto name = "interrupt_pending";

		inline auto is_enabled(const gsl::not_null<phys_iommu *> iommu) noexcept
		{ return is_bit_set(get(iommu), from); }

		inline auto is_enabled(const value_type &pectl_reg) noexcept
		{ return is_bit_set(pectl_reg, from); }

		inline auto is_disabled(const gsl::not_null<phys_iommu *> iommu) noexcept
		{ return !is_bit_set(get(iommu), from); }

		inline auto is_disabled(const value_type &pectl_reg) noexcept
		{ return !is_bit_set(pectl_reg, from); }

		inline void dump(int level, const value_type &pectl_reg, std::string *msg = nullptr)
		{ bfdebug_subbool(level, name, is_enabled(pectl_reg), msg); }
	}

	namespace im
	{
		constexpr const auto mask = 0x80000000ULL;
		constexpr const auto from = 31ULL;
		constexpr const auto name = "interrupt_mask";

		inline auto is_enabled(const gsl::not_null<phys_iommu *> iommu) noexcept
		{ return is_bit_set(get(iommu), from); }

		inline auto is_enabled(const value_type &pectl_reg) noexcept
		{ return is_bit_set(pectl_reg, from); }

		inline auto is_disabled(const gsl::not_null<phys_iommu *> iommu) noexcept
		{ return !is_bit_set(get(iommu), from); }

		inline auto is_disabled(const value_type &pectl_reg) noexcept
		{ return !is_bit_set(pectl_reg, from); }

		inline void enable(const gsl::not_null<phys_iommu *> iommu) noexcept
		{ set(iommu, set_bit(get(iommu), from)); }

		inline void enable(value_type &pectl_reg) noexcept
		{ pectl_reg = set_bit(pectl_reg, from); }

		inline void disable(const gsl::not_null<phys_iommu *> iommu) noexcept
		{ set(iommu, clear_bit(get(iommu), from)); }

		inline void disable(value_type &pectl_reg) noexcept
		{ pectl_reg = clear_bit(pectl_reg, from); }

		inline void dump(int level, const value_type &pectl_reg, std::string *msg = nullptr)
		{ bfdebug_subbool(level, name, is_enabled(pectl_reg), msg); }
	}

	inline void dump(int level, const value_type &pectl_reg, std::string *msg = nullptr)
	{
		bfdebug_nhex(level, name, pectl_reg, msg);

		ip::dump(level, pectl_reg, msg);
		im::dump(level, pectl_reg, msg);
	}

	inline void dump(int level, const gsl::not_null<phys_iommu *> iommu, std::string *msg = nullptr)
	{
		auto reg_val = get(iommu);
		dump(level, reg_val, msg);
	}
}

namespace pedata_reg
{
	constexpr const auto name = "page_request_event_data_register";
	constexpr const auto offset = 0x0e4;

	using value_type = uint32_t;

	inline auto get(const gsl::not_null<phys_iommu *> iommu) noexcept
	{ return iommu->read_32(offset); }

	inline auto set(const gsl::not_null<phys_iommu *> iommu, value_type val) noexcept
	{ return iommu->write_32(offset, val); }

	namespace imd
	{
		constexpr const auto mask = 0xFFFFULL;
		constexpr const auto from = 0ULL;
		constexpr const auto name = "interrupt_message_data";

		inline auto get(const gsl::not_null<phys_iommu *> iommu) noexcept
		{ return get_bits(iommu->read_32(offset), mask) >> from; }

		inline auto get(const value_type &pedata_reg) noexcept
		{ return get_bits(pedata_reg, mask) >> from; }

		inline void set(const gsl::not_null<phys_iommu *> iommu, uint64_t val) noexcept
		{ set(iommu, set_bits(iommu->read_32(offset), mask, val << from)); }

		inline void set(value_type &pedata_reg, uint64_t val) noexcept
		{ pedata_reg = set_bits(pedata_reg, mask, val << from); }

		inline void dump(int level, const value_type &pedata_reg, std::string *msg = nullptr)
		{ bfdebug_subnhex(level, name, get(pedata_reg), msg); }
	}

	namespace interrupt_message_data
	{
		constexpr const auto mask = 0xFFFF0000ULL;
		constexpr const auto from = 16ULL;
		constexpr const auto name = "extended_interrupt_message_data";

		inline auto get(const gsl::not_null<phys_iommu *> iommu) noexcept
		{ return get_bits(iommu->read_32(offset), mask) >> from; }

		inline auto get(const value_type &pedata_reg) noexcept
		{ return get_bits(pedata_reg, mask) >> from; }

		inline void set(const gsl::not_null<phys_iommu *> iommu, uint64_t val) noexcept
		{ set(iommu, set_bits(iommu->read_32(offset), mask, val << from)); }

		inline void set(value_type &pedata_reg, uint64_t val) noexcept
		{ pedata_reg = set_bits(pedata_reg, mask, val << from); }

		inline void dump(int level, const value_type &pedata_reg, std::string *msg = nullptr)
		{ bfdebug_subnhex(level, name, get(pedata_reg), msg); }
	}

	inline void dump(int level, const value_type &pedata_reg, std::string *msg = nullptr)
	{
		bfdebug_nhex(level, name, pedata_reg, msg);

		imd::dump(level, pedata_reg, msg);
		interrupt_message_data::dump(level, pedata_reg, msg);
	}

	inline void dump(int level, const gsl::not_null<phys_iommu *> iommu, std::string *msg = nullptr)
	{
		auto reg_val = get(iommu);
		dump(level, reg_val, msg);
	}
}

namespace peaddr_reg
{
	constexpr const auto name = "page_request_event_address_register";
	constexpr const auto offset = 0x0e8;

	using value_type = uint32_t;

	inline auto get(const gsl::not_null<phys_iommu *> iommu) noexcept
	{ return iommu->read_32(offset); }

	inline auto set(const gsl::not_null<phys_iommu *> iommu, value_type val) noexcept
	{ return iommu->write_32(offset, val); }

	namespace ma
	{
		constexpr const auto mask = 0xFFFFFFFCULL;
		constexpr const auto from = 2ULL;
		constexpr const auto name = "message_address";

		inline auto get(const gsl::not_null<phys_iommu *> iommu) noexcept
		{ return get_bits(iommu->read_32(offset), mask) >> from; }

		inline auto get(const value_type &peaddr_reg) noexcept
		{ return get_bits(peaddr_reg, mask) >> from; }

		inline void set(const gsl::not_null<phys_iommu *> iommu, uint64_t val) noexcept
		{ set(iommu, set_bits(iommu->read_32(offset), mask, val << from)); }

		inline void set(value_type &peaddr_reg, uint64_t val) noexcept
		{ peaddr_reg = set_bits(peaddr_reg, mask, val << from); }

		inline void dump(int level, const value_type &peaddr_reg, std::string *msg = nullptr)
		{ bfdebug_subnhex(level, name, get(peaddr_reg), msg); }
	}

	inline void dump(int level, const value_type &peaddr_reg, std::string *msg = nullptr)
	{
		bfdebug_nhex(level, name, peaddr_reg, msg);

		ma::dump(level, peaddr_reg, msg);
	}

	inline void dump(int level, const gsl::not_null<phys_iommu *> iommu, std::string *msg = nullptr)
	{
		auto reg_val = get(iommu);
		dump(level, reg_val, msg);
	}
}

namespace peuaddr_reg
{
	constexpr const auto name = "page_request_event_upper_address_register";
	constexpr const auto offset = 0x0ec;

	using value_type = uint32_t;

	inline auto get(const gsl::not_null<phys_iommu *> iommu) noexcept
	{ return iommu->read_32(offset); }

	inline auto set(const gsl::not_null<phys_iommu *> iommu, value_type val) noexcept
	{ return iommu->write_32(offset, val); }

	namespace mua
	{
		constexpr const auto mask = 0xFFFFFFFFULL;
		constexpr const auto from = 0ULL;
		constexpr const auto name = "message_upper_address";

		inline auto get(const gsl::not_null<phys_iommu *> iommu) noexcept
		{ return get_bits(iommu->read_32(offset), mask) >> from; }

		inline auto get(const value_type &peuaddr_reg) noexcept
		{ return get_bits(peuaddr_reg, mask) >> from; }

		inline void set(const gsl::not_null<phys_iommu *> iommu, uint64_t val) noexcept
		{ set(iommu, set_bits(iommu->read_32(offset), mask, val << from)); }

		inline void set(value_type &peuaddr_reg, uint64_t val) noexcept
		{ peuaddr_reg = set_bits(peuaddr_reg, mask, val << from); }

		inline void dump(int level, const value_type &peuaddr_reg, std::string *msg = nullptr)
		{ bfdebug_subnhex(level, name, get(peuaddr_reg), msg); }
	}

	inline void dump(int level, const value_type &peuaddr_reg, std::string *msg = nullptr)
	{
		bfdebug_nhex(level, name, peuaddr_reg, msg);

		mua::dump(level, peuaddr_reg, msg);
	}

	inline void dump(int level, const gsl::not_null<phys_iommu *> iommu, std::string *msg = nullptr)
	{
		auto reg_val = get(iommu);
		dump(level, reg_val, msg);
	}
}

namespace mtrrcap_reg
{
	constexpr const auto name = "mtrr_capability_register";
	constexpr const auto offset = 0x100;

	using value_type = uint64_t;

	inline auto get(const gsl::not_null<phys_iommu *> iommu) noexcept
	{ return iommu->read_64(offset); }

	namespace vcnt
	{
		constexpr const auto mask = 0xFFULL;
		constexpr const auto from = 0ULL;
		constexpr const auto name = "variable_mtrr_countr";

		inline auto get(const gsl::not_null<phys_iommu *> iommu) noexcept
		{ return get_bits(iommu->read_64(offset), mask) >> from; }

		inline auto get(const value_type &mtrrcap_reg) noexcept
		{ return get_bits(mtrrcap_reg, mask) >> from; }

		inline void dump(int level, const value_type &mtrrcap_reg, std::string *msg = nullptr)
		{ bfdebug_subnhex(level, name, get(mtrrcap_reg), msg); }
	}

	namespace fix
	{
		constexpr const auto mask = 0x100ULL;
		constexpr const auto from = 8ULL;
		constexpr const auto name = "fixed_range_mtrrs_supported";

		inline auto is_enabled(const gsl::not_null<phys_iommu *> iommu) noexcept
		{ return is_bit_set(get(iommu), from); }

		inline auto is_enabled(const value_type &mtrrcap_reg) noexcept
		{ return is_bit_set(mtrrcap_reg, from); }

		inline auto is_disabled(const gsl::not_null<phys_iommu *> iommu) noexcept
		{ return !is_bit_set(get(iommu), from); }

		inline auto is_disabled(const value_type &mtrrcap_reg) noexcept
		{ return !is_bit_set(mtrrcap_reg, from); }

		inline void dump(int level, const value_type &mtrrcap_reg, std::string *msg = nullptr)
		{ bfdebug_subbool(level, name, is_enabled(mtrrcap_reg), msg); }
	}

	namespace wc
	{
		constexpr const auto mask = 0x400ULL;
		constexpr const auto from = 10ULL;
		constexpr const auto name = "write_combining";

		inline auto is_enabled(const gsl::not_null<phys_iommu *> iommu) noexcept
		{ return is_bit_set(get(iommu), from); }

		inline auto is_enabled(const value_type &mtrrcap_reg) noexcept
		{ return is_bit_set(mtrrcap_reg, from); }

		inline auto is_disabled(const gsl::not_null<phys_iommu *> iommu) noexcept
		{ return !is_bit_set(get(iommu), from); }

		inline auto is_disabled(const value_type &mtrrcap_reg) noexcept
		{ return !is_bit_set(mtrrcap_reg, from); }

		inline void dump(int level, const value_type &mtrrcap_reg, std::string *msg = nullptr)
		{ bfdebug_subbool(level, name, is_enabled(mtrrcap_reg), msg); }
	}

	inline void dump(int level, const value_type &mtrrcap_reg, std::string *msg = nullptr)
	{
		bfdebug_nhex(level, name, mtrrcap_reg, msg);

		vcnt::dump(level, mtrrcap_reg, msg);
		fix::dump(level, mtrrcap_reg, msg);
		wc::dump(level, mtrrcap_reg, msg);
	}

	inline void dump(int level, const gsl::not_null<phys_iommu *> iommu, std::string *msg = nullptr)
	{
		auto reg_val = get(iommu);
		dump(level, reg_val, msg);
	}
}

namespace mtrrdef_reg
{
	constexpr const auto name = "mtrr_default_type_register";
	constexpr const auto offset = 0x108;

	using value_type = uint64_t;

	inline auto get(const gsl::not_null<phys_iommu *> iommu) noexcept
	{ return iommu->read_64(offset); }

	inline auto set(const gsl::not_null<phys_iommu *> iommu, value_type val) noexcept
	{ return iommu->write_64(offset, val); }

	namespace type
	{
		constexpr const auto mask = 0xFFULL;
		constexpr const auto from = 0ULL;
		constexpr const auto name = "default_memory_type";

		inline auto get(const gsl::not_null<phys_iommu *> iommu) noexcept
		{ return get_bits(iommu->read_64(offset), mask) >> from; }

		inline auto get(const value_type &mtrrdef_reg) noexcept
		{ return get_bits(mtrrdef_reg, mask) >> from; }

		inline void dump(int level, const value_type &mtrrdef_reg, std::string *msg = nullptr)
		{ bfdebug_subnhex(level, name, get(mtrrdef_reg), msg); }
	}

	namespace fe
	{
		constexpr const auto mask = 0x400ULL;
		constexpr const auto from = 10ULL;
		constexpr const auto name = "fixed_range_mtrr_enable";

		inline auto is_enabled(const gsl::not_null<phys_iommu *> iommu) noexcept
		{ return is_bit_set(get(iommu), from); }

		inline auto is_enabled(const value_type &mtrrdef_reg) noexcept
		{ return is_bit_set(mtrrdef_reg, from); }

		inline auto is_disabled(const gsl::not_null<phys_iommu *> iommu) noexcept
		{ return !is_bit_set(get(iommu), from); }

		inline auto is_disabled(const value_type &mtrrdef_reg) noexcept
		{ return !is_bit_set(mtrrdef_reg, from); }

		inline void enable(const gsl::not_null<phys_iommu *> iommu) noexcept
		{ set(iommu, set_bit(get(iommu), from)); }

		inline void enable(value_type &mtrrdef_reg) noexcept
		{ mtrrdef_reg = set_bit(mtrrdef_reg, from); }

		inline void disable(const gsl::not_null<phys_iommu *> iommu) noexcept
		{ set(iommu, clear_bit(get(iommu), from)); }

		inline void disable(value_type &mtrrdef_reg) noexcept
		{ mtrrdef_reg = clear_bit(mtrrdef_reg, from); }

		inline void dump(int level, const value_type &mtrrdef_reg, std::string *msg = nullptr)
		{ bfdebug_subbool(level, name, is_enabled(mtrrdef_reg), msg); }
	}

	namespace e
	{
		constexpr const auto mask = 0x800ULL;
		constexpr const auto from = 11ULL;
		constexpr const auto name = "mtrr_enable";

		inline auto is_enabled(const gsl::not_null<phys_iommu *> iommu) noexcept
		{ return is_bit_set(get(iommu), from); }

		inline auto is_enabled(const value_type &mtrrdef_reg) noexcept
		{ return is_bit_set(mtrrdef_reg, from); }

		inline auto is_disabled(const gsl::not_null<phys_iommu *> iommu) noexcept
		{ return !is_bit_set(get(iommu), from); }

		inline auto is_disabled(const value_type &mtrrdef_reg) noexcept
		{ return !is_bit_set(mtrrdef_reg, from); }

		inline void enable(const gsl::not_null<phys_iommu *> iommu) noexcept
		{ set(iommu, set_bit(get(iommu), from)); }

		inline void enable(value_type &mtrrdef_reg) noexcept
		{ mtrrdef_reg = set_bit(mtrrdef_reg, from); }

		inline void disable(const gsl::not_null<phys_iommu *> iommu) noexcept
		{ set(iommu, clear_bit(get(iommu), from)); }

		inline void disable(value_type &mtrrdef_reg) noexcept
		{ mtrrdef_reg = clear_bit(mtrrdef_reg, from); }

		inline void dump(int level, const value_type &mtrrdef_reg, std::string *msg = nullptr)
		{ bfdebug_subbool(level, name, is_enabled(mtrrdef_reg), msg); }
	}

	inline void dump(int level, const value_type &mtrrdef_reg, std::string *msg = nullptr)
	{
		bfdebug_nhex(level, name, mtrrdef_reg, msg);

		type::dump(level, mtrrdef_reg, msg);
		fe::dump(level, mtrrdef_reg, msg);
		e::dump(level, mtrrdef_reg, msg);
	}

	inline void dump(int level, const gsl::not_null<phys_iommu *> iommu, std::string *msg = nullptr)
	{
		auto reg_val = get(iommu);
		dump(level, reg_val, msg);
	}
}

}
}
}

// *INDENT-ON*

#endif
