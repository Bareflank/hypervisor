//
// Copyright (C) 2019 Assured Information Security, Inc.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

#include <bfdebug.h>

#include <intrinsics.h>
#include <hve/arch/intel_x64/mtrrs.h>

namespace bfvmm::intel_x64
{

static inline auto
physbase_to_base(uint64_t physbase)
{
    return physbase << 12;
}

static inline auto
physmask_to_size(uint64_t physmask)
{
    static auto addr_size = ::x64::cpuid::addr_size::phys::get();
    return ((~(physmask << 12)) & ((1ULL << addr_size) - 1U)) + 1U;
}

mtrrs *
mtrrs::instance() noexcept
{
    static mtrrs self;
    return &self;
}

void
mtrrs::dump(int level, const char *str) const
{
    bfdebug_transaction(level, [&](std::string * msg) {
        bfdebug_lnbr(level, msg);
        bfdebug_info(level, str, msg);
        bfdebug_brk2(level, msg);

        for (uint8_t i = 0U; i < m_num; i++) {
            auto &range = m_ranges.at(i);

            bfdebug_info(level, "range", msg);

            switch (range.type) {
                case ept::mmap::memory_type::write_back:
                    bfdebug_subtext(level, "type", "write_back", msg);
                    break;

                case ept::mmap::memory_type::write_protected:
                    bfdebug_subtext(level, "type", "write_protected", msg);
                    break;

                case ept::mmap::memory_type::write_through:
                    bfdebug_subtext(level, "type", "write_through", msg);
                    break;

                case ept::mmap::memory_type::write_combining:
                    bfdebug_subtext(level, "type", "write_combining", msg);
                    break;

                default:
                    bfdebug_subtext(level, "type", "uncacheable", msg);
                    break;
            }

            bfdebug_subnhex(level, "base", range.base, msg);
            bfdebug_subnhex(level, "size", range.size, msg);
        }
    });
}

// Constructor
//
// The constructor first gets both the fixed and variable MTRRs and adds all of
// the ranges to the ranges list. From there, the ranges are corrected to
// remove any issues with the ranges being non-continuous or overlapping. Once
// the ranges are corrected, the last step is to add an overlapping range for
// all of memory that defines the default memory type and then correct the
// ranges again to ensure the overlapping range is removed. The result is ever
// single phyiscal address is accounted for my the range list, which makes
// processing code like EPT much easier.
//
// Note that if an error occurs, we clear out the ranges list, which has the
// effect of telling code like EPT that something went wrong, and that code
// can expect at least one range, which is the default memory type.
//
mtrrs::mtrrs() noexcept
{
    using namespace ::intel_x64::msrs;

    guard_exceptions([&]() {
        if (ia32_mtrr_def_type::mtrr_enable::is_disabled()) {
            this->add_range({
                ept::mmap::memory_type::write_back, 0, 0xFFFFFFFFFFFFFFFF
            });

            return;
        }

        this->get_fixed_ranges();
        this->get_variable_ranges();

        dump(1, "original mtrrs");

        while (!this->make_continuous())
        { }

        ept::mmap::memory_type type;
        switch (ia32_mtrr_def_type::type::get()) {
            case ::intel_x64::msrs::ia32_mtrr_def_type::type::write_back:
                type = ept::mmap::memory_type::write_back;
                break;

            case ::intel_x64::msrs::ia32_mtrr_def_type::type::write_protected:
                type = ept::mmap::memory_type::write_protected;
                break;

            case ::intel_x64::msrs::ia32_mtrr_def_type::type::write_through:
                type = ept::mmap::memory_type::write_through;
                break;

            case ::intel_x64::msrs::ia32_mtrr_def_type::type::write_combining:
                type = ept::mmap::memory_type::write_combining;
                break;

            default:
                type = ept::mmap::memory_type::uncacheable;
                break;
        }

        this->add_range({
            type, 0, 0xFFFFFFFFFFFFFFFF
        });

        while (!this->make_continuous())
        { }

        dump(1, "corrected mtrrs");
    },
    [&] {
        for (auto &range : m_ranges)
        {
            range = {};
        }

        m_num = 0;
    });
}

void
mtrrs::get_fixed_ranges()
{
    this->add_range({
        ept::mmap::memory_type::uncacheable,
        0,
        0x100000
    });
}

void
mtrrs::get_variable_ranges()
{
    using namespace ::intel_x64::msrs;

    auto vcnt = ::x64::msrs::ia32_mtrrcap::vcnt::get();
    auto base_addr = ia32_mtrr_physbase::addr;
    auto mask_addr = ia32_mtrr_physmask::addr;

    for (uint32_t i = 0U; i < vcnt * 2U; i += 2U) {

        auto ia32_mtrr_physbase = get(base_addr + i);
        auto ia32_mtrr_physmask = get(mask_addr + i);

        if (ia32_mtrr_physmask::valid::is_disabled(ia32_mtrr_physmask)) {
            continue;
        }

        this->add_range(ia32_mtrr_physbase, ia32_mtrr_physmask);
    }
}

// Is Subset
//
// A set is a subset of a superset if the subset is completely contained
// within the superset. We support subsets, we do not support intersecting
// sets that are not subsets, which is why this is important.
//
// { range1 [range2] }
//
// @param range1 superset
// @param range2 test set
// @return returns true if range2 is a subset of range1, false otherwise.
//
static auto is_subset(
    const mtrrs::range_t &range1,
    const mtrrs::range_t &range2)
{
    return
        range2.base >= range1.base &&
        range2.base + range2.size <= range1.base + range1.size;
}

// Is Intersecting
//
// A set is intersecting another set if the set touches the other set in some
// way. In our case, we only care about non-inclusive intersections (i.e. the
// edge of a set does count as intersection). If a set is intersection, but
// is not a subset, we have an MTRR configuration we do not support.
//
// { range1 [range2 } ]
//
// @param range1 superset
// @param range2 test set
// @return returns true if range2 is a subset of range1, false otherwise.
//
static auto is_intersecting(
    const mtrrs::range_t &range1,
    const mtrrs::range_t &range2)
{
    return
        range2.base > range1.base &&
        range2.base < range1.base + range1.size;
}

// Compare
//
// The following function compares two ranges. The goal of the compare function
// is to support sorting in ascending order. If both ranges have the same base,
// the range with the larger size (i.e. the possible superset), gets moved to
// the left, which supports the make_continuous function WRT to how it attempts
// to detect subsets.
//
// @param range1 range to test
// @param range2 range to test
// @return returns the comparison of the two ranges
//
static auto compare(
    const mtrrs::range_t &range1,
    const mtrrs::range_t &range2)
{
    if (range1.base == range2.base) {
        return range1.size > range2.size;
    }

    return range1.base < range2.base;
}

// Make Continuous
//
// The goal of this function is to flatten the MTRRs into non-overlapping,
// continuous ranges. To do this, the function first sorts the ranges into
// ascending order and then looks for overlapping ranges. There are two
// types of overlapping ranges:
// - subsets (one range completely encapsulates the other)
// - intersecting (two ranges touch)
//
// If a range is a subset of another, we break the superset apart and then
// return from this function with "false", telling the caller to run the
// function again to continue attempting to make the ranges continuous. This
// process will repeat until all of the ranges are continuous and
// non-overlapping. If two ranges are not subsets, but are intersecting, we
// error out as this type of MTRR setup is not supported currently.
//
bool
mtrrs::make_continuous()
{
    std::sort(
        m_ranges.begin(), m_ranges.end(), compare
    );

    for (uint8_t i = 0U; i < m_num - 1U; i++) {
        auto &r1 = m_ranges.at(i);
        auto &r2 = m_ranges.at(i + 1U);

        if (is_subset(r1, r2)) {
            auto size1 = r2.base - r1.base;
            auto size2 = r1.base + r1.size - r2.base - r2.size;

            if (size1 != 0) {
                this->add_range({
                    r1.type,
                    r1.base,
                    size1
                });
            }

            if (size2 != 0) {
                this->add_range({
                    r1.type,
                    r2.base + r2.size,
                    size2
                });
            }

            r1 = {
                ept::mmap::memory_type::uncacheable,
                invalid,
                invalid
            };

            m_num--;
            return false;
        }

        if (is_intersecting(r1, r2)) {
            throw std::runtime_error("Unable to create mutually exclusive MTRRs");
        }
    }

    return true;
}

void
mtrrs::add_range(const range_t &range)
{
    expects(m_num < 255);
    expects(range.size >= ::intel_x64::ept::pt::page_size);

    m_ranges.at(m_num++) = range;
}

void
mtrrs::add_range(uint64_t ia32_mtrr_physbase, uint64_t ia32_mtrr_physmask)
{
    using namespace ::intel_x64::msrs;

    ept::mmap::memory_type type;
    switch (ia32_mtrr_physbase::type::get(ia32_mtrr_physbase)) {
        case ::intel_x64::msrs::ia32_mtrr_physbase::type::write_back:
            type = ept::mmap::memory_type::write_back;
            break;

        case ::intel_x64::msrs::ia32_mtrr_physbase::type::write_protected:
            type = ept::mmap::memory_type::write_protected;
            break;

        case ::intel_x64::msrs::ia32_mtrr_physbase::type::write_through:
            type = ept::mmap::memory_type::write_through;
            break;

        case ::intel_x64::msrs::ia32_mtrr_physbase::type::write_combining:
            type = ept::mmap::memory_type::write_combining;
            break;

        default:
            type = ept::mmap::memory_type::uncacheable;
            break;
    }

    return this->add_range({
        type,
        physbase_to_base(ia32_mtrr_physbase::physbase::get(ia32_mtrr_physbase)),
        physmask_to_size(ia32_mtrr_physmask::physmask::get(ia32_mtrr_physmask))
    });
}

}
