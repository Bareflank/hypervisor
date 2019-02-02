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

#ifndef MTRR_INTEL_X64_H
#define MTRR_INTEL_X64_H

#include "ept/mmap.h"

// -----------------------------------------------------------------------------
// Definitions
// -----------------------------------------------------------------------------

namespace bfvmm::intel_x64
{

/// MTRRs
///
/// There are two types of ranges that MTRRs specify: fixed and variable.
/// The first 1MB of physical memory is specified by the 11 fixed-range MTRRs
/// (i.e. 11 MSRs), with each MTRR divided into eight, 1-byte sub-ranges:
///
/// [0x00000, 0x7FFFF] (1 MSR * 8 sub-ranges * 64KB each == 512KB)
/// [0x80000, 0xBFFFF] (2 MSR * 8 sub-ranges * 16KB each == 256KB)
/// [0xC0000, 0xFFFFF] (8 MSR * 8 sub-ranges * 4KB  each == 256KB)
///
/// The number of variable ranges is IA32_MTRRCAP[7:0], and each range
/// is specified with two MSRs; one that describes the base and memory type,
/// and another that helps determine the range size.
///
/// This class reads the MTRRs and produces a list of MTRRs that can be
/// processed by the user. It should be noted that the list of MTRRs does not
/// match what is in the MSRs, but instead provides a corrected version that
/// is continuous and non-overlapping.
///
class mtrrs
{
public:

    constexpr static auto invalid = 0xFFFFFFFFFFFFFFFF;     ///< Invalid

    /// Range
    ///
    /// Defines an memory type range
    ///
    struct range_t {

        /// Type
        ///
        /// Define the type of memory the range represents. Note that we use
        /// EPT memory types for the MTRRs for consistency and ease of use by
        /// the EPT logic
        ///
        ept::mmap::memory_type type{ept::mmap::memory_type::uncacheable};

        /// Base Address
        ///
        /// Defines the starting address of the range.
        ///
        uint64_t base{invalid};

        /// Size
        ///
        /// Defines the size of the range.
        ///
        uint64_t size{invalid};

        /// Contains
        ///
        /// @param addr the address to test
        /// @return returns true if the provided address is contained in the
        ///     range, false otherwise
        ///
        bool contains(uint64_t addr) const
        { return addr >= base && addr <= base + size; }

        /// Distance
        ///
        /// @param addr the address to test
        /// @return returns the distance from the provided address to the end
        ///     of the range. If the provided address is not contained in the
        ///     range, the result is undefined.
        ///
        uint64_t distance(uint64_t addr) const
        { return size - (addr - base);  }
    };

    /// Destructor
    ///
    /// @expects
    /// @ensures
    ///
    ~mtrrs() noexcept = default;

    /// Get Singleton Instance
    ///
    /// Get an instance to the singleton class.
    ///
    /// @expects none
    /// @ensures ret != nullptr
    ///
    /// @return a singleton instance of mtrrs
    ///
    static mtrrs *instance() noexcept;

    /// Ranges
    ///
    /// Returns a list of the ranges identified by the MTRRs. Note that the
    /// ranges are guaranteed to be continuous, which means that they do not
    /// overlap, and the base address plus the size for the first range is
    /// always less than the next range. As a result, the ranges might not
    /// match what you see from /proc/mtrr as this code will automatically
    /// normalize the ranges to a form that is usable. Also not that the ranges
    /// are not guaranteed to contain sizes that are a multiple of 2 as the
    /// ranges might need to be broken up if overlapping regions exist,
    /// but the size if guaranteed to be larger than a 4k page.
    /// Finally, the ranges list will cover all of physical memory, so the
    /// caller may expect the ranges list to contain at least one range, which
    /// would be the default memory type for all of memory. If this list is
    /// empty, and error has occurred.
    ///
    /// @expects
    /// @ensures
    ///
    /// @return returns the corrected MTRR ranges. If this function returns
    ///     no ranges, an error has occurred. If All 256 ranges are used, and
    ///     error has also occurred.
    ///
    const std::array<range_t, 256> &ranges() const
    { return m_ranges; }

    /// Size
    ///
    /// @return returns the total number of valid ranges in the range list.
    ///
    auto size() const
    { return m_num; }

    /// Dump
    ///
    /// Prints the MTRR ranges.
    ///
    /// @param level the debug level to use
    /// @param str the title of the dump
    ///
    void dump(int level = 0, const char *str = "mtrrs") const;

#ifndef ENABLE_BUILD_TEST
private:
#endif

    mtrrs() noexcept;

    void get_fixed_ranges();
    void get_variable_ranges();

    bool make_continuous();

    void add_range(const range_t &range);
    void add_range(uint64_t ia32_mtrr_physbase, uint64_t ia32_mtrr_physmask);

private:

    uint8_t m_num{0};
    std::array<range_t, 256> m_ranges;

public:

    // @cond

    mtrrs(mtrrs &&) = default;
    mtrrs &operator=(mtrrs &&) = default;

    mtrrs(const mtrrs &) = delete;
    mtrrs &operator=(const mtrrs &) = delete;

    /// @endcond
};

/// Comparison Overload
///
/// @return true if both ranges are equal, false otherwise
///
inline bool operator==(const mtrrs::range_t &lhs, const mtrrs::range_t &rhs)
{ return (lhs.type == rhs.type) && (lhs.base == rhs.base) && (lhs.size == rhs.size); }

}

/// Global MTRRs
///
/// The following can be used to quickly get a list of the global MTRRs
///
/// @expects
/// @ensures g_mtrrs != nullptr
///
#define g_mtrrs bfvmm::intel_x64::mtrrs::instance()

#endif
