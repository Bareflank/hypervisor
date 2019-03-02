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

#ifndef CR3_HELPERS_X64_H
#define CR3_HELPERS_X64_H

#include "mmap.h"

namespace bfvmm::x64::cr3
{

/// The VMM's CR3
///
/// This function returns the memory map that is used by the VMM.
/// This memory map stores and maintains the page tables for the VMM,
/// and all VMM mapping moves through this map.
///
/// It should be noted that the VMM's memory map is a bit complex as the VMM
/// has to mimic part of the Host OS's memory map for init/fini of the VMM.
///
/// Specifically, but default, the VMM looks like the following:
///
///                       0x0 +------------------+
///                           | Unusable         |
///                  0x100000 +------------------+
///                           | BIOS/EFI         |
///                       xxx +------------------+
///                           | VMM for BIOS/EFI |
///                 xxx + VMM +------------------+
///                           | Unusable         |
///             0xBF000000000 +------------------+
///                           | VMM Map Space    |
///            0x7FFFFFFFFFFF +------------------+
///                           | Unusable         |
///        0xFFFF800000000000 +------------------+
///                           | Host OS Kernel   |
///        0xFFFF800000000xxx +------------------+
///                           | VMM for Host OS  |
///  0xFFFF800000000xxx + VMM +------------------+
///                           | Unusable         |
///        0xFFFFFFFFFFFFFFFF +------------------+
///
/// There are two different locations the VMM could exist:
/// - If the VMM is loaded by BIOS/EFI, the VMM is likely loaded into the lower
///   half of the canoncial space, which means its virtual memory space is in
///   the lower one half.
/// - If the VMM is loaded by a Host OS, the VMM is likely loaded into the
///   high half of the canonical space, as most 64bit operating systems load
///   themselves into the high half, and leave the lower half for applications.
///
/// In either case, we place the VMM map space (by default) at 0xBF000000000
/// which is high enough in the lower half to stay out of the way of BIOS/EFI,
/// while at the same time, not touching any address in the higher half which
/// might accidentally collide with the Host OS.
///
gsl::not_null<mmap *>
vmm_cr3();

/// Identity Map with 1g Granularity
///
/// Adds a 1:1 map from the starting address to the ending address
/// using 1g maps.
///
/// @param map the map to apply the identity map too
/// @param saddr the starting address for the map
/// @param eaddr the ending address for the map
/// @param attr the memory attributes to apply to the map
/// @param cache the memory type to apply to the map
///
void
identity_map_1g(
    mmap &map,
    mmap::phys_addr_t saddr,
    mmap::phys_addr_t eaddr,
    mmap::attr_type attr = mmap::attr_type::read_write,
    mmap::memory_type cache = mmap::memory_type::write_back);

/// Identity Map with 2m Granularity
///
/// Adds a 1:1 map from the starting address to the ending address
/// using 2m maps.
///
/// @param map the map to apply the identity map too
/// @param saddr the starting address for the map
/// @param eaddr the ending address for the map
/// @param attr the memory attributes to apply to the map
/// @param cache the memory type to apply to the map
///
void
identity_map_2m(
    mmap &map,
    mmap::phys_addr_t saddr,
    mmap::phys_addr_t eaddr,
    mmap::attr_type attr = mmap::attr_type::read_write,
    mmap::memory_type cache = mmap::memory_type::write_back);

/// Identity Map with 4k Granularity
///
/// Adds a 1:1 map from the starting address to the ending address
/// using 4k maps.
///
/// @param map the map to apply the identity map too
/// @param saddr the starting address for the map
/// @param eaddr the ending address for the map
/// @param attr the memory attributes to apply to the map
/// @param cache the memory type to apply to the map
///
void
identity_map_4k(
    mmap &map,
    mmap::phys_addr_t saddr,
    mmap::phys_addr_t eaddr,
    mmap::attr_type attr = mmap::attr_type::read_write,
    mmap::memory_type cache = mmap::memory_type::write_back);

/// Identity Unmap with 1g Granularity
///
/// Unmaps a 1:1 map from the starting address to the ending address
/// using 1g maps.
///
/// @param map the map to apply the identity map too
/// @param saddr the starting address for the map
/// @param eaddr the ending address for the map
///
void
identity_unmap_1g(
    mmap &map,
    mmap::phys_addr_t saddr,
    mmap::phys_addr_t eaddr);

/// Identity Unmap with 2m Granularity
///
/// Unmaps a 1:1 map from the starting address to the ending address
/// using 2m maps.
///
/// @param map the map to apply the identity map too
/// @param saddr the starting address for the map
/// @param eaddr the ending address for the map
///
void
identity_unmap_2m(
    mmap &map,
    mmap::phys_addr_t saddr,
    mmap::phys_addr_t eaddr);

/// Identity Unmap with 4k Granularity
///
/// Unmaps a 1:1 map from the starting address to the ending address
/// using 4k maps.
///
/// @param map the map to apply the identity map too
/// @param saddr the starting address for the map
/// @param eaddr the ending address for the map
///
void
identity_unmap_4k(
    mmap &map,
    mmap::phys_addr_t saddr,
    mmap::phys_addr_t eaddr);

/// Identity Release with 1g Granularity
///
/// Releases a 1:1 map from the starting address to the ending address
/// using 1g maps.
///
/// @param map the map to apply the identity map too
/// @param saddr the starting address for the map
/// @param eaddr the ending address for the map
///
void
identity_release_1g(
    mmap &map,
    mmap::phys_addr_t saddr,
    mmap::phys_addr_t eaddr);

/// Identity Release with 2m Granularity
///
/// Releases a 1:1 map from the starting address to the ending address
/// using 2m maps.
///
/// @param map the map to apply the identity map too
/// @param saddr the starting address for the map
/// @param eaddr the ending address for the map
///
void
identity_release_2m(
    mmap &map,
    mmap::phys_addr_t saddr,
    mmap::phys_addr_t eaddr);

/// Identity Release with 4k Granularity
///
/// Releases a 1:1 map from the starting address to the ending address
/// using 4k maps.
///
/// @param map the map to apply the identity map too
/// @param saddr the starting address for the map
/// @param eaddr the ending address for the map
///
void
identity_release_4k(
    mmap &map,
    mmap::phys_addr_t saddr,
    mmap::phys_addr_t eaddr);

/// Convert Identity Map Granularity
///
/// Converts the granularity of a map from 1g to 2m.
///
/// @param map the map to apply the identity map too
/// @param addr the address to convert
/// @param attr the memory attributes to apply to the map
/// @param cache the memory type to apply to the map
///
void
identity_map_convert_1g_to_2m(
    mmap &map,
    mmap::phys_addr_t addr,
    mmap::attr_type attr = mmap::attr_type::read_write,
    mmap::memory_type cache = mmap::memory_type::write_back);

/// Convert Identity Map Granularity
///
/// Converts the granularity of a map from 1g to 4k.
///
/// @param map the map to apply the identity map too
/// @param addr the address to convert
/// @param attr the memory attributes to apply to the map
/// @param cache the memory type to apply to the map
///
void
identity_map_convert_1g_to_4k(
    mmap &map,
    mmap::phys_addr_t addr,
    mmap::attr_type attr = mmap::attr_type::read_write,
    mmap::memory_type cache = mmap::memory_type::write_back);

/// Convert Identity Map Granularity
///
/// Converts the granularity of a map from 2m to 1g.
///
/// @param map the map to apply the identity map too
/// @param addr the address to convert
/// @param attr the memory attributes to apply to the map
/// @param cache the memory type to apply to the map
///
void
identity_map_convert_2m_to_1g(
    mmap &map,
    mmap::phys_addr_t addr,
    mmap::attr_type attr = mmap::attr_type::read_write,
    mmap::memory_type cache = mmap::memory_type::write_back);

/// Convert Identity Map Granularity
///
/// Converts the granularity of a map from 4k to 1g.
///
/// @param map the map to apply the identity map too
/// @param addr the address to convert
/// @param attr the memory attributes to apply to the map
/// @param cache the memory type to apply to the map
///
void
identity_map_convert_4k_to_1g(
    mmap &map,
    mmap::phys_addr_t addr,
    mmap::attr_type attr = mmap::attr_type::read_write,
    mmap::memory_type cache = mmap::memory_type::write_back);

/// Convert Identity Map Granularity
///
/// Converts the granularity of a map from 2m to 4k.
///
/// @param map the map to apply the identity map too
/// @param addr the address to convert
/// @param attr the memory attributes to apply to the map
/// @param cache the memory type to apply to the map
///
void
identity_map_convert_2m_to_4k(
    mmap &map,
    mmap::phys_addr_t addr,
    mmap::attr_type attr = mmap::attr_type::read_write,
    mmap::memory_type cache = mmap::memory_type::write_back);

/// Convert Identity Map Granularity
///
/// Converts the granularity of a map from 4k to 2m.
///
/// @param map the map to apply the identity map too
/// @param addr the address to convert
/// @param attr the memory attributes to apply to the map
/// @param cache the memory type to apply to the map
///
void
identity_map_convert_4k_to_2m(
    mmap &map,
    mmap::phys_addr_t addr,
    mmap::attr_type attr = mmap::attr_type::read_write,
    mmap::memory_type cache = mmap::memory_type::write_back);

}

/// Global CR3
///
/// Returns a pointer to the CR3 map used by the VMM.
///
#define g_cr3 bfvmm::x64::cr3::vmm_cr3().get()

#endif
