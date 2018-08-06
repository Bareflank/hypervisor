//
// Bareflank Extended APIs
//
// Copyright (C) 2015 Assured Information Security, Inc.
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

#ifndef CR3_HELPERS_X64_H
#define CR3_HELPERS_X64_H

#include "mmap.h"

namespace bfvmm
{
namespace x64
{
namespace cr3
{

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
inline void
identity_map_1g(
    mmap &map,
    mmap::phys_addr_t saddr,
    mmap::phys_addr_t eaddr,
    mmap::attr_type attr = mmap::attr_type::read_write,
    mmap::memory_type cache = mmap::memory_type::write_back)
{
    using namespace ::intel_x64::ept;

    expects(bfn::lower(saddr, pdpt::from) == 0);
    expects(bfn::lower(eaddr, pdpt::from) == 0);

    for (auto gpa = saddr; gpa < eaddr; gpa += pdpt::page_size) {
        map.map_1g(gpa, gpa, attr, cache);
    }
}

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
inline void
identity_map_2m(
    mmap &map,
    mmap::phys_addr_t saddr,
    mmap::phys_addr_t eaddr,
    mmap::attr_type attr = mmap::attr_type::read_write,
    mmap::memory_type cache = mmap::memory_type::write_back)
{
    using namespace ::intel_x64::ept;

    expects(bfn::lower(saddr, pd::from) == 0);
    expects(bfn::lower(eaddr, pd::from) == 0);

    for (auto gpa = saddr; gpa < eaddr; gpa += pd::page_size) {
        map.map_2m(gpa, gpa, attr, cache);
    }
}

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
inline void
identity_map_4k(
    mmap &map,
    mmap::phys_addr_t saddr,
    mmap::phys_addr_t eaddr,
    mmap::attr_type attr = mmap::attr_type::read_write,
    mmap::memory_type cache = mmap::memory_type::write_back)
{
    using namespace ::intel_x64::ept;

    expects(bfn::lower(saddr, pt::from) == 0);
    expects(bfn::lower(eaddr, pt::from) == 0);

    for (auto gpa = saddr; gpa < eaddr; gpa += pt::page_size) {
        map.map_4k(gpa, gpa, attr, cache);
    }
}

/// Identity Unmap with 1g Granularity
///
/// Unmaps a 1:1 map from the starting address to the ending address
/// using 1g maps.
///
/// @param map the map to apply the identity map too
/// @param saddr the starting address for the map
/// @param eaddr the ending address for the map
///
inline void
identity_unmap_1g(
    mmap &map,
    mmap::phys_addr_t saddr,
    mmap::phys_addr_t eaddr)
{
    using namespace ::intel_x64::ept;

    expects(bfn::lower(saddr, pdpt::from) == 0);
    expects(bfn::lower(eaddr, pdpt::from) == 0);

    for (auto gpa = saddr; gpa < eaddr; gpa += pdpt::page_size) {
        map.unmap(gpa);
    }
}

/// Identity Unmap with 2m Granularity
///
/// Unmaps a 1:1 map from the starting address to the ending address
/// using 2m maps.
///
/// @param map the map to apply the identity map too
/// @param saddr the starting address for the map
/// @param eaddr the ending address for the map
///
inline void
identity_unmap_2m(
    mmap &map,
    mmap::phys_addr_t saddr,
    mmap::phys_addr_t eaddr)
{
    using namespace ::intel_x64::ept;

    expects(bfn::lower(saddr, pd::from) == 0);
    expects(bfn::lower(eaddr, pd::from) == 0);

    for (auto gpa = saddr; gpa < eaddr; gpa += pd::page_size) {
        map.unmap(gpa);
    }
}

/// Identity Unmap with 4k Granularity
///
/// Unmaps a 1:1 map from the starting address to the ending address
/// using 4k maps.
///
/// @param map the map to apply the identity map too
/// @param saddr the starting address for the map
/// @param eaddr the ending address for the map
///
inline void
identity_unmap_4k(
    mmap &map,
    mmap::phys_addr_t saddr,
    mmap::phys_addr_t eaddr)
{
    using namespace ::intel_x64::ept;

    expects(bfn::lower(saddr, pt::from) == 0);
    expects(bfn::lower(eaddr, pt::from) == 0);

    for (auto gpa = saddr; gpa < eaddr; gpa += pt::page_size) {
        map.unmap(gpa);
    }
}

/// Identity Release with 1g Granularity
///
/// Releases a 1:1 map from the starting address to the ending address
/// using 1g maps.
///
/// @param map the map to apply the identity map too
/// @param saddr the starting address for the map
/// @param eaddr the ending address for the map
///
inline void
identity_release_1g(
    mmap &map,
    mmap::phys_addr_t saddr,
    mmap::phys_addr_t eaddr)
{
    using namespace ::intel_x64::ept;

    expects(bfn::lower(saddr, pdpt::from) == 0);
    expects(bfn::lower(eaddr, pdpt::from) == 0);

    for (auto gpa = saddr; gpa < eaddr; gpa += pdpt::page_size) {
        map.release(gpa);
    }
}

/// Identity Release with 2m Granularity
///
/// Releases a 1:1 map from the starting address to the ending address
/// using 2m maps.
///
/// @param map the map to apply the identity map too
/// @param saddr the starting address for the map
/// @param eaddr the ending address for the map
///
inline void
identity_release_2m(
    mmap &map,
    mmap::phys_addr_t saddr,
    mmap::phys_addr_t eaddr)
{
    using namespace ::intel_x64::ept;

    expects(bfn::lower(saddr, pd::from) == 0);
    expects(bfn::lower(eaddr, pd::from) == 0);

    for (auto gpa = saddr; gpa < eaddr; gpa += pd::page_size) {
        map.release(gpa);
    }
}

/// Identity Release with 4k Granularity
///
/// Releases a 1:1 map from the starting address to the ending address
/// using 4k maps.
///
/// @param map the map to apply the identity map too
/// @param saddr the starting address for the map
/// @param eaddr the ending address for the map
///
inline void
identity_release_4k(
    mmap &map,
    mmap::phys_addr_t saddr,
    mmap::phys_addr_t eaddr)
{
    using namespace ::intel_x64::ept;

    expects(bfn::lower(saddr, pt::from) == 0);
    expects(bfn::lower(eaddr, pt::from) == 0);

    for (auto gpa = saddr; gpa < eaddr; gpa += pt::page_size) {
        map.release(gpa);
    }
}

/// Convert Identity Map Granularity
///
/// Converts the granularity of a map from 1g to 2m.
///
/// @param map the map to apply the identity map too
/// @param addr the address to convert
/// @param attr the memory attributes to apply to the map
/// @param cache the memory type to apply to the map
///
inline void
identity_map_convert_1g_to_2m(
    mmap &map,
    mmap::phys_addr_t addr,
    mmap::attr_type attr = mmap::attr_type::read_write,
    mmap::memory_type cache = mmap::memory_type::write_back)
{
    using namespace ::intel_x64::ept;

    expects(bfn::lower(addr, pdpt::from) == 0);
    expects(map.is_1g(addr));

    map.unmap(addr);

    identity_map_2m(
        map, addr, addr + pdpt::page_size, attr, cache
    );
}

/// Convert Identity Map Granularity
///
/// Converts the granularity of a map from 1g to 4k.
///
/// @param map the map to apply the identity map too
/// @param addr the address to convert
/// @param attr the memory attributes to apply to the map
/// @param cache the memory type to apply to the map
///
inline void
identity_map_convert_1g_to_4k(
    mmap &map,
    mmap::phys_addr_t addr,
    mmap::attr_type attr = mmap::attr_type::read_write,
    mmap::memory_type cache = mmap::memory_type::write_back)
{
    using namespace ::intel_x64::ept;

    expects(bfn::lower(addr, pdpt::from) == 0);
    expects(map.is_1g(addr));

    map.unmap(addr);

    identity_map_4k(
        map, addr, addr + pdpt::page_size, attr, cache
    );
}

/// Convert Identity Map Granularity
///
/// Converts the granularity of a map from 2m to 1g.
///
/// @param map the map to apply the identity map too
/// @param addr the address to convert
/// @param attr the memory attributes to apply to the map
/// @param cache the memory type to apply to the map
///
inline void
identity_map_convert_2m_to_1g(
    mmap &map,
    mmap::phys_addr_t addr,
    mmap::attr_type attr = mmap::attr_type::read_write,
    mmap::memory_type cache = mmap::memory_type::write_back)
{
    using namespace ::intel_x64::ept;

    expects(bfn::lower(addr, pdpt::from) == 0);
    expects(map.is_2m(addr));

    identity_release_2m(
        map, addr, addr + pdpt::page_size
    );

    map.map_1g(addr, addr, attr, cache);
}

/// Convert Identity Map Granularity
///
/// Converts the granularity of a map from 4k to 1g.
///
/// @param map the map to apply the identity map too
/// @param addr the address to convert
/// @param attr the memory attributes to apply to the map
/// @param cache the memory type to apply to the map
///
inline void
identity_map_convert_4k_to_1g(
    mmap &map,
    mmap::phys_addr_t addr,
    mmap::attr_type attr = mmap::attr_type::read_write,
    mmap::memory_type cache = mmap::memory_type::write_back)
{
    using namespace ::intel_x64::ept;

    expects(bfn::lower(addr, pdpt::from) == 0);
    expects(map.is_4k(addr));

    identity_release_4k(
        map, addr, addr + pdpt::page_size
    );

    map.map_1g(addr, addr, attr, cache);
}

/// Convert Identity Map Granularity
///
/// Converts the granularity of a map from 2m to 4k.
///
/// @param map the map to apply the identity map too
/// @param addr the address to convert
/// @param attr the memory attributes to apply to the map
/// @param cache the memory type to apply to the map
///
inline void
identity_map_convert_2m_to_4k(
    mmap &map,
    mmap::phys_addr_t addr,
    mmap::attr_type attr = mmap::attr_type::read_write,
    mmap::memory_type cache = mmap::memory_type::write_back)
{
    using namespace ::intel_x64::ept;

    expects(bfn::lower(addr, pd::from) == 0);
    expects(map.is_2m(addr));

    map.unmap(addr);

    identity_map_4k(
        map, addr, addr + pd::page_size, attr, cache
    );
}

/// Convert Identity Map Granularity
///
/// Converts the granularity of a map from 4k to 2m.
///
/// @param map the map to apply the identity map too
/// @param addr the address to convert
/// @param attr the memory attributes to apply to the map
/// @param cache the memory type to apply to the map
///
inline void
identity_map_convert_4k_to_2m(
    mmap &map,
    mmap::phys_addr_t addr,
    mmap::attr_type attr = mmap::attr_type::read_write,
    mmap::memory_type cache = mmap::memory_type::write_back)
{
    using namespace ::intel_x64::ept;

    expects(bfn::lower(addr, pd::from) == 0);
    expects(map.is_4k(addr));

    identity_release_4k(
        map, addr, addr + pd::page_size
    );

    map.map_2m(addr, addr, attr, cache);
}

}
}
}

#endif
