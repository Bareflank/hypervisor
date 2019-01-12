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

#include <bfupperlower.h>
#include <memory_manager/arch/x64/cr3/helpers.h>

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

namespace bfvmm::x64::cr3
{

gsl::not_null<mmap *>
vmm_cr3()
{
    static mmap s_mmap;
    return &s_mmap;
}

void
identity_map_1g(
    mmap &map,
    mmap::phys_addr_t saddr,
    mmap::phys_addr_t eaddr,
    mmap::attr_type attr,
    mmap::memory_type cache)
{
    using namespace ::intel_x64::ept;

    expects(bfn::lower(saddr, pdpt::from) == 0);
    expects(bfn::lower(eaddr, pdpt::from) == 0);

    for (auto gpa = saddr; gpa < eaddr; gpa += pdpt::page_size) {
        map.map_1g(gpa, gpa, attr, cache);
    }
}

void
identity_map_2m(
    mmap &map,
    mmap::phys_addr_t saddr,
    mmap::phys_addr_t eaddr,
    mmap::attr_type attr,
    mmap::memory_type cache)
{
    using namespace ::intel_x64::ept;

    expects(bfn::lower(saddr, pd::from) == 0);
    expects(bfn::lower(eaddr, pd::from) == 0);

    for (auto gpa = saddr; gpa < eaddr; gpa += pd::page_size) {
        map.map_2m(gpa, gpa, attr, cache);
    }
}

void
identity_map_4k(
    mmap &map,
    mmap::phys_addr_t saddr,
    mmap::phys_addr_t eaddr,
    mmap::attr_type attr,
    mmap::memory_type cache)
{
    using namespace ::intel_x64::ept;

    expects(bfn::lower(saddr, pt::from) == 0);
    expects(bfn::lower(eaddr, pt::from) == 0);

    for (auto gpa = saddr; gpa < eaddr; gpa += pt::page_size) {
        map.map_4k(gpa, gpa, attr, cache);
    }
}

void
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

void
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

void
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

void
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

void
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

void
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

void
identity_map_convert_1g_to_2m(
    mmap &map,
    mmap::phys_addr_t addr,
    mmap::attr_type attr,
    mmap::memory_type cache)
{
    using namespace ::intel_x64::ept;

    expects(bfn::lower(addr, pdpt::from) == 0);
    expects(map.is_1g(addr));

    map.unmap(addr);

    identity_map_2m(
        map, addr, addr + pdpt::page_size, attr, cache
    );
}

void
identity_map_convert_1g_to_4k(
    mmap &map,
    mmap::phys_addr_t addr,
    mmap::attr_type attr,
    mmap::memory_type cache)
{
    using namespace ::intel_x64::ept;

    expects(bfn::lower(addr, pdpt::from) == 0);
    expects(map.is_1g(addr));

    map.unmap(addr);

    identity_map_4k(
        map, addr, addr + pdpt::page_size, attr, cache
    );
}

void
identity_map_convert_2m_to_1g(
    mmap &map,
    mmap::phys_addr_t addr,
    mmap::attr_type attr,
    mmap::memory_type cache)
{
    using namespace ::intel_x64::ept;

    expects(bfn::lower(addr, pdpt::from) == 0);
    expects(map.is_2m(addr));

    identity_release_2m(
        map, addr, addr + pdpt::page_size
    );

    map.map_1g(addr, addr, attr, cache);
}

void
identity_map_convert_4k_to_1g(
    mmap &map,
    mmap::phys_addr_t addr,
    mmap::attr_type attr,
    mmap::memory_type cache)
{
    using namespace ::intel_x64::ept;

    expects(bfn::lower(addr, pdpt::from) == 0);
    expects(map.is_4k(addr));

    identity_release_4k(
        map, addr, addr + pdpt::page_size
    );

    map.map_1g(addr, addr, attr, cache);
}

void
identity_map_convert_2m_to_4k(
    mmap &map,
    mmap::phys_addr_t addr,
    mmap::attr_type attr,
    mmap::memory_type cache)
{
    using namespace ::intel_x64::ept;

    expects(bfn::lower(addr, pd::from) == 0);
    expects(map.is_2m(addr));

    map.unmap(addr);

    identity_map_4k(
        map, addr, addr + pd::page_size, attr, cache
    );
}

void
identity_map_convert_4k_to_2m(
    mmap &map,
    mmap::phys_addr_t addr,
    mmap::attr_type attr,
    mmap::memory_type cache)
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
