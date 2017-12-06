//
// Bareflank Hypervisor
// Copyright (C) 2015 Assured Information Security, Inc.
//
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 2.1 of the License, or (at your option) any later version.  //
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
// Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public
// License along with this library; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA

#include <catch/catch.hpp>
#include <intrinsics/x86/common_x64.h>
#include <intrinsics/x86/intel_x64.h>
#include <hippomocks.h>

#ifdef _HIPPOMOCKS__ENABLE_CFUNC_MOCKING_SUPPORT

using namespace intel_x64;
using namespace acpi;

uint8_t g_rsdp[36] = {
    'R', 'S', 'D', ' ', 'P', 'T', 'R', ' ',     // Signature
    0,                                          // Checksum
    'O', 'E', 'M', ' ', 'I', 'D',               // OEM ID
    2,                                          // Revision
    0, 0, 0, 0,                                 // RSDT Address (Not a real address)
    36, 0, 0, 0,                                // Length
    0, 0, 0, 0,                                 // XSDT Address (Not a real address)
    0,                                          // Extended Checksum
    0, 0, 0                                     // Reserved
};

uint8_t g_xsdt[52] = {
    'X', 'S', 'D', 'T',                         // Signature
    52, 0, 0, 0,                                // Length
    1,                                          // Revision
    0,                                          // Checksum
    'O', 'E', 'M', ' ', 'I', 'D',               // OEM ID
    'O', 'E', 'M', ' ', 'X', 'S', 'D', 'T',     // OEM Table ID
    1, 0, 0, 0,                                 // OEM Revision
    'T', 'E', 'S', 'T',                         // Creator ID
    1, 0, 0, 0,                                 // Creator Revision
    1, 0, 0, 0, 0, 0, 0, 0,                     // Entry 1 (Not a real address)
    2, 0, 0, 0, 0, 0, 0, 0                      // Entry 2 (Not a real address)
};

uint8_t g_rsdt[44] = {
    'R', 'S', 'D', 'T',                         // Signature
    44, 0, 0, 0,                                // Length
    1,                                          // Revision
    0,                                          // Checksum
    'O', 'E', 'M', ' ', 'I', 'D',               // OEM ID
    'O', 'E', 'M', ' ', 'R', 'S', 'D', 'T',     // OEM Table ID
    1, 0, 0, 0,                                 // OEM Revision
    'T', 'E', 'S', 'T',                         // Creator ID
    1, 0, 0, 0,                                 // Creator Revision
    1, 0, 0, 0,                                 // Entry 1 (Not a real address)
    2, 0, 0, 0                                  // Entry 2 (Not a real address)
};

uint8_t g_madt[84] = {
    'A', 'P', 'I', 'C',                         // Signature
    84, 0, 0, 0,                                // Length
    4,                                          // Revision
    0,                                          // Checksum
    'O', 'E', 'M', ' ', 'I', 'D',               // OEM ID
    'O', 'E', 'M', ' ', 'M', 'A', 'D', 'T',     // OEM Table ID
    1, 0, 0, 0,                                 // OEM Revision
    'T', 'E', 'S', 'T',                         // Creator ID
    1, 0, 0, 0,                                 // Creator Revision
    1, 0, 0, 0,                                 // Local Interrupt Address
    1, 0, 0, 0,                                 // Flags
    // Local APIC 1
    0,                                          // Type
    8,                                          // Length
    1,                                          // ACPI UID
    1,                                          // APIC ID
    1, 0, 0, 0,                                 // Flags
    // Local APIC 2
    0,                                          // Type
    8,                                          // Length
    2,                                          // ACPI UID
    2,                                          // APIC ID
    1, 0, 0, 0,                                 // Flags
    // IO APIC 1
    1,                                          // Type
    12,                                         // Length
    1,                                          // IO APIC ID
    0,                                          // Reserved
    1, 0, 0, 0,                                 // IO APIC Address
    1, 0, 0, 0,                                 // Global System Interrupt Base
    // IO Apic 2
    1,                                          // Type
    12,                                         // Length
    2,                                          // IO APIC ID
    0,                                          // Reserved
    2, 0, 0, 0,                                 // IO APIC Address
    1, 0, 0, 0                                  // Global System Interrupt Base
};

uint8_t g_lapic[8] = {
    0,                                          // Type
    8,                                          // Length
    1,                                          // ACPI UID
    1,                                          // APIC ID
    1, 0, 0, 0                                  // Flags
};

uint8_t g_ioapic[12] = {
    1,                                          // Type
    12,                                         // Length
    1,                                          // IO APIC ID
    0,                                          // Reserved
    1, 0, 0, 0,                                 // IO APIC Address
    1, 0, 0, 0                                  // Global System Interrupt Base
};

TEST_CASE("test name goes here")
{
    CHECK(true);
}

TEST_CASE("acpi_header: constructor")
{
    acpi_header h = acpi_header(g_xsdt);

    CHECK(strcmp(h.signature, "XSDT") == 0);
    CHECK(h.length == 52);
    CHECK(h.revision == 1);
    CHECK(h.checksum == 0);
    CHECK(strcmp(h.oem_id, "OEM ID") == 0);
    CHECK(strcmp(h.oem_table_id, "OEM XSDT") == 0);
    CHECK(h.oem_revision == 1);
    CHECK(strcmp(h.creator_id, "TEST") == 0);
    CHECK(h.creator_revision == 1);
}

TEST_CASE("ics_header: constructor")
{
    ics_header h = ics_header(g_lapic);

    CHECK(h.type == 0);
    CHECK(h.length == 8);
}

TEST_CASE("local_apic: constructor")
{
    local_apic l = local_apic(g_lapic);

    CHECK(l.base == g_lapic);
    CHECK(l.header.type == 0);
    CHECK(l.header.length == 8);
    CHECK(l.acpi_uid == 1);
    CHECK(l.apic_id == 1);
    CHECK(l.flags == 1);
}

TEST_CASE("local_apic: is_enabled")
{
    local_apic l = local_apic(g_lapic);
    l.flags = 1;

    CHECK(l.is_enabled());

    l.flags = 0;
    CHECK_FALSE(l.is_enabled());
}

TEST_CASE("io_apic: constructor")
{
    io_apic io = io_apic(g_ioapic);

    CHECK(io.base == g_ioapic);
    CHECK(io.header.type == 1);
    CHECK(io.header.length == 12);
    CHECK(io.io_apic_address == 1);
    CHECK(io.global_interrupt_base == 1);
}

TEST_CASE("madt: constructor")
{
    madt m = madt(g_madt);

    CHECK(m.base == g_madt);
    CHECK(strcmp(m.header.signature, "APIC") == 0);
    CHECK(m.header.length == 84);
    CHECK(m.header.revision == 4);
    CHECK(m.header.checksum == 0);
    CHECK(strcmp(m.header.oem_id, "OEM ID") == 0);
    CHECK(strcmp(m.header.oem_table_id, "OEM MADT") == 0);
    CHECK(m.header.oem_revision == 1);
    CHECK(strcmp(m.header.creator_id, "TEST") == 0);
    CHECK(m.header.creator_revision == 1);
    CHECK(m.ics == g_madt + 44);
}

TEST_CASE("madt: is_pcat_compatible")
{
    madt m = madt(g_madt);

    m.flags = 1;
    CHECK(m.is_pcat_compatible());

    m.flags = 0;
    CHECK_FALSE(m.is_pcat_compatible());
}

TEST_CASE("madt: get_local_apic_set")
{
    madt m = madt(g_madt);
    std::set<local_apic> lapic_set = m.get_lapic_set();

    CHECK(lapic_set.size() == 2);

    auto iter = lapic_set.begin();
    CHECK(iter->apic_id == 1);

    iter++;
    CHECK(iter->apic_id == 2);
}

TEST_CASE("madt: get_io_apic_set")
{
    madt m = madt(g_madt);
    std::set<io_apic> ioapic_set = m.get_ioapic_set();

    CHECK(ioapic_set.size() == 2);

    auto iter = ioapic_set.begin();
    CHECK(iter->io_apic_id == 1);

    iter++;
    CHECK(iter->io_apic_id == 2);
}

TEST_CASE("rsdt: constructor")
{
    rsdt systable = rsdt(g_rsdt);

    CHECK(systable.base == g_rsdt);
    CHECK(strcmp(systable.header.signature, "RSDT") == 0);
    CHECK(systable.header.length == 44);
    CHECK(systable.header.revision == 1);
    CHECK(systable.header.checksum == 0);
    CHECK(strcmp(systable.header.oem_id, "OEM ID") == 0);
    CHECK(strcmp(systable.header.oem_table_id, "OEM RSDT") == 0);
    CHECK(systable.header.oem_revision == 1);
    CHECK(strcmp(systable.header.creator_id, "TEST") == 0);
    CHECK(systable.header.creator_revision == 1);
    CHECK(systable.entries[0] == 1);
    CHECK(systable.entries[1] == 2);
}

// TODO RSDT get_madt
TEST_CASE("rsdt: get_madt")
{
    CHECK(true);
}

TEST_CASE("xsdt: constructor")
{
    xsdt systable = xsdt(g_xsdt);

    CHECK(systable.base == g_xsdt);
    CHECK(strcmp(systable.header.signature, "XSDT") == 0);
    CHECK(systable.header.length == 52);
    CHECK(systable.header.revision == 1);
    CHECK(systable.header.checksum == 0);
    CHECK(strcmp(systable.header.oem_id, "OEM ID") == 0);
    CHECK(strcmp(systable.header.oem_table_id, "OEM XSDT") == 0);
    CHECK(systable.header.oem_revision == 1);
    CHECK(strcmp(systable.header.creator_id, "TEST") == 0);
    CHECK(systable.header.creator_revision == 1);
    CHECK(systable.entries[0] == 1);
    CHECK(systable.entries[1] == 2);
}

TEST_CASE("xsdt: get_madt")
{
    xsdt systab = xsdt(g_xsdt);
    systab.entries[0] = reinterpret_cast<uintptr_t>(g_madt);
    madt m = systab.get_madt();

    CHECK(m.base == g_madt);
    CHECK(strcmp(m.header.signature, "APIC") == 0);
    CHECK(m.header.length == 84);
    CHECK(m.header.revision == 4);
    CHECK(m.header.checksum == 0);
    CHECK(strcmp(m.header.oem_id, "OEM ID") == 0);
    CHECK(strcmp(m.header.oem_table_id, "OEM MADT") == 0);
    CHECK(m.header.oem_revision == 1);
    CHECK(strcmp(m.header.creator_id, "TEST") == 0);
    CHECK(m.header.creator_revision == 1);
    CHECK(m.ics == g_madt + 44);
}

TEST_CASE("rsdp: constructor")
{
    rsdp root = rsdp(g_rsdp);

    CHECK(root.base == g_rsdp);
    CHECK(strcmp(root.signature, "RSD PTR ") == 0);
    CHECK(root.checksum == 0);
    CHECK(strcmp(root.oem_id, "OEM ID") == 0);
    CHECK(root.revision == 2);
    CHECK(root.rsdt_address == 0);
    CHECK(root.length == 36);
    CHECK(root.xsdt_address == 0);
    CHECK(root.ext_checksum == 0);
}

TEST_CASE("rsdp: get_madt")
{
    rsdp root = rsdp(g_rsdp);
    xsdt systab = xsdt(g_xsdt);
    systab.entries[0] = reinterpret_cast<uintptr_t>(g_madt);
    root.xsdt_address = reinterpret_cast<uintptr_t>(systab.base);
    root.revision = 2;

    madt m = root.get_madt();
    CHECK(m.base == g_madt);
    CHECK(strcmp(m.header.signature, "APIC") == 0);
    CHECK(m.header.length == 84);
    CHECK(m.header.revision == 4);
    CHECK(m.header.checksum == 0);
    CHECK(strcmp(m.header.oem_id, "OEM ID") == 0);
    CHECK(strcmp(m.header.oem_table_id, "OEM MADT") == 0);
    CHECK(m.header.oem_revision == 1);
    CHECK(strcmp(m.header.creator_id, "TEST") == 0);
    CHECK(m.header.creator_revision == 1);
    CHECK(m.ics == g_madt + 44);

    // TODO Revision < 2
}

#endif
