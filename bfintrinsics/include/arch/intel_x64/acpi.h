//
// Bareflank Hypervisor
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

#ifndef ACPI_INTEL_X64_H
#define ACPI_INTEL_X64_H

#include <set>

// *INDENT-OFF*

// -----------------------------------------------------------------------------
// Exports
// -----------------------------------------------------------------------------

#include <bfexports.h>

namespace intel_x64
{
namespace acpi
{

using acpi_ptr = uint8_t *;

struct acpi_header {
    char signature[5] = { ' ', ' ', ' ', ' ', '\0' };
    uint32_t length = 0;
    uint8_t revision = 0;
    uint8_t checksum = 1;
    char oem_id[7] = { ' ', ' ', ' ', ' ', ' ', ' ', '\0' };
    char oem_table_id[9] = { ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', '\0' };
    uint32_t oem_revision = 0;
    char creator_id[5] = { ' ', ' ', ' ', ' ', '\0' };
    uint32_t creator_revision = 0;

    acpi_header() = default;
    acpi_header(acpi_ptr base)
    {
        memcpy(&signature, base, 4);
        memcpy(&length, base + 4, 4);
        memcpy(&revision, base + 8, 1);
        memcpy(&checksum, base + 9, 1);
        memcpy(oem_id, base + 10, 6);
        memcpy(&oem_table_id, base + 16, 8);
        memcpy(&oem_revision, base + 24, 4);
        memcpy(&creator_id, base + 28, 4);
        memcpy(&creator_revision, base + 32, 4);
    }
};

struct ics_header {
    uint8_t type = 0;
    uint8_t length = 0;

    ics_header() = default;
    ics_header(acpi_ptr base)
    {
        memcpy(&type, base, 1);
        memcpy(&length, base + 1, 1);
    }
};

struct local_apic {
    acpi_ptr base = NULL;
    ics_header header;
    uint8_t acpi_uid = 0;
    uint8_t apic_id = 0;
    uint32_t flags = 0;

    local_apic() = default;
    local_apic(acpi_ptr b)
    {
        base = b;
        header = ics_header(base);
        memcpy(&acpi_uid, base + 2, 1);
        memcpy(&apic_id, base + 3, 1);
        memcpy(&flags, base + 4, 4);
    }

    bool operator<(const local_apic& rhs) const
    { return acpi_uid < rhs.acpi_uid; }

    bool operator==(const local_apic& rhs) const
    { return acpi_uid == rhs.acpi_uid; }

    bool is_enabled()
    { return (flags & 0x1U); }
};

struct io_apic {
    acpi_ptr base = NULL;
    ics_header header;
    uint8_t io_apic_id = 0;
    uint32_t io_apic_address = 0;
    uint32_t global_interrupt_base = 0;

    io_apic() = default;
    io_apic(acpi_ptr b)
    {
        base = b;
        header = ics_header(base);
        memcpy(&io_apic_id, base + 2, 1);
        // Empty reserved bit at base + 3
        memcpy(&io_apic_address, base + 4, 4);
        memcpy(&global_interrupt_base, base + 8, 4);
    }

    bool operator<(const io_apic& rhs) const
    { return io_apic_id < rhs.io_apic_id; }

    bool operator==(const io_apic& rhs) const
    { return io_apic_id == rhs.io_apic_id; }
};

struct madt {
    enum ics_type : uint32_t {
        LAPIC,
        IOAPIC,
        INTERRUPT_SOURCE_OVERRIDE,
        NMI,
        LAPIC_NMI,
        LAPIC_ADDRESS_OVERRIDE,
        IOSAPIC,
        LSAPIC,
        PLATFORM_INTERRUPT_SOURCES,
        X2_LAPIC_NMI,
        GICC,
        GICD,
        GIC_MSI_FRAME,
        GICR,
        GIC_ITS
    };

    acpi_ptr base;
    acpi_header header;
    uint32_t local_interrupt_address;
    uint32_t flags;
    acpi_ptr ics;

    madt() = default;
    madt(acpi_ptr b)
    {
        base = b;
        header = acpi_header(base);
        memcpy(&local_interrupt_address, base + 36, 4);
        memcpy(&flags, base + 40, 4);
        ics = base + 44;
    }

    bool is_pcat_compatible()
    { return (flags & 0x1U); }

    std::set<local_apic> get_lapic_set()
    {
        std::set<local_apic> lapic_set;
        acpi_ptr p = ics;
        acpi_ptr end = ics + (header.length - 44);

        while (p < end) {
            ics_header h = ics_header(p);
            if (h.type == LAPIC) {
                local_apic l = local_apic(p);
                lapic_set.insert(l);
            }

            p += h.length;
        }

        return lapic_set;
    }

    std::set<io_apic> get_ioapic_set()
    {
        std::set<io_apic> ioapic_set;
        acpi_ptr p = ics;
        acpi_ptr end = ics + (header.length - 44);

        while (p < end) {
            ics_header h = ics_header(p);
            if (h.type == IOAPIC) {
                io_apic io = io_apic(p);
                ioapic_set.insert(io);
            }

            p += h.length;
        }

        return ioapic_set;
    }
};

struct rsdt {
    acpi_ptr base = NULL;
    acpi_header header;
    uint32_t * entries = NULL;

    rsdt() = default;
    rsdt(acpi_ptr b)
    {
        base = b;
        header = acpi_header(base);
        entries = reinterpret_cast<uint32_t*>(base + 36);
    }

    madt get_madt()
    {
        uint32_t num_entries = (header.length - 36) / 4;
        for (uint32_t i = 0; i < num_entries; i++) {
            acpi_ptr p = reinterpret_cast<acpi_ptr>(entries[i]);
            char signature[5] = { ' ', ' ', ' ', ' ', '\0' };
            memcpy(signature, p, 4);
            if (strcmp(signature, "APIC") == 0) {
                return madt(p);
            }
        }

        bferror_info(0, "Unable to find Multiple APIC Description Table");
        // Return default empty MADT if not found.
        // Should never get this far due to error thrown above
        return madt();
    }
};

struct xsdt {
    acpi_ptr base = NULL;
    acpi_header header;
    uint64_t * entries = NULL;

    xsdt() = default;
    xsdt(acpi_ptr b)
    {
        base = b;
        header = acpi_header(base);
        entries = reinterpret_cast<uint64_t*>(base + 36);
    }

    madt get_madt()
    {
        uint32_t num_entries = (header.length - 36) / 8;
        for (uint32_t i = 0; i < num_entries; i++) {
            acpi_ptr p = reinterpret_cast<acpi_ptr>(entries[i]);
            char signature[5] = { ' ', ' ', ' ', ' ', '\0' };
            memcpy(signature, p, 4);
            if (strcmp(signature, "APIC") == 0) {
                return madt(p);
            }
        }

        bferror_info(0, "Unable to find Multiple APIC Description Table");
        // Return default empty MADT if not found.
        // Should never get this far due to error thrown above
        return madt();
    }
};

struct rsdp {
    acpi_ptr base = NULL;
    char signature[9] = { ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', '\0' };
    uint8_t checksum = 1;
    char oem_id[7] = { ' ', ' ', ' ', ' ', ' ', ' ', '\0' };
    uint8_t revision = 0;
    uint32_t rsdt_address = 0;
    uint32_t length = 0;
    uint64_t xsdt_address = 0;
    uint8_t ext_checksum = 1;

    rsdp() = default;
    rsdp(acpi_ptr b)
    {
        base = b;
        memcpy(signature, base, 8);
        memcpy(&checksum, base + 8, 1);
        memcpy(oem_id, base + 9, 6);
        memcpy(&revision, base + 15, 1);
        memcpy(&rsdt_address, base + 16, 4);
        memcpy(&length, base + 20, 4);
        memcpy(&xsdt_address, base + 24, 8);
        memcpy(&ext_checksum, base + 32, 1);
    }

    madt get_madt()
    {
        // Use XSDT if available
        if (revision >= 2) {
            xsdt system_table = xsdt(reinterpret_cast<acpi_ptr>(xsdt_address));
            return system_table.get_madt();
        }

        // Use RSDT if XSDT is not available
        rsdt system_table = rsdt(reinterpret_cast<acpi_ptr>(rsdt_address));
        return system_table.get_madt();
    }
};

}
}

// *INDENT-ON*

#endif
