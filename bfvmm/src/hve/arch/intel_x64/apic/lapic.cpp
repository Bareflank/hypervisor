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

#include <arch/intel_x64/apic/lapic.h>

namespace intel_x64
{
namespace lapic
{

std::unordered_map<uint32_t, attr_t> attributes;

namespace offset
{

/// Lapic register offsets
std::array<uint32_t, 47> list = {
    {
        id,
        version,
        tpr,
        apr,
        ppr,
        eoi,
        ldr,
        dfr,
        svr,

        isr0,
        isr1,
        isr2,
        isr3,
        isr4,
        isr5,
        isr6,
        isr7,

        tmr0,
        tmr1,
        tmr2,
        tmr3,
        tmr4,
        tmr5,
        tmr6,
        tmr7,

        irr0,
        irr1,
        irr2,
        irr3,
        irr4,
        irr5,
        irr6,
        irr7,

        esr,
        lvt_cmci,
        icr0,
        icr1,
        lvt_timer,
        lvt_thermal,
        lvt_pmi,
        lvt_lint0,
        lvt_lint1,
        lvt_error,
        init_count,
        cur_count,
        dcr,
        self_ipi
    }
};

}
}
}
