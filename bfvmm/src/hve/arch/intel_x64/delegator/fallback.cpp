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

#include <vcpu/vcpu.h>
#include <hve/arch/intel_x64/delegator/fallback.h>

namespace bfvmm::intel_x64::fallback
{

bool
delegator::handle(vcpu_t vcpu)
{
    bfignored(vcpu);

    // TODO: Once all legacy handlers have been retired, turn this back on
    // using namespace ::intel_x64::vmcs;
    //
    // bfdebug_transaction(0, [&](std::string * msg) {
    //     bferror_lnbr(0, msg);
    //     bferror_info(0, "unhandled exit reason", msg);
    //     bferror_brk1(0, msg);
    //
    //     bferror_subtext(
    //         0, "exit_reason",
    //         exit_reason::basic_exit_reason::description(), msg
    //     );
    // });
    //
    // if (exit_reason::vm_entry_failure::is_enabled()) {
    //     debug::dump();
    //     check::all();
    // }

    return false;
}

}
