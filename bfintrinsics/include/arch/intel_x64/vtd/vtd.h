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

#ifndef VTD_INTEL_X64_H
#define VTD_INTEL_X64_H

#include <arch/intel_x64/vtd/context_entry.h>
#include <arch/intel_x64/vtd/extended_context_entry.h>
#include <arch/intel_x64/vtd/extended_root_entry.h>
#include <arch/intel_x64/vtd/fault_record.h>
#include <arch/intel_x64/vtd/first_level_paging_entries.h>
#include <arch/intel_x64/vtd/irte.h>
#include <arch/intel_x64/vtd/pasid_entry.h>
#include <arch/intel_x64/vtd/pasid_state_entry.h>
#include <arch/intel_x64/vtd/pid.h>
#include <arch/intel_x64/vtd/root_entry.h>
#include <arch/intel_x64/vtd/second_level_paging_entries.h>
#include <arch/intel_x64/vtd/iommu.h>
#include <bfvmm/hve/arch/intel_x64/vtd/phys_iommu.h>

#endif
