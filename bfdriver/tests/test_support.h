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

#ifndef TEST_SUPPORT_H
#define TEST_SUPPORT_H

extern file g_file;
extern std::vector<std::string> g_filenames_success;
extern std::vector<std::string> g_filenames_init_fails;
extern std::vector<std::string> g_filenames_fini_fails;
extern std::vector<std::string> g_filenames_add_mdl_fails;
extern std::vector<std::string> g_filenames_get_drr_fails;
extern std::vector<std::string> g_filenames_set_rsdp_fails;
extern std::vector<std::string> g_filenames_vmm_init_fails;
extern std::vector<std::string> g_filenames_vmm_fini_fails;

#endif
