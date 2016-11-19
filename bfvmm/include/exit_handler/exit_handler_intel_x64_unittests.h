//
// Bareflank Hypervisor
//
// Copyright (C) 2015 Assured Information Security, Inc.
// Author: Rian Quinn        <quinnr@ainfosec.com>
// Author: Brendan Kerrigan  <kerriganb@ainfosec.com>
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

#ifndef EXIT_HANDLER_INTEL_X64_UNITTESTS_H
#define EXIT_HANDLER_INTEL_X64_UNITTESTS_H

#include <gsl/gsl>

#include <debug.h>
#include <exit_handler/exit_handler_intel_x64.h>

inline void
expect_true_with_args(bool cond, const char *func, int line)
{ if (!cond) throw std::runtime_error("unittest failed ["_s + std::to_string(line) + "]: "_s + func); }

inline void
expect_false_with_args(bool cond, const char *func, int line)
{ if (cond) throw std::runtime_error("unittest failed ["_s + std::to_string(line) + "]: "_s + func); }

#define expect_true(a) expect_true_with_args(a, __FUNC__, __LINE__);
#define expect_false(a) expect_false_with_args(a, __FUNC__, __LINE__);

#endif
