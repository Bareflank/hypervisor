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

#ifndef DEBUG_H
#define DEBUG_H

#include <iostream>
#include <assert.h>

/// Bareflank Manager Debug
///
/// This is a version of std::cout that adds a header to the output statement
/// as well as provides a means to be disabled when debugging is not preferred.
///
#define bfm_debug if(is_debug_enabled() == true) std::cout << "[" << __FILE__ << ":" << __LINE__ << "]: "

/// Bareflank Manager Error
///
/// This is a version of std::cerr that adds a header to the output statement
/// as well as provides a means to be disabled when debugging is not preferred.
///
#define bfm_error if(is_error_enabled() == true) std::cerr << "[" << __FILE__ << ":" << __LINE__ << "] ERROR: "

/// Enable Debuging
///
/// When this is called, subsequent calls to bfm_debug are not ignored.
///
void enable_debug();

/// Disable Debuging
///
/// When this is called, subsequent calls to bfm_debug are ignored.
///
void disable_debug();

/// Enable Error Debuging
///
/// When this is called, subsequent calls to bfm_error are not ignored.
///
void enable_error();

/// Disable Error Debuging
///
/// When this is called, subsequent calls to bfm_error are ignored.
///
void disable_error();

/// Is Debugging Enabled
///
/// @return true if debugging is enabled
///
bool is_debug_enabled();

/// Is Error Debugging Enabled
///
/// @return true if error debugging is enabled
///
bool is_error_enabled();

#endif
