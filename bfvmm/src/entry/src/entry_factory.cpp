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

#ifdef CROSS_COMPILED

#include <entry/entry_factory.h>

entry_factory *ef()
{
    // We use static local variable here instead of a global variable to
    // ensure that the constructor / destructor are actually called, since
    // we do not support global c++ objects in the cross compiled code. Note
    // that this functions is only need by the cross compiler as native test
    // code will create it's own version and export as needed (in order to
    // fake the classes being returned)

    static entry_factory ef;
    return &ef;
}

#endif
