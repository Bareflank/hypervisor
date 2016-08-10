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

#include <stdint.h>
#include <dummy_code.h>
#include <error_codes.h>

derived g_derived;

void func00() {}
void func01() {}
void func02() {}
void func03() {}
void func04() {}
void func05() {}
void func06() {}
void func07() {}
void func08() {}
void func09() {}

void func10() {}
void func11() {}
void func12() {}
void func13() {}
void func14() {}
void func15() {}
void func16() {}
void func17() {}
void func18() {}
void func19() {}

void func20() {}
void func21() {}
void func22() {}
void func23() {}
void func24() {}
void func25() {}
void func26() {}
void func27() {}
void func28() {}
void func29() {}

extern "C" int __attribute__((weak))
foo(int arg)
{
    return g_derived.foo(arg);
}

void
operator delete(void *ptr)
{
    (void) ptr;
}

extern "C" int64_t
register_eh_frame(void *addr, uint64_t size)
{
    (void) addr;
    (void) size;

    return REGISTER_EH_FRAME_SUCCESS;
}

extern "C" void
__cxa_end_catch(void)
{  }

extern "C" void
__cxa_begin_catch(void)
{  }

extern "C" void
__gxx_personality_v0(void)
{  }

void func30() {}
void func31() {}
void func32() {}
void func33() {}
void func34() {}
void func35() {}
void func36() {}
void func37() {}
void func38() {}
void func39() {}

void func40() {}
void func41() {}
void func42() {}
void func43() {}
void func44() {}
void func45() {}
void func46() {}
void func47() {}
void func48() {}
void func49() {}

void func50() {}
void func51() {}
void func52() {}
void func53() {}
void func54() {}
void func55() {}
void func56() {}
void func57() {}
void func58() {}
void func59() {}
