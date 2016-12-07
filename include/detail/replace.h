// HippoMocks, a library for using mocks in unit testing of C++ code.
// Copyright (C) 2008, Bas van Tiel, Christian Rexwinkel, Mike Looijmans,
// Peter Bindels
//
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 2.1 of the License, or (at your option) any later version.
//
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public
// License along with this library; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
//
// You can also retrieve it from http://www.gnu.org/licenses/lgpl-2.1.html

#ifndef HIPPOMOCKS_REPLACE_H
#define HIPPOMOCKS_REPLACE_H

# if defined(_M_IX86) || defined(__i386__) || defined(i386) || defined(_X86_) || defined(__THW_INTEL) ||  defined(__x86_64__) || defined(_M_X64)
#  define SOME_X86
# elif defined(arm) || defined(__arm__) || defined(ARM) || defined(_ARM_) || defined(__aarch64__)
#  define SOME_ARM
# endif

# if defined(__x86_64__) || defined(_M_X64)
#  define CMOCK_FUNC_PLATFORMIS64BIT
# endif

# ifdef SOME_X86
#  if defined(_MSC_VER) && (defined(_WIN32) || defined(_WIN64))
#   define _HIPPOMOCKS__ENABLE_CFUNC_MOCKING_SUPPORT
#  elif defined(__linux__) && defined(__GNUC__)
#   define _HIPPOMOCKS__ENABLE_CFUNC_MOCKING_SUPPORT
#  elif defined(__APPLE__)
#   define _HIPPOMOCKS__ENABLE_CFUNC_MOCKING_SUPPORT
#  endif
# elif defined(SOME_ARM) && defined(__GNUC__)
#  define _HIPPOMOCKS__ENABLE_CFUNC_MOCKING_SUPPORT

// This clear-cache is *required*. The tests will fail if you remove it.
extern "C" void __clear_cache(char *beg, char *end);
# endif

# ifdef _HIPPOMOCKS__ENABLE_CFUNC_MOCKING_SUPPORT
#  include <memory.h>

#  ifdef _WIN32
// De-windows.h-ified import to avoid including that file.
#   ifdef _WIN64
extern "C" __declspec(dllimport) int WINCALL VirtualProtect(void *func, unsigned long long byteCount, unsigned long flags, unsigned long *oldFlags);
#   else
extern "C" __declspec(dllimport) int WINCALL VirtualProtect(void *func, unsigned long byteCount, unsigned long flags, unsigned long *oldFlags);
#   endif

#   ifndef PAGE_EXECUTE_READWRITE
#   define PAGE_EXECUTE_READWRITE 0x40
#   endif

#   ifndef NO_HIPPOMOCKS_NAMESPACE
namespace HippoMocks
{
#   endif

class Unprotect
{
public:
    Unprotect(void *location, size_t byteCount)
        : origFunc(location)
        , byteCount(byteCount)
    {
        VirtualProtect(origFunc, byteCount, PAGE_EXECUTE_READWRITE, &oldprotect);
    }
    ~Unprotect()
    {
        unsigned long dontcare;
        VirtualProtect(origFunc, byteCount, oldprotect, &dontcare);
    }
private:
    void *origFunc;
    size_t byteCount;
    unsigned long oldprotect;
};
#  else
#   include <sys/mman.h>
#   include <stdint.h>

#   ifndef NO_HIPPOMOCKS_NAMESPACE
namespace HippoMocks
{
#   endif


class Unprotect
{
public:
    Unprotect(void *location, size_t count)
        : origFunc((intptr_t)location & (~0xFFF))
        , byteCount(count + ((intptr_t)location - origFunc))
    {
        mprotect((void *)origFunc, this->byteCount, PROT_READ | PROT_WRITE | PROT_EXEC);
    };
    ~Unprotect()
    {
        mprotect((void *)origFunc, byteCount, PROT_READ | PROT_EXEC);
    }
private:
    intptr_t origFunc;
    int byteCount;
};
#  endif

typedef unsigned int e9ptrsize_t;

template <typename T, typename U>
T horrible_cast(U u)
{
    union { T t; U u; } un;
    un.u = u;
    return un.t;
}

class Replace
{
private:
    void *origFunc;
    char backupData[16]; // typical use is 5 for 32-bit and 14 for 64-bit code.
public:
    template <typename T>
    Replace(T funcptr, T replacement)
        : origFunc(horrible_cast<void *>(funcptr))
    {
        Unprotect _allow_write(origFunc, sizeof(backupData));
        memcpy(backupData, origFunc, sizeof(backupData));
#  ifdef SOME_X86
#   ifdef CMOCK_FUNC_PLATFORMIS64BIT
        if (llabs((long long)origFunc - (long long)replacement) < 0x80000000LL)
        {
#   endif
            *(unsigned char *)origFunc = 0xE9;
            *(e9ptrsize_t *)(horrible_cast<intptr_t>(origFunc) + 1) = (e9ptrsize_t)(horrible_cast<intptr_t>(replacement) - horrible_cast<intptr_t>(origFunc) - sizeof(e9ptrsize_t) - 1);
#   ifdef CMOCK_FUNC_PLATFORMIS64BIT
        }
        else
        {
            unsigned char *func = (unsigned char *)origFunc;
            func[0] = 0xFF; // jmp (rip + imm32)
            func[1] = 0x25;
            func[2] = 0x00; // imm32 of 0, so immediately after the instruction
            func[3] = 0x00;
            func[4] = 0x00;
            func[5] = 0x00;
            *(long long *)(horrible_cast<intptr_t>(origFunc) + 6) = (long long)(horrible_cast<intptr_t>(replacement));
        }
#   endif
#  elif defined(SOME_ARM)
        unsigned int *rawptr = (unsigned int *)((intptr_t)(origFunc) & (~3));
        if ((intptr_t)origFunc & 1)
        {
            rawptr[0] = 0x6800A001;
            rawptr[1] = 0x46874687;
            rawptr[2] = (intptr_t)replacement;
        }
        else
        {
            rawptr[0] = 0xE59FF000;
            rawptr[1] = (intptr_t)replacement;
            rawptr[2] = (intptr_t)replacement;
        }
        __clear_cache((char *)rawptr, (char *)rawptr + 16);
#  endif
    }
    ~Replace()
    {
        Unprotect _allow_write(origFunc, sizeof(backupData));
        memcpy(origFunc, backupData, sizeof(backupData));
#  ifdef SOME_ARM
        unsigned int *rawptr = (unsigned int *)((intptr_t)(origFunc) & (~3));
        __clear_cache((char *)rawptr, (char *)rawptr + 16);
#  endif
    }
};
# endif

# ifndef NO_HIPPOMOCKS_NAMESPACE
}
# endif

#endif
