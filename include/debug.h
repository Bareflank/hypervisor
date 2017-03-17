/*
 * Bareflank Hypervisor
 *
 * Copyright (C) 2015 Assured Information Security, Inc.
 * Author: Rian Quinn        <quinnr@ainfosec.com>
 * Author: Brendan Kerrigan  <kerriganb@ainfosec.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef BFDEBUG_H
#define BFDEBUG_H

/* -------------------------------------------------------------------------- */
/* C++ Debugging                                                              */
/* -------------------------------------------------------------------------- */

#ifdef __cplusplus

#include <iomanip>
#include <iostream>
#include <sstream>

#include <view_as_pointer.h>

#define bfcolor_green "\033[1;32m"
#define bfcolor_red "\033[1;31m"

#define bfcolor_end "\033[0m"
#define bfcolor_debug "\033[1;32m"
#define bfcolor_warning "\033[1;33m"
#define bfcolor_error "\033[1;31m"
#define bfcolor_func "\033[1;36m"
#define bfcolor_line "\033[1;35m"

/*
 * Current Function Macro
 *
 * Clang Tidy does not like the built in macros that return character pointers
 * as they claim it breaks the Core Guidelines which is obnoxious, so this
 * macro redefines how this is done.
 */
#define __FUNC__ static_cast<const char *>(__PRETTY_FUNCTION__)

/*
 * Output To Core
 *
 * All std::cout and std::cerr are sent to a specific debug_ring
 * based on the vcpuid that you provide, instead of being
 * sent to vcpuid=0 and serial.
 *
 * @param vcpuid the vcpu to send the output to
 * @param func a lambda function containing the output to redirect
 */
template<class V, class T>
void output_to_vcpu(V vcpuid, T func)
{
    std::cout << "$vcpuid=" << std::setw(18) << view_as_pointer(vcpuid);
    func();
}

/*
 * Newline macro
 */
#ifndef bfendl
#define bfendl '\n'
#endif

/*
 * This macro is a shortcut for std::cout that adds some text and color.
 * Use it like std::cout
 *
 * @code
 * bfinfo << "hello world" << bfend;
 * @endcode
 */
#ifndef bfinfo
#define bfinfo \
    std::cout
#endif

/*
 * This macro is a shortcut for std::cout that adds some text and color.
 * Use it like std::cout
 *
 * @code
 * bfdebug << "hello world" << bfend;
 * @endcode
 */
#ifndef bfdebug
#define bfdebug \
    std::cout << bfcolor_debug << "DEBUG" << bfcolor_end << ": "
#endif

/*
 * This macro is a shortcut for std::cout that adds some text and color.
 * Use it like std::cout
 *
 * @code
 * bfwarning << "hello world" << bfend;
 * @endcode
 */
#ifndef bfwarning
#define bfwarning \
    std::cerr << bfcolor_warning << "WARNING" << bfcolor_end << ": "
#endif

/*
 * This macro is a shortcut for std::cout that adds some text and color.
 * Use it like std::cout
 *
 * @code
 * bferror << "hello world" << bfend;
 * @endcode
 */
#ifndef bferror
#define bferror \
    std::cerr << bfcolor_error << "ERROR" << bfcolor_end << ": "
#endif

/*
 * This macro is a shortcut for std::cout that adds some text and color.
 * Use it like std::cout
 *
 * @code
 * bffatal << "hello world" << bfend;
 * @endcode
 */
#ifndef bffatal
#define bffatal \
    std::cerr << bfcolor_error << "FATAL ERROR" << bfcolor_end << ": "
#endif

#endif

/* -------------------------------------------------------------------------- */
/* C Debugging                                                                */
/* -------------------------------------------------------------------------- */

#ifndef KERNEL
#include <stdio.h>
#define INFO(...) printf(__VA_ARGS__)
#define DEBUG(...) printf("[BAREFLANK DEBUG]: " __VA_ARGS__)
#define ALERT(...) printf("[BAREFLANK ERROR]: " __VA_ARGS__)
#endif

/* -------------------------------------------------------------------------- */
/* Linux Debugging                                                            */
/* -------------------------------------------------------------------------- */

#ifdef KERNEL
#if defined(__linux__)
#include <linux/module.h>
#define INFO(...) printk(KERN_INFO __VA_ARGS__)
#define DEBUG(...) printk(KERN_INFO "[BAREFLANK DEBUG]: " __VA_ARGS__)
#define ALERT(...) printk(KERN_ALERT "[BAREFLANK ERROR]: " __VA_ARGS__)
#endif
#endif

/* -------------------------------------------------------------------------- */
/* Windows Debugging                                                          */
/* -------------------------------------------------------------------------- */

#ifdef KERNEL
#ifdef _WIN32
#include <wdm.h>
#define INFO(...) DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, __VA_ARGS__)
#define DEBUG(...) DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "[BAREFLANK DEBUG]: " __VA_ARGS__)
#define ALERT(...) DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[BAREFLANK ERROR]: " __VA_ARGS__)
#endif
#endif

/* -------------------------------------------------------------------------- */
/* OSX Debugging                                                              */
/* -------------------------------------------------------------------------- */

#ifdef KERNEL
#ifdef __APPLE__
#include <IOKit/IOLib.h>
#define INFO(...) IOLog(__VA_ARGS__)
#define DEBUG(...) IOLog("[BAREFLANK DEBUG]: " __VA_ARGS__)
#define ALERT(...) IOLog("[BAREFLANK ERROR]: " __VA_ARGS__)
#endif
#endif

#endif
