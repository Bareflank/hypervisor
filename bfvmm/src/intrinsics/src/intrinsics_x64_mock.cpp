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

#include <gsl/gsl>

#include <iostream>
#include <view_as_pointer.h>

extern "C" void
__attribute__((weak)) __halt(void) noexcept
{
    std::cerr << static_cast<const char *>(__PRETTY_FUNCTION__) << " called" << '\n';
    abort();
}

extern "C" void
__attribute__((weak)) __stop(void) noexcept
{
    std::cerr << static_cast<const char *>(__PRETTY_FUNCTION__) << " called" << '\n';
    abort();
}

extern "C" void
__attribute__((weak)) __invd(void) noexcept
{
    std::cerr << static_cast<const char *>(__PRETTY_FUNCTION__) << " called" << '\n';
    abort();
}

extern "C" void
__attribute__((weak)) __wbinvd(void) noexcept
{
    std::cerr << static_cast<const char *>(__PRETTY_FUNCTION__) << " called" << '\n';
    abort();
}

extern "C" uint32_t
__attribute__((weak)) __cpuid_eax(uint32_t val) noexcept
{
    std::cerr << static_cast<const char *>(__PRETTY_FUNCTION__) << " called with: " << view_as_pointer(val) << '\n';
    abort();
}

extern "C" uint32_t
__attribute__((weak)) __cpuid_ebx(uint32_t val) noexcept
{
    std::cerr << static_cast<const char *>(__PRETTY_FUNCTION__) << " called with: " << view_as_pointer(val) << '\n';
    abort();
}

extern "C" uint32_t
__attribute__((weak)) __cpuid_ecx(uint32_t val) noexcept
{
    std::cerr << static_cast<const char *>(__PRETTY_FUNCTION__) << " called with: " << view_as_pointer(val) << '\n';
    abort();
}

extern "C" uint32_t
__attribute__((weak)) __cpuid_edx(uint32_t val) noexcept
{
    std::cerr << static_cast<const char *>(__PRETTY_FUNCTION__) << " called with: " << view_as_pointer(val) << '\n';
    abort();
}

extern "C" void
__attribute__((weak)) __cpuid(uint64_t *rax, uint64_t *rbx, uint64_t *rcx, uint64_t *rdx) noexcept
{
    expects(rax);
    expects(rbx);
    expects(rcx);
    expects(rdx);

    std::cerr << static_cast<const char *>(__PRETTY_FUNCTION__) << " called with: " << '\n';
    std::cerr << "    - rax: " << view_as_pointer(*rax) << '\n';
    std::cerr << "    - rbx: " << view_as_pointer(*rbx) << '\n';
    std::cerr << "    - rcx: " << view_as_pointer(*rcx) << '\n';
    std::cerr << "    - rdx: " << view_as_pointer(*rdx) << '\n';
    abort();
}

extern "C" uint64_t
__attribute__((weak)) __read_rflags(void) noexcept
{
    std::cerr << static_cast<const char *>(__PRETTY_FUNCTION__) << " called" << '\n';
    abort();
}

extern "C" void
__attribute__((weak)) __write_rflags(uint64_t val) noexcept
{
    std::cerr << static_cast<const char *>(__PRETTY_FUNCTION__) << " called with: " << view_as_pointer(val) << '\n';
    abort();
}

extern "C" uint64_t
__attribute__((weak)) __read_msr(uint32_t addr) noexcept
{
    std::cerr << static_cast<const char *>(__PRETTY_FUNCTION__) << " called with: " << '\n';
    std::cerr << "    - msr: " << view_as_pointer(addr) << '\n';
    abort();
}

extern "C" void
__attribute__((weak)) __write_msr(uint32_t addr, uint64_t val) noexcept
{
    std::cerr << static_cast<const char *>(__PRETTY_FUNCTION__) << " called with: " << '\n';
    std::cerr << "    - msr: " << view_as_pointer(addr) << '\n';
    std::cerr << "    - val: " << view_as_pointer(val) << '\n';
    abort();
}

extern "C" uint64_t
__attribute__((weak)) __read_rip(void) noexcept
{
    std::cerr << static_cast<const char *>(__PRETTY_FUNCTION__) << " called" << '\n';
    abort();
}

extern "C" uint64_t
__attribute__((weak)) __read_cr0(void) noexcept
{
    std::cerr << static_cast<const char *>(__PRETTY_FUNCTION__) << " called" << '\n';
    abort();
}

extern "C" void
__attribute__((weak)) __write_cr0(uint64_t val) noexcept
{
    std::cerr << static_cast<const char *>(__PRETTY_FUNCTION__) << " called with: " << view_as_pointer(val) << '\n';
    abort();
}

extern "C" uint64_t
__attribute__((weak)) __read_cr3(void) noexcept
{
    std::cerr << static_cast<const char *>(__PRETTY_FUNCTION__) << " called" << '\n';
    abort();
}

extern "C" void
__attribute__((weak)) __write_cr3(uint64_t val) noexcept
{
    std::cerr << static_cast<const char *>(__PRETTY_FUNCTION__) << " called with: " << view_as_pointer(val) << '\n';
    abort();
}

extern "C" uint64_t
__attribute__((weak)) __read_cr4(void) noexcept
{
    std::cerr << static_cast<const char *>(__PRETTY_FUNCTION__) << " called" << '\n';
    abort();
}

extern "C" void
__attribute__((weak)) __write_cr4(uint64_t val) noexcept
{
    std::cerr << static_cast<const char *>(__PRETTY_FUNCTION__) << " called with: " << view_as_pointer(val) << '\n';
    abort();
}

extern "C" uint64_t
__attribute__((weak)) __read_dr7(void) noexcept
{
    std::cerr << static_cast<const char *>(__PRETTY_FUNCTION__) << " called" << '\n';
    abort();
}

extern "C" void
__attribute__((weak)) __write_dr7(uint64_t val) noexcept
{
    std::cerr << static_cast<const char *>(__PRETTY_FUNCTION__) << " called with: " << view_as_pointer(val) << '\n';
    abort();
}

extern "C" uint16_t
__attribute__((weak)) __read_es(void) noexcept
{
    std::cerr << static_cast<const char *>(__PRETTY_FUNCTION__) << " called" << '\n';
    abort();
}

extern "C" void
__attribute__((weak)) __write_es(uint16_t val) noexcept
{
    std::cerr << static_cast<const char *>(__PRETTY_FUNCTION__) << " called with: " << view_as_pointer(val) << '\n';
    abort();
}

extern "C" uint16_t
__attribute__((weak)) __read_cs(void) noexcept
{
    std::cerr << static_cast<const char *>(__PRETTY_FUNCTION__) << " called" << '\n';
    abort();
}

extern "C" void
__attribute__((weak)) __write_cs(uint16_t val) noexcept
{
    std::cerr << static_cast<const char *>(__PRETTY_FUNCTION__) << " called with: " << view_as_pointer(val) << '\n';
    abort();
}

extern "C" uint16_t
__attribute__((weak)) __read_ss(void) noexcept
{
    std::cerr << static_cast<const char *>(__PRETTY_FUNCTION__) << " called" << '\n';
    abort();
}

extern "C" void
__attribute__((weak)) __write_ss(uint16_t val) noexcept
{
    std::cerr << static_cast<const char *>(__PRETTY_FUNCTION__) << " called with: " << view_as_pointer(val) << '\n';
    abort();
}

extern "C" uint16_t
__attribute__((weak)) __read_ds(void) noexcept
{
    std::cerr << static_cast<const char *>(__PRETTY_FUNCTION__) << " called" << '\n';
    abort();
}

extern "C" void
__attribute__((weak)) __write_ds(uint16_t val) noexcept
{
    std::cerr << static_cast<const char *>(__PRETTY_FUNCTION__) << " called with: " << view_as_pointer(val) << '\n';
    abort();
}

extern "C" uint16_t
__attribute__((weak)) __read_fs(void) noexcept
{
    std::cerr << static_cast<const char *>(__PRETTY_FUNCTION__) << " called" << '\n';
    abort();
}

extern "C" void
__attribute__((weak)) __write_fs(uint16_t val) noexcept
{
    std::cerr << static_cast<const char *>(__PRETTY_FUNCTION__) << " called with: " << view_as_pointer(val) << '\n';
    abort();
}

extern "C" uint16_t
__attribute__((weak)) __read_gs(void) noexcept
{
    std::cerr << static_cast<const char *>(__PRETTY_FUNCTION__) << " called" << '\n';
    abort();
}

extern "C" void
__attribute__((weak)) __write_gs(uint16_t val) noexcept
{
    std::cerr << static_cast<const char *>(__PRETTY_FUNCTION__) << " called with: " << view_as_pointer(val) << '\n';
    abort();
}

extern "C" uint16_t
__attribute__((weak)) __read_tr(void) noexcept
{
    std::cerr << static_cast<const char *>(__PRETTY_FUNCTION__) << " called" << '\n';
    abort();
}

extern "C" void
__attribute__((weak)) __write_tr(uint16_t val) noexcept
{
    std::cerr << static_cast<const char *>(__PRETTY_FUNCTION__) << " called with: " << view_as_pointer(val) << '\n';
    abort();
}

extern "C" uint16_t
__attribute__((weak)) __read_ldtr(void) noexcept
{
    std::cerr << static_cast<const char *>(__PRETTY_FUNCTION__) << " called" << '\n';
    abort();
}

extern "C" void
__attribute__((weak)) __write_ldtr(uint16_t val) noexcept
{
    std::cerr << static_cast<const char *>(__PRETTY_FUNCTION__) << " called with: " << view_as_pointer(val) << '\n';
    abort();
}

extern "C" uint64_t
__attribute__((weak)) __read_rsp(void) noexcept
{
    std::cerr << static_cast<const char *>(__PRETTY_FUNCTION__) << " called" << '\n';
    abort();
}

extern "C" void
__attribute__((weak)) __read_gdt(void *gdt) noexcept
{
    std::cerr << static_cast<const char *>(__PRETTY_FUNCTION__) << " called with: " << '\n';
    std::cerr << "    - gdt: " << gdt << '\n';
    abort();
}

extern "C" void
__attribute__((weak)) __write_gdt(void *gdt) noexcept
{
    std::cerr << static_cast<const char *>(__PRETTY_FUNCTION__) << " called with: " << '\n';
    std::cerr << "    - gdt: " << gdt << '\n';
    abort();
}

extern "C" void
__attribute__((weak)) __read_idt(void *idt) noexcept
{
    std::cerr << static_cast<const char *>(__PRETTY_FUNCTION__) << " called with: " << '\n';
    std::cerr << "    - idt: " << idt << '\n';
    abort();
}

extern "C" void
__attribute__((weak)) __write_idt(void *idt) noexcept
{
    std::cerr << static_cast<const char *>(__PRETTY_FUNCTION__) << " called with: " << '\n';
    std::cerr << "    - idt: " << idt << '\n';
    abort();
}

extern "C" void
__attribute__((weak)) __outb(uint16_t port, uint8_t val) noexcept
{
    std::cerr << static_cast<const char *>(__PRETTY_FUNCTION__) << " called with: " << '\n';
    std::cerr << "    - port: " << view_as_pointer(port) << '\n';
    std::cerr << "    - val: " << view_as_pointer(val) << '\n';
    abort();
}

extern "C" void
__attribute__((weak)) __outw(uint16_t port, uint16_t val) noexcept
{
    std::cerr << static_cast<const char *>(__PRETTY_FUNCTION__) << " called with: " << '\n';
    std::cerr << "    - port: " << view_as_pointer(port) << '\n';
    std::cerr << "    - val: " << view_as_pointer(val) << '\n';
    abort();
}

extern "C" uint8_t
__attribute__((weak)) __inb(uint16_t port) noexcept
{
    std::cerr << static_cast<const char *>(__PRETTY_FUNCTION__) << " called with: " << '\n';
    std::cerr << "    - port: " << view_as_pointer(port) << '\n';
    abort();
}

extern "C" uint16_t
__attribute__((weak)) __inw(uint16_t port) noexcept
{
    std::cerr << static_cast<const char *>(__PRETTY_FUNCTION__) << " called with: " << '\n';
    std::cerr << "    - port: " << view_as_pointer(port) << '\n';
    abort();
}
