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

#ifndef CPUID_X64_H
#define CPUID_X64_H

#include <debug.h>
#include <bitmanip.h>

extern "C" uint32_t __cpuid_eax(uint32_t val) noexcept;
extern "C" uint32_t __cpuid_ebx(uint32_t val) noexcept;
extern "C" uint32_t __cpuid_ecx(uint32_t val) noexcept;
extern "C" uint32_t __cpuid_edx(uint32_t val) noexcept;
extern "C" void __cpuid(void *eax, void *ebx, void *ecx, void *edx) noexcept;

// *INDENT-OFF*

namespace x64
{
namespace cpuid
{
    using field_type = uint32_t;
    using value_type = uint32_t;

    template<class T1, class T2, class T3, class T4,
             class = typename std::enable_if<std::is_integral<T1>::value>::type,
             class = typename std::enable_if<std::is_integral<T2>::value>::type,
             class = typename std::enable_if<std::is_integral<T3>::value>::type,
             class = typename std::enable_if<std::is_integral<T4>::value>::type>
    auto get(T1 eax, T2 ebx, T3 ecx, T4 edx) noexcept
    {
        __cpuid(&eax, &ebx, &ecx, &edx);
        return std::make_tuple(eax, ebx, ecx, edx);
    }

    namespace eax
    {
        template<class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        auto get(T eax) noexcept { return __cpuid_eax(gsl::narrow_cast<uint32_t>(eax)); }
    }

    namespace ebx
    {
        template<class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        auto get(T ebx) noexcept { return __cpuid_ebx(gsl::narrow_cast<uint32_t>(ebx)); }
    }

    namespace ecx
    {
        template<class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        auto get(T ecx) noexcept { return __cpuid_ecx(gsl::narrow_cast<uint32_t>(ecx)); }
    }

    namespace edx
    {
        template<class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        auto get(T edx) noexcept { return __cpuid_edx(gsl::narrow_cast<uint32_t>(edx)); }
    }

    namespace addr_size
    {
        constexpr const auto addr = 0x80000008U;
        constexpr const auto name = "addr_size";

        namespace phys
        {
            constexpr const auto mask = 0x000000FFU;
            constexpr const auto from = 0;
            constexpr const auto name = "phys";

            inline auto get() noexcept
            { return get_bits(__cpuid_eax(addr), mask) >> from; }
        }

        namespace linear
        {
            constexpr const auto mask = 0x0000FF00U;
            constexpr const auto from = 8;
            constexpr const auto name = "linear";

            inline auto get() noexcept
            { return get_bits(__cpuid_eax(addr), mask) >> from; }
        }
    }

    namespace feature_information
    {
        constexpr const auto addr = 0x00000001U;
        constexpr const auto name = "feature_information";

        namespace ecx
        {
            namespace sse3
            {
                constexpr const auto mask = 0x00000001U;
                constexpr const auto from = 0;
                constexpr const auto name = "sse3";

                inline auto get() noexcept
                { return get_bit(__cpuid_ecx(addr), from) != 0; }
            }

            namespace pclmulqdq
            {
                constexpr const auto mask = 0x00000002U;
                constexpr const auto from = 1;
                constexpr const auto name = "pclmulqdq";

                inline auto get() noexcept
                { return get_bit(__cpuid_ecx(addr), from) != 0; }
            }

            namespace dtes64
            {
                constexpr const auto mask = 0x00000004U;
                constexpr const auto from = 2;
                constexpr const auto name = "dtes64";

                inline auto get() noexcept
                { return get_bit(__cpuid_ecx(addr), from) != 0; }
            }

            namespace monitor
            {
                constexpr const auto mask = 0x00000008U;
                constexpr const auto from = 3;
                constexpr const auto name = "monitor";

                inline auto get() noexcept
                { return get_bit(__cpuid_ecx(addr), from) != 0; }
            }

            namespace ds_cpl
            {
                constexpr const auto mask = 0x00000010U;
                constexpr const auto from = 4;
                constexpr const auto name = "ds_cpl";

                inline auto get() noexcept
                { return get_bit(__cpuid_ecx(addr), from) != 0; }
            }

            namespace vmx
            {
                constexpr const auto mask = 0x00000020U;
                constexpr const auto from = 5;
                constexpr const auto name = "vmx";

                inline auto get() noexcept
                { return get_bit(__cpuid_ecx(addr), from) != 0; }
            }

            namespace smx
            {
                constexpr const auto mask = 0x00000040U;
                constexpr const auto from = 6;
                constexpr const auto name = "smx";

                inline auto get() noexcept
                { return get_bit(__cpuid_ecx(addr), from) != 0; }
            }

            namespace eist
            {
                constexpr const auto mask = 0x00000080U;
                constexpr const auto from = 7;
                constexpr const auto name = "eist";

                inline auto get() noexcept
                { return get_bit(__cpuid_ecx(addr), from) != 0; }
            }

            namespace tm2
            {
                constexpr const auto mask = 0x00000100U;
                constexpr const auto from = 8;
                constexpr const auto name = "tm2";

                inline auto get() noexcept
                { return get_bit(__cpuid_ecx(addr), from) != 0; }
            }

            namespace ssse3
            {
                constexpr const auto mask = 0x00000200U;
                constexpr const auto from = 9;
                constexpr const auto name = "ssse3";

                inline auto get() noexcept
                { return get_bit(__cpuid_ecx(addr), from) != 0; }
            }

            namespace cnxt_id
            {
                constexpr const auto mask = 0x00000400U;
                constexpr const auto from = 10;
                constexpr const auto name = "cnxt_id";

                inline auto get() noexcept
                { return get_bit(__cpuid_ecx(addr), from) != 0; }
            }

            namespace sdbg
            {
                constexpr const auto mask = 0x00000800U;
                constexpr const auto from = 11;
                constexpr const auto name = "sdbg";

                inline auto get() noexcept
                { return get_bit(__cpuid_ecx(addr), from) != 0; }
            }

            namespace fma
            {
                constexpr const auto mask = 0x00001000U;
                constexpr const auto from = 12;
                constexpr const auto name = "fma";

                inline auto get() noexcept
                { return get_bit(__cpuid_ecx(addr), from) != 0; }
            }

            namespace cmpxchg16b
            {
                constexpr const auto mask = 0x00002000U;
                constexpr const auto from = 13;
                constexpr const auto name = "cmpxchg16b";

                inline auto get() noexcept
                { return get_bit(__cpuid_ecx(addr), from) != 0; }
            }

            namespace xtpr_update_control
            {
                constexpr const auto mask = 0x00004000U;
                constexpr const auto from = 14;
                constexpr const auto name = "xtpr_update_control";

                inline auto get() noexcept
                { return get_bit(__cpuid_ecx(addr), from) != 0; }
            }

            namespace pdcm
            {
                constexpr const auto mask = 0x00008000U;
                constexpr const auto from = 15;
                constexpr const auto name = "pdcm";

                inline auto get() noexcept
                { return get_bit(__cpuid_ecx(addr), from) != 0; }
            }

            namespace pcid
            {
                constexpr const auto mask = 0x00020000U;
                constexpr const auto from = 17;
                constexpr const auto name = "pcid";

                inline auto get() noexcept
                { return get_bit(__cpuid_ecx(addr), from) != 0; }
            }

            namespace dca
            {
                constexpr const auto mask = 0x00040000U;
                constexpr const auto from = 18;
                constexpr const auto name = "dca";

                inline auto get() noexcept
                { return get_bit(__cpuid_ecx(addr), from) != 0; }
            }

            namespace sse41
            {
                constexpr const auto mask = 0x00080000U;
                constexpr const auto from = 19;
                constexpr const auto name = "sse41";

                inline auto get() noexcept
                { return get_bit(__cpuid_ecx(addr), from) != 0; }
            }

            namespace sse42
            {
                constexpr const auto mask = 0x00100000U;
                constexpr const auto from = 20;
                constexpr const auto name = "sse42";

                inline auto get() noexcept
                { return get_bit(__cpuid_ecx(addr), from) != 0; }
            }

            namespace x2apic
            {
                constexpr const auto mask = 0x00200000U;
                constexpr const auto from = 21;
                constexpr const auto name = "x2apic";

                inline auto get() noexcept
                { return get_bit(__cpuid_ecx(addr), from) != 0; }
            }

            namespace movbe
            {
                constexpr const auto mask = 0x00400000U;
                constexpr const auto from = 22;
                constexpr const auto name = "movbe";

                inline auto get() noexcept
                { return get_bit(__cpuid_ecx(addr), from) != 0; }
            }

            namespace popcnt
            {
                constexpr const auto mask = 0x00800000U;
                constexpr const auto from = 23;
                constexpr const auto name = "popcnt";

                inline auto get() noexcept
                { return get_bit(__cpuid_ecx(addr), from) != 0; }
            }

            namespace tsc_deadline
            {
                constexpr const auto mask = 0x01000000U;
                constexpr const auto from = 24;
                constexpr const auto name = "tsc_deadline";

                inline auto get() noexcept
                { return get_bit(__cpuid_ecx(addr), from) != 0; }
            }

            namespace aesni
            {
                constexpr const auto mask = 0x02000000U;
                constexpr const auto from = 25;
                constexpr const auto name = "aesni";

                inline auto get() noexcept
                { return get_bit(__cpuid_ecx(addr), from) != 0; }
            }

            namespace xsave
            {
                constexpr const auto mask = 0x04000000U;
                constexpr const auto from = 26;
                constexpr const auto name = "xsave";

                inline auto get() noexcept
                { return get_bit(__cpuid_ecx(addr), from) != 0; }
            }

            namespace osxsave
            {
                constexpr const auto mask = 0x08000000U;
                constexpr const auto from = 27;
                constexpr const auto name = "osxsave";

                inline auto get() noexcept
                { return get_bit(__cpuid_ecx(addr), from) != 0; }
            }

            namespace avx
            {
                constexpr const auto mask = 0x10000000U;
                constexpr const auto from = 28;
                constexpr const auto name = "avx";

                inline auto get() noexcept
                { return get_bit(__cpuid_ecx(addr), from) != 0; }
            }

            namespace f16c
            {
                constexpr const auto mask = 0x20000000U;
                constexpr const auto from = 29;
                constexpr const auto name = "f16c";

                inline auto get() noexcept
                { return get_bit(__cpuid_ecx(addr), from) != 0; }
            }

            namespace rdrand
            {
                constexpr const auto mask = 0x40000000U;
                constexpr const auto from = 30;
                constexpr const auto name = "rdrand";

                inline auto get() noexcept
                { return get_bit(__cpuid_ecx(addr), from) != 0; }
            }

            inline void dump() noexcept
            {
                bfdebug << "cpuid::feature_information::ecx enabled flags:" << bfendl;

                if (sse3::get())
                    bfdebug << "    - sse3" << bfendl;

                if (pclmulqdq::get())
                    bfdebug << "    - pclmulqdq" << bfendl;

                if (dtes64::get())
                    bfdebug << "    - dtes64" << bfendl;

                if (monitor::get())
                    bfdebug << "    - monitor" << bfendl;

                if (ds_cpl::get())
                    bfdebug << "    - ds_cpl" << bfendl;

                if (vmx::get())
                    bfdebug << "    - vmx" << bfendl;

                if (smx::get())
                    bfdebug << "    - smx" << bfendl;

                if (eist::get())
                    bfdebug << "    - eist" << bfendl;

                if (tm2::get())
                    bfdebug << "    - tm2" << bfendl;

                if (ssse3::get())
                    bfdebug << "    - ssse3" << bfendl;

                if (cnxt_id::get())
                    bfdebug << "    - cnxt_id" << bfendl;

                if (sdbg::get())
                    bfdebug << "    - sdbg" << bfendl;

                if (fma::get())
                    bfdebug << "    - fma" << bfendl;

                if (cmpxchg16b::get())
                    bfdebug << "    - cmpxchg16b" << bfendl;

                if (xtpr_update_control::get())
                    bfdebug << "    - xtpr_update_control" << bfendl;

                if (pdcm::get())
                    bfdebug << "    - pdcm" << bfendl;

                if (pcid::get())
                    bfdebug << "    - pcid" << bfendl;

                if (dca::get())
                    bfdebug << "    - dca" << bfendl;

                if (sse41::get())
                    bfdebug << "    - sse41" << bfendl;

                if (sse42::get())
                    bfdebug << "    - sse42" << bfendl;

                if (x2apic::get())
                    bfdebug << "    - x2apic" << bfendl;

                if (movbe::get())
                    bfdebug << "    - movbe" << bfendl;

                if (popcnt::get())
                    bfdebug << "    - popcnt" << bfendl;

                if (tsc_deadline::get())
                    bfdebug << "    - tsc_deadline" << bfendl;

                if (aesni::get())
                    bfdebug << "    - aesni" << bfendl;

                if (xsave::get())
                    bfdebug << "    - xsave" << bfendl;

                if (osxsave::get())
                    bfdebug << "    - osxsave" << bfendl;

                if (avx::get())
                    bfdebug << "    - avx" << bfendl;

                if (f16c::get())
                    bfdebug << "    - f16c" << bfendl;

                if (rdrand::get())
                    bfdebug << "    - rdrand" << bfendl;
            }
        }
    }

    namespace extended_feature_flags
    {
        constexpr const auto addr = 0x00000007UL;
        constexpr const auto name = "extended_feature_flags";

        namespace subleaf0
        {
            namespace ebx
            {
                namespace sgx
                {
                    constexpr const auto mask = 0x00000004UL;
                    constexpr const auto from = 2;
                    constexpr const auto name = "sgx";

                    inline auto get() noexcept
                    {
                        value_type eax = addr;
                        value_type ebx = 0U;
                        value_type ecx = 0U;
                        value_type edx = 0U;

                        __cpuid(&eax, &ebx, &ecx, &edx);

                        return (ebx & mask) != 0;
                    }
                }

                namespace rtm
                {
                    constexpr const auto mask = 0x00000800UL;
                    constexpr const auto from = 11;
                    constexpr const auto name = "rtm";

                    inline auto get() noexcept
                    {
                        value_type eax = addr;
                        value_type ebx = 0U;
                        value_type ecx = 0U;
                        value_type edx = 0U;

                        __cpuid(&eax, &ebx, &ecx, &edx);

                        return (ebx & mask) != 0;
                    }
                }

                inline void dump() noexcept
                {
                    bfdebug << "cpuid::extended_feature_flags::subleaf0::ebx enabled flags:" << bfendl;

                    if (sgx::get())
                        bfdebug << "    - sgx" << bfendl;

                    if (rtm::get())
                        bfdebug << "    - rtm" << bfendl;
                }
            }
        }
    }

}
}

// *INDENT-ON*

#endif
