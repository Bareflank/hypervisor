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

#ifndef SRS_X64_H
#define SRS_X64_H

#include <gsl/gsl>

#include <debug.h>
#include <bitmanip.h>

extern "C" uint16_t __read_es(void) noexcept;
extern "C" void __write_es(uint16_t val) noexcept;

extern "C" uint16_t __read_cs(void) noexcept;
extern "C" void __write_cs(uint16_t val) noexcept;

extern "C" uint16_t __read_ss(void) noexcept;
extern "C" void __write_ss(uint16_t val) noexcept;

extern "C" uint16_t __read_ds(void) noexcept;
extern "C" void __write_ds(uint16_t val) noexcept;

extern "C" uint16_t __read_fs(void) noexcept;
extern "C" void __write_fs(uint16_t val) noexcept;

extern "C" uint16_t __read_gs(void) noexcept;
extern "C" void __write_gs(uint16_t val) noexcept;

extern "C" uint16_t __read_ldtr(void) noexcept;
extern "C" void __write_ldtr(uint16_t val) noexcept;

extern "C" uint16_t __read_tr(void) noexcept;
extern "C" void __write_tr(uint16_t val) noexcept;

// *INDENT-OFF*

namespace x64
{
namespace segment_register
{

using type = uint16_t;

namespace es
{
    inline auto get() noexcept
    { return __read_es(); }

    template<class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
    void set(T val) noexcept { __write_es(gsl::narrow_cast<type>(val)); }

    namespace rpl
    {
        constexpr const auto mask = 0x00000003U;
        constexpr const auto from = 0;
        constexpr const auto name = "rpl";

        inline auto get() noexcept
        { return gsl::narrow_cast<type>(get_bits(__read_es(), mask) >> from); }

        template<class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set(T val) noexcept { __write_es(gsl::narrow_cast<type>(set_bits(__read_es(), mask, val << from))); }
    }

    namespace ti
    {
        constexpr const auto mask = 0x00000004U;
        constexpr const auto from = 2;
        constexpr const auto name = "ti";

        inline auto get() noexcept
        { return gsl::narrow_cast<type>(get_bit(__read_es(), from)); }

        inline void set(bool val) noexcept
        { __write_es(gsl::narrow_cast<type>(val ? set_bit(__read_es(), from) : clear_bit(__read_es(), from))); }
    }

    namespace index
    {
        constexpr const auto mask = 0x0000FFF8U;
        constexpr const auto from = 3;
        constexpr const auto name = "index";

        inline auto get() noexcept
        { return gsl::narrow_cast<type>(get_bits(__read_es(), mask) >> from); }

        template<class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set(T val) noexcept { __write_es(gsl::narrow_cast<type>(set_bits(__read_es(), mask, val << from))); }
    }
}

namespace cs
{
    inline auto get() noexcept
    { return __read_cs(); }

    template<class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
    void set(T val) noexcept { __write_cs(gsl::narrow_cast<type>(val)); }

    namespace rpl
    {
        constexpr const auto mask = 0x00000003U;
        constexpr const auto from = 0;
        constexpr const auto name = "rpl";

        inline auto get() noexcept
        { return gsl::narrow_cast<type>(get_bits(__read_cs(), mask) >> from); }

        template<class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set(T val) noexcept { __write_cs(gsl::narrow_cast<type>(set_bits(__read_cs(), mask, val << from))); }
    }

    namespace ti
    {
        constexpr const auto mask = 0x00000004U;
        constexpr const auto from = 2;
        constexpr const auto name = "ti";

        inline auto get() noexcept
        { return gsl::narrow_cast<type>(get_bit(__read_cs(), from)); }

        inline void set(bool val) noexcept
        { __write_cs(gsl::narrow_cast<type>(val ? set_bit(__read_cs(), from) : clear_bit(__read_cs(), from))); }
    }

    namespace index
    {
        constexpr const auto mask = 0x0000FFF8U;
        constexpr const auto from = 3;
        constexpr const auto name = "index";

        inline auto get() noexcept
        { return gsl::narrow_cast<type>(get_bits(__read_cs(), mask) >> from); }

        template<class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set(T val) noexcept { __write_cs(gsl::narrow_cast<type>(set_bits(__read_cs(), mask, val << from))); }
    }
}

namespace ss
{
    inline auto get() noexcept
    { return __read_ss(); }

    template<class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
    void set(T val) noexcept { __write_ss(gsl::narrow_cast<type>(val)); }

    namespace rpl
    {
        constexpr const auto mask = 0x00000003U;
        constexpr const auto from = 0;
        constexpr const auto name = "rpl";

        inline auto get() noexcept
        { return gsl::narrow_cast<type>(get_bits(__read_ss(), mask) >> from); }

        template<class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set(T val) noexcept { __write_ss(gsl::narrow_cast<type>(set_bits(__read_ss(), mask, val << from))); }
    }

    namespace ti
    {
        constexpr const auto mask = 0x00000004U;
        constexpr const auto from = 2;
        constexpr const auto name = "ti";

        inline auto get() noexcept
        { return gsl::narrow_cast<type>(get_bit(__read_ss(), from)); }

        inline void set(bool val) noexcept
        { __write_ss(gsl::narrow_cast<type>(val ? set_bit(__read_ss(), from) : clear_bit(__read_ss(), from))); }
    }

    namespace index
    {
        constexpr const auto mask = 0x0000FFF8U;
        constexpr const auto from = 3;
        constexpr const auto name = "index";

        inline auto get() noexcept
        { return gsl::narrow_cast<type>(get_bits(__read_ss(), mask) >> from); }

        template<class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set(T val) noexcept { __write_ss(gsl::narrow_cast<type>(set_bits(__read_ss(), mask, val << from))); }
    }
}

namespace ds
{
    inline auto get() noexcept
    { return __read_ds(); }

    template<class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
    void set(T val) noexcept { __write_ds(gsl::narrow_cast<type>(val)); }

    namespace rpl
    {
        constexpr const auto mask = 0x00000003U;
        constexpr const auto from = 0;
        constexpr const auto name = "rpl";

        inline auto get() noexcept
        { return gsl::narrow_cast<type>(get_bits(__read_ds(), mask) >> from); }

        template<class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set(T val) noexcept { __write_ds(gsl::narrow_cast<type>(set_bits(__read_ds(), mask, val << from))); }
    }

    namespace ti
    {
        constexpr const auto mask = 0x00000004U;
        constexpr const auto from = 2;
        constexpr const auto name = "ti";

        inline auto get() noexcept
        { return gsl::narrow_cast<type>(get_bit(__read_ds(), from)); }

        inline void set(bool val) noexcept
        { __write_ds(gsl::narrow_cast<type>(val ? set_bit(__read_ds(), from) : clear_bit(__read_ds(), from))); }
    }

    namespace index
    {
        constexpr const auto mask = 0x0000FFF8U;
        constexpr const auto from = 3;
        constexpr const auto name = "index";

        inline auto get() noexcept
        { return gsl::narrow_cast<type>(get_bits(__read_ds(), mask) >> from); }

        template<class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set(T val) noexcept { __write_ds(gsl::narrow_cast<type>(set_bits(__read_ds(), mask, val << from))); }
    }
}

namespace fs
{
    inline auto get() noexcept
    { return __read_fs(); }

    template<class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
    void set(T val) noexcept { __write_fs(gsl::narrow_cast<type>(val)); }

    namespace rpl
    {
        constexpr const auto mask = 0x00000003U;
        constexpr const auto from = 0;
        constexpr const auto name = "rpl";

        inline auto get() noexcept
        { return gsl::narrow_cast<type>(get_bits(__read_fs(), mask) >> from); }

        template<class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set(T val) noexcept { __write_fs(gsl::narrow_cast<type>(set_bits(__read_fs(), mask, val << from))); }
    }

    namespace ti
    {
        constexpr const auto mask = 0x00000004U;
        constexpr const auto from = 2;
        constexpr const auto name = "ti";

        inline auto get() noexcept
        { return gsl::narrow_cast<type>(get_bit(__read_fs(), from)); }

        inline void set(bool val) noexcept
        { __write_fs(gsl::narrow_cast<type>(val ? set_bit(__read_fs(), from) : clear_bit(__read_fs(), from))); }
    }

    namespace index
    {
        constexpr const auto mask = 0x0000FFF8U;
        constexpr const auto from = 3;
        constexpr const auto name = "index";

        inline auto get() noexcept
        { return gsl::narrow_cast<type>(get_bits(__read_fs(), mask) >> from); }

        template<class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set(T val) noexcept { __write_fs(gsl::narrow_cast<type>(set_bits(__read_fs(), mask, val << from))); }
    }
}

namespace gs
{
    inline auto get() noexcept
    { return __read_gs(); }

    template<class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
    void set(T val) noexcept { __write_gs(gsl::narrow_cast<type>(val)); }

    namespace rpl
    {
        constexpr const auto mask = 0x00000003U;
        constexpr const auto from = 0;
        constexpr const auto name = "rpl";

        inline auto get() noexcept
        { return gsl::narrow_cast<type>(get_bits(__read_gs(), mask) >> from); }

        template<class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set(T val) noexcept { __write_gs(gsl::narrow_cast<type>(set_bits(__read_gs(), mask, val << from))); }
    }

    namespace ti
    {
        constexpr const auto mask = 0x00000004U;
        constexpr const auto from = 2;
        constexpr const auto name = "ti";

        inline auto get() noexcept
        { return gsl::narrow_cast<type>(get_bit(__read_gs(), from)); }

        inline void set(bool val) noexcept
        { __write_gs(gsl::narrow_cast<type>(val ? set_bit(__read_gs(), from) : clear_bit(__read_gs(), from))); }
    }

    namespace index
    {
        constexpr const auto mask = 0x0000FFF8U;
        constexpr const auto from = 3;
        constexpr const auto name = "index";

        inline auto get() noexcept
        { return gsl::narrow_cast<type>(get_bits(__read_gs(), mask) >> from); }

        template<class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set(T val) noexcept { __write_gs(gsl::narrow_cast<type>(set_bits(__read_gs(), mask, val << from))); }
    }
}

namespace ldtr
{
    inline auto get() noexcept
    { return __read_ldtr(); }

    template<class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
    void set(T val) noexcept { __write_ldtr(gsl::narrow_cast<type>(val)); }

    namespace rpl
    {
        constexpr const auto mask = 0x00000003U;
        constexpr const auto from = 0;
        constexpr const auto name = "rpl";

        inline auto get() noexcept
        { return gsl::narrow_cast<type>(get_bits(__read_ldtr(), mask) >> from); }

        template<class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set(T val) noexcept { __write_ldtr(gsl::narrow_cast<type>(set_bits(__read_ldtr(), mask, val << from))); }
    }

    namespace ti
    {
        constexpr const auto mask = 0x00000004U;
        constexpr const auto from = 2;
        constexpr const auto name = "ti";

        inline auto get() noexcept
        { return gsl::narrow_cast<type>(get_bit(__read_ldtr(), from)); }

        inline void set(bool val) noexcept
        { __write_ldtr(gsl::narrow_cast<type>(val ? set_bit(__read_ldtr(), from) : clear_bit(__read_ldtr(), from))); }
    }

    namespace index
    {
        constexpr const auto mask = 0x0000FFF8U;
        constexpr const auto from = 3;
        constexpr const auto name = "index";

        inline auto get() noexcept
        { return gsl::narrow_cast<type>(get_bits(__read_ldtr(), mask) >> from); }

        template<class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set(T val) noexcept { __write_ldtr(gsl::narrow_cast<type>(set_bits(__read_ldtr(), mask, val << from))); }
    }
}

namespace tr
{
    inline auto get() noexcept
    { return __read_tr(); }

    template<class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
    void set(T val) noexcept { __write_tr(gsl::narrow_cast<type>(val)); }

    namespace rpl
    {
        constexpr const auto mask = 0x00000003U;
        constexpr const auto from = 0;
        constexpr const auto name = "rpl";

        inline auto get() noexcept
        { return gsl::narrow_cast<type>(get_bits(__read_tr(), mask) >> from); }

        template<class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set(T val) noexcept { __write_tr(gsl::narrow_cast<type>(set_bits(__read_tr(), mask, val << from))); }
    }

    namespace ti
    {
        constexpr const auto mask = 0x00000004U;
        constexpr const auto from = 2;
        constexpr const auto name = "ti";

        inline auto get() noexcept
        { return gsl::narrow_cast<type>(get_bit(__read_tr(), from)); }

        inline void set(bool val) noexcept
        { __write_tr(gsl::narrow_cast<type>(val ? set_bit(__read_tr(), from) : clear_bit(__read_tr(), from))); }
    }

    namespace index
    {
        constexpr const auto mask = 0x0000FFF8U;
        constexpr const auto from = 3;
        constexpr const auto name = "index";

        inline auto get() noexcept
        { return gsl::narrow_cast<type>(get_bits(__read_tr(), mask) >> from); }

        template<class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set(T val) noexcept { __write_tr(gsl::narrow_cast<type>(set_bits(__read_tr(), mask, val << from))); }
    }
}
}
}

// *INDENT-ON*

#endif
