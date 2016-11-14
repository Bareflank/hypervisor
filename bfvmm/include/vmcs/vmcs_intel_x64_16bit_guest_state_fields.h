//
// Bareflank Hypervisor
//
// Copyright (C) 2015 Assured Information Security, Inc.
// Author: Rian Quinn        <quinnr@ainfosec.com>
// Author: Brendan Kerrigan  <kerriganb@ainfosec.com>
// Author: Connor Davis      <davisc@ainfosec.com>
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

#ifndef VMCS_INTEL_X64_16BIT_GUEST_STATE_FIELDS_H
#define VMCS_INTEL_X64_16BIT_GUEST_STATE_FIELDS_H

#include <vmcs/vmcs_intel_x64.h>
#include <intrinsics/msrs_intel_x64.h>


/// Intel x86_64 VMCS 16-Bit Guest-State Fields
///
/// The following provides the interface for the 16-bit guest-state VMCS
/// fields as defined in Appendix B.1.2, Vol. 3 of the Intel Software Developer's
/// Manual.
///

// *INDENT-OFF*
namespace intel_x64
{
namespace vmcs
{

namespace guest_es_selector
{
    constexpr const auto addr = 0x0000000000000800UL;
    constexpr const auto name = "guest_es_selector";

    inline bool exists() noexcept
    { return true; }

    inline auto get()
    { return get_vmcs_field(addr, name, exists()); }

    inline auto get_if_exists(bool verbose = false) noexcept
    { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }

    template<class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
    void set(T val) { set_vmcs_field(val, addr, name, exists()); }

    template<class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
    void set_if_exists(T val, bool verbose = false) noexcept
    { set_vmcs_field_if_exists(val, addr, name, verbose, exists()); }

    namespace rpl
    {
        constexpr const auto mask = 0x00000003U;
        constexpr const auto from = 0;
        constexpr const auto name = "rpl";

        inline auto get()
        { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

        inline auto get_if_exists(bool verbose = false) noexcept
        { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }

        template<class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set(T val)
        {
            auto&& field = get_vmcs_field(addr, name, exists());
            set_vmcs_field(set_bits(field, mask, (val << from)), addr, name, exists());
        }

        template<class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set_if_exists(T val, bool verbose = false) noexcept
        {
            auto&& field = get_vmcs_field_if_exists(addr, name, verbose, exists());
            set_vmcs_field_if_exists(set_bits(field, mask, (val << from)), addr, name, verbose, exists());
        }
    }

    namespace ti
    {
        constexpr const auto mask = 0x00000004U;
        constexpr const auto from = 2;
        constexpr const auto name = "ti";

        inline auto get()
        { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

        inline auto get_if_exists(bool verbose = false) noexcept
        { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline void set(bool b)
        {
            auto&& field = get_vmcs_field(addr, name, exists());
            set_vmcs_field(b ? set_bit(field, from) : clear_bit(field, from), addr, name, exists());
        }

        inline void set_if_exists(bool b, bool verbose = false) noexcept
        {
            auto&& field = get_vmcs_field_if_exists(addr, name, verbose, exists());
            set_vmcs_field_if_exists(b ? set_bit(field, from) : clear_bit(field, from), addr, name, verbose, exists());
        }
    }

    namespace index
    {
        constexpr const auto mask = 0x0000FFF8U;
        constexpr const auto from = 3;
        constexpr const auto name = "index";

        inline auto get()
        { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

        inline auto get_if_exists(bool verbose = false) noexcept
        { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }

        template<class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set(T val)
        {
            auto&& field = get_vmcs_field(addr, name, exists());
            set_vmcs_field(set_bits(field, mask, (val << from)), addr, name, exists());
        }

        template<class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set_if_exists(T val, bool verbose = false) noexcept
        {
            auto&& field = get_vmcs_field_if_exists(addr, name, verbose, exists());
            set_vmcs_field_if_exists(set_bits(field, mask, (val << from)), addr, name, verbose, exists());
        }
    }
}

namespace guest_cs_selector
{
    constexpr const auto addr = 0x0000000000000802UL;
    constexpr const auto name = "guest_cs_selector";

    inline bool exists() noexcept
    { return true; }

    inline auto get()
    { return get_vmcs_field(addr, name, exists()); }

    inline auto get_if_exists(bool verbose = false) noexcept
    { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }

    template<class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
    void set(T val) { set_vmcs_field(val, addr, name, exists()); }

    template<class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
    void set_if_exists(T val, bool verbose = false) noexcept
    { set_vmcs_field_if_exists(val, addr, name, verbose, exists()); }

    namespace rpl
    {
        constexpr const auto mask = 0x00000003U;
        constexpr const auto from = 0;
        constexpr const auto name = "rpl";

        inline auto get()
        { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

        inline auto get_if_exists(bool verbose = false) noexcept
        { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }

        template<class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set(T val)
        {
            auto&& field = get_vmcs_field(addr, name, exists());
            set_vmcs_field(set_bits(field, mask, (val << from)), addr, name, exists());
        }

        template<class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set_if_exists(T val, bool verbose = false) noexcept
        {
            auto&& field = get_vmcs_field_if_exists(addr, name, verbose, exists());
            set_vmcs_field_if_exists(set_bits(field, mask, (val << from)), addr, name, verbose, exists());
        }
    }

    namespace ti
    {
        constexpr const auto mask = 0x00000004U;
        constexpr const auto from = 2;
        constexpr const auto name = "ti";

        inline auto get()
        { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

        inline auto get_if_exists(bool verbose = false) noexcept
        { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline void set(bool b)
        {
            auto&& field = get_vmcs_field(addr, name, exists());
            set_vmcs_field(b ? set_bit(field, from) : clear_bit(field, from), addr, name, exists());
        }

        inline void set_if_exists(bool b, bool verbose = false) noexcept
        {
            auto&& field = get_vmcs_field_if_exists(addr, name, verbose, exists());
            set_vmcs_field_if_exists(b ? set_bit(field, from) : clear_bit(field, from), addr, name, verbose, exists());
        }
    }

    namespace index
    {
        constexpr const auto mask = 0x0000FFF8U;
        constexpr const auto from = 3;
        constexpr const auto name = "index";

        inline auto get()
        { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

        inline auto get_if_exists(bool verbose = false) noexcept
        { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }

        template<class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set(T val)
        {
            auto&& field = get_vmcs_field(addr, name, exists());
            set_vmcs_field(set_bits(field, mask, (val << from)), addr, name, exists());
        }

        template<class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set_if_exists(T val, bool verbose = false) noexcept
        {
            auto&& field = get_vmcs_field_if_exists(addr, name, verbose, exists());
            set_vmcs_field_if_exists(set_bits(field, mask, (val << from)), addr, name, verbose, exists());
        }
    }
}

namespace guest_ss_selector
{
    constexpr const auto addr = 0x0000000000000804UL;
    constexpr const auto name = "guest_ss_selector";

    inline bool exists() noexcept
    { return true; }

    inline auto get()
    { return get_vmcs_field(addr, name, exists()); }

    inline auto get_if_exists(bool verbose = false) noexcept
    { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }

    template<class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
    void set(T val) { set_vmcs_field(val, addr, name, exists()); }

    template<class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
    void set_if_exists(T val, bool verbose = false) noexcept
    { set_vmcs_field_if_exists(val, addr, name, verbose, exists()); }

    namespace rpl
    {
        constexpr const auto mask = 0x00000003U;
        constexpr const auto from = 0;
        constexpr const auto name = "rpl";

        inline auto get()
        { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

        inline auto get_if_exists(bool verbose = false) noexcept
        { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }

        template<class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set(T val)
        {
            auto&& field = get_vmcs_field(addr, name, exists());
            set_vmcs_field(set_bits(field, mask, (val << from)), addr, name, exists());
        }

        template<class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set_if_exists(T val, bool verbose = false) noexcept
        {
            auto&& field = get_vmcs_field_if_exists(addr, name, verbose, exists());
            set_vmcs_field_if_exists(set_bits(field, mask, (val << from)), addr, name, verbose, exists());
        }
    }

    namespace ti
    {
        constexpr const auto mask = 0x00000004U;
        constexpr const auto from = 2;
        constexpr const auto name = "ti";

        inline auto get()
        { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

        inline auto get_if_exists(bool verbose = false) noexcept
        { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline void set(bool b)
        {
            auto&& field = get_vmcs_field(addr, name, exists());
            set_vmcs_field(b ? set_bit(field, from) : clear_bit(field, from), addr, name, exists());
        }

        inline void set_if_exists(bool b, bool verbose = false) noexcept
        {
            auto&& field = get_vmcs_field_if_exists(addr, name, verbose, exists());
            set_vmcs_field_if_exists(b ? set_bit(field, from) : clear_bit(field, from), addr, name, verbose, exists());
        }
    }

    namespace index
    {
        constexpr const auto mask = 0x0000FFF8U;
        constexpr const auto from = 3;
        constexpr const auto name = "index";

        inline auto get()
        { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

        inline auto get_if_exists(bool verbose = false) noexcept
        { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }

        template<class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set(T val)
        {
            auto&& field = get_vmcs_field(addr, name, exists());
            set_vmcs_field(set_bits(field, mask, (val << from)), addr, name, exists());
        }

        template<class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set_if_exists(T val, bool verbose = false) noexcept
        {
            auto&& field = get_vmcs_field_if_exists(addr, name, verbose, exists());
            set_vmcs_field_if_exists(set_bits(field, mask, (val << from)), addr, name, verbose, exists());
        }
    }
}

namespace guest_ds_selector
{
    constexpr const auto addr = 0x0000000000000806UL;
    constexpr const auto name = "guest_ds_selector";

    inline bool exists() noexcept
    { return true; }

    inline auto get()
    { return get_vmcs_field(addr, name, exists()); }

    inline auto get_if_exists(bool verbose = false) noexcept
    { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }

    template<class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
    void set(T val) { set_vmcs_field(val, addr, name, exists()); }

    template<class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
    void set_if_exists(T val, bool verbose = false) noexcept
    { set_vmcs_field_if_exists(val, addr, name, verbose, exists()); }

    namespace rpl
    {
        constexpr const auto mask = 0x00000003U;
        constexpr const auto from = 0;
        constexpr const auto name = "rpl";

        inline auto get()
        { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

        inline auto get_if_exists(bool verbose = false) noexcept
        { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }

        template<class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set(T val)
        {
            auto&& field = get_vmcs_field(addr, name, exists());
            set_vmcs_field(set_bits(field, mask, (val << from)), addr, name, exists());
        }

        template<class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set_if_exists(T val, bool verbose = false) noexcept
        {
            auto&& field = get_vmcs_field_if_exists(addr, name, verbose, exists());
            set_vmcs_field_if_exists(set_bits(field, mask, (val << from)), addr, name, verbose, exists());
        }
    }

    namespace ti
    {
        constexpr const auto mask = 0x00000004U;
        constexpr const auto from = 2;
        constexpr const auto name = "ti";

        inline auto get()
        { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

        inline auto get_if_exists(bool verbose = false) noexcept
        { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline void set(bool b)
        {
            auto&& field = get_vmcs_field(addr, name, exists());
            set_vmcs_field(b ? set_bit(field, from) : clear_bit(field, from), addr, name, exists());
        }

        inline void set_if_exists(bool b, bool verbose = false) noexcept
        {
            auto&& field = get_vmcs_field_if_exists(addr, name, verbose, exists());
            set_vmcs_field_if_exists(b ? set_bit(field, from) : clear_bit(field, from), addr, name, verbose, exists());
        }
    }

    namespace index
    {
        constexpr const auto mask = 0x0000FFF8U;
        constexpr const auto from = 3;
        constexpr const auto name = "index";

        inline auto get()
        { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

        inline auto get_if_exists(bool verbose = false) noexcept
        { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }

        template<class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set(T val)
        {
            auto&& field = get_vmcs_field(addr, name, exists());
            set_vmcs_field(set_bits(field, mask, (val << from)), addr, name, exists());
        }

        template<class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set_if_exists(T val, bool verbose = false) noexcept
        {
            auto&& field = get_vmcs_field_if_exists(addr, name, verbose, exists());
            set_vmcs_field_if_exists(set_bits(field, mask, (val << from)), addr, name, verbose, exists());
        }
    }
}

namespace guest_fs_selector
{
    constexpr const auto addr = 0x0000000000000808UL;
    constexpr const auto name = "guest_fs_selector";

    inline bool exists() noexcept
    { return true; }

    inline auto get()
    { return get_vmcs_field(addr, name, exists()); }

    inline auto get_if_exists(bool verbose = false) noexcept
    { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }

    template<class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
    void set(T val) { set_vmcs_field(val, addr, name, exists()); }

    template<class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
    void set_if_exists(T val, bool verbose = false) noexcept
    { set_vmcs_field_if_exists(val, addr, name, verbose, exists()); }

    namespace rpl
    {
        constexpr const auto mask = 0x00000003U;
        constexpr const auto from = 0;
        constexpr const auto name = "rpl";

        inline auto get()
        { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

        inline auto get_if_exists(bool verbose = false) noexcept
        { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }

        template<class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set(T val)
        {
            auto&& field = get_vmcs_field(addr, name, exists());
            set_vmcs_field(set_bits(field, mask, (val << from)), addr, name, exists());
        }

        template<class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set_if_exists(T val, bool verbose = false) noexcept
        {
            auto&& field = get_vmcs_field_if_exists(addr, name, verbose, exists());
            set_vmcs_field_if_exists(set_bits(field, mask, (val << from)), addr, name, verbose, exists());
        }
    }

    namespace ti
    {
        constexpr const auto mask = 0x00000004U;
        constexpr const auto from = 2;
        constexpr const auto name = "ti";

        inline auto get()
        { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

        inline auto get_if_exists(bool verbose = false) noexcept
        { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline void set(bool b)
        {
            auto&& field = get_vmcs_field(addr, name, exists());
            set_vmcs_field(b ? set_bit(field, from) : clear_bit(field, from), addr, name, exists());
        }

        inline void set_if_exists(bool b, bool verbose = false) noexcept
        {
            auto&& field = get_vmcs_field_if_exists(addr, name, verbose, exists());
            set_vmcs_field_if_exists(b ? set_bit(field, from) : clear_bit(field, from), addr, name, verbose, exists());
        }
    }

    namespace index
    {
        constexpr const auto mask = 0x0000FFF8U;
        constexpr const auto from = 3;
        constexpr const auto name = "index";

        inline auto get()
        { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

        inline auto get_if_exists(bool verbose = false) noexcept
        { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }

        template<class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set(T val)
        {
            auto&& field = get_vmcs_field(addr, name, exists());
            set_vmcs_field(set_bits(field, mask, (val << from)), addr, name, exists());
        }

        template<class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set_if_exists(T val, bool verbose = false) noexcept
        {
            auto&& field = get_vmcs_field_if_exists(addr, name, verbose, exists());
            set_vmcs_field_if_exists(set_bits(field, mask, (val << from)), addr, name, verbose, exists());
        }
    }
}

namespace guest_gs_selector
{
    constexpr const auto addr = 0x000000000000080AUL;
    constexpr const auto name = "guest_gs_selector";

    inline bool exists() noexcept
    { return true; }

    inline auto get()
    { return get_vmcs_field(addr, name, exists()); }

    inline auto get_if_exists(bool verbose = false) noexcept
    { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }

    template<class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
    void set(T val) { set_vmcs_field(val, addr, name, exists()); }

    template<class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
    void set_if_exists(T val, bool verbose = false) noexcept
    { set_vmcs_field_if_exists(val, addr, name, verbose, exists()); }

    namespace rpl
    {
        constexpr const auto mask = 0x00000003U;
        constexpr const auto from = 0;
        constexpr const auto name = "rpl";

        inline auto get()
        { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

        inline auto get_if_exists(bool verbose = false) noexcept
        { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }

        template<class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set(T val)
        {
            auto&& field = get_vmcs_field(addr, name, exists());
            set_vmcs_field(set_bits(field, mask, (val << from)), addr, name, exists());
        }

        template<class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set_if_exists(T val, bool verbose = false) noexcept
        {
            auto&& field = get_vmcs_field_if_exists(addr, name, verbose, exists());
            set_vmcs_field_if_exists(set_bits(field, mask, (val << from)), addr, name, verbose, exists());
        }
    }

    namespace ti
    {
        constexpr const auto mask = 0x00000004U;
        constexpr const auto from = 2;
        constexpr const auto name = "ti";

        inline auto get()
        { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

        inline auto get_if_exists(bool verbose = false) noexcept
        { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline void set(bool b)
        {
            auto&& field = get_vmcs_field(addr, name, exists());
            set_vmcs_field(b ? set_bit(field, from) : clear_bit(field, from), addr, name, exists());
        }

        inline void set_if_exists(bool b, bool verbose = false) noexcept
        {
            auto&& field = get_vmcs_field_if_exists(addr, name, verbose, exists());
            set_vmcs_field_if_exists(b ? set_bit(field, from) : clear_bit(field, from), addr, name, verbose, exists());
        }
    }

    namespace index
    {
        constexpr const auto mask = 0x0000FFF8U;
        constexpr const auto from = 3;
        constexpr const auto name = "index";

        inline auto get()
        { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

        inline auto get_if_exists(bool verbose = false) noexcept
        { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }

        template<class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set(T val)
        {
            auto&& field = get_vmcs_field(addr, name, exists());
            set_vmcs_field(set_bits(field, mask, (val << from)), addr, name, exists());
        }

        template<class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set_if_exists(T val, bool verbose = false) noexcept
        {
            auto&& field = get_vmcs_field_if_exists(addr, name, verbose, exists());
            set_vmcs_field_if_exists(set_bits(field, mask, (val << from)), addr, name, verbose, exists());
        }
    }
}

namespace guest_ldtr_selector
{
    constexpr const auto addr = 0x000000000000080CUL;
    constexpr const auto name = "guest_ldtr_selector";

    inline bool exists() noexcept
    { return true; }

    inline auto get()
    { return get_vmcs_field(addr, name, exists()); }

    inline auto get_if_exists(bool verbose = false) noexcept
    { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }

    template<class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
    void set(T val) { set_vmcs_field(val, addr, name, exists()); }

    template<class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
    void set_if_exists(T val, bool verbose = false) noexcept
    { set_vmcs_field_if_exists(val, addr, name, verbose, exists()); }

    namespace rpl
    {
        constexpr const auto mask = 0x00000003U;
        constexpr const auto from = 0;
        constexpr const auto name = "rpl";

        inline auto get()
        { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

        inline auto get_if_exists(bool verbose = false) noexcept
        { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }

        template<class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set(T val)
        {
            auto&& field = get_vmcs_field(addr, name, exists());
            set_vmcs_field(set_bits(field, mask, (val << from)), addr, name, exists());
        }

        template<class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set_if_exists(T val, bool verbose = false) noexcept
        {
            auto&& field = get_vmcs_field_if_exists(addr, name, verbose, exists());
            set_vmcs_field_if_exists(set_bits(field, mask, (val << from)), addr, name, verbose, exists());
        }
    }

    namespace ti
    {
        constexpr const auto mask = 0x00000004U;
        constexpr const auto from = 2;
        constexpr const auto name = "ti";

        inline auto get()
        { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

        inline auto get_if_exists(bool verbose = false) noexcept
        { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline void set(bool b)
        {
            auto&& field = get_vmcs_field(addr, name, exists());
            set_vmcs_field(b ? set_bit(field, from) : clear_bit(field, from), addr, name, exists());
        }

        inline void set_if_exists(bool b, bool verbose = false) noexcept
        {
            auto&& field = get_vmcs_field_if_exists(addr, name, verbose, exists());
            set_vmcs_field_if_exists(b ? set_bit(field, from) : clear_bit(field, from), addr, name, verbose, exists());
        }
    }

    namespace index
    {
        constexpr const auto mask = 0x0000FFF8U;
        constexpr const auto from = 3;
        constexpr const auto name = "index";

        inline auto get()
        { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

        inline auto get_if_exists(bool verbose = false) noexcept
        { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }

        template<class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set(T val)
        {
            auto&& field = get_vmcs_field(addr, name, exists());
            set_vmcs_field(set_bits(field, mask, (val << from)), addr, name, exists());
        }

        template<class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set_if_exists(T val, bool verbose = false) noexcept
        {
            auto&& field = get_vmcs_field_if_exists(addr, name, verbose, exists());
            set_vmcs_field_if_exists(set_bits(field, mask, (val << from)), addr, name, verbose, exists());
        }
    }
}

namespace guest_tr_selector
{
    constexpr const auto addr = 0x000000000000080EUL;
    constexpr const auto name = "guest_tr_selector";

    inline bool exists() noexcept
    { return true; }

    inline auto get()
    { return get_vmcs_field(addr, name, exists()); }

    inline auto get_if_exists(bool verbose = false) noexcept
    { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }

    template<class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
    void set(T val) { set_vmcs_field(val, addr, name, exists()); }

    template<class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
    void set_if_exists(T val, bool verbose = false) noexcept
    { set_vmcs_field_if_exists(val, addr, name, verbose, exists()); }

    namespace rpl
    {
        constexpr const auto mask = 0x00000003U;
        constexpr const auto from = 0;
        constexpr const auto name = "rpl";

        inline auto get()
        { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

        inline auto get_if_exists(bool verbose = false) noexcept
        { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }

        template<class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set(T val)
        {
            auto&& field = get_vmcs_field(addr, name, exists());
            set_vmcs_field(set_bits(field, mask, (val << from)), addr, name, exists());
        }

        template<class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set_if_exists(T val, bool verbose = false) noexcept
        {
            auto&& field = get_vmcs_field_if_exists(addr, name, verbose, exists());
            set_vmcs_field_if_exists(set_bits(field, mask, (val << from)), addr, name, verbose, exists());
        }
    }

    namespace ti
    {
        constexpr const auto mask = 0x00000004U;
        constexpr const auto from = 2;
        constexpr const auto name = "ti";

        inline auto get()
        { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

        inline auto get_if_exists(bool verbose = false) noexcept
        { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline void set(bool b)
        {
            auto&& field = get_vmcs_field(addr, name, exists());
            set_vmcs_field(b ? set_bit(field, from) : clear_bit(field, from), addr, name, exists());
        }

        inline void set_if_exists(bool b, bool verbose = false) noexcept
        {
            auto&& field = get_vmcs_field_if_exists(addr, name, verbose, exists());
            set_vmcs_field_if_exists(b ? set_bit(field, from) : clear_bit(field, from), addr, name, verbose, exists());
        }
    }

    namespace index
    {
        constexpr const auto mask = 0x0000FFF8U;
        constexpr const auto from = 3;
        constexpr const auto name = "index";

        inline auto get()
        { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

        inline auto get_if_exists(bool verbose = false) noexcept
        { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }

        template<class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set(T val)
        {
            auto&& field = get_vmcs_field(addr, name, exists());
            set_vmcs_field(set_bits(field, mask, (val << from)), addr, name, exists());
        }

        template<class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
        void set_if_exists(T val, bool verbose = false) noexcept
        {
            auto&& field = get_vmcs_field_if_exists(addr, name, verbose, exists());
            set_vmcs_field_if_exists(set_bits(field, mask, (val << from)), addr, name, verbose, exists());
        }
    }
}

namespace guest_interrupt_status
{
    constexpr const auto addr = 0x0000000000000810UL;
    constexpr const auto name = "guest_interrupt_status";

    inline bool exists() noexcept
    {
        return msrs::ia32_vmx_true_procbased_ctls::activate_secondary_controls::is_allowed1() &&
               msrs::ia32_vmx_procbased_ctls2::virtual_interrupt_delivery::is_allowed1();
    }

    inline auto get()
    { return get_vmcs_field(addr, name, exists()); }

    inline auto get_if_exists(bool verbose = false) noexcept
    { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }

    template<class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
    void set(T val) { set_vmcs_field(val, addr, name, exists()); }

    template<class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
    void set_if_exists(T val, bool verbose = false) noexcept
    { set_vmcs_field_if_exists(val, addr, name, verbose, exists()); }
}

}
}

// *INDENT-OFF*

#endif
