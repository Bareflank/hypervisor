/// @copyright
/// Copyright (C) 2020 Assured Information Security, Inc.
///
/// @copyright
/// Permission is hereby granted, free of charge, to any person obtaining a copy
/// of this software and associated documentation files (the "Software"), to deal
/// in the Software without restriction, including without limitation the rights
/// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
/// copies of the Software, and to permit persons to whom the Software is
/// furnished to do so, subject to the following conditions:
///
/// @copyright
/// The above copyright notice and this permission notice shall be included in
/// all copies or substantial portions of the Software.
///
/// @copyright
/// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
/// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
/// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
/// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
/// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
/// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
/// SOFTWARE.

#ifndef TLS_T_HPP
#define TLS_T_HPP

#include <state_save_t.hpp>

#include <bsl/convert.hpp>
#include <bsl/cstdint.hpp>
#include <bsl/details/carray.hpp>
#include <bsl/safe_integral.hpp>

#pragma pack(push, 1)

namespace mk
{
    namespace details
    {
        /// @brief defines the size of the reserved0 field in the tls_t
        constexpr bsl::safe_uintmax TLS_T_RESERVED0_SIZE{bsl::to_umax(0x078U)};
        /// @brief defines the size of the reserved1 field in the tls_t
        constexpr bsl::safe_uintmax TLS_T_RESERVED1_SIZE{bsl::to_umax(0x078U)};
        /// @brief defines the size of the reserved2 field in the tls_t
        constexpr bsl::safe_uintmax TLS_T_RESERVED2_SIZE{bsl::to_umax(0x530U)};
        /// @brief defines the size of the reserved3 field in the tls_t
        constexpr bsl::safe_uintmax TLS_T_RESERVED3_SIZE{bsl::to_umax(0x0A0U)};
        /// @brief defines the size of the reserved4 field in the tls_t
        constexpr bsl::safe_uintmax TLS_T_RESERVED4_SIZE{bsl::to_umax(0x098U)};
        /// @brief defines the size of the reserved5 field in the tls_t
        constexpr bsl::safe_uintmax TLS_T_RESERVED5_SIZE{bsl::to_umax(0x600U)};
    }

    /// @struct mk::tls_t
    ///
    /// <!-- description -->
    ///   @brief Defines the layout of the microkernel's TLS block. This
    ///     should not be confused with the TLS blocks given to an extension,
    ///     for which there are two, the TLS block for thread_local and the
    ///     TLS block provided by the microkernel's ABI.
    ///
    struct tls_t final
    {
        /// --------------------------------------------------------------------
        /// Microkernel State
        /// --------------------------------------------------------------------

        /// @brief stores the value of rax for the microkernel (0x000)
        bsl::uintmax mk_rax;
        /// @brief stores the value of rbx for the microkernel (0x008)
        bsl::uintmax mk_rbx;
        /// @brief stores the value of rcx for the microkernel (0x010)
        bsl::uintmax mk_rcx;
        /// @brief stores the value of rdx for the microkernel (0x018)
        bsl::uintmax mk_rdx;
        /// @brief stores the value of rbp for the microkernel (0x020)
        bsl::uintmax mk_rbp;
        /// @brief stores the value of rsi for the microkernel (0x028)
        bsl::uintmax mk_rsi;
        /// @brief stores the value of rdi for the microkernel (0x030)
        bsl::uintmax mk_rdi;
        /// @brief stores the value of r8 for the microkernel (0x038)
        bsl::uintmax mk_r8;
        /// @brief stores the value of r9 for the microkernel (0x040)
        bsl::uintmax mk_r9;
        /// @brief stores the value of r10 for the microkernel (0x048)
        bsl::uintmax mk_r10;
        /// @brief stores the value of r11 for the microkernel (0x050)
        bsl::uintmax mk_r11;
        /// @brief stores the value of r12 for the microkernel (0x058)
        bsl::uintmax mk_r12;
        /// @brief stores the value of r13 for the microkernel (0x060)
        bsl::uintmax mk_r13;
        /// @brief stores the value of r14 for the microkernel (0x068)
        bsl::uintmax mk_r14;
        /// @brief stores the value of r15 for the microkernel (0x070)
        bsl::uintmax mk_r15;
        /// @brief stores the value of rip for the microkernel (0x078)
        bsl::uintmax mk_rip;
        /// @brief stores the value of rsp for the microkernel (0x080)
        bsl::uintmax mk_rsp;

        /// @brief reserve the rest of the TLS block for later use.
        bsl::details::carray<bsl::uint8, details::TLS_T_RESERVED0_SIZE.get()> reserved0;

        /// --------------------------------------------------------------------
        /// Extension State
        /// --------------------------------------------------------------------

        /// @brief stores the value of the syscall for the extension (0x100)
        bsl::uintmax ext_syscall;
        /// @brief reserved (0x108)
        bsl::uintmax reserved_reg1;
        /// @brief reserved (0x110)
        bsl::uintmax reserved_reg2;
        /// @brief stores the value of REG2 for the extension (0x118)
        bsl::uintmax ext_reg2;
        /// @brief reserved (0x120)
        bsl::uintmax reserved_reg3;
        /// @brief stores the value of REG1 for the extension (0x128)
        bsl::uintmax ext_reg1;
        /// @brief stores the value of REG0 for the extension (0x130)
        bsl::uintmax ext_reg0;
        /// @brief stores the value of REG4 for the extension (0x138)
        bsl::uintmax ext_reg4;
        /// @brief stores the value of REG5 for the extension (0x140)
        bsl::uintmax ext_reg5;
        /// @brief stores the value of REG3 for the extension (0x148)
        bsl::uintmax ext_reg3;
        /// @brief reserved (0x150)
        bsl::uintmax reserved_reg4;
        /// @brief reserved (0x158)
        bsl::uintmax reserved_reg5;
        /// @brief reserved (0x160)
        bsl::uintmax reserved_reg6;
        /// @brief reserved (0x168)
        bsl::uintmax reserved_reg7;
        /// @brief reserved (0x170)
        bsl::uintmax reserved_reg8;
        /// @brief reserved (0x178)
        bsl::uintmax reserved_reg9;
        /// @brief reserved (0x180)
        bsl::uintmax reserved_rega;

        /// @brief reserve the rest of the TLS block for later use.
        bsl::details::carray<bsl::uint8, details::TLS_T_RESERVED1_SIZE.get()> reserved1;

        /// --------------------------------------------------------------------
        /// ESR State
        /// --------------------------------------------------------------------

        /// @brief stores the value of rax for the ESR (0x200)
        bsl::uintmax esr_rax;
        /// @brief stores the value of rbx for the ESR (0x208)
        bsl::uintmax esr_rbx;
        /// @brief stores the value of rcx for the ESR (0x210)
        bsl::uintmax esr_rcx;
        /// @brief stores the value of rdx for the ESR (0x218)
        bsl::uintmax esr_rdx;
        /// @brief stores the value of rbp for the ESR (0x220)
        bsl::uintmax esr_rbp;
        /// @brief stores the value of rsi for the ESR (0x228)
        bsl::uintmax esr_rsi;
        /// @brief stores the value of rdi for the ESR (0x230)
        bsl::uintmax esr_rdi;
        /// @brief stores the value of r8 for the ESR (0x238)
        bsl::uintmax esr_r8;
        /// @brief stores the value of r9 for the ESR (0x240)
        bsl::uintmax esr_r9;
        /// @brief stores the value of r10 for the ESR (0x248)
        bsl::uintmax esr_r10;
        /// @brief stores the value of r11 for the ESR (0x250)
        bsl::uintmax esr_r11;
        /// @brief stores the value of r12 for the ESR (0x258)
        bsl::uintmax esr_r12;
        /// @brief stores the value of r13 for the ESR (0x260)
        bsl::uintmax esr_r13;
        /// @brief stores the value of r14 for the ESR (0x268)
        bsl::uintmax esr_r14;
        /// @brief stores the value of r15 for the ESR (0x270)
        bsl::uintmax esr_r15;
        /// @brief stores the value of rip for the ESR (0x278)
        bsl::uintmax esr_rip;
        /// @brief stores the value of rsp for the ESR (0x280)
        bsl::uintmax esr_rsp;

        /// @brief stores the value of the ESR vector (0x288)
        bsl::uintmax esr_vector;
        /// @brief stores the value of the ESR error code (0x290)
        bsl::uintmax esr_error_code;

        /// @brief stores the value of cr0 for the ESR (0x298)
        bsl::uintmax esr_cr0;
        /// @brief stores the value of cr2 for the ESR (0x2A0)
        bsl::uintmax esr_cr2;
        /// @brief stores the value of cr3 for the ESR (0x2A8)
        bsl::uintmax esr_cr3;
        /// @brief stores the value of cr4 for the ESR (0x2B0)
        bsl::uintmax esr_cr4;

        /// @brief stores the value of cs for the ESR (0x2B8)
        bsl::uintmax esr_cs;
        /// @brief stores the value of ss for the ESR (0x2C0)
        bsl::uintmax esr_ss;

        /// @brief stores the value of ss for the ESR (0x2C8)
        bsl::uintmax esr_rflags;

        /// @brief reserve the rest of the TLS block for later use.
        bsl::details::carray<bsl::uint8, details::TLS_T_RESERVED2_SIZE.get()> reserved2;

        /// --------------------------------------------------------------------
        /// Context Information
        /// --------------------------------------------------------------------

        /// @brief stores the virtual address of this TLS block (0x800).
        tls_t *self;

        /// @brief stores the thread ID for this TLS block (0x808).
        bsl::uintmax thread_id;

        /// @brief stores the currently running extension (0x810)
        void *ext;
        /// @brief stores the extension registered for VMExits (0x818)
        void *ext_vmexit;
        /// @brief stores the extension registered for fast fail events (0x820)
        void *ext_fail;

        /// @brief stores the loader provided state for the microkernel (0x828)
        loader::state_save_t *mk_state;
        /// @brief stores the loader provided state for the root VP (0x830)
        loader::state_save_t *root_vp_state;

        /// @brief stores the ID of the active VPS
        bsl::uint16 active_vpsid;
        /// @brief reserved.
        bsl::uint16 reserved_id1;
        /// @brief reserved.
        bsl::uint16 reserved_id2;
        /// @brief reserved.
        bsl::uint16 reserved_id3;

        /// @brief stores the sp used by extensions for callbacks (0x840).
        bsl::uintmax sp;
        /// @brief stores the tps used by extensions for callbacks (0x848).
        bsl::uintmax tp;

        /// @brief used to store a return address for unsafe ops (0x850).
        bsl::uintmax unsafe_rip;

        /// @brief used to signal NMIs are not safe (0x858).
        bsl::uintmax nmi_lock;
        /// @brief used to singal an NMI has fired (0x860).
        bsl::uintmax nmi_pending;

        /// @brief on Intel, stores the currently loaded VPS (0x868).
        void *loaded_vps;

        /// @brief stores whether or not the first launch succeeded (0x870).
        bsl::uintmax first_launch_succeeded;

        /// @brief reserve the rest of the TLS block for later use.
        bsl::details::carray<bsl::uint8, details::TLS_T_RESERVED3_SIZE.get()> reserved3;

        /// --------------------------------------------------------------------
        /// Fast Fail Information
        /// --------------------------------------------------------------------

        /// @brief stores the current fast fail address (0x900).
        bsl::uintmax current_fast_fail_ip;
        /// @brief stores the current fast fail stack (0x908).
        bsl::uintmax current_fast_fail_sp;

        /// @brief stores the mk_main fast fail address (0x910).
        bsl::uintmax mk_main_fast_fail_ip;
        /// @brief stores the mk_main fast fail stack (0x918).
        bsl::uintmax mk_main_fast_fail_sp;

        /// @brief stores the call_ext fast fail address (0x920).
        bsl::uintmax call_ext_fast_fail_ip;
        /// @brief stores the call_ext fast fail stack (0x928).
        bsl::uintmax call_ext_fast_fail_sp;

        /// @brief stores the dispatch_syscall fast fail address (0x930).
        bsl::uintmax dispatch_syscall_fast_fail_ip;
        /// @brief stores the dispatch_syscall fast fail stack (0x938).
        bsl::uintmax dispatch_syscall_fast_fail_sp;

        /// @brief stores the vmexit loop address (0x940).
        bsl::uintmax vmexit_loop_ip;
        /// @brief stores the vmexit loop stack (0x948).
        bsl::uintmax vmexit_loop_sp;

        /// @brief reserve the rest of the TLS block for later use.
        bsl::details::carray<bsl::uint8, details::TLS_T_RESERVED4_SIZE.get()> reserved4;

        /// --------------------------------------------------------------------
        /// Reserved
        /// --------------------------------------------------------------------

        /// @brief reserve the rest of the TLS block for later use.
        bsl::details::carray<bsl::uint8, details::TLS_T_RESERVED5_SIZE.get()> reserved5;

        /// --------------------------------------------------------------------
        /// Helpers
        /// --------------------------------------------------------------------

        /// <!-- description -->
        ///   @brief Returns the extension ID
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the extension ID
        ///
        [[nodiscard]] constexpr auto
        extid() const noexcept -> bsl::safe_uint16
        {
            constexpr bsl::safe_uintmax mask{bsl::to_umax(0xFFFF000000000000U)};
            constexpr bsl::safe_uintmax shift{bsl::to_umax(48)};

            return bsl::to_u16((thread_id & mask) >> shift);
        }

        /// <!-- description -->
        ///   @brief Returns the virtual machine ID
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the virtual machine ID
        ///
        [[nodiscard]] constexpr auto
        vmid() const noexcept -> bsl::safe_uint16
        {
            constexpr bsl::safe_uintmax mask{bsl::to_umax(0x0000FFFF00000000U)};
            constexpr bsl::safe_uintmax shift{bsl::to_umax(32)};

            return bsl::to_u16((thread_id & mask) >> shift);
        }

        /// <!-- description -->
        ///   @brief Returns the virtual processor ID
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the virtual processor ID
        ///
        [[nodiscard]] constexpr auto
        vpid() const noexcept -> bsl::safe_uint16
        {
            constexpr bsl::safe_uintmax mask{bsl::to_umax(0x00000000FFFF0000U)};
            constexpr bsl::safe_uintmax shift{bsl::to_umax(16)};

            return bsl::to_u16((thread_id & mask) >> shift);
        }

        /// <!-- description -->
        ///   @brief Returns the physical processor ID
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the physical processor ID
        ///
        [[nodiscard]] constexpr auto
        ppid() const noexcept -> bsl::safe_uint16
        {
            constexpr bsl::safe_uintmax mask{bsl::to_umax(0x000000000000FFFFU)};
            constexpr bsl::safe_uintmax shift{bsl::to_umax(0)};

            return bsl::to_u16((thread_id & mask) >> shift);
        }

        /// <!-- description -->
        ///   @brief Sets the current extension ID
        ///
        /// <!-- inputs/outputs -->
        ///   @param val the value to set the current extension ID to
        ///
        constexpr void
        set_extid(bsl::safe_uint16 const &val) noexcept
        {
            constexpr bsl::safe_uintmax mask{bsl::to_umax(0x0000FFFFFFFFFFFFU)};
            constexpr bsl::safe_uintmax shift{bsl::to_umax(48)};

            thread_id = ((thread_id & mask) | (bsl::to_umax(val) << shift)).get();
        }

        /// <!-- description -->
        ///   @brief Sets the current virtual machine ID
        ///
        /// <!-- inputs/outputs -->
        ///   @param val the value to set the current virtual machine ID to
        ///
        constexpr void
        set_vmid(bsl::safe_uint16 const &val) noexcept
        {
            constexpr bsl::safe_uintmax mask{bsl::to_umax(0xFFFF0000FFFFFFFFU)};
            constexpr bsl::safe_uintmax shift{bsl::to_umax(32)};

            thread_id = ((thread_id & mask) | (bsl::to_umax(val) << shift)).get();
        }

        /// <!-- description -->
        ///   @brief Sets the current virtual processor ID
        ///
        /// <!-- inputs/outputs -->
        ///   @param val the value to set the current virtual processor ID to
        ///
        constexpr void
        set_vpid(bsl::safe_uint16 const &val) noexcept
        {
            constexpr bsl::safe_uintmax mask{bsl::to_umax(0xFFFFFFFF0000FFFFU)};
            constexpr bsl::safe_uintmax shift{bsl::to_umax(16)};

            thread_id = ((thread_id & mask) | (bsl::to_umax(val) << shift)).get();
        }

        /// <!-- description -->
        ///   @brief Sets the current physical processor ID
        ///
        /// <!-- inputs/outputs -->
        ///   @param val the value to set the current physical processor ID to
        ///
        constexpr void
        set_ppid(bsl::safe_uint16 const &val) noexcept
        {
            constexpr bsl::safe_uintmax mask{bsl::to_umax(0xFFFFFFFFFFFF0000U)};
            constexpr bsl::safe_uintmax shift{bsl::to_umax(0)};

            thread_id = ((thread_id & mask) | (bsl::to_umax(val) << shift)).get();
        }
    };

    /// @brief make sure the tls_t is the size of a page
    static_assert(sizeof(tls_t) == bsl::to_umax(HYPERVISOR_PAGE_SIZE));
}

#pragma pack(pop)

#endif
