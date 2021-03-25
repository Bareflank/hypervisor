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

#ifndef DISPATCH_ESR_HPP
#define DISPATCH_ESR_HPP

#include <dispatch_esr_nmi.hpp>
#include <dispatch_esr_page_fault.hpp>
#include <ext_t.hpp>
#include <intrinsic_t.hpp>
#include <tls_t.hpp>

#include <bsl/debug.hpp>
#include <bsl/exit_code.hpp>
#include <bsl/finally.hpp>
#include <bsl/likely.hpp>
#include <bsl/safe_integral.hpp>
#include <bsl/string_view.hpp>

namespace mk
{
    /// @brief defines a constant for the exception vector #0
    constexpr auto EXCEPTION_VECTOR_0{0_umax};
    /// @brief defines a constant for the exception vector #1
    constexpr auto EXCEPTION_VECTOR_1{1_umax};
    /// @brief defines a constant for the exception vector #2
    constexpr auto EXCEPTION_VECTOR_2{2_umax};
    /// @brief defines a constant for the exception vector #3
    constexpr auto EXCEPTION_VECTOR_3{3_umax};
    /// @brief defines a constant for the exception vector #4
    constexpr auto EXCEPTION_VECTOR_4{4_umax};
    /// @brief defines a constant for the exception vector #5
    constexpr auto EXCEPTION_VECTOR_5{5_umax};
    /// @brief defines a constant for the exception vector #6
    constexpr auto EXCEPTION_VECTOR_6{6_umax};
    /// @brief defines a constant for the exception vector #7
    constexpr auto EXCEPTION_VECTOR_7{7_umax};
    /// @brief defines a constant for the exception vector #8
    constexpr auto EXCEPTION_VECTOR_8{8_umax};
    /// @brief defines a constant for the exception vector #10
    constexpr auto EXCEPTION_VECTOR_10{10_umax};
    /// @brief defines a constant for the exception vector #11
    constexpr auto EXCEPTION_VECTOR_11{11_umax};
    /// @brief defines a constant for the exception vector #12
    constexpr auto EXCEPTION_VECTOR_12{12_umax};
    /// @brief defines a constant for the exception vector #13
    constexpr auto EXCEPTION_VECTOR_13{13_umax};
    /// @brief defines a constant for the exception vector #14
    constexpr auto EXCEPTION_VECTOR_14{14_umax};
    /// @brief defines a constant for the exception vector #16
    constexpr auto EXCEPTION_VECTOR_16{16_umax};
    /// @brief defines a constant for the exception vector #17
    constexpr auto EXCEPTION_VECTOR_17{17_umax};
    /// @brief defines a constant for the exception vector #18
    constexpr auto EXCEPTION_VECTOR_18{18_umax};
    /// @brief defines a constant for the exception vector #19
    constexpr auto EXCEPTION_VECTOR_19{19_umax};

    /// <!-- description -->
    ///   @brief Returns the name of an ESR given it's vector
    ///
    /// <!-- inputs/outputs -->
    ///   @param vector the vector of the ESR to get the name for
    ///   @return Returns the name of an ESR given it's vector
    ///
    [[nodiscard]] constexpr auto
    vector_to_name(bsl::safe_uintmax const &vector) noexcept -> bsl::string_view
    {
        switch (vector.get()) {
            case EXCEPTION_VECTOR_0.get(): {
                return "divide error";
            }

            case EXCEPTION_VECTOR_1.get(): {
                return "debug exception";
            }

            case EXCEPTION_VECTOR_3.get(): {
                return "breakpoint";
            }

            case EXCEPTION_VECTOR_4.get(): {
                return "overflow";
            }

            case EXCEPTION_VECTOR_5.get(): {
                return "bound range exceeded";
            }

            case EXCEPTION_VECTOR_6.get(): {
                return "invalid opcode";
            }

            case EXCEPTION_VECTOR_7.get(): {
                return "device not available";
            }

            case EXCEPTION_VECTOR_8.get(): {
                return "double fault";
            }

            case EXCEPTION_VECTOR_10.get(): {
                return "invalid tss";
            }

            case EXCEPTION_VECTOR_11.get(): {
                return "segment not present";
            }

            case EXCEPTION_VECTOR_12.get(): {
                return "stack-segment fault";
            }

            case EXCEPTION_VECTOR_13.get(): {
                return "general protection";
            }

            case EXCEPTION_VECTOR_14.get(): {
                return "page fault";
            }

            case EXCEPTION_VECTOR_16.get(): {
                return "x87 fpu floating-point error";
            }

            case EXCEPTION_VECTOR_17.get(): {
                return "alignment check";
            }

            case EXCEPTION_VECTOR_18.get(): {
                return "machine check";
            }

            case EXCEPTION_VECTOR_19.get(): {
                return "simd floating-point exception";
            }

            default: {
                break;
            }
        }

        return "unknown";
    }

    /// <!-- description -->
    ///   @brief Print the contents of a register
    ///
    /// <!-- inputs/outputs -->
    ///   @param name the name of the register
    ///   @param val the value of the register
    ///
    constexpr void
    dispatch_esr_dump(bsl::string_view const &name, bsl::safe_uintmax const &val) noexcept
    {
        bsl::print() << bsl::ylw << "| ";
        bsl::print() << bsl::rst << bsl::fmt{"<16s", name};
        bsl::print() << bsl::ylw << "| ";
        if (val.is_zero()) {
            bsl::print() << bsl::blk << "    " << bsl::hex(val) << "    ";
        }
        else {
            bsl::print() << bsl::rst << "    " << bsl::hex(val) << "    ";
        }
        bsl::print() << bsl::ylw << "| ";
        bsl::print() << bsl::rst << bsl::endl;
    }

    /// <!-- description -->
    ///   @brief Print the contents of a register
    ///
    /// <!-- inputs/outputs -->
    ///   @param name the name of the register
    ///   @param val the value of the register
    ///
    constexpr void
    dispatch_esr_dump(bsl::string_view const &name, bsl::safe_uint16 const &val) noexcept
    {
        bsl::print() << bsl::ylw << "| ";
        bsl::print() << bsl::rst << bsl::fmt{"<16s", name};
        bsl::print() << bsl::ylw << "| ";
        bsl::print() << bsl::rst << "          " << bsl::hex(val) << "          ";
        bsl::print() << bsl::ylw << "| ";
        bsl::print() << bsl::rst << bsl::endl;
    }

    /// <!-- description -->
    ///   @brief Print the contents of a register and it's segment
    ///
    /// <!-- inputs/outputs -->
    ///   @param name the name of the register
    ///   @param val the value of the register
    ///   @param seg the value of the register's segment
    ///
    constexpr void
    dispatch_esr_dump_with_segment(
        bsl::string_view const name,
        bsl::safe_uintmax const &val,
        bsl::safe_uintmax const &seg) noexcept
    {
        bsl::print() << bsl::ylw << "| ";
        bsl::print() << bsl::rst << bsl::fmt{"<16s", name};
        bsl::print() << bsl::ylw << "| ";
        bsl::print() << bsl::rst << bsl::hex(bsl::to_u16(seg)) << ':';
        bsl::print() << bsl::rst << bsl::hex(val) << ' ';
        bsl::print() << bsl::ylw << "| ";
        bsl::print() << bsl::rst << bsl::endl;
    }

    /// <!-- description -->
    ///   @brief Provides the main entry point for all exceptions. This
    ///     function will dispatch exceptions as needed.
    ///
    /// <!-- inputs/outputs -->
    ///   @param tls the current TLS block
    ///   @param page_pool the page_pool_t to use
    ///   @param ext the extension that made the syscall
    ///   @param intrinsic the intrinsics to use
    ///   @return Returns bsl::exit_success if the exception was handled,
    ///     bsl::exit_failure otherwise
    ///
    [[nodiscard]] constexpr auto
    dispatch_esr(
        tls_t &tls, page_pool_t &page_pool, intrinsic_t &intrinsic, ext_t *const ext) noexcept
        -> bsl::exit_code
    {
        bsl::finally reset_on_exit{[&tls]() noexcept -> void {
            /// NOTE:
            /// - This tells our spinlock_ts that we are no longer in an ESR,
            ///   which is needed to ensure deadlock detection is handled
            ///   properly.
            ///

            tls.esr_ip = {};
        }};

        switch (tls.esr_vector) {
            case EXCEPTION_VECTOR_2.get(): {
                if (bsl::likely(dispatch_esr_nmi(tls, intrinsic))) {
                    return bsl::exit_success;
                }

                break;
            }

            case EXCEPTION_VECTOR_14.get(): {
                if (bsl::likely(dispatch_esr_page_fault(tls, page_pool, ext))) {
                    return bsl::exit_success;
                }

                break;
            }

            default: {
                break;
            }
        }

        bsl::print() << bsl::red << "...<EXCEPTION>\n\n";
        bsl::print() << bsl::mag << vector_to_name(tls.esr_vector) << " [";
        bsl::print() << bsl::cyn << "ec: ";
        bsl::print() << bsl::rst << bsl::hex(bsl::to_u8_unsafe(tls.esr_error_code));
        bsl::print() << bsl::mag << "] dump: ";
        bsl::print() << bsl::rst << bsl::endl;

        if constexpr (BSL_DEBUG_LEVEL == bsl::CRITICAL_ONLY) {
            return bsl::exit_failure;
        }

        /// Header
        ///

        bsl::print() << bsl::ylw << "+---------------------------------------------+";
        bsl::print() << bsl::rst << bsl::endl;

        bsl::print() << bsl::ylw << "| ";
        bsl::print() << bsl::cyn << bsl::fmt{"^16s", "description "};
        bsl::print() << bsl::ylw << "| ";
        bsl::print() << bsl::cyn << bsl::fmt{"^26s", "value "};
        bsl::print() << bsl::ylw << "| ";
        bsl::print() << bsl::rst << bsl::endl;

        bsl::print() << bsl::ylw << "+---------------------------------------------+";
        bsl::print() << bsl::rst << bsl::endl;

        /// IP/SP
        ///

        dispatch_esr_dump_with_segment("rip", tls.esr_ip, tls.esr_cs);
        dispatch_esr_dump_with_segment("rsp", tls.esr_sp, tls.esr_ss);

        /// Flags
        ///

        bsl::print() << bsl::ylw << "+---------------------------------------------+";
        bsl::print() << bsl::rst << bsl::endl;

        dispatch_esr_dump("rflags", tls.esr_rflags);

        /// General Purpose Registers
        ///

        bsl::print() << bsl::ylw << "+---------------------------------------------+";
        bsl::print() << bsl::rst << bsl::endl;

        dispatch_esr_dump("rax", tls.esr_rax);
        dispatch_esr_dump("rbx", tls.esr_rbx);
        dispatch_esr_dump("rcx", tls.esr_rcx);
        dispatch_esr_dump("rdx", tls.esr_rdx);
        dispatch_esr_dump("rbp", tls.esr_rbp);
        dispatch_esr_dump("rsi", tls.esr_rsi);
        dispatch_esr_dump("rdi", tls.esr_rdi);
        dispatch_esr_dump("r8", tls.esr_r8);
        dispatch_esr_dump("r9", tls.esr_r9);
        dispatch_esr_dump("r10", tls.esr_r10);
        dispatch_esr_dump("r11", tls.esr_r11);
        dispatch_esr_dump("r12", tls.esr_r12);
        dispatch_esr_dump("r13", tls.esr_r13);
        dispatch_esr_dump("r14", tls.esr_r14);
        dispatch_esr_dump("r15", tls.esr_r15);

        /// Control Registers
        ///

        bsl::print() << bsl::ylw << "+---------------------------------------------+";
        bsl::print() << bsl::rst << bsl::endl;

        dispatch_esr_dump("cr0", tls.esr_cr0);
        dispatch_esr_dump("cr2", tls.esr_pf_addr);
        dispatch_esr_dump("cr3", tls.esr_cr3);
        dispatch_esr_dump("cr4", tls.esr_cr4);

        /// TLS State
        ///

        bsl::print() << bsl::ylw << "+---------------------------------------------+";
        bsl::print() << bsl::rst << bsl::endl;

        dispatch_esr_dump("ppid", tls.ppid);
        dispatch_esr_dump("online_pps", tls.online_pps);
        dispatch_esr_dump("active_extid", tls.active_extid);
        dispatch_esr_dump("active_vmid", tls.active_vmid);
        dispatch_esr_dump("active_vpid", tls.active_vpid);
        dispatch_esr_dump("active_vpsid", tls.active_vpsid);
        dispatch_esr_dump("sp", tls.sp);
        dispatch_esr_dump("tp", tls.tp);

        /// Footer
        ///

        bsl::print() << bsl::ylw << "+---------------------------------------------+";
        bsl::print() << bsl::rst << bsl::endl;

        bsl::print() << bsl::mag << "\nbacktrace:";
        bsl::print() << bsl::rst << bsl::endl;

        return bsl::exit_failure;
    }
}

#endif
