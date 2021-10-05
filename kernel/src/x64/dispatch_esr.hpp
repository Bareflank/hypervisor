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
#include <errc_types.hpp>
#include <ext_t.hpp>
#include <intrinsic_t.hpp>
#include <promote.hpp>
#include <return_to_mk.hpp>
#include <tls_t.hpp>

#include <bsl/debug.hpp>
#include <bsl/exit_code.hpp>
#include <bsl/finally.hpp>
#include <bsl/safe_integral.hpp>
#include <bsl/string_view.hpp>

namespace mk
{
    /// @brief defines a constant for the exception vector #0
    constexpr auto EXCEPTION_VECTOR_0{0_umx};
    /// @brief defines a constant for the exception vector #1
    constexpr auto EXCEPTION_VECTOR_1{1_umx};
    /// @brief defines a constant for the exception vector #2
    constexpr auto EXCEPTION_VECTOR_2{2_umx};
    /// @brief defines a constant for the exception vector #3
    constexpr auto EXCEPTION_VECTOR_3{3_umx};
    /// @brief defines a constant for the exception vector #4
    constexpr auto EXCEPTION_VECTOR_4{4_umx};
    /// @brief defines a constant for the exception vector #5
    constexpr auto EXCEPTION_VECTOR_5{5_umx};
    /// @brief defines a constant for the exception vector #6
    constexpr auto EXCEPTION_VECTOR_6{6_umx};
    /// @brief defines a constant for the exception vector #7
    constexpr auto EXCEPTION_VECTOR_7{7_umx};
    /// @brief defines a constant for the exception vector #8
    constexpr auto EXCEPTION_VECTOR_8{8_umx};
    /// @brief defines a constant for the exception vector #10
    constexpr auto EXCEPTION_VECTOR_10{10_umx};
    /// @brief defines a constant for the exception vector #11
    constexpr auto EXCEPTION_VECTOR_11{11_umx};
    /// @brief defines a constant for the exception vector #12
    constexpr auto EXCEPTION_VECTOR_12{12_umx};
    /// @brief defines a constant for the exception vector #13
    constexpr auto EXCEPTION_VECTOR_13{13_umx};
    /// @brief defines a constant for the exception vector #14
    constexpr auto EXCEPTION_VECTOR_14{14_umx};
    /// @brief defines a constant for the exception vector #16
    constexpr auto EXCEPTION_VECTOR_16{16_umx};
    /// @brief defines a constant for the exception vector #17
    constexpr auto EXCEPTION_VECTOR_17{17_umx};
    /// @brief defines a constant for the exception vector #18
    constexpr auto EXCEPTION_VECTOR_18{18_umx};
    /// @brief defines a constant for the exception vector #19
    constexpr auto EXCEPTION_VECTOR_19{19_umx};

    /// <!-- description -->
    ///   @brief Returns the name of an ESR given it's vector
    ///
    /// <!-- inputs/outputs -->
    ///   @param vector the vector of the ESR to get the name for
    ///   @return Returns the name of an ESR given it's vector
    ///
    [[nodiscard]] constexpr auto
    vector_to_name(bsl::safe_umx const &vector) noexcept -> bsl::string_view
    {
        switch (vector.get()) {
            case EXCEPTION_VECTOR_0.get(): {
                return "divide error";
            }

            case EXCEPTION_VECTOR_1.get(): {
                return "debug exception";
            }

            case EXCEPTION_VECTOR_3.get(): {
                return "assertion";
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
    dispatch_esr_dump(bsl::string_view const &name, bsl::safe_umx const &val) noexcept
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
    dispatch_esr_dump(bsl::string_view const &name, bsl::safe_u16 const &val) noexcept
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
        bsl::string_view const &name, bsl::safe_umx const &val, bsl::safe_umx const &seg) noexcept
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
    ///   @brief Returns true if the exception came from the microkernel.
    ///     Returns false if the exception came from an extension
    ///
    /// <!-- inputs/outputs -->
    ///   @param mut_tls the current TLS block
    ///   @return Returns true if the exception came from the microkernel.
    ///     Returns false if the exception came from an extension
    ///
    [[nodiscard]] constexpr auto
    is_mk_exception(tls_t &mut_tls) noexcept -> bool
    {
        constexpr auto mk_cs{0x10_u64};
        return mk_cs == mut_tls.esr_cs;
    }

    /// <!-- description -->
    ///   @brief Sends the exception to the extension so that it can handle
    ///     it. Only exceptions that originate from the extension can be
    ///     handled by the exception.
    ///
    /// <!-- inputs/outputs -->
    ///   @param mut_tls the current TLS block
    ///   @param mut_intrinsic the intrinsic_t to use
    ///   @param errc the reason for the failure, which is CPU
    ///     specific. On x86, this is a combination of the exception
    ///     vector and error code.
    ///   @param addr contains a faulting address if the fail reason
    ///     is associated with an error that involves a faulting address (
    ///     for example like a page fault). Otherwise, the value of this
    ///     input is undefined.
    ///   @return Returns bsl::errc_success if the fail was handled,
    ///     bsl::errc_failure otherwise.
    ///
    [[nodiscard]] constexpr auto
    send_exception_to_ext(
        tls_t &mut_tls,
        intrinsic_t &mut_intrinsic,
        bsl::safe_u64 const &errc,
        bsl::safe_u64 const &addr) noexcept -> bsl::errc_type
    {
        if (bsl::unlikely(is_mk_exception(mut_tls))) {
            return bsl::errc_failure;
        }

        if (bsl::unlikely(nullptr == mut_tls.ext_fail)) {
            return bsl::errc_failure;
        }

        /// NOTE:
        /// - The fail handler has a couple of options on how it
        ///   might attempt to return. It could return failure, which
        ///   means that there is nothing we can do but return. If
        ///   we have not successfully launched yet, we will be able
        ///   to promote back to the root. If not, we will have to
        ///   halt the PP
        ///
        /// - The fail handler could call bf_control_op_again. If it
        ///   does, it is because it has corrected the issue, and
        ///   the extension should try to execute the faulting
        ///   instruction again. When bf_control_op_again is called,
        ///   the microkernel will call return_to_mk with a success
        ///   code. In this case, there is nothing for us to do but
        ///   return success. This will make it's way back to the ESR
        ///   entry point and IRET back to the extension.
        ///
        /// - There is another option though. The extension could ask
        ///   to run a VS. This would normally be the case when the
        ///   extension is implementing guest support and basically
        ///   says the VM is dead, so lets execute something else. If
        ///   this happens, we cannot return back to the extension.
        ///   Instead, we need to return to where the microkenrel was
        ///   when the VMExit occurred. When this happens, run will
        ///   execute with the new VS. So we need to actually run
        ///   return_to_mk again. This is because when the fail handler
        ///   executes, it is really two calls deep at this point, so
        ///   two return_to_mk calls is needed to get all the way
        ///   back to where we started.
        ///

        auto const ret{mut_tls.ext_fail->fail(mut_tls, mut_intrinsic, errc, addr)};
        if (ret != vmexit_success) {
            return ret;
        }

        mut_tls.mk_sp = mut_tls.mk_fail_sp;
        return_to_mk(ret);

        /// Unreachable except during unit testing
        return bsl::errc_success;
    }

    /// <!-- description -->
    ///   @brief Return a failure. If we can promote to the root VM, we will,
    ///     otherwise, we will report an error, which will cause the PP to
    ///     halt as there is nothing left to do.
    ///
    /// <!-- inputs/outputs -->
    ///   @param mut_tls the current TLS block
    ///   @return Returns bsl::errc_success if the exception was handled,
    ///     bsl::errc_failure otherwise
    ///
    [[nodiscard]] constexpr auto
    return_failure(tls_t &mut_tls) noexcept -> bsl::errc_type
    {
        if (EXCEPTION_VECTOR_3 != mut_tls.esr_vector) {
            bsl::print() << bsl::red << "...<EXCEPTION>\n\n";
        }
        else {
            bsl::print() << bsl::endl;
        }

        bsl::print() << bsl::mag << vector_to_name(bsl::to_umx(mut_tls.esr_vector)) << " [";
        bsl::print() << bsl::cyn << "ec: ";
        bsl::print() << bsl::rst << bsl::hex(bsl::to_u8_unsafe(mut_tls.esr_error_code));
        bsl::print() << bsl::mag << "] dump: ";
        bsl::print() << bsl::rst << bsl::endl;

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

        dispatch_esr_dump_with_segment(
            "rip", bsl::to_umx(mut_tls.esr_ip), bsl::to_umx(mut_tls.esr_cs));
        dispatch_esr_dump_with_segment(
            "rsp", bsl::to_umx(mut_tls.esr_sp), bsl::to_umx(mut_tls.esr_ss));

        /// Flags
        ///

        bsl::print() << bsl::ylw << "+---------------------------------------------+";
        bsl::print() << bsl::rst << bsl::endl;

        dispatch_esr_dump("rflags", bsl::to_umx(mut_tls.esr_rflags));

        /// General Purpose Registers
        ///

        bsl::print() << bsl::ylw << "+---------------------------------------------+";
        bsl::print() << bsl::rst << bsl::endl;

        dispatch_esr_dump("rax", bsl::to_umx(mut_tls.esr_rax));
        dispatch_esr_dump("rbx", bsl::to_umx(mut_tls.esr_rbx));
        dispatch_esr_dump("rcx", bsl::to_umx(mut_tls.esr_rcx));
        dispatch_esr_dump("rdx", bsl::to_umx(mut_tls.esr_rdx));
        dispatch_esr_dump("rbp", bsl::to_umx(mut_tls.esr_rbp));
        dispatch_esr_dump("rsi", bsl::to_umx(mut_tls.esr_rsi));
        dispatch_esr_dump("rdi", bsl::to_umx(mut_tls.esr_rdi));
        dispatch_esr_dump("r8", bsl::to_umx(mut_tls.esr_r8));
        dispatch_esr_dump("r9", bsl::to_umx(mut_tls.esr_r9));
        dispatch_esr_dump("r10", bsl::to_umx(mut_tls.esr_r10));
        dispatch_esr_dump("r11", bsl::to_umx(mut_tls.esr_r11));
        dispatch_esr_dump("r12", bsl::to_umx(mut_tls.esr_r12));
        dispatch_esr_dump("r13", bsl::to_umx(mut_tls.esr_r13));
        dispatch_esr_dump("r14", bsl::to_umx(mut_tls.esr_r14));
        dispatch_esr_dump("r15", bsl::to_umx(mut_tls.esr_r15));

        /// Control Registers
        ///

        bsl::print() << bsl::ylw << "+---------------------------------------------+";
        bsl::print() << bsl::rst << bsl::endl;

        dispatch_esr_dump("cr0", bsl::to_umx(mut_tls.esr_cr0));
        dispatch_esr_dump("cr2", bsl::to_umx(mut_tls.esr_pf_addr));
        dispatch_esr_dump("cr3", bsl::to_umx(mut_tls.esr_cr3));
        dispatch_esr_dump("cr4", bsl::to_umx(mut_tls.esr_cr4));

        /// TLS State
        ///

        bsl::print() << bsl::ylw << "+---------------------------------------------+";
        bsl::print() << bsl::rst << bsl::endl;

        dispatch_esr_dump("ppid", bsl::to_umx(mut_tls.ppid));
        dispatch_esr_dump("online_pps", bsl::to_umx(mut_tls.online_pps));
        dispatch_esr_dump("active_extid", bsl::to_umx(mut_tls.active_extid));
        dispatch_esr_dump("active_vmid", bsl::to_umx(mut_tls.active_vmid));
        dispatch_esr_dump("active_vpid", bsl::to_umx(mut_tls.active_vpid));
        dispatch_esr_dump("active_vsid", bsl::to_umx(mut_tls.active_vsid));
        dispatch_esr_dump("sp", bsl::to_umx(mut_tls.sp));
        dispatch_esr_dump("tp", bsl::to_umx(mut_tls.tp));

        /// Footer
        ///

        bsl::print() << bsl::ylw << "+---------------------------------------------+";
        bsl::print() << bsl::rst << bsl::endl;

        bsl::print() << bsl::mag << "\nbacktrace:";
        bsl::print() << bsl::rst << bsl::endl;

        if (bsl::safe_u64::magic_0() != mut_tls.first_launch_succeeded) {
            bsl::print<bsl::V>() << bsl::here();
            return bsl::errc_failure;
        }

        bsl::print<bsl::V>() << bsl::here();
        promote(mut_tls.root_vp_state, bsl::safe_umx::max_value().get());

        /// Unreachable except during unit testing
        return bsl::errc_failure;
    }

    /// <!-- description -->
    ///   @brief Provides the main entry point for all exceptions. This
    ///     function will dispatch exceptions as needed.
    ///
    /// <!-- inputs/outputs -->
    ///   @param mut_tls the current TLS block
    ///   @param mut_intrinsic the intrinsic_t to use
    ///   @return Returns bsl::errc_success if the exception was handled,
    ///     bsl::errc_failure otherwise
    ///
    [[nodiscard]] constexpr auto
    dispatch_esr(tls_t &mut_tls, intrinsic_t &mut_intrinsic) noexcept -> bsl::errc_type
    {
        constexpr auto ec_shft{32_u64};

        if (bsl::unlikely(bsl::safe_u64::magic_0() != mut_tls.mk_handling_esr)) {
            bsl::alert() << "nested exception detected\n";
            return return_failure(mut_tls);
        }

        mut_tls.mk_handling_esr = bsl::safe_u64::magic_1().get();

        switch (mut_tls.esr_vector) {
            case EXCEPTION_VECTOR_2.get(): {
                dispatch_esr_nmi(mut_tls, mut_intrinsic);
                return bsl::errc_success;
            }

            default: {
                break;
            }
        }

        auto const errc{(mut_tls.esr_error_code << ec_shft) | mut_tls.esr_vector};
        auto const addr{bsl::to_u64(mut_tls.esr_pf_addr)};

        if (send_exception_to_ext(mut_tls, mut_intrinsic, errc, addr)) {
            return bsl::errc_success;
        }

        return return_failure(mut_tls);
    }
}

#endif
