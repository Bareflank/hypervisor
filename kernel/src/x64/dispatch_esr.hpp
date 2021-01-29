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

#include <bsl/debug.hpp>
#include <bsl/exit_code.hpp>
#include <bsl/safe_integral.hpp>
#include <bsl/string_view.hpp>

namespace mk
{
    /// @brief defines a constant for the exception vector #0
    constexpr bsl::safe_uintmax EXCEPTION_VECTOR_0{bsl::to_umax(0)};
    /// @brief defines a constant for the exception vector #1
    constexpr bsl::safe_uintmax EXCEPTION_VECTOR_1{bsl::to_umax(1)};
    /// @brief defines a constant for the exception vector #2
    constexpr bsl::safe_uintmax EXCEPTION_VECTOR_2{bsl::to_umax(2)};
    /// @brief defines a constant for the exception vector #3
    constexpr bsl::safe_uintmax EXCEPTION_VECTOR_3{bsl::to_umax(3)};
    /// @brief defines a constant for the exception vector #4
    constexpr bsl::safe_uintmax EXCEPTION_VECTOR_4{bsl::to_umax(4)};
    /// @brief defines a constant for the exception vector #5
    constexpr bsl::safe_uintmax EXCEPTION_VECTOR_5{bsl::to_umax(5)};
    /// @brief defines a constant for the exception vector #6
    constexpr bsl::safe_uintmax EXCEPTION_VECTOR_6{bsl::to_umax(6)};
    /// @brief defines a constant for the exception vector #7
    constexpr bsl::safe_uintmax EXCEPTION_VECTOR_7{bsl::to_umax(7)};
    /// @brief defines a constant for the exception vector #8
    constexpr bsl::safe_uintmax EXCEPTION_VECTOR_8{bsl::to_umax(8)};
    /// @brief defines a constant for the exception vector #10
    constexpr bsl::safe_uintmax EXCEPTION_VECTOR_10{bsl::to_umax(10)};
    /// @brief defines a constant for the exception vector #11
    constexpr bsl::safe_uintmax EXCEPTION_VECTOR_11{bsl::to_umax(11)};
    /// @brief defines a constant for the exception vector #12
    constexpr bsl::safe_uintmax EXCEPTION_VECTOR_12{bsl::to_umax(12)};
    /// @brief defines a constant for the exception vector #13
    constexpr bsl::safe_uintmax EXCEPTION_VECTOR_13{bsl::to_umax(13)};
    /// @brief defines a constant for the exception vector #14
    constexpr bsl::safe_uintmax EXCEPTION_VECTOR_14{bsl::to_umax(14)};
    /// @brief defines a constant for the exception vector #16
    constexpr bsl::safe_uintmax EXCEPTION_VECTOR_16{bsl::to_umax(16)};
    /// @brief defines a constant for the exception vector #17
    constexpr bsl::safe_uintmax EXCEPTION_VECTOR_17{bsl::to_umax(17)};
    /// @brief defines a constant for the exception vector #18
    constexpr bsl::safe_uintmax EXCEPTION_VECTOR_18{bsl::to_umax(18)};
    /// @brief defines a constant for the exception vector #19
    constexpr bsl::safe_uintmax EXCEPTION_VECTOR_19{bsl::to_umax(19)};

    /// <!-- description -->
    ///   @brief Returns the name of an ESR given it's vector
    ///
    /// <!-- inputs/outputs -->
    ///   @param vector the vector of the ESR to get the name for
    ///   @return Returns the name of an ESR given it's vector
    ///
    [[nodiscard]] constexpr auto
    dispatch_esr_vector_to_name(bsl::safe_uintmax const &vector) noexcept -> bsl::string_view
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
                return "unknown";
            }
        }
    }

    /// <!-- description -->
    ///   @brief Print a line
    ///
    constexpr void
    dispatch_esr_print_line() noexcept
    {
        bsl::print() << bsl::yellow;
        bsl::print() << "+--------------------------------------+";
        bsl::print() << bsl::reset_color << bsl::endl;
    }

    /// <!-- description -->
    ///   @brief Print a header
    ///
    constexpr void
    dispatch_esr_print_header() noexcept
    {
        bsl::print() << bsl::yellow << "| " << bsl::cyan;
        bsl::print() << "Register ";
        bsl::print() << bsl::yellow << "| " << bsl::cyan;
        bsl::print() << "Value                     ";
        bsl::print() << bsl::yellow << "|" << bsl::reset_color << bsl::endl;
    }

    /// <!-- description -->
    ///   @brief Print the contents of a register
    ///
    /// <!-- inputs/outputs -->
    ///   @param name the name of the register
    ///   @param val the value of the register
    ///
    constexpr void
    dispatch_esr_print_reg(bsl::string_view const name, bsl::safe_uintmax const &val) noexcept
    {
        constexpr bsl::safe_uintmax name_col_size{bsl::to_umax(9)};

        bsl::print() << bsl::yellow << "| " << bsl::reset_color;
        bsl::print() << name;

        for (bsl::safe_uintmax i{}; i < name_col_size - name.size(); ++i) {
            bsl::print() << ' ';
        }

        bsl::print() << bsl::yellow << "| " << bsl::reset_color;

        if (val.is_zero()) {
            bsl::print() << bsl::black << bsl::hex(val) << bsl::reset_color;
        }
        else {
            bsl::print() << bsl::hex(val);
        }

        bsl::print() << bsl::yellow << "        |" << bsl::reset_color;
        bsl::print() << bsl::endl;
    }

    /// <!-- description -->
    ///   @brief Print the contents of a register and it's segment
    ///
    /// <!-- inputs/outputs -->
    ///   @param name the name of the register
    ///   @param val the value of the register
    ///   @param seg_val the value of the register's segment
    ///
    constexpr void
    dispatch_esr_print_reg_with_segment(
        bsl::string_view const name,
        bsl::safe_uintmax const &val,
        bsl::safe_uintmax const &seg_val) noexcept
    {
        bsl::print() << bsl::yellow << "| " << bsl::reset_color;
        bsl::print() << name << "      ";
        bsl::print() << bsl::yellow << "| " << bsl::reset_color;
        bsl::print() << bsl::hex(bsl::to_u16(seg_val));
        bsl::print() << ":";
        bsl::print() << bsl::hex(val);
        bsl::print() << bsl::yellow << " |" << bsl::reset_color;
        bsl::print() << bsl::endl;
    }

    /// <!-- description -->
    ///   @brief Provides the main entry point for all exceptions. This
    ///     function will dispatch exceptions as needed.
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam TLS_CONCEPT defines the type of TLS block to use
    ///   @tparam INTRINSIC_CONCEPT defines the type of intrinsics to use
    ///   @param tls the current TLS block
    ///   @param intrinsic the intrinsics to use
    ///   @return Returns bsl::exit_success if the exception was handled,
    ///     bsl::exit_failure otherwise
    ///
    template<typename TLS_CONCEPT, typename INTRINSIC_CONCEPT>
    [[nodiscard]] constexpr auto
    dispatch_esr(TLS_CONCEPT &tls, INTRINSIC_CONCEPT &intrinsic) noexcept -> bsl::exit_code
    {
        if (tls.esr_vector == EXCEPTION_VECTOR_2) {
            return dispatch_esr_nmi(tls, intrinsic);
        }

        bsl::print() << bsl::bold_red                                                          // --
                     << "...<EXCEPTION>\n\n"                                                   // --
                     << bsl::bold_magenta                                                      // --
                     << dispatch_esr_vector_to_name(tls.esr_vector) << ' '                     // --
                     << bsl::reset_color                                                       // --
                     << "[" << bsl::red                                                        // --
                     << bsl::hex(bsl::to_u8_unsafe(tls.esr_error_code)) << bsl::reset_color    // --
                     << "]: "                                                                  // --
                     << bsl::endl;                                                             // --

        dispatch_esr_print_line();
        dispatch_esr_print_header();
        dispatch_esr_print_line();

        dispatch_esr_print_reg_with_segment("rip", tls.esr_rip, tls.esr_cs);
        dispatch_esr_print_reg_with_segment("rsp", tls.esr_rsp, tls.esr_ss);
        dispatch_esr_print_line();

        dispatch_esr_print_reg("rflags", tls.esr_rflags);
        dispatch_esr_print_line();

        dispatch_esr_print_reg("rax", tls.esr_rax);
        dispatch_esr_print_reg("rbx", tls.esr_rbx);
        dispatch_esr_print_reg("rcx", tls.esr_rcx);
        dispatch_esr_print_reg("rdx", tls.esr_rdx);
        dispatch_esr_print_reg("rbp", tls.esr_rbp);
        dispatch_esr_print_reg("rsi", tls.esr_rsi);
        dispatch_esr_print_reg("rdi", tls.esr_rdi);
        dispatch_esr_print_reg("r8", tls.esr_r8);
        dispatch_esr_print_reg("r9", tls.esr_r9);
        dispatch_esr_print_reg("r10", tls.esr_r10);
        dispatch_esr_print_reg("r11", tls.esr_r11);
        dispatch_esr_print_reg("r12", tls.esr_r12);
        dispatch_esr_print_reg("r13", tls.esr_r13);
        dispatch_esr_print_reg("r14", tls.esr_r14);
        dispatch_esr_print_reg("r15", tls.esr_r15);
        dispatch_esr_print_line();

        dispatch_esr_print_reg("cr0", tls.esr_cr0);
        dispatch_esr_print_reg("cr2", tls.esr_cr2);
        dispatch_esr_print_reg("cr3", tls.esr_cr3);
        dispatch_esr_print_reg("cr4", tls.esr_cr4);
        dispatch_esr_print_line();

        bsl::print() << bsl::endl            // --
                     << bsl::bold_magenta    // --
                     << "backtrace:"         // --
                     << bsl::reset_color     // --
                     << bsl::endl;           // --

        return bsl::exit_failure;
    }
}

#endif
