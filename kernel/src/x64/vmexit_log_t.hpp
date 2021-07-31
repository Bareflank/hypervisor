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

#ifndef VMEXIT_LOG_T_HPP
#define VMEXIT_LOG_T_HPP

#include <vmexit_log_pp_t.hpp>

#include <bsl/array.hpp>
#include <bsl/debug.hpp>
#include <bsl/safe_integral.hpp>
#include <bsl/string_view.hpp>
#include <bsl/unlikely.hpp>

namespace mk
{
    /// @class mk::vmexit_log_t
    ///
    /// <!-- description -->
    ///   @brief Stores a log of all VMExits that occur. Each PP has one log
    ///     that is shared between all of the VSs so that you get a consistent
    ///     view of what actually happened during execution, which is more
    ///     important when implementing guest support as VSs can swap between
    ///     execution on the same PP as the hypervisor is moving between VMs.
    ///
    class vmexit_log_t final
    {
        /// @brief stores the VMExit log
        bsl::array<vmexit_log_pp_t, HYPERVISOR_MAX_PPS.get()> m_vmexit_logs{};

        /// <!-- description -->
        ///   @brief Dumps the contents of the VMExit log for the requested PP
        ///
        /// <!-- inputs/outputs -->
        ///   @param str the name of the field
        ///   @param val the value of the field
        ///
        static constexpr void
        dump_field(bsl::string_view const &str, bsl::safe_umx const &val) noexcept
        {
            if (val.is_zero()) {
                bsl::print() << bsl::ylw << str << bsl::blk << bsl::hex(val);
            }
            else {
                bsl::print() << bsl::ylw << str << bsl::rst << bsl::hex(val);
            }
        }

    public:
        /// <!-- description -->
        ///   @brief Adds a record in the VMExit log
        ///
        /// <!-- inputs/outputs -->
        ///   @param ppid the id of the PP whose log should be added to
        ///   @param rec the record to add to the log
        ///
        constexpr void
        add(bsl::safe_u16 const &ppid, vmexit_log_record_t const &rec) noexcept
        {
            if constexpr (!bsl::debug_level_is_at_least_vv()) {
                return;
            }

            auto *const pmut_pp_log{m_vmexit_logs.at_if(bsl::to_idx(ppid))};
            if (bsl::unlikely(nullptr == pmut_pp_log)) {
                return;
            }

            *pmut_pp_log->log.at_if(pmut_pp_log->crsr) = rec;

            ++pmut_pp_log->crsr;
            if (pmut_pp_log->crsr < pmut_pp_log->log.size()) {
                bsl::touch();
            }
            else {
                pmut_pp_log->crsr = {};
            }
        }

        /// <!-- description -->
        ///   @brief Dumps the contents of the VMExit log for the requested PP
        ///
        /// <!-- inputs/outputs -->
        ///   @param ppid the ID of the PP whose log should be dumped
        ///
        constexpr void
        dump(bsl::safe_u16 const &ppid) const noexcept
        {
            if constexpr (!bsl::debug_level_is_at_least_vv()) {
                return;
            }

            auto const *const pp_log{m_vmexit_logs.at_if(bsl::to_idx(ppid))};
            if (bsl::unlikely(nullptr == pp_log)) {
                bsl::error() << "invalid ppid "    // --
                             << bsl::hex(ppid)     // --
                             << bsl::endl          // --
                             << bsl::here();       // --

                return;
            }

            bsl::print() << bsl::mag << "vmexit log for pp [";
            bsl::print() << bsl::rst << bsl::hex(ppid);
            bsl::print() << bsl::mag << "]: ";
            bsl::print() << bsl::rst << bsl::endl;

            bsl::print() << bsl::ylw << "+---------------------------------";
            bsl::print() << bsl::ylw << "----------------------------------";
            bsl::print() << bsl::ylw << "----------------------------------+";
            bsl::print() << bsl::rst << bsl::endl;

            bsl::safe_idx mut_crsr{pp_log->crsr};
            for (bsl::safe_idx mut_i{}; mut_i < pp_log->log.size(); ++mut_i) {
                auto const *const rec{pp_log->log.at_if(mut_crsr)};

                if (rec->rip.is_pos()) {
                    bsl::print() << bsl::ylw << "| ";
                    bsl::print() << bsl::blu << "VM:";
                    bsl::print() << bsl::cyn << bsl::fmt{"04x", rec->vmid};
                    bsl::print() << bsl::rst << ", ";
                    bsl::print() << bsl::blu << "VP:";
                    bsl::print() << bsl::cyn << bsl::fmt{"04x", rec->vpid};
                    bsl::print() << bsl::rst << ", ";
                    bsl::print() << bsl::blu << "VS:";
                    bsl::print() << bsl::cyn << bsl::fmt{"04x", rec->vsid};
                    bsl::print() << bsl::rst << ", ";
                    bsl::print() << bsl::blu << "REASON:";
                    bsl::print() << bsl::cyn << bsl::fmt{">2d", rec->exit_reason};
                    bsl::print() << bsl::rst << "                                ";
                    bsl::print() << bsl::ylw << "                               |";
                    bsl::print() << bsl::rst << bsl::endl;

                    bsl::print() << bsl::ylw << "| ";
                    bsl::print() << bsl::rst << "  -";
                    this->dump_field(" rip: ", rec->rip);
                    this->dump_field(" ei1: ", rec->ei1);
                    this->dump_field(" ei2: ", rec->ei2);
                    this->dump_field(" ei3: ", rec->ei3);
                    bsl::print() << bsl::ylw << " |";
                    bsl::print() << bsl::rst << bsl::endl;

                    bsl::print() << bsl::ylw << "| ";
                    bsl::print() << bsl::rst << "  -";
                    this->dump_field(" rax: ", rec->rax);
                    this->dump_field(" rbx: ", rec->rbx);
                    this->dump_field(" rcx: ", rec->rcx);
                    this->dump_field(" rdx: ", rec->rdx);
                    bsl::print() << bsl::ylw << " |";
                    bsl::print() << bsl::rst << bsl::endl;

                    bsl::print() << bsl::ylw << "| ";
                    bsl::print() << bsl::rst << "  -";
                    this->dump_field(" rbp: ", rec->rbp);
                    this->dump_field(" rsi: ", rec->rsi);
                    this->dump_field(" rdi: ", rec->rdi);
                    this->dump_field(" r08: ", rec->r8);
                    bsl::print() << bsl::ylw << " |";
                    bsl::print() << bsl::rst << bsl::endl;

                    bsl::print() << bsl::ylw << "| ";
                    bsl::print() << bsl::rst << "  -";
                    this->dump_field(" r09: ", rec->r9);
                    this->dump_field(" r10: ", rec->r10);
                    this->dump_field(" r11: ", rec->r11);
                    this->dump_field(" r12: ", rec->r12);
                    bsl::print() << bsl::ylw << " |";
                    bsl::print() << bsl::rst << bsl::endl;

                    bsl::print() << bsl::ylw << "| ";
                    bsl::print() << bsl::rst << "  -";
                    this->dump_field(" r13: ", rec->r13);
                    this->dump_field(" r14: ", rec->r14);
                    this->dump_field(" r15: ", rec->r15);
                    this->dump_field(" rsp: ", rec->rsp);
                    bsl::print() << bsl::ylw << " |";
                    bsl::print() << bsl::rst << bsl::endl;

                    bsl::print() << bsl::ylw << "+---------------------------------";
                    bsl::print() << bsl::ylw << "----------------------------------";
                    bsl::print() << bsl::ylw << "----------------------------------+";
                    bsl::print() << bsl::rst << bsl::endl;
                }
                else {
                    bsl::touch();
                }

                ++mut_crsr;
                if (mut_crsr < pp_log->log.size()) {
                    bsl::touch();
                }
                else {
                    mut_crsr = {};
                }
            }
        }
    };
}

#endif
