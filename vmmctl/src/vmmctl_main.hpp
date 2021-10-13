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

#ifndef VMMCTL_MAIN_HPP
#define VMMCTL_MAIN_HPP

#include <debug_ring_t.hpp>
#include <dump_vmm_args_t.hpp>
#include <ifmap_t.hpp>
#include <ioctl_t.hpp>
#include <loader_platform_interface.hpp>
#include <start_vmm_args_t.hpp>
#include <stop_vmm_args_t.hpp>

#include <bsl/arguments.hpp>
#include <bsl/array.hpp>
#include <bsl/carray.hpp>
#include <bsl/convert.hpp>
#include <bsl/debug.hpp>
#include <bsl/errc_type.hpp>
#include <bsl/safe_idx.hpp>
#include <bsl/safe_integral.hpp>
#include <bsl/span.hpp>
#include <bsl/string_view.hpp>
#include <bsl/touch.hpp>
#include <bsl/unlikely.hpp>

namespace vmmctl
{
    /// @brief defines the IOCTL version this code supports.
    constexpr auto IOCTL_VERSION{1_umx};

    /// <!-- description -->
    ///   @brief Provides the main implementation of the vmmctl application.
    ///     This application is used to start and stop the VMM as well as
    ///     to dump the contents of the VMM's internal debug ring to the
    ///     console for debugging.
    ///
    class vmmctl_main final
    {
        /// <!-- description -->
        ///   @brief Displays the help menu for vmmctl
        ///
        static constexpr void
        help() noexcept
        {
            bsl::print() << "Usage: vmmctl start microkernel ext1 <ext2> ..." << bsl::endl;
            bsl::print() << "  or:  vmmctl stop" << bsl::endl;
            bsl::print() << "  or:  vmmctl dump" << bsl::endl;
            bsl::print() << bsl::endl;
            bsl::print() << "A utility for managing the Bareflank Hypervisor's VMM";
            bsl::print() << bsl::endl;
        }

        /// <!-- description -->
        ///   @brief Starts the VMM given a set of ioctl_t arguments to send
        ///     to the loader.
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_args the command line arguments provided by the user.
        ///   @param mut_ioctl the ioctl_t to use
        ///   @return Returns bsl::errc_success if the VMM was successfully
        ///     started, otherwise returns bsl::errc_failure.
        ///
        [[nodiscard]] static constexpr auto
        start_vmm(bsl::arguments &mut_args, ioctl_t &mut_ioctl) noexcept -> bsl::errc_type
        {
            loader::start_vmm_args_t mut_start_args{IOCTL_VERSION.get(), {}, {}, {}, {}};

            auto const mk_filename{mut_args.front<bsl::string_view>()};
            if (mk_filename.empty()) {
                bsl::error() << "the microkernel's path is either missing or empty\n";
                help();
                return bsl::errc_failure;
            }

            ifmap_t const mk_map{mk_filename};
            if (bsl::unlikely(mk_map.empty())) {
                help();
                return bsl::errc_failure;
            }

            mut_start_args.mk_elf_file = mk_map.view();

            ++mut_args;
            auto mut_ext_filename{mut_args.front<bsl::string_view>()};
            if (mut_ext_filename.empty()) {
                bsl::error() << "the extension's path is either missing or empty\n";
                help();
                return bsl::errc_failure;
            }

            bsl::array<ifmap_t, HYPERVISOR_MAX_EXTENSIONS.get()> mut_ext_maps{};
            for (bsl::safe_idx mut_i{}; mut_i < HYPERVISOR_MAX_EXTENSIONS; ++mut_i) {
                auto *const pmut_ext_map{mut_ext_maps.at_if(mut_i)};
                auto *const pmut_ext_elf{mut_start_args.ext_elf_files.at_if(mut_i)};

                *pmut_ext_map = ifmap_t{mut_ext_filename};
                if (bsl::unlikely(pmut_ext_map->empty())) {
                    help();
                    return bsl::errc_failure;
                }

                *pmut_ext_elf = pmut_ext_map->view();

                ++mut_args;
                mut_ext_filename = mut_args.front<bsl::string_view>();
                if (mut_ext_filename.empty()) {
                    break;
                }

                bsl::touch();
            }

            auto const ret{mut_ioctl.write(loader::START_VMM, &mut_start_args)};
            if (bsl::unlikely(ret.is_neg())) {
                bsl::error() << "vmmctl failed. check kernel logs details\n";
                return bsl::errc_failure;
            }

            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Stops the VMM given a set of ioctl_t arguments to send
        ///     to the loader.
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_ioctl the ioctl_t to use
        ///   @return Returns bsl::errc_success if the VMM was successfully
        ///     stopped, otherwise returns bsl::errc_failure.
        ///
        [[nodiscard]] static constexpr auto
        stop_vmm(ioctl_t &mut_ioctl) noexcept -> bsl::errc_type
        {
            loader::stop_vmm_args_t const stop_args{IOCTL_VERSION.get()};

            auto const ret{mut_ioctl.write(loader::STOP_VMM, &stop_args)};
            if (bsl::unlikely(ret.is_neg())) {
                bsl::error() << "vmmctl failed. check kernel logs details\n";
                return bsl::errc_failure;
            }

            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Dumps the VMM given a set of ioctl_t arguments to send
        ///     to the loader.
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_ioctl the ioctl_t to use
        ///   @return Returns bsl::errc_success if the VMM was successfully
        ///     dumped to the console, otherwise returns bsl::errc_failure.
        ///
        [[nodiscard]] static constexpr auto
        dump_vmm(ioctl_t &mut_ioctl) noexcept -> bsl::errc_type
        {
            loader::dump_vmm_args_t mut_dump_args{IOCTL_VERSION.get(), {}};

            auto const ret{mut_ioctl.read_write(loader::DUMP_VMM, &mut_dump_args)};
            if (bsl::unlikely(ret.is_neg())) {
                bsl::error() << "vmmctl failed. check kernel logs details\n";
                return bsl::errc_failure;
            }

            bsl::safe_idx mut_epos{mut_dump_args.debug_ring.epos};
            bsl::safe_idx mut_spos{mut_dump_args.debug_ring.spos};

            if (bsl::unlikely(mut_epos >= mut_dump_args.debug_ring.buf.size())) {
                bsl::error() << "kernel returned an invalid debug ring\n";
                return bsl::errc_failure;
            }

            if (bsl::unlikely(mut_spos >= mut_dump_args.debug_ring.buf.size())) {
                bsl::error() << "kernel returned an invalid debug ring\n";
                return bsl::errc_failure;
            }

            if (mut_spos == mut_epos) {
                bsl::alert() << "no debug data to dump\n";
                return bsl::errc_success;
            }

            while (mut_spos != mut_epos) {
                if (mut_spos >= mut_dump_args.debug_ring.buf.size()) {
                    mut_spos = {};
                }
                else {
                    bsl::touch();
                }

                bsl::print() << *mut_dump_args.debug_ring.buf.at_if(mut_spos.get());
                ++mut_spos;
            }

            bsl::print() << bsl::endl;
            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Process the user provided command line arguments assuming
        ///     the first argument is the command while also ignoring "help".
        ///     If the user provided command succeeds, this function
        ///     will return bsl::errc_success, otherwise this function
        ///     will return bsl::errc_failure.
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_args the command line arguments provided by the user.
        ///   @param mut_ioctl the ioctl_t to use
        ///   @return If the user provided command succeeds, this function
        ///     will return bsl::errc_success, otherwise this function
        ///     will return bsl::errc_failure.
        ///
        [[nodiscard]] constexpr auto
        process_cmd(bsl::arguments &mut_args, ioctl_t &mut_ioctl) noexcept -> bsl::errc_type
        {
            auto const cmd{mut_args.front<bsl::string_view>()};
            ++mut_args;

            if (cmd == "start") {
                return this->start_vmm(mut_args, mut_ioctl);
            }

            if (cmd == "stop") {
                return this->stop_vmm(mut_ioctl);
            }

            if (cmd == "dump") {
                return this->dump_vmm(mut_ioctl);
            }

            if (cmd.empty()) {
                bsl::error() << "missing command\n";
            }
            else {
                bsl::error() << "invalid command: \"" << cmd << "\"\n";
            }

            help();
            return bsl::errc_failure;
        }

    public:
        /// <!-- description -->
        ///   @brief Process the user provided command line arguments.
        ///     If the user provided command succeeds, this function
        ///     will return bsl::errc_success, otherwise this function
        ///     will return bsl::errc_failure.
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_args the command line arguments provided by the user.
        ///   @param mut_ioctl the ioctl_t to use
        ///   @return If the user provided command succeeds, this function
        ///     will return bsl::errc_success, otherwise this function
        ///     will return bsl::errc_failure.
        ///
        [[nodiscard]] constexpr auto
        process(bsl::arguments &mut_args, ioctl_t &mut_ioctl) noexcept -> bsl::errc_type
        {
            if (mut_args.get<bool>("-h")) {
                this->help();
                return bsl::errc_success;
            }

            if (mut_args.get<bool>("--help")) {
                this->help();
                return bsl::errc_success;
            }

            return this->process_cmd(mut_args, mut_ioctl);
        }
    };
}

#endif
