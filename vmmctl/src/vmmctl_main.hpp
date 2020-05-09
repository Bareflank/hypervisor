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

#include <loader_interface.h>

#include <bsl/arguments.hpp>
#include <bsl/array.hpp>
#include <bsl/convert.hpp>
#include <bsl/exit_code.hpp>
#include <bsl/debug.hpp>
#include <bsl/string_view.hpp>

namespace vmmctl
{
    /// @class vmmctl::vmmctl_main
    ///
    /// <!-- description -->
    ///   @brief Provides the main implementation of the vmmctl application.
    ///     This application is used to start and stop the VMM as well as
    ///     to dump the contents of the VMM's internal debug ring to the
    ///     console for debugging.
    ///
    /// <!-- template parameters -->
    ///   @tparam IOCTL the ioctl implementation to use. Normally this is just
    ///     bsl::ioctl, but during testing this might be a mock.
    ///   @tparam IFMAP the ifmap implementation to use. Normally this is just
    ///     bsl::ifmap, but during testing this might be a mock.
    ///
    template<typename IOCTL, typename IFMAP>
    class vmmctl_main final
    {
        /// <!-- description -->
        ///   @brief Displays the help menu for vmmctl
        ///
        /// <!-- inputs/outputs -->
        ///   @return Always returns bsl::exit_success
        ///
        [[nodiscard]] constexpr bsl::exit_code
        help() const noexcept
        {
            bsl::print() << "Usage: vmmctl start binary1 <binary2> ..." << bsl::endl;
            bsl::print() << "  or:  vmmctl stop" << bsl::endl;
            bsl::print() << "  or:  vmmctl dump" << bsl::endl;
            bsl::print() << bsl::endl;
            bsl::print() << "A utility for managing the Bareflank Hypervisor's VMM";
            bsl::print() << bsl::endl;

            return bsl::exit_success;
        }

        /// <!-- description -->
        ///   @brief Starts the VMM by mapping in all of the binaries that
        ///     the user provided, and sending them to the Bareflank loader
        ///     with a BAREFLANK_LOADER_START_VMM command.
        ///
        /// <!-- inputs/outputs -->
        ///   @param args the command line arguments provided by the user.
        ///   @return Returns bsl::exit_success if the VMM was successfully
        ///     started, otherwise returns bsl::exit_failure.
        ///
        [[nodiscard]] constexpr bsl::exit_code
        start_vmm(bsl::arguments const &args) const noexcept
        {
            bsl::discard(args);
            IOCTL ctl{BAREFLANK_LOADER_DEVICE_NAME};

            if (!ctl.send(BAREFLANK_LOADER_START_VMM)) {
                bsl::error() << "failed to start the VMM. check kernel logs for more details.\n";
                return bsl::exit_failure;
            }

            return bsl::exit_success;
        }

        /// <!-- description -->
        ///   @brief Stops the VMM by sending the Bareflank loader a
        ///     BAREFLANK_LOADER_STOP_VMM command.
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns bsl::exit_success if the VMM was successfully
        ///     stopped, otherwise returns bsl::exit_failure.
        ///
        [[nodiscard]] constexpr bsl::exit_code
        stop_vmm() const noexcept
        {
            IOCTL ctl{BAREFLANK_LOADER_DEVICE_NAME};

            if (!ctl.send(BAREFLANK_LOADER_STOP_VMM)) {
                bsl::error() << "failed to stop the VMM. check kernel logs for more details.\n";
                return bsl::exit_failure;
            }

            return bsl::exit_success;
        }

        /// <!-- description -->
        ///   @brief Dumps the contents of the VMM's debug ring by sending the
        ///     Bareflank loader a BAREFLANK_LOADER_DUMP_VMM command.
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns bsl::exit_success if the VMM was successfully
        ///     dumped to the console, otherwise returns bsl::exit_failure.
        ///
        [[nodiscard]] constexpr bsl::exit_code
        dump_vmm() const noexcept
        {
            IOCTL ctl{BAREFLANK_LOADER_DEVICE_NAME};

            if (!ctl.send(BAREFLANK_LOADER_DUMP_VMM)) {
                bsl::error() << "failed to dump the VMM. check kernel logs for more details.\n";
                return bsl::exit_failure;
            }

            return bsl::exit_success;
        }

    public:
        /// <!-- description -->
        ///   @brief Default constructor.
        ///
        constexpr vmmctl_main() noexcept = default;

        /// <!-- description -->
        ///   @brief Process the user provided command line arguments.
        ///     If the user provided commands succeed, this function
        ///     will return bsl::exit_success, otherwise this function
        ///     will return bsl::exit_failure.
        ///
        /// <!-- inputs/outputs -->
        ///   @param args the command line arguments provided by the user.
        ///   @return If the user provided commands succeed, this function
        ///     will return bsl::exit_success, otherwise this function
        ///     will return bsl::exit_failure.
        ///
        [[nodiscard]] constexpr bsl::exit_code
        process(bsl::arguments const &args) const noexcept
        {
            if (args.get<bool>("-h") || args.get<bool>("--help")) {
                return this->help();
            }

            bsl::string_view cmd{args.get<bsl::string_view>(bsl::to_umax(1))};

            if (cmd.empty()) {
                bsl::error() << "missing command. use vmmctl -h for usage info\n";
                return bsl::exit_failure;
            }

            if (cmd == "start") {
                return this->start_vmm(args);
            }

            if (cmd == "stop") {
                return this->stop_vmm();
            }

            if (cmd == "dump") {
                return this->dump_vmm();
            }

            bsl::error() << "invalid command: \"" << cmd << "\". use vmmctl -h for usage info\n";
            return bsl::exit_failure;
        }
    };
}

#endif
