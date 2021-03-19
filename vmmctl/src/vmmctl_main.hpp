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

#include <dump_vmm_args_t.hpp>
#include <loader_platform_interface.hpp>
#include <start_vmm_args_t.hpp>
#include <stop_vmm_args_t.hpp>

#include <bsl/arguments.hpp>
#include <bsl/array.hpp>
#include <bsl/byte.hpp>
#include <bsl/convert.hpp>
#include <bsl/debug.hpp>
#include <bsl/discard.hpp>
#include <bsl/errc_type.hpp>
#include <bsl/exit_code.hpp>
#include <bsl/is_same.hpp>
#include <bsl/move.hpp>
#include <bsl/result.hpp>
#include <bsl/string_view.hpp>
#include <bsl/touch.hpp>

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
        /// @brief stores the mapped ELF file for the microkernel
        IFMAP m_mapped_mk_elf_file{};
        /// @brief stores the mapped ELF files for each extension
        bsl::array<IFMAP, HYPERVISOR_MAX_EXTENSIONS> m_mapped_ext_elf_files{};
        /// @brief stores the arguments for stopping the VMM.
        loader::stop_vmm_args_t m_stop_vmm_ctl_args{bsl::ONE_UMAX.get()};
        /// @brief stores the arguments for dumping the VMM.
        loader::dump_vmm_args_t m_dump_vmm_ctl_args{bsl::ONE_UMAX.get(), {}};

        /// <!-- description -->
        ///   @brief Displays the help menu for vmmctl
        ///
        constexpr void
        help() const noexcept
        {
            bsl::print() << "Usage: vmmctl start microkernel ext1 <ext2> ..." << bsl::endl;
            bsl::print() << "  or:  vmmctl stop" << bsl::endl;
            bsl::print() << "  or:  vmmctl dump" << bsl::endl;
            bsl::print() << bsl::endl;
            bsl::print() << "A utility for managing the Bareflank Hypervisor's VMM";
            bsl::print() << bsl::endl;
        }

        /// <!-- description -->
        ///   @brief Writes a provided request to the loader given an IOCTL
        ///     to the loader as well as the arguments to send to the loader.
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam R the type that defines the request to give the loader
        ///   @tparam A the type that defines the arguments to give the loader
        ///   @param request the request to give the loader
        ///   @param ctl the IOCTL to the loader
        ///   @param ctl_args the arguments to give the loader
        ///   @return Returns bsl::exit_success on success, bsl::exit_failure
        ///     otherwise
        ///
        template<typename R, typename A>
        [[nodiscard]] constexpr auto
        write(R const &request, IOCTL const &ctl, A const *const ctl_args) const noexcept
            -> bsl::exit_code
        {
            if (!ctl.write(request, ctl_args, bsl::size_of<A>())) {
                bsl::error() << "vmmctl failed. check kernel logs details\n";
                return bsl::exit_failure;
            }

            return bsl::exit_success;
        }

        /// <!-- description -->
        ///   @brief Writes a provided request to the loader given an IOCTL
        ///     to the loader as well as the arguments to send to the loader.
        ///     The results of the IOCTL are returned in the provided args.
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam R the type that defines the request to give the loader
        ///   @tparam A the type that defines the arguments to give the loader
        ///   @param request the request to give the loader
        ///   @param ctl the IOCTL to the loader
        ///   @param ctl_args the arguments to give the loader
        ///   @return Returns bsl::exit_success on success, bsl::exit_failure
        ///     otherwise
        ///
        template<typename R, typename A>
        [[nodiscard]] constexpr auto
        read_write(R const &request, IOCTL const &ctl, A *const ctl_args) const noexcept
            -> bsl::exit_code
        {
            if (!ctl.read_write(request, ctl_args, bsl::size_of<A>())) {
                bsl::error() << "vmmctl failed. check kernel logs details\n";
                return bsl::exit_failure;
            }

            return bsl::exit_success;
        }

        /// <!-- description -->
        ///   @brief Starts the VMM given a set of IOCTL arguments to send
        ///     to the loader.
        ///
        /// <!-- inputs/outputs -->
        ///   @param ctl_args the command line arguments provided by the user.
        ///   @return Returns bsl::exit_success if the VMM was successfully
        ///     started, otherwise returns bsl::exit_failure.
        ///
        [[nodiscard]] constexpr auto
        start_vmm(loader::start_vmm_args_t const *const ctl_args) const noexcept -> bsl::exit_code
        {
            IOCTL ctl{loader::DEVICE_NAME};
            if (ctl) {
                return this->write(loader::START_VMM, ctl, ctl_args);
            }

            return bsl::exit_failure;
        }

        /// <!-- description -->
        ///   @brief Stops the VMM given a set of IOCTL arguments to send
        ///     to the loader.
        ///
        /// <!-- inputs/outputs -->
        ///   @param ctl_args the command line arguments provided by the user.
        ///   @return Returns bsl::exit_success if the VMM was successfully
        ///     stopped, otherwise returns bsl::exit_failure.
        ///
        [[nodiscard]] constexpr auto
        stop_vmm(loader::stop_vmm_args_t const *const ctl_args) const noexcept -> bsl::exit_code
        {
            IOCTL ctl{loader::DEVICE_NAME};
            if (ctl) {
                return this->write(loader::STOP_VMM, ctl, ctl_args);
            }

            return bsl::exit_failure;
        }

        /// <!-- description -->
        ///   @brief Dumps the VMM given a set of IOCTL arguments to send
        ///     to the loader.
        ///
        /// <!-- inputs/outputs -->
        ///   @param ctl_args the command line arguments provided by the user.
        ///   @return Returns bsl::exit_success if the VMM was successfully
        ///     dumped to the console, otherwise returns bsl::exit_failure.
        ///
        [[nodiscard]] constexpr auto
        dump_vmm(loader::dump_vmm_args_t *const ctl_args) const noexcept -> bsl::exit_code
        {
            IOCTL ctl{loader::DEVICE_NAME};
            if (ctl) {
                if (bsl::exit_success != this->read_write(loader::DUMP_VMM, ctl, ctl_args)) {
                    return bsl::exit_failure;
                }

                bsl::touch();
            }
            else {
                return bsl::exit_failure;
            }

            bsl::safe_uintmax epos{ctl_args->debug_ring.epos};
            bsl::safe_uintmax spos{ctl_args->debug_ring.spos};

            if (!(ctl_args->debug_ring.buf.size() > epos)) {
                epos = {};
            }
            else {
                bsl::touch();
            }

            if (spos == epos) {
                bsl::alert() << "no debug data to dump\n";
                return bsl::exit_success;
            }

            while (spos != epos) {
                if (!(ctl_args->debug_ring.buf.size() > spos)) {
                    spos = {};
                }
                else {
                    bsl::touch();
                }

                bsl::print() << *ctl_args->debug_ring.buf.at_if(spos);
                ++spos;
            }

            bsl::print() << bsl::endl;
            return bsl::exit_success;
        }

        /// <!-- description -->
        ///   @brief Maps an ELF file by getting the filename and path from
        ///     the arguments provided by the user, opening the ELF file, and
        ///     then storing the newly opened map in the map provided. Returns
        ///     bsl::errc_success and increments the provided arguments if the
        ///     ELF file was successfully mapped, otherwise this function
        ///     returns bsl::errc_failure.
        ///
        /// <!-- inputs/outputs -->
        ///   @param args the user provided arguments. It is assumed that the
        ///     "front" of these args stores a string containing the filename
        ///     and path to the ELF file to map and store.
        ///   @param map the map to store the newly opened ELF file.
        ///   @return Returns bsl::errc_success and increments the provided
        ///     arguments if the ELF file was successfully mapped, otherwise
        ///     this function returns bsl::errc_failure.
        ///
        [[nodiscard]] constexpr auto
        map_elf_file(bsl::arguments &args, IFMAP *const map) const noexcept -> bsl::errc_type
        {
            if ((*map = IFMAP{args.front<bsl::string_view>()})) {
                ++args;
                return bsl::errc_success;
            }

            return bsl::errc_failure;
        }

        /// <!-- description -->
        ///   @brief This function maps the microkernel ELF file provided by
        ///     the user. When we map the ELF file, we store the map in a
        ///     private member variable. This ensures the map is not unmapped
        ///     until the start command is complete.
        ///
        /// <!-- inputs/outputs -->
        ///   @param args the arguments provided by the user.
        ///   @return Returns bsl::errc_success and increments the provided
        ///     arguments if the microkernel ELF file was successfully mapped,
        ///     otherwise this function returns bsl::errc_failure.
        ///
        [[nodiscard]] constexpr auto
        map_mk_elf_file_from_user(bsl::arguments &args) noexcept -> bsl::errc_type
        {
            return this->map_elf_file(args, &m_mapped_mk_elf_file);
        }

        /// <!-- description -->
        ///   @brief This function maps the extension ELF files provided by
        ///     the user. When we map the ELF files, we store the maps in a
        ///     private member variable. This ensures the maps are not unmapped
        ///     until the start command is complete.
        ///
        /// <!-- inputs/outputs -->
        ///   @param args the arguments provided by the user.
        ///   @return Returns bsl::errc_success and increments the provided
        ///     arguments if the extension ELF filed were successfully mapped,
        ///     otherwise this function returns bsl::errc_failure.
        ///
        [[nodiscard]] constexpr auto
        map_ext_elf_files_from_user(bsl::arguments &args) noexcept -> bsl::errc_type
        {
            for (auto const &elem : m_mapped_ext_elf_files) {
                if (!args) {
                    break;
                }

                if (!this->map_elf_file(args, elem.data)) {
                    return bsl::errc_failure;
                }

                bsl::touch();
            }

            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Converts the extension ELF files from an array of IFMAPs
        ///     to an array of buffer_t structs so that the ELF files can be
        ///     passed to the loader.
        ///
        /// <!-- inputs/outputs -->
        ///   @return Return resulting array of buffer_t structs
        ///
        [[nodiscard]] constexpr auto
        convert_mapped_ext_elf_files_to_array_of_spans() const noexcept
            -> bsl::array<bsl::span<bsl::byte const>, HYPERVISOR_MAX_EXTENSIONS>
        {
            bsl::array<bsl::span<bsl::byte const>, HYPERVISOR_MAX_EXTENSIONS> files{};
            for (auto const &elem : m_mapped_ext_elf_files) {
                if (nullptr != elem.data) {
                    *files.at_if(elem.index) = elem.data->view();
                }
                else {
                    bsl::touch();
                }
            }

            return files;
        }

        /// <!-- description -->
        ///   @brief Given arguments from the user, this function creates the
        ///     IOCTL equivalent arguments that the loader expects for
        ///     starting the VMM
        ///
        /// <!-- inputs/outputs -->
        ///   @param args the user provided arguments
        ///   @return The resulting IOCTL arguments
        ///
        [[nodiscard]] constexpr auto
        make_start_vmm_args(bsl::arguments &args) noexcept -> bsl::result<loader::start_vmm_args_t>
        {
            auto remaining{args.remaining()};

            if (bsl::to_umax(0) == remaining) {
                bsl::error() << "missing the microkernel elf file\n";
                return {bsl::errc_failure};
            }

            if (bsl::to_umax(1) == remaining) {
                bsl::error() << "at least one extension is required\n";
                return {bsl::errc_failure};
            }

            if (!this->map_mk_elf_file_from_user(args)) {
                return {bsl::errc_failure};
            }

            if (!this->map_ext_elf_files_from_user(args)) {
                return {bsl::errc_failure};
            }

            return {loader::start_vmm_args_t{
                bsl::ONE_UMAX.get(),
                0U,
                0U,
                m_mapped_mk_elf_file.view(),
                this->convert_mapped_ext_elf_files_to_array_of_spans()}};
        }

        /// <!-- description -->
        ///   @brief This function is called if an error was encountered while
        ///     attempting to parse the command that the user provided.
        ///
        /// <!-- inputs/outputs -->
        ///   @param cmd the user provided command
        ///
        constexpr void
        process_cmd_output_error(bsl::string_view const &cmd) noexcept
        {
            if (cmd.empty()) {
                bsl::error() << "missing command. ";
            }
            else {
                bsl::error() << "invalid command: \"" << cmd << "\". ";
            }

            bsl::print() << "use vmmctl -h for usage info\n";
        }

        /// <!-- description -->
        ///   @brief Process the user provided command line arguments assuming
        ///     the first argument is the command while also ignoring "help".
        ///     If the user provided command succeeds, this function
        ///     will return bsl::exit_success, otherwise this function
        ///     will return bsl::exit_failure.
        ///
        /// <!-- inputs/outputs -->
        ///   @param args the command line arguments provided by the user.
        ///   @return If the user provided command succeeds, this function
        ///     will return bsl::exit_success, otherwise this function
        ///     will return bsl::exit_failure.
        ///
        [[nodiscard]] constexpr auto
        process_cmd(bsl::arguments &&args) noexcept -> bsl::exit_code
        {
            bsl::string_view cmd{args.front<bsl::string_view>()};
            ++args;

            if (cmd == "start") {
                auto ctl_args{this->make_start_vmm_args(args)};
                if (auto ptr{ctl_args.get_if()}) {
                    return this->start_vmm(ptr);
                }

                return bsl::exit_failure;
            }

            if (cmd == "stop") {
                return this->stop_vmm(&m_stop_vmm_ctl_args);
            }

            if (cmd == "dump") {
                return this->dump_vmm(&m_dump_vmm_ctl_args);
            }

            this->process_cmd_output_error(cmd);
            return bsl::exit_failure;
        }

    public:
        /// <!-- description -->
        ///   @brief Process the user provided command line arguments.
        ///     If the user provided command succeeds, this function
        ///     will return bsl::exit_success, otherwise this function
        ///     will return bsl::exit_failure.
        ///
        /// <!-- inputs/outputs -->
        ///   @param args the command line arguments provided by the user.
        ///   @return If the user provided command succeeds, this function
        ///     will return bsl::exit_success, otherwise this function
        ///     will return bsl::exit_failure.
        ///
        [[nodiscard]] constexpr auto
        process(bsl::arguments &&args) noexcept -> bsl::exit_code
        {
            if (args.get<bool>("-h")) {
                this->help();
                return bsl::exit_success;
            }

            if (args.get<bool>("--help")) {
                this->help();
                return bsl::exit_success;
            }

            return this->process_cmd(bsl::move(args));
        }
    };
}

#endif
