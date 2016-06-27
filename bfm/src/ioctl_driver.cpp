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

#include <iostream>

#include <exception.h>
#include <ioctl_driver.h>
#include <commit_or_rollback.h>
#include <driver_entry_interface.h>

ioctl_driver::ioctl_driver() noexcept
{
}

ioctl_driver::~ioctl_driver()
{
}

void
ioctl_driver::process(std::shared_ptr<file> f,
                      std::shared_ptr<ioctl> ctl,
                      std::shared_ptr<command_line_parser> clp)
{
    if (f == 0)
        throw std::invalid_argument("f == NULL");

    if (ctl == 0)
        throw std::invalid_argument("ctl == NULL");

    if (clp == 0)
        throw std::invalid_argument("clp == NULL");

    switch (clp->cmd())
    {
        case command_line_parser_command::help:
            return;

        case command_line_parser_command::load:
            return this->load_vmm(f, ctl, clp);

        case command_line_parser_command::unload:
            return this->unload_vmm(ctl);

        case command_line_parser_command::start:
            return this->start_vmm(ctl);

        case command_line_parser_command::stop:
            return this->stop_vmm(ctl);

        case command_line_parser_command::dump:
            return this->dump_vmm(ctl, clp->vcpuid());

        case command_line_parser_command::status:
            return this->vmm_status(ctl);
    }
}

std::string
trim(const std::string &str)
{
    auto comment = str.substr(0, str.find_first_of('#'));

    auto f = comment.find_first_not_of(" \t");
    auto l = comment.find_last_not_of(" \t");

    if (f == std::string::npos)
        return std::string();

    return str.substr(f, (l - f + 1));
}

void
ioctl_driver::load_vmm(const std::shared_ptr<file> &f,
                       const std::shared_ptr<ioctl> &ctl,
                       const std::shared_ptr<command_line_parser> &clp)
{
    switch (get_status(ctl))
    {
        case VMM_RUNNING:
            stop_vmm(ctl);

        case VMM_LOADED:
        case VMM_UNLOADED:
            unload_vmm(ctl);
            break;

        case VMM_CORRUPT:
            throw corrupt_vmm();

        default:
            throw unknown_status();
    }

    auto cor1 = commit_or_rollback([&]
    { unload_vmm(ctl); });

    for (const auto &module : split(f->read(clp->modules()), '\n'))
    {
        auto trimmed = trim(module);

        if (trimmed.empty() == true)
            continue;

        ctl->call_ioctl_add_module(f->read(trimmed));
    }

    ctl->call_ioctl_load_vmm();

    cor1.commit();
}

void
ioctl_driver::unload_vmm(const std::shared_ptr<ioctl> &ctl)
{
    switch (get_status(ctl))
    {
        case VMM_RUNNING: stop_vmm(ctl);
        case VMM_LOADED: break;
        case VMM_UNLOADED: break;
        case VMM_CORRUPT: throw corrupt_vmm();
        default: throw unknown_status();
    }

    ctl->call_ioctl_unload_vmm();
}

void
ioctl_driver::start_vmm(const std::shared_ptr<ioctl> &ctl)
{
    switch (get_status(ctl))
    {
        case VMM_RUNNING: stop_vmm(ctl);
        case VMM_LOADED: break;
        case VMM_UNLOADED: throw invalid_vmm_state("vmm must be loaded first");
        case VMM_CORRUPT: throw corrupt_vmm();
        default: throw unknown_status();
    }

    ctl->call_ioctl_start_vmm();
}

void
ioctl_driver::stop_vmm(const std::shared_ptr<ioctl> &ctl)
{
    switch (get_status(ctl))
    {
        case VMM_RUNNING: break;
        case VMM_LOADED: return;
        case VMM_UNLOADED: return;
        case VMM_CORRUPT: throw corrupt_vmm();
        default: throw unknown_status();
    }

    ctl->call_ioctl_stop_vmm();
}

void
ioctl_driver::dump_vmm(const std::shared_ptr<ioctl> &ctl, uint64_t vcpuid)
{
    auto drr = debug_ring_resources_t();
    auto buffer = std::make_unique<char[]>(DEBUG_RING_SIZE);

    switch (get_status(ctl))
    {
        case VMM_RUNNING: break;
        case VMM_LOADED: break;
        case VMM_UNLOADED: throw invalid_vmm_state("vmm must be loaded first");
        case VMM_CORRUPT: break;
        default: throw unknown_status();
    }

    ctl->call_ioctl_dump_vmm(&drr, vcpuid);

    if (debug_ring_read(&drr, buffer.get(), DEBUG_RING_SIZE) > 0)
        std::cout << buffer.get();
}

void
ioctl_driver::vmm_status(const std::shared_ptr<ioctl> &ctl)
{
    switch (get_status(ctl))
    {
        case VMM_UNLOADED: std::cout << "VMM_UNLOADED\n"; return;
        case VMM_LOADED: std::cout << "VMM_LOADED\n"; return;
        case VMM_RUNNING: std::cout << "VMM_RUNNING\n"; return;
        case VMM_CORRUPT: std::cout << "VMM_CORRUPT\n"; return;
        default: throw unknown_status();
    }
}

int64_t
ioctl_driver::get_status(const std::shared_ptr<ioctl> &ctl)
{
    int64_t status = -1;

    ctl->call_ioctl_vmm_status(&status);

    return status;
}
