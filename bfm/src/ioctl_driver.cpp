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

#include <ioctl_driver.h>

ioctl_driver::ioctl_driver(const file *const f,
                           const ioctl *const ctl,
                           const command_line_parser *const clp) :
    m_f(f),
    m_ctl(ctl),
    m_clp(clp)
{
}

ioctl_driver::~ioctl_driver()
{
}

ioctl_driver_error::type
ioctl_driver::process() const
{
    if (m_f == NULL ||
        m_ctl == NULL ||
        m_clp == NULL)
    {
        bfm_error << "Invalid IOCTL driver" << std::endl;
        return ioctl_driver_error::failure;
    }

    if (m_clp->is_valid() == false)
    {
        bfm_error << "Invalid command line parser" << std::endl;
        return ioctl_driver_error::failure;
    }

    switch (m_clp->cmd())
    {
        case command_line_parser_command::start:
            return this->start_vmm();

        case command_line_parser_command::stop:
            return this->stop_vmm();

        case command_line_parser_command::dump:
            return this->dump_vmm();

        default:
        {
            bfm_error << "Unable to process command. Command is unknown" << std::endl;
            return ioctl_driver_error::failure;
        }
    }

    return ioctl_driver_error::success;
}

ioctl_driver_error::type
ioctl_driver::start_vmm() const
{
    assert(m_f != NULL);
    assert(m_ctl != NULL);
    assert(m_clp != NULL);

    auto modules_filename = m_clp->modules();

    if (modules_filename.empty() == true)
    {
        bfm_error << "Unable to start vmm. List of modules was not provided" << std::endl;
        return ioctl_driver_error::failure;
    }

    if (m_f->exists(modules_filename) == false)
    {
        bfm_error << "Unable to start vmm. Provided filename for the list of modules does not exist" << std::endl;
        return ioctl_driver_error::failure;
    }

    auto modules = m_f->read(modules_filename);

    if (modules.empty() == true)
    {
        bfm_error << "Unable to start vmm. Provided list of modules is empty" << std::endl;
        return ioctl_driver_error::failure;
    }

    for (const auto &module : split(modules, '\n'))
    {
        if (module.empty() == true)
            continue;

        if (m_f->exists(module) == false)
        {
            bfm_error << "Unable to start vmm. module does not exist: " << module << std::endl;
            return ioctl_driver_error::failure;
        }

        auto contents = m_f->read(module);

        if (contents.empty() == true)
        {
            bfm_error << "Unable to start vmm. module is empty: " << module << std::endl;
            return ioctl_driver_error::failure;
        }

        auto result = m_ctl->call(ioctl_commands::add_module,
                                  contents.c_str(),
                                  contents.length());

        if (result != ioctl_error::success)
        {
            bfm_error << "Unable to start vmm. failed to add module: " << module << std::endl;
            return ioctl_driver_error::failure;
        }
    }

    if (m_ctl->call(ioctl_commands::start, NULL, 0) != ioctl_error::success)
    {
        bfm_error << "failed to start vmm: " << std::endl;
        return ioctl_driver_error::failure;
    }

    return ioctl_driver_error::success;
}

ioctl_driver_error::type
ioctl_driver::stop_vmm() const
{
    assert(m_f != NULL);
    assert(m_ctl != NULL);
    assert(m_clp != NULL);

    if (m_ctl->call(ioctl_commands::stop, NULL, 0) != ioctl_error::success)
    {
        bfm_error << "failed to stop vmm: " << std::endl;
        return ioctl_driver_error::failure;
    }

    return ioctl_driver_error::success;
}

ioctl_driver_error::type
ioctl_driver::dump_vmm() const
{
    assert(m_f != NULL);
    assert(m_ctl != NULL);
    assert(m_clp != NULL);

    if (m_ctl->call(ioctl_commands::dump, NULL, 0) != ioctl_error::success)
    {
        bfm_error << "failed to dump vmm: " << std::endl;
        return ioctl_driver_error::failure;
    }

    return ioctl_driver_error::success;
}
