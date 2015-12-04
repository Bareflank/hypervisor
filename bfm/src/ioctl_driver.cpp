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

ioctl_driver::ioctl_driver(const file_base *const fb,
                           const ioctl_base *const ioctlb,
                           const command_line_parser_base *const clpb) :
    m_fb(fb),
    m_ioctlb(ioctlb),
    m_clpb(clpb)
{
}

ioctl_driver::~ioctl_driver()
{
}

ioctl_driver_error::type
ioctl_driver::process() const
{
    if (m_fb == NULL ||
        m_clpb == NULL ||
        m_ioctlb == NULL)
    {
        bfm_error << "Invalid IOCTL driver" << std::endl;
        return ioctl_driver_error::failure;
    }

    if (m_clpb->is_valid() == false)
    {
        bfm_error << "Invalid command line parser" << std::endl;
        return ioctl_driver_error::failure;
    }

    switch (m_clpb->cmd())
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
    assert(m_fb != NULL);
    assert(m_clpb != NULL);
    assert(m_ioctlb != NULL);

    auto modules_filename = m_clpb->modules();

    if (modules_filename.empty() == true)
    {
        bfm_error << "Unable to start vmm. List of modules was not provided" << std::endl;
        return ioctl_driver_error::failure;
    }

    if (m_fb->exists(modules_filename) == false)
    {
        bfm_error << "Unable to start vmm. Provided filename for the list of modules does not exist" << std::endl;
        return ioctl_driver_error::failure;
    }

    auto modules = m_fb->read(modules_filename);

    if (modules.empty() == true)
    {
        bfm_error << "Unable to start vmm. Provided list of modules is empty" << std::endl;
        return ioctl_driver_error::failure;
    }

    for (const auto &module : split(modules, '\n'))
    {
        if (module.empty() == true)
            continue;

        if (m_fb->exists(module) == false)
        {
            bfm_error << "Unable to start vmm. module does not exist: " << module << std::endl;
            return ioctl_driver_error::failure;
        }

        auto contents = m_fb->read(module);

        if (contents.empty() == true)
        {
            bfm_error << "Unable to start vmm. module is empty: " << module << std::endl;
            return ioctl_driver_error::failure;
        }

        auto result = m_ioctlb->call(ioctl_commands::add_module,
                                     contents.c_str(),
                                     contents.length());

        if (result != ioctl_error::success)
        {
            bfm_error << "Unable to start vmm. failed to add module: " << module << std::endl;
            return ioctl_driver_error::failure;
        }
    }

    if (m_ioctlb->call(ioctl_commands::start, NULL, 0) != ioctl_error::success)
    {
        bfm_error << "failed to start vmm: " << std::endl;
        return ioctl_driver_error::failure;
    }

    return ioctl_driver_error::success;
}

ioctl_driver_error::type
ioctl_driver::stop_vmm() const
{
    assert(m_fb != NULL);
    assert(m_clpb != NULL);
    assert(m_ioctlb != NULL);

    if (m_ioctlb->call(ioctl_commands::stop, NULL, 0) != ioctl_error::success)
    {
        bfm_error << "failed to stop vmm: " << std::endl;
        return ioctl_driver_error::failure;
    }

    return ioctl_driver_error::success;
}

ioctl_driver_error::type
ioctl_driver::dump_vmm() const
{
    assert(m_fb != NULL);
    assert(m_clpb != NULL);
    assert(m_ioctlb != NULL);

    if (m_ioctlb->call(ioctl_commands::dump, NULL, 0) != ioctl_error::success)
    {
        bfm_error << "failed to dump vmm: " << std::endl;
        return ioctl_driver_error::failure;
    }

    return ioctl_driver_error::success;
}
