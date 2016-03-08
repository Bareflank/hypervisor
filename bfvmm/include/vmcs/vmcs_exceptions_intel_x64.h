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

#ifndef VMCS_EXCEPTIONS_INTEL_X64_H
#define VMCS_EXCEPTIONS_INTEL_X64_H

#include <exception.h>

namespace bfn
{

// -----------------------------------------------------------------------------
// VMCS Invalid
// -----------------------------------------------------------------------------

class invalid_vmcs_error : public bfn::general_exception
{
public:
    virtual std::ostream &print(std::ostream &os) const
    { return os << "invalid vmcs"; }
};

#define invalid_vmcs() bfn::invalid_vmcs_error()

// -----------------------------------------------------------------------------
// VMCS Failure
// -----------------------------------------------------------------------------

class vmcs_failure_error : public bfn::general_exception
{
public:
    vmcs_failure_error(const std::string &mesg,
                       const std::string &func,
                       uint64_t line) :
        m_mesg(mesg),
        m_func(func),
        m_line(line)
    {}

    virtual std::ostream &print(std::ostream &os) const
    {
        os << "vmcs failure:";
        os << std::endl << "    - mesg: " << m_mesg;
        os << std::endl << "    - func: " << m_func;
        os << std::endl << "    - line: " << m_line;

        return os;
    }

private:
    std::string m_mesg;
    std::string m_func;
    uint64_t m_line;
};

#define vmcs_failure(a) \
    bfn::vmcs_failure_error(a,__func__,__LINE__)

// -----------------------------------------------------------------------------
// VMCS Read Failure
// -----------------------------------------------------------------------------

class vmcs_read_failure_error : public bfn::general_exception
{
public:
    vmcs_read_failure_error(uint64_t field,
                            const std::string &func,
                            uint64_t line) :
        m_field(field),
        m_func(func),
        m_line(line)
    {}

    virtual std::ostream &print(std::ostream &os) const
    {
        os << "vmcs read failure:";
        os << std::endl << "    - field: " << (void *)m_field;
        os << std::endl << "    - func: " << m_func;
        os << std::endl << "    - line: " << m_line;

        return os;
    }

private:
    uint64_t m_field;
    std::string m_func;
    uint64_t m_line;
};

#define vmcs_read_failure(a) \
    bfn::vmcs_read_failure_error(a,__func__,__LINE__)

// -----------------------------------------------------------------------------
// VMCS Write Failure
// -----------------------------------------------------------------------------

class vmcs_write_failure_error : public bfn::general_exception
{
public:
    vmcs_write_failure_error(uint64_t field,
                             uint64_t value,
                             const std::string &func,
                             uint64_t line) :
        m_field(field),
        m_value(value),
        m_func(func),
        m_line(line)
    {}

    virtual std::ostream &print(std::ostream &os) const
    {
        os << "vmcs write failure:";
        os << std::endl << "    - field: " << (void *)m_field;
        os << std::endl << "    - value: " << (void *)m_value;
        os << std::endl << "    - func: " << m_func;
        os << std::endl << "    - line: " << m_line;

        return os;
    }

private:
    uint64_t m_field;
    uint64_t m_value;
    std::string m_func;
    uint64_t m_line;
};

#define vmcs_write_failure(a,b) \
    bfn::vmcs_write_failure_error(a,b,__func__,__LINE__)

// -----------------------------------------------------------------------------
// VMCS Launch Failure
// -----------------------------------------------------------------------------

class vmcs_launch_failure_error : public bfn::general_exception
{
public:
    vmcs_launch_failure_error(const std::string &mesg,
                              const std::string &func,
                              uint64_t line) :
        m_mesg(mesg),
        m_func(func),
        m_line(line)
    {}

    virtual std::ostream &print(std::ostream &os) const
    {
        os << "vmcs launch failure:";
        os << std::endl << "    - mesg: " << m_mesg;
        os << std::endl << "    - func: " << m_func;
        os << std::endl << "    - line: " << m_line;

        return os;
    }

private:
    std::string m_mesg;
    std::string m_func;
    uint64_t m_line;
};

#define vmcs_launch_failure(a) \
    bfn::vmcs_launch_failure_error(a,__func__,__LINE__)

// -----------------------------------------------------------------------------
// VMCS Invalid CTLS
// -----------------------------------------------------------------------------

class vmcs_invalid_ctls_error : public bfn::general_exception
{
public:
    vmcs_invalid_ctls_error(const std::string &mesg,
                            uint64_t msr_lower,
                            uint64_t msr_upper,
                            uint64_t controls_lower,
                            uint64_t controls_upper,
                            const std::string &func,
                            uint64_t line) :
        m_mesg(mesg),
        m_msr_lower(msr_lower),
        m_msr_upper(msr_upper),
        m_controls_lower(controls_lower),
        m_controls_upper(controls_upper),
        m_func(func),
        m_line(line)
    {}

    virtual std::ostream &print(std::ostream &os) const
    {
        os << m_func << " failed:";
        os << std::endl << "    - mesg: " << m_mesg
           << " controls not setup properly";
        os << std::endl << "    - msr_lower: " << m_msr_lower;
        os << std::endl << "    - msr_upper: " << m_msr_upper;
        os << std::endl << "    - controls_lower: " << m_controls_lower;
        os << std::endl << "    - controls_upper: " << m_controls_upper;
        os << std::endl << "    - line: " << m_line;

        return os;
    }

private:
    std::string m_mesg;
    uint64_t m_msr_lower;
    uint64_t m_msr_upper;
    uint64_t m_controls_lower;
    uint64_t m_controls_upper;
    std::string m_func;
    uint64_t m_line;
};

#define vmcs_invalid_ctls(a,b,c,d,e) \
    bfn::vmcs_invalid_ctls_error(a,b,c,d,e,__func__,__LINE__)

// -----------------------------------------------------------------------------
// VMCS Invalid Field
// -----------------------------------------------------------------------------

class vmcs_invalid_field_error : public bfn::general_exception
{
public:
    vmcs_invalid_field_error(const std::string &mesg,
                             const std::string &field_str,
                             uint64_t field,
                             const std::string &func,
                             uint64_t line) :
        m_mesg(mesg),
        m_field_str(field_str),
        m_field(field),
        m_func(func),
        m_line(line)
    {}

    virtual std::ostream &print(std::ostream &os) const
    {
        os << m_func << " failed:";
        os << std::endl << "    - mesg: " << m_mesg;
        os << std::endl << "    - " << m_field_str << ": " << m_field;
        os << std::endl << "    - line: " << m_line;

        return os;
    }

private:
    std::string m_mesg;
    std::string m_field_str;
    uint64_t m_field;
    std::string m_func;
    uint64_t m_line;
};

#define vmcs_invalid_field(a,b) \
    bfn::vmcs_invalid_field_error(a,#b,b,__func__,__LINE__)

}

#endif
