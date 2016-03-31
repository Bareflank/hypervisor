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

#ifndef EXCEPTION_H
#define EXCEPTION_H

#include <string>
#include <ostream>
#include <typeinfo>
#include <stdexcept>

namespace bfn
{

// -----------------------------------------------------------------------------
// General Exception
// -----------------------------------------------------------------------------

/// The following defines a general exception used in Bareflank. This should
/// not thrown and instead, an exception that inherits from this should be
/// thrown that provides more decent output. This exception type can however
/// be inherited from, and caught. There are two main reasons why this exception
/// is used instead of using std::exception directly:
///
/// - std::exception uses 'what()' to provide information about what was thrown
///   which returns a const char *. In most cases, it's almost impossible to
///   return something using const char * without constructing a string, which
///   can be dangerous. More importantly, if the risk is ok, it's a pain (
///   for example, imagine returning an integer). Instead, we use a stream
///   operator, which is more likely to succeed (still has issues though), but
///   at least it's simple to use.
///
/// - Having a different type than std::exception gives us a simple means to
///   detect when the execption is something that we defined, vs something that
///   came from the STL.
///
class general_exception : public std::exception
{
public:

    /// Default Constructor
    ///
    general_exception() noexcept
    {}

    /// Destructor
    ///
    virtual ~general_exception()
    {}

    /// What
    ///
    /// Returns a description of the exception. This function provides a simple
    /// means for unit testing to identify which exception was thrown, while
    /// still being able to support catching STL exceptions as well. This
    /// should not be used directly. Instead, use the stream operator.
    ///
    virtual const char *what() const throw()
    { return typeid(*this).name(); }

public:

    virtual std::ostream &print(std::ostream &os) const
    { return os << "general exception"; }
};

}

/// General Exception Stream
///
/// Used to print out a description of a thrown exception. This should be used
/// instead of "what()" for general exceptions."
///
/// @code
///
/// try
/// {
///     throw bfn::general_exception;
/// }
/// catch(bfn::general_exception &ge)
/// {
///     std::cerr << ge << std::endl;
/// }
///
/// @endcode
///
inline std::ostream &
operator<<(std::ostream &os, const bfn::general_exception &ge)
{ return ge.print(os); }

namespace bfn
{

// -----------------------------------------------------------------------------
// Unknown Command Error
// -----------------------------------------------------------------------------

class unknown_command_error : public bfn::general_exception
{
public:
    unknown_command_error(const std::string &mesg) :
        m_mesg(mesg)
    {}

    virtual std::ostream &print(std::ostream &os) const
    { return os << "unknown command: `" << m_mesg << "`"; }

private:
    std::string m_mesg;
};

#define unknown_command(a) bfn::unknown_command_error(a)

// -----------------------------------------------------------------------------
// Missing Argument Error
// -----------------------------------------------------------------------------

class missing_argument_error : public bfn::general_exception
{
public:
    virtual std::ostream &print(std::ostream &os) const
    { return os << "missing argument"; }
};

#define missing_argument() bfn::missing_argument_error()

// -----------------------------------------------------------------------------
// Invalid Filename Error
// -----------------------------------------------------------------------------

class invalid_file_error : public bfn::general_exception
{
public:
    invalid_file_error(const std::string &mesg) :
        m_mesg(mesg)
    {}

    virtual std::ostream &print(std::ostream &os) const
    { return os << "invalid filename: `" << m_mesg << "`"; }

private:
    std::string m_mesg;
};

#define invalid_file(a) bfn::invalid_file_error(a)

// -----------------------------------------------------------------------------
// Driver Inaccessible
// -----------------------------------------------------------------------------

class driver_inaccessible_error : public bfn::general_exception
{
public:
    virtual std::ostream &print(std::ostream &os) const
    {
        os << "bareflank driver inaccessible:";
        os << std::endl << "    - check that the bareflank driver is loaded";
        os << std::endl << "    - check that bfm was exectued with the "
           << "proper permissions";
        return os;
    }
};

#define driver_inaccessible(a) bfn::driver_inaccessible_error(a)

// -----------------------------------------------------------------------------
// IOCTL Failed
// -----------------------------------------------------------------------------

class ioctl_failed_error : public bfn::general_exception
{
public:
    ioctl_failed_error(const std::string &ioctl) :
        m_ioctl(ioctl)
    {}

    virtual std::ostream &print(std::ostream &os) const
    { return os << "ioctl failed: `" << m_ioctl << "`"; }

private:
    std::string m_ioctl;
};

#define ioctl_failed(a) bfn::ioctl_failed_error(#a)

// -----------------------------------------------------------------------------
// Corrupt VMM
// -----------------------------------------------------------------------------

class corrupt_vmm_error : public bfn::general_exception
{
public:
    virtual std::ostream &print(std::ostream &os) const
    { return os << "unable to process request. vmm is in a corrupt state"; }
};

#define corrupt_vmm() bfn::corrupt_vmm_error()

// -----------------------------------------------------------------------------
// Unknown VMM Status
// -----------------------------------------------------------------------------

class unknown_status_error : public bfn::general_exception
{
public:
    virtual std::ostream &print(std::ostream &os) const
    { return os << "unable to process request. vmm status unknown"; }
};

#define unknown_status() bfn::unknown_status_error()

// -----------------------------------------------------------------------------
// Invalid VMM Status
// -----------------------------------------------------------------------------

class invalid_vmm_state_error : public bfn::general_exception
{
public:
    invalid_vmm_state_error(const std::string &mesg) :
        m_mesg(mesg)
    {}

    virtual std::ostream &print(std::ostream &os) const
    { return os << m_mesg; }

private:
    std::string m_mesg;
};

#define invalid_vmm_state(a) bfn::invalid_vmm_state_error(a)

// -----------------------------------------------------------------------------
// Invalid Alignment
// -----------------------------------------------------------------------------

class invalid_alignment_error : public bfn::general_exception
{
public:
    invalid_alignment_error(const std::string &mesg,
                            uint64_t addr) :
        m_mesg(mesg),
        m_addr(addr)
    {}

    virtual std::ostream &print(std::ostream &os) const
    {
        os << "invalid address alignment: ";
        os << std::endl << "    - mesg: " << m_mesg;
        os << std::endl << "    - addr: " << m_addr;

        return os;
    }

private:
    std::string m_mesg;
    uint64_t m_addr;
};

#define invalid_alignment(a,b) bfn::invalid_alignment_error(a,b)

// -----------------------------------------------------------------------------
// Invalid Address
// -----------------------------------------------------------------------------

class invalid_address_error : public bfn::general_exception
{
public:
    invalid_address_error(const std::string &mesg,
                          uint64_t addr) :
        m_mesg(mesg),
        m_addr(addr)
    {}

    virtual std::ostream &print(std::ostream &os) const
    {
        os << "invalid address: ";
        os << std::endl << "    - mesg: " << m_mesg;
        os << std::endl << "    - addr: " << m_addr;

        return os;
    }

private:
    std::string m_mesg;
    uint64_t m_addr;
};

#define invalid_address(a,b) bfn::invalid_address_error(a,b)

// -----------------------------------------------------------------------------
// Hardware Unsupported
// -----------------------------------------------------------------------------

class hardware_unsupported_error : public bfn::general_exception
{
public:
    hardware_unsupported_error(const std::string &mesg,
                               const std::string &func,
                               uint64_t line) :
        m_mesg(mesg),
        m_func(func),
        m_line(line)
    {}

    virtual std::ostream &print(std::ostream &os) const
    {
        os << "hardware unsupported: ";
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

#define hardware_unsupported(a) \
    bfn::hardware_unsupported_error(a,__func__,__LINE__)

}

#endif
