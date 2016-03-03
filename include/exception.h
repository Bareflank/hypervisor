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

namespace bfn
{

/// General Exception
///
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
inline std::ostream &operator<<(std::ostream &os, const bfn::general_exception &ge)
{ return ge.print(os); }

namespace bfn
{

// -----------------------------------------------------------------------------

/// Unknown Command Error
///
/// Thrown when an unknown command has been provided. The unknown command
/// should be provided to the exception's constructor
///
class unknown_command_error : public bfn::general_exception
{
public:
    unknown_command_error(const std::string &msg) :
        m_msg(msg)
    {}

    virtual std::ostream &print(std::ostream &os) const
    { return os << "unknown command: `" << m_msg << "`"; }

private:
    std::string m_msg;
};

#define unknown_command(a) bfn::unknown_command_error(a)

// -----------------------------------------------------------------------------

/// Missing Argument Error
///
/// Thrown when an argument is missing.
///
class missing_argument_error : public bfn::general_exception
{
public:
    virtual std::ostream &print(std::ostream &os) const
    { return os << "missing argument"; }
};

#define missing_argument() bfn::missing_argument_error()

// -----------------------------------------------------------------------------

/// Invalid Filename Error
///
/// Thrown when a filename is invalid. This usually happens when a file
/// cannot be openned which could occur because the file does not exist, or
/// the current user does not have the proper permissions. The filename
/// should be provided to the constructor.
///
class invalid_file_error : public bfn::general_exception
{
public:
    invalid_file_error(const std::string &msg) :
        m_msg(msg)
    {}

    virtual std::ostream &print(std::ostream &os) const
    { return os << "invalid filename: `" << m_msg << "`"; }

private:
    std::string m_msg;
};

#define invalid_file(a) bfn::invalid_file_error(a)

// -----------------------------------------------------------------------------

/// Driver Inaccessible
///
/// Thrown when the bareflank manager cannot open a connection to the
/// bareflank driver. This is likely because the bareflank driver is not
/// installed or loaded, but could be for other reasons such as invalid
/// permissions.
///
class driver_inaccessible_error : public bfn::general_exception
{
public:
    virtual std::ostream &print(std::ostream &os) const
    {
        os << "bareflank driver inaccessible:";
        os << std::endl << "    - check that the bareflank driver is loaded";
        os << std::endl << "    - check that bfm was exectued with the proper permissions";

        return os;
    }
};

#define driver_inaccessible(a) bfn::driver_inaccessible_error(a)

// -----------------------------------------------------------------------------

/// Invalid Argument
///
/// Thrown when a function is called with invalid arguments. This is a logic
/// error that should be corrected if thrown
///
class invalid_argument_error : public bfn::general_exception
{
public:
    invalid_argument_error(const std::string &func,
                           const std::string &arg,
                           const std::string &issue) :
        m_func(func),
        m_arg(arg),
        m_issue(issue)
    {}

    virtual std::ostream &print(std::ostream &os) const
    {
        os << "invalid argument:";
        os << std::endl << "    - func: " << m_func;
        os << std::endl << "    - arg: " << m_arg;
        os << std::endl << "    - issue: " << m_issue;

        return os;
    }

private:
    std::string m_func;
    std::string m_arg;
    std::string m_issue;
};

#define invalid_argument(a,b) \
    bfn::invalid_argument_error(__PRETTY_FUNCTION__,#a,b)

// -----------------------------------------------------------------------------

/// IOCTL Failed
///
/// Thrown when a call to an IOCTL fails. This generally means that something
/// went wrong in the driver entry
///
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

/// Corrupt VMM
///
/// Thrown when a call the VMM is made when the VMM has entered a corrupt
/// state. Once the VMM is in a corrupt state, the system is no longer
/// revoerable (restart is needed at minimum, likely will result in fault)
///
class corrupt_vmm_error : public bfn::general_exception
{
public:
    virtual std::ostream &print(std::ostream &os) const
    { return os << "unable to process request. vmm is in a corrupt state"; }
};

#define corrupt_vmm() bfn::corrupt_vmm_error()

// -----------------------------------------------------------------------------

/// Unknown VMM Status
///
/// Thrown when the VMM status is unknown. This really should not happen.
///
class unknown_status_error : public bfn::general_exception
{
public:
    virtual std::ostream &print(std::ostream &os) const
    { return os << "unable to process request. vmm status unknown"; }
};

#define unknown_status() bfn::unknown_status_error()

// -----------------------------------------------------------------------------

/// Invalid VMM Status
///
/// Thrown when the user attempts to put the VMM in a state in the wrong order.
/// For example, if the user attempts to start the VMM prior to loading the
/// VMM
///
class invalid_vmm_state_error : public bfn::general_exception
{
public:
    invalid_vmm_state_error(const std::string &msg) :
        m_msg(msg)
    {}

    virtual std::ostream &print(std::ostream &os) const
    { return os << m_msg; }

private:
    std::string m_msg;
};

#define invalid_vmm_state(a) bfn::invalid_vmm_state_error(a)

// -----------------------------------------------------------------------------

/// Out Of Range
///
class range_error : public bfn::general_exception
{
public:
    range_error(const std::string &msg,
                const std::string &func,
                uint64_t line,
                uint64_t got,
                uint64_t lower,
                uint64_t upper) :
        m_msg(msg),
        m_func(func),
        m_line(line),
        m_got(got),
        m_lower(lower),
        m_upper(upper)
    {}

    virtual std::ostream &print(std::ostream &os) const
    {
        os << "out of range:";
        os << std::endl << "    - got: " << m_got;
        os << std::endl << "    - lower: " << m_lower;
        os << std::endl << "    - upper: " << m_upper;
        os << std::endl << "    - func: " << m_func;
        os << std::endl << "    - line: " << m_line;

        return os;
    }

private:
    std::string m_msg;
    std::string m_func;
    uint64_t m_line;
    uint64_t m_got;
    uint64_t m_lower;
    uint64_t m_upper;
};

#define range_error(a,b,c,d) \
    bfn::range_error(a,__PRETTY_FUNCTION__,__LINE__,b,c,d)

}

#endif
