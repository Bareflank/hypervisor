//
// Copyright (C) 2019 Assured Information Security, Inc.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

#ifndef IOCTL_DRIVER_H
#define IOCTL_DRIVER_H

#include <ioctl.h>
#include <command_line_parser.h>

#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable : 4251)
#endif

// -----------------------------------------------------------------------------
// Definitions
// -----------------------------------------------------------------------------

/// IOCTL Driver
///
/// The IOCTL driver is the main work horse of the Bareflank Manager. The
/// IOCTL driver takes the command line parser, and using a file class, and
/// IOCTL class, tells the driver entry what to do based on input provided by
/// the command line parser.
///
/// If certain conditions are not meet, the IOCTL driver will error out on
/// it's attempt to process, and return an error.
///
class ioctl_driver
{
public:

    using status_type = ioctl::status_type;                         ///< Status type
    using filename_type = std::string;                              ///< Filename type
    using list_type = std::vector<std::string>;                     ///< List type

    /// Default Constructor
    ///
    /// @expects f != nullptr
    /// @expects ctl != nullptr
    /// @expects clp != nullptr
    /// @ensures none
    ///
    /// @param f file class used to read/write from/to the filesystem
    /// @param ctl ioctl class used to communicate with the driver entry
    /// @param clp command line parser used to parse user input
    ///
    ioctl_driver(gsl::not_null<file *> f,
                 gsl::not_null<ioctl *> ctl,
                 gsl::not_null<command_line_parser *> clp);

    /// Destructor
    ///
    /// @expects none
    /// @ensures none
    ///
    ~ioctl_driver() = default;

    /// Process
    ///
    /// Processes the IOCTL driver based on the information provided during
    /// construction. If the IOCTL driver has a problem during processing,
    /// this function will return with an error.
    ///
    /// @expects none
    /// @ensures none
    ///
    void process();

#ifndef ENABLE_BUILD_TEST
private:
#endif

    void load_vmm();
    void unload_vmm();
    void start_vmm();
    void stop_vmm();
    void quick_vmm();
    void dump_vmm();
    void vmm_status();

    status_type get_status() const;

    list_type library_path();
    filename_type vmm_filename();
    list_type vmm_module_list(const filename_type &filename);

private:

    gsl::not_null<file *> m_file;
    gsl::not_null<ioctl *> m_ioctl;
    gsl::not_null<command_line_parser *> m_clp;
};

#ifdef _MSC_VER
#pragma warning(pop)
#endif

#endif
