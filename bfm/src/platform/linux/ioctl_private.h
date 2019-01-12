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

#ifndef IOCTL_PRIVATE_H
#define IOCTL_PRIVATE_H

#include <ioctl.h>

class ioctl_private : public ioctl_private_base
{
public:

    using module_len_type = size_t;
    using module_data_type = const char *;
    using drr_pointer = ioctl::drr_pointer;
    using vcpuid_type = ioctl::vcpuid_type;
    using status_pointer = ioctl::status_pointer;
    using handle_type = int;

    ioctl_private();
    ~ioctl_private() override;

    virtual void open();
    virtual void call_ioctl_add_module_length(module_len_type len);
    virtual void call_ioctl_add_module(gsl::not_null<module_data_type> data);
    virtual void call_ioctl_load_vmm();
    virtual void call_ioctl_unload_vmm();
    virtual void call_ioctl_start_vmm();
    virtual void call_ioctl_stop_vmm();
    virtual void call_ioctl_dump_vmm(gsl::not_null<drr_pointer> drr, vcpuid_type vcpuid);
    virtual void call_ioctl_vmm_status(gsl::not_null<status_pointer> status);

private:

    handle_type fd;
};

#endif
