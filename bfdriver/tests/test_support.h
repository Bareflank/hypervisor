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

#ifndef TEST_SUPPORT_H
#define TEST_SUPPORT_H

extern file g_file;
extern std::vector<std::string> g_filenames_success;
extern std::vector<std::string> g_filenames_init_fails;
extern std::vector<std::string> g_filenames_fini_fails;
extern std::vector<std::string> g_filenames_add_mdl_fails;
extern std::vector<std::string> g_filenames_get_drr_fails;
extern std::vector<std::string> g_filenames_set_rsdp_fails;
extern std::vector<std::string> g_filenames_vmm_init_fails;
extern std::vector<std::string> g_filenames_vmm_fini_fails;

#endif
