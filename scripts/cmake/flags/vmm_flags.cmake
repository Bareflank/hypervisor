#
# Bareflank Hypervisor
# Copyright (C) 2015 Assured Information Security, Inc.
#
# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 2.1 of the License, or (at your option) any later version.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this library; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA

# TODO: Move this to an appropriate place and/or get rid of it
execute_process(COMMAND uname -o OUTPUT_VARIABLE UNAME OUTPUT_STRIP_TRAILING_WHITESPACE)
if(UNAME STREQUAL "Cygwin" OR WIN32)
    set(OSTYPE "WIN64" CACHE INTERNAL "")
    set(ABITYPE "MS64" CACHE INTERNAL "")
    set(WIN64 ON)
else()
    set(OSTYPE "UNIX" CACHE INTERNAL "")
    set(ABITYPE "SYSV" CACHE INTERNAL "")
endif()

list(APPEND BFFLAGS_VMM
    "-fpic"
    "-mno-red-zone"
    "-mstackrealign"
    "-fstack-protector-strong"
    "-DVMM"
    "-D${OSTYPE}"
    "-D${ABITYPE}"
    "-DMALLOC_PROVIDED"
    "-DGSL_THROW_ON_CONTRACT_VIOLATION"
    "-D_HAVE_LONG_DOUBLE"
    "-D_LDBL_EQ_DBL"
    "-D_POSIX_TIMERS"
    "-D_POSIX_PRIORITY_SCHEDULING"
    "-U__STRICT_ANSI__"
    "-DCLOCK_MONOTONIC"
)

list(APPEND BFFLAGS_VMM_C
    "-std=c11"
)

list(APPEND BFFLAGS_VMM_CXX
    "-x c++"
    "-std=c++1z"
    "-DNOSTDINC_CXX"
)

list(APPEND BFFLAGS_VMM_X86_64
    "-msse"
    "-msse2"
    "-msse3"
)

list(APPEND BFFLAGS_VMM_AARCH64
    ""
)
