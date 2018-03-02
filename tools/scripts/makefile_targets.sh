#!/bin/bash -e
#
# Bareflank Hypervisor
#
# Copyright (C) 2015 Assured Information Security, Inc.
# Author: Rian Quinn        <quinnr@ainfosec.com>
# Author: Brendan Kerrigan  <kerriganb@ainfosec.com>
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

SCRIPT='
  /^# Make data base/,/^# Files/d             # skip until files section
  /^# Not a target/,+1          d             # following target isnt
  /^\.PHONY:/                   d             # special target
  /^\.SUFFIXES:/                d             # special target
  /^\.DEFAULT:/                 d             # special target
  /^\.PRECIOUS:/                d             # special target
  /^\.INTERMEDIATE:/            d             # special target
  /^\.SECONDARY:/               d             # special target
  /^\.SECONDEXPANSION/          d             # special target
  /^\.DELETE_ON_ERROR:/         d             # special target
  /^\.IGNORE:/                  d             # special target
  /^\.LOW_RESOLUTION_TIME:/     d             # special target
  /^\.SILENT:/                  d             # special target
  /^\.EXPORT_ALL_VARIABLES:/    d             # special target
  /^\.NOTPARALLEL:/             d             # special target
  /^\.ONESHELL:/                d             # special target
  /^\.POSIX:/                   d             # special target
  /^\.NOEXPORT:/                d             # special target
  /^\.MAKE:/                    d             # special target

# The stuff above here describes lines that are not
#  explicit targets or not targets other than special ones
# The stuff below here decides whether an explicit target
#  should be output.

  /^[^#\t:=%]+:([^=]|$)/ {                    # found target block
    h                                         # hold target
    d                                         # delete line
  }
  /^# File is an intermediate prerequisite/ { # nope
    s/^.*$//;x                                # unhold target
    d                                         # delete line
  }
  /^([^#]|$)/ {                               # end of target block
    s/^.*$//;x                                # unhold target
    s/:.*$//p                                 # write current target
    d                                         # hide any bugs
  }
'

make -npq .DEFAULT 2>/dev/null | sed -n -r "$SCRIPT" | sort | uniq | \
  perl -p -e 's/\n/ /' | sed 's/Makefile //g' | sed 's/makefile //g'
