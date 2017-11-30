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

# ------------------------------------------------------------------------------
# README
# ------------------------------------------------------------------------------

# This file exists to overcome buggy behaviour when installing files using
# the built-in cmake function ExternalProject_Add_Step.
#
# Usage:
# ExternalProject_Add_Step(
#     <external_project_target_name>
#     <name_of_this_step>
#     DEPENDEES <target_dependencies>
#     COMMAND	${CMAKE_COMMAND}
#         -DGLOB_DIR=${GLOB_DIR}
#         -DGLOB_EXPR=${GLOB_EXPR}
#         -DINSTALL_DIR=${INSTALL_DIR}
#         -P ${BF_SCRIPTS_DIR}/cmake/copy_files_if_different.cmake
# )

include(${CMAKE_CURRENT_LIST_DIR}/macros.cmake)
copy_files_if_different(
    GLOB_DIR ${GLOB_DIR}
    GLOB_EXPR ${GLOB_EXPR}
    INSTALL_DIR ${INSTALL_DIR}
)
