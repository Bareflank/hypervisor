//
// Bareflank Unwind Library
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

#ifndef DWARF4_H
#define DWARF4_H

#include <stdint.h>
#include <eh_frame.h>
#include <registers_intel_x64.h>

#define MAX_ROWS 17

// -----------------------------------------------------------------------------
// Overview
// -----------------------------------------------------------------------------
//
// The DWARF specification describes all of the compiled debug information that
// GCC and Clang use. For unwinding, we only care about the Call Frame
// Information (section 6.4). For this implementation, we used the 4th version
// of this specification:
//
// http://www.dwarfstd.org/doc/DWARF4.pdf
//
// When compiling, information about each stack frame is stored (usually
// referred to as a function call, but it could be more than that), in a
// section called .debug_frames and .eh_frames. We only care about the
// .eh_frames section for this implementation. Also note that there are
// differences, so you need to read both specifications (see eh_frame.h).
//
// The call frame information might seem complicated but it is pretty simple
// (at least for x86_64). Take for example, the following function
//
// 00410814:
//     push   rbp
//     mov    rbp,rsp
//     <throw>...
//     pop    rbp
//     ret
//
// This function is really simple (it does nothing). No suppose, the code
// threw an exception. The stack has been altered, and needs to be unwound.
// We cannot simply unwind all of the instructions because we are part of the
// way into the function, and thus can only unwind instructions up the throw
// (or if you keep unwinding, from the call instruction of the previous
// function, and so on....). The DWARF instructions for this code are as
// follows (you can get these by running readelf):
//
// CIE Part:
// DW_CFA_def_cfa: r7 (rsp) ofs 8
// DW_CFA_offset: r16 (rip) at cfa-8
//
// FDE Part:
// DW_CFA_advance_loc: 1 to 00410814
// DW_CFA_def_cfa_offset: 16
// DW_CFA_offset: r6 (rbp) at cfa-16
// DW_CFA_advance_loc: 3 to 00410817
// DW_CFA_def_cfa_register: r6 (rbp)
// <stop>
// DW_CFA_advance_loc: 15 to 00410826
// DW_CFA_def_cfa: r7 (rsp) ofs 8
//
// We only care about the instructions up to the stop location, which is
// where the throw occurred. The first part of these instructions move an
// invisible "cursor" to location: 00410814, which is the initial push
// instruction. Here it says that if you want access to the Canonical Frame
// Address (cfa), you can find it in register r7 (which is the stack pointer),
// with an offset of 8 (prior to the cursor being moved, i.e. the CIE part).
// It also says that you can find the return address -8 into the CFA, which
// make sense (executing a call instruction places the return address onto
// the stack, which means it's the first "thing" on the call frame). Once the
// push instruction occurs (i.e. DW_CFA_advance_loc), you are then given an
// instruction that says the CFA is now located 16 bytes from r7. This makes
// sense because r7 is the stack pointer, and pushing rbp to the stack will
// cause the stack pointer to move. The CFA is always located in the same spot,
// and thus to calculate the the location of the CFA, you need a new offset.
// The next instruction states that rbp can be located -16 from the CFA, which
// makes sense because we just pushed it onto the stack. This can later be
// used to recover rbp when unwinding. Once that is done, the invisible cursor
// is moved to 00410817 stating that the CFA can now be located using RBP.
// This is done because RSP is about to be modified a ton, and this will keep
// the calculated of CFA simple. The next set of instruction roll back some
// of the previous instructions because the code is now cleaning itself up.
// In our example, we don't want to use these instructions because our throw,
// occurs prior to these cleanup instructions. This is why we care about the
// _loc instructions. They tell us when to stop looking for instructions.
//
// The DWARF specification states that you are building a "table", which you
// are. The table would look like this
//
// --
// -----
// --------
// -----
// --
//
// Each row is the same as the next, with a couple more instructions added,
// until you hit cleanup code. This is really useful for a debugger, but for
// the unwinder, the only information that we care about is the "current" row.
// For this reason, we don't need to follow the "add a row" instructions that
// you will see in the spec. We simple keep modifying the existing row. Note
// that this implementation does have a couple of limitations that at some
// point we might want to address:
//
// - At the moment we don't have expression support. We have not been able to
//   reproduce any example that would generate this code, so we have left it
//   out for now to simplify the implementation. At some point, we might want
//   to add support for this.
//
// - Right now we don't support the restore instructions because that requires
//   the initial row (what's defined in the CIE). The problem is, this would
//   double the about of stack space we require, and we are pretty limited in
//   the kernel (on Linux it's only 8k), so for now, we have left it out as
//   we have not seen these instructions either.
//
// - We also do not support the state instructions. The way this is usually
//   implemented is with a malloc/free, which should not be used in an unwinder
//   because a throw might be due to bad_alloc. For this reason, GCC does
//   not output these instructions so we should be fine here.
//

// -----------------------------------------------------------------------------
// Call Frame Information (section 6.4.1)
// -----------------------------------------------------------------------------

enum register_rules {
    rule_undefined       = 0,
    rule_same_value      = 1,
    rule_offsetn         = 2,
    rule_val_offsetn     = 3,
    rule_register        = 4,
    rule_expression      = 5,
    rule_val_expression  = 6
};

// -----------------------------------------------------------------------------
// Call Frame Information (section 7.23)
// -----------------------------------------------------------------------------

#define DW_CFA_advance_loc          0x40
#define DW_CFA_offset               0x80
#define DW_CFA_restore              0xC0
#define DW_CFA_nop                  0x00
#define DW_CFA_set_loc              0x01
#define DW_CFA_advance_loc1         0x02
#define DW_CFA_advance_loc2         0x03
#define DW_CFA_advance_loc4         0x04
#define DW_CFA_offset_extended      0x05
#define DW_CFA_restore_extended     0x06
#define DW_CFA_undefined            0x07
#define DW_CFA_same_value           0x08
#define DW_CFA_register             0x09
#define DW_CFA_remember_state       0x0A
#define DW_CFA_restore_state        0x0B
#define DW_CFA_def_cfa              0x0C
#define DW_CFA_def_cfa_register     0x0D
#define DW_CFA_def_cfa_offset       0x0E
#define DW_CFA_def_cfa_expression   0x0F
#define DW_CFA_expression           0x10
#define DW_CFA_offset_extended_sf   0x11
#define DW_CFA_def_cfa_sf           0x12
#define DW_CFA_def_cfa_offset_sf    0x13
#define DW_CFA_val_offset           0x14
#define DW_CFA_val_offset_sf        0x15
#define DW_CFA_val_expression       0x16

#define DW_OP_addr                  0x03
#define DW_OP_deref                 0x06
#define DW_OP_const1u               0x08
#define DW_OP_const1s               0x09
#define DW_OP_const2u               0x0A
#define DW_OP_const2s               0x0B
#define DW_OP_const4u               0x0C
#define DW_OP_const4s               0x0D
#define DW_OP_const8u               0x0E
#define DW_OP_const8s               0x0F
#define DW_OP_constu                0x10
#define DW_OP_consts                0x11
#define DW_OP_dup                   0x12
#define DW_OP_drop                  0x13
#define DW_OP_over                  0x14
#define DW_OP_pick                  0x15
#define DW_OP_swap                  0x16
#define DW_OP_rot                   0x17
#define DW_OP_xderef                0x18
#define DW_OP_abs                   0x19
#define DW_OP_and                   0x1A
#define DW_OP_div                   0x1B
#define DW_OP_minus                 0x1C
#define DW_OP_mod                   0x1D
#define DW_OP_mul                   0x1E
#define DW_OP_neg                   0x1F
#define DW_OP_not                   0x20
#define DW_OP_or                    0x21
#define DW_OP_plus                  0x22
#define DW_OP_plus_uconst           0x23
#define DW_OP_shl                   0x24
#define DW_OP_shr                   0x25
#define DW_OP_shra                  0x26
#define DW_OP_xor                   0x27
#define DW_OP_skip                  0x2F
#define DW_OP_bra                   0x28
#define DW_OP_eq                    0x29
#define DW_OP_ge                    0x2A
#define DW_OP_gt                    0x2B
#define DW_OP_le                    0x2C
#define DW_OP_lt                    0x2D
#define DW_OP_ne                    0x2E
#define DW_OP_lit0                  0x30
#define DW_OP_lit1                  0x31
#define DW_OP_lit2                  0x32
#define DW_OP_lit3                  0x33
#define DW_OP_lit4                  0x34
#define DW_OP_lit5                  0x35
#define DW_OP_lit6                  0x36
#define DW_OP_lit7                  0x37
#define DW_OP_lit8                  0x38
#define DW_OP_lit9                  0x39
#define DW_OP_lit10                 0x3A
#define DW_OP_lit11                 0x3B
#define DW_OP_lit12                 0x3C
#define DW_OP_lit13                 0x3D
#define DW_OP_lit14                 0x3E
#define DW_OP_lit15                 0x3F
#define DW_OP_lit16                 0x40
#define DW_OP_lit17                 0x41
#define DW_OP_lit18                 0x42
#define DW_OP_lit19                 0x43
#define DW_OP_lit20                 0x44
#define DW_OP_lit21                 0x45
#define DW_OP_lit22                 0x46
#define DW_OP_lit23                 0x47
#define DW_OP_lit24                 0x48
#define DW_OP_lit25                 0x49
#define DW_OP_lit26                 0x4A
#define DW_OP_lit27                 0x4B
#define DW_OP_lit28                 0x4C
#define DW_OP_lit29                 0x4D
#define DW_OP_lit30                 0x4E
#define DW_OP_lit31                 0x4F
#define DW_OP_reg0                  0x50
#define DW_OP_reg1                  0x51
#define DW_OP_reg2                  0x52
#define DW_OP_reg3                  0x53
#define DW_OP_reg4                  0x54
#define DW_OP_reg5                  0x55
#define DW_OP_reg6                  0x56
#define DW_OP_reg7                  0x57
#define DW_OP_reg8                  0x58
#define DW_OP_reg9                  0x59
#define DW_OP_reg10                 0x5A
#define DW_OP_reg11                 0x5B
#define DW_OP_reg12                 0x5C
#define DW_OP_reg13                 0x5D
#define DW_OP_reg14                 0x5E
#define DW_OP_reg15                 0x5F
#define DW_OP_reg16                 0x60
#define DW_OP_reg17                 0x61
#define DW_OP_reg18                 0x62
#define DW_OP_reg19                 0x63
#define DW_OP_reg20                 0x64
#define DW_OP_reg21                 0x65
#define DW_OP_reg22                 0x66
#define DW_OP_reg23                 0x67
#define DW_OP_reg24                 0x68
#define DW_OP_reg25                 0x69
#define DW_OP_reg26                 0x6A
#define DW_OP_reg27                 0x6B
#define DW_OP_reg28                 0x6C
#define DW_OP_reg29                 0x6D
#define DW_OP_reg30                 0x6E
#define DW_OP_reg31                 0x6F
#define DW_OP_breg0                 0x70
#define DW_OP_breg1                 0x71
#define DW_OP_breg2                 0x72
#define DW_OP_breg3                 0x73
#define DW_OP_breg4                 0x74
#define DW_OP_breg5                 0x75
#define DW_OP_breg6                 0x76
#define DW_OP_breg7                 0x77
#define DW_OP_breg8                 0x78
#define DW_OP_breg9                 0x79
#define DW_OP_breg10                0x7A
#define DW_OP_breg11                0x7B
#define DW_OP_breg12                0x7C
#define DW_OP_breg13                0x7D
#define DW_OP_breg14                0x7E
#define DW_OP_breg15                0x7F
#define DW_OP_breg16                0x80
#define DW_OP_breg17                0x81
#define DW_OP_breg18                0x82
#define DW_OP_breg19                0x83
#define DW_OP_breg20                0x84
#define DW_OP_breg21                0x85
#define DW_OP_breg22                0x86
#define DW_OP_breg23                0x87
#define DW_OP_breg24                0x88
#define DW_OP_breg25                0x89
#define DW_OP_breg26                0x8A
#define DW_OP_breg27                0x8B
#define DW_OP_breg28                0x8C
#define DW_OP_breg29                0x8D
#define DW_OP_breg30                0x8E
#define DW_OP_breg31                0x8F
#define DW_OP_regx                  0x90
#define DW_OP_fbreg                 0x91
#define DW_OP_bregx                 0x92
#define DW_OP_piece                 0x93
#define DW_OP_deref_size            0x94
#define DW_OP_xderef_size           0x95
#define DW_OP_nop                   0x96
#define DW_OP_push_object_addres    0x97
#define DW_OP_call2                 0x98
#define DW_OP_call4                 0x99
#define DW_OP_call_ref              0x9A
#define DW_OP_form_tls_address      0x9B
#define DW_OP_call_frame_cfa        0x9C
#define DW_OP_bit_piece             0x9D
#define DW_OP_implicit_value        0x9E
#define DW_OP_stack_value           0x9F
#define DW_OP_lo_user               0xE0
#define DW_OP_hi_user               0xFF


// -----------------------------------------------------------------------------
// Tags (Section 7.5.4)
// -----------------------------------------------------------------------------

#define DW_TAG_array_type                  0x01
#define DW_TAG_class_type                  0x02
#define DW_TAG_entry_point                 0x03
#define DW_TAG_enumeration_type            0x04
#define DW_TAG_formal_parameter            0x05
#define DW_TAG_imported_declaration        0x08
#define DW_TAG_label                       0x0a
#define DW_TAG_lexical_block               0x0b
#define DW_TAG_member                      0x0d
#define DW_TAG_pointer_type                0x0f
#define DW_TAG_reference_type              0x10
#define DW_TAG_compile_unit                0x11
#define DW_TAG_string_type                 0x12
#define DW_TAG_structure_type              0x13
#define DW_TAG_subroutine_type             0x15
#define DW_TAG_typedef                     0x16
#define DW_TAG_union_type                  0x17
#define DW_TAG_unspecified_parameters      0x18
#define DW_TAG_variant                     0x19
#define DW_TAG_common_block                0x1a
#define DW_TAG_common_inclusion            0x1b
#define DW_TAG_inheritance                 0x1c
#define DW_TAG_inlined_subroutine          0x1d
#define DW_TAG_module                      0x1e
#define DW_TAG_ptr_to_member_type          0x1f
#define DW_TAG_set_type                    0x20
#define DW_TAG_subrange_type               0x21
#define DW_TAG_with_stmt                   0x22
#define DW_TAG_access_declaration          0x23
#define DW_TAG_base_type                   0x24
#define DW_TAG_catch_block                 0x25
#define DW_TAG_const_type                  0x26
#define DW_TAG_constant                    0x27
#define DW_TAG_enumerator                  0x28
#define DW_TAG_file_type                   0x29
#define DW_TAG_friend                      0x2a
#define DW_TAG_namelist                    0x2b
#define DW_TAG_namelist_item               0x2c
#define DW_TAG_packed_type                 0x2d
#define DW_TAG_subprogram                  0x2e
#define DW_TAG_template_type_parameter     0x2f
#define DW_TAG_template_value_parameter    0x30
#define DW_TAG_thrown_type                 0x31
#define DW_TAG_try_block                   0x32
#define DW_TAG_variant_part                0x33
#define DW_TAG_variable                    0x34
#define DW_TAG_volatile_type               0x35
#define DW_TAG_dwarf_procedure             0x36
#define DW_TAG_restrict_type               0x37
#define DW_TAG_interface_type              0x38
#define DW_TAG_namespace                   0x39
#define DW_TAG_imported_module             0x3a
#define DW_TAG_unspecified_type            0x3b
#define DW_TAG_partial_unit                0x3c
#define DW_TAG_imported_unit               0x3d
/* 0x3e reserved.  */
#define DW_TAG_condition                   0x3f
#define DW_TAG_shared_type                 0x40
#define DW_TAG_type_unit                   0x41
#define DW_TAG_rvalue_reference_type       0x42
#define DW_TAG_template_alias              0x43

/* DWARF 5.  */
#define DW_TAG_atomic_type                 0x47

#define DW_TAG_lo_user                     0x4080

#define DW_TAG_MIPS_loop                   0x4081
#define DW_TAG_format_label                0x4101
#define DW_TAG_function_template           0x4102
#define DW_TAG_class_template              0x4103

#define DW_TAG_GNU_BINCL                   0x4104
#define DW_TAG_GNU_EINCL                   0x4105

#define DW_TAG_GNU_template_template_param 0x4106
#define DW_TAG_GNU_template_parameter_pack 0x4107
#define DW_TAG_GNU_formal_parameter_pack   0x4108
#define DW_TAG_GNU_call_site               0x4109
#define DW_TAG_GNU_call_site_parameter     0x410a

#define DW_TAG_hi_user                     0xffff

// -----------------------------------------------------------------------------
// Children Determination (Section 7.5.4)
// -----------------------------------------------------------------------------

#define DW_CHILDREN_no  0
#define DW_CHILDREN_yes 1

// -----------------------------------------------------------------------------
// Attribute Encodings (Section 7.5.4)
// -----------------------------------------------------------------------------

#define DW_AT_sibling                          0x01
#define DW_AT_location                         0x02
#define DW_AT_name                             0x03
#define DW_AT_ordering                         0x09
#define DW_AT_subscr_data                      0x0a
#define DW_AT_byte_size                        0x0b
#define DW_AT_bit_offset                       0x0c
#define DW_AT_bit_size                         0x0d
#define DW_AT_element_list                     0x0f
#define DW_AT_stmt_list                        0x10
#define DW_AT_low_pc                           0x11
#define DW_AT_high_pc                          0x12
#define DW_AT_language                         0x13
#define DW_AT_member                           0x14
#define DW_AT_discr                            0x15
#define DW_AT_discr_value                      0x16
#define DW_AT_visibility                       0x17
#define DW_AT_import                           0x18
#define DW_AT_string_length                    0x19
#define DW_AT_common_reference                 0x1a
#define DW_AT_comp_dir                         0x1b
#define DW_AT_const_value                      0x1c
#define DW_AT_containing_type                  0x1d
#define DW_AT_default_value                    0x1e
#define DW_AT_inline                           0x20
#define DW_AT_is_optional                      0x21
#define DW_AT_lower_bound                      0x22
#define DW_AT_producer                         0x25
#define DW_AT_prototyped                       0x27
#define DW_AT_return_addr                      0x2a
#define DW_AT_start_scope                      0x2c
#define DW_AT_bit_stride                       0x2e
#define DW_AT_upper_bound                      0x2f
#define DW_AT_abstract_origin                  0x31
#define DW_AT_accessibility                    0x32
#define DW_AT_address_class                    0x33
#define DW_AT_artificial                       0x34
#define DW_AT_base_types                       0x35
#define DW_AT_calling_convention               0x36
#define DW_AT_count                            0x37
#define DW_AT_data_member_location             0x38
#define DW_AT_decl_column                      0x39
#define DW_AT_decl_file                        0x3a
#define DW_AT_decl_line                        0x3b
#define DW_AT_declaration                      0x3c
#define DW_AT_discr_list                       0x3d
#define DW_AT_encoding                         0x3e
#define DW_AT_external                         0x3f
#define DW_AT_frame_base                       0x40
#define DW_AT_friend                           0x41
#define DW_AT_identifier_case                  0x42
#define DW_AT_macro_info                       0x43
#define DW_AT_namelist_item                    0x44
#define DW_AT_priority                         0x45
#define DW_AT_segment                          0x46
#define DW_AT_specification                    0x47
#define DW_AT_static_link                      0x48
#define DW_AT_type                             0x49
#define DW_AT_use_location                     0x4a
#define DW_AT_variable_parameter               0x4b
#define DW_AT_virtuality                       0x4c
#define DW_AT_vtable_elem_location             0x4d
#define DW_AT_allocated                        0x4e
#define DW_AT_associated                       0x4f
#define DW_AT_data_location                    0x50
#define DW_AT_byte_stride                      0x51
#define DW_AT_entry_pc                         0x52
#define DW_AT_use_UTF8                         0x53
#define DW_AT_extension                        0x54
#define DW_AT_ranges                           0x55
#define DW_AT_trampoline                       0x56
#define DW_AT_call_column                      0x57
#define DW_AT_call_file                        0x58
#define DW_AT_call_line                        0x59
#define DW_AT_description                      0x5a
#define DW_AT_binary_scale                     0x5b
#define DW_AT_decimal_scale                    0x5c
#define DW_AT_small                            0x5d
#define DW_AT_decimal_sign                     0x5e
#define DW_AT_digit_count                      0x5f
#define DW_AT_picture_string                   0x60
#define DW_AT_mutable                          0x61
#define DW_AT_threads_scaled                   0x62
#define DW_AT_explicit                         0x63
#define DW_AT_object_pointer                   0x64
#define DW_AT_endianity                        0x65
#define DW_AT_elemental                        0x66
#define DW_AT_pure                             0x67
#define DW_AT_recursive                        0x68
#define DW_AT_signature                        0x69
#define DW_AT_main_subprogram                  0x6a
#define DW_AT_data_bit_offset                  0x6b
#define DW_AT_const_expr                       0x6c
#define DW_AT_enum_class                       0x6d
#define DW_AT_linkage_name                     0x6e

/* DWARF5 attribute values.  */
#define DW_AT_noreturn                         0x87

#define DW_AT_lo_user                          0x2000

#define DW_AT_MIPS_fde                         0x2001
#define DW_AT_MIPS_loop_begin                  0x2002
#define DW_AT_MIPS_tail_loop_begin             0x2003
#define DW_AT_MIPS_epilog_begin                0x2004
#define DW_AT_MIPS_loop_unroll_factor          0x2005
#define DW_AT_MIPS_software_pipeline_depth     0x2006
#define DW_AT_MIPS_linkage_name                0x2007
#define DW_AT_MIPS_stride                      0x2008
#define DW_AT_MIPS_abstract_name               0x2009
#define DW_AT_MIPS_clone_origin                0x200a
#define DW_AT_MIPS_has_inlines                 0x200b
#define DW_AT_MIPS_stride_byte                 0x200c
#define DW_AT_MIPS_stride_elem                 0x200d
#define DW_AT_MIPS_ptr_dopetype                0x200e
#define DW_AT_MIPS_allocatable_dopetype        0x200f
#define DW_AT_MIPS_assumed_shape_dopetype      0x2010
#define DW_AT_MIPS_assumed_size                0x2011

/* GNU extensions.  */
#define DW_AT_sf_names                         0x2101
#define DW_AT_src_info                         0x2102
#define DW_AT_mac_info                         0x2103
#define DW_AT_src_coords                       0x2104
#define DW_AT_body_begin                       0x2105
#define DW_AT_body_end                         0x2106
#define DW_AT_GNU_vector                       0x2107
#define DW_AT_GNU_guarded_by                   0x2108
#define DW_AT_GNU_pt_guarded_by                0x2109
#define DW_AT_GNU_guarded                      0x210a
#define DW_AT_GNU_pt_guarded                   0x210b
#define DW_AT_GNU_locks_excluded               0x210c
#define DW_AT_GNU_exclusive_locks_required     0x210d
#define DW_AT_GNU_shared_locks_required        0x210e
#define DW_AT_GNU_odr_signature                0x210f
#define DW_AT_GNU_template_name                0x2110
#define DW_AT_GNU_call_site_value              0x2111
#define DW_AT_GNU_call_site_data_value         0x2112
#define DW_AT_GNU_call_site_target             0x2113
#define DW_AT_GNU_call_site_target_clobbered   0x2114
#define DW_AT_GNU_tail_call                    0x2115
#define DW_AT_GNU_all_tail_call_sites          0x2116
#define DW_AT_GNU_all_call_sites               0x2117
#define DW_AT_GNU_all_source_call_sites        0x2118
#define DW_AT_GNU_macros                       0x2119
#define DW_AT_GNU_deleted                      0x211a

#define DW_AT_hi_user                          0x3fff

// -----------------------------------------------------------------------------
// Form Encodings (Section 7.5.4)
// -----------------------------------------------------------------------------

#define DW_FORM_addr         0x01
#define DW_FORM_block2       0x03
#define DW_FORM_block4       0x04
#define DW_FORM_data2        0x05
#define DW_FORM_data4        0x06
#define DW_FORM_data8        0x07
#define DW_FORM_string       0x08
#define DW_FORM_block        0x09
#define DW_FORM_block1       0x0a
#define DW_FORM_data1        0x0b
#define DW_FORM_flag         0x0c
#define DW_FORM_sdata        0x0d
#define DW_FORM_strp         0x0e
#define DW_FORM_udata        0x0f
#define DW_FORM_ref_addr     0x10
#define DW_FORM_ref1         0x11
#define DW_FORM_ref2         0x12
#define DW_FORM_ref4         0x13
#define DW_FORM_ref8         0x14
#define DW_FORM_ref_udata    0x15
#define DW_FORM_indirect     0x16
#define DW_FORM_sec_offset   0x17
#define DW_FORM_exprloc      0x18
#define DW_FORM_flag_present 0x19
#define DW_FORM_ref_sig8     0x20

#define DW_FORM_GNU_ref_alt  0x1f20
#define DW_FORM_GNU_strp_alt 0x1f21

// -----------------------------------------------------------------------------
// DWARF Class
// -----------------------------------------------------------------------------

class dwarf4
{
public:

    /// Decode Signed LEB128
    ///
    /// Decodes a signed LEB128 compressed number that is stored at addr, and
    /// more addr forward by the number of bytes that were used to store the
    /// compressed number (which varies).
    ///
    /// @param addr the address of the compressed number
    /// @return the resulting decompressed number.
    ///
    static int64_t decode_sleb128(char **addr);

    /// Decode Unsigned LEB128
    ///
    /// Decodes a unsigned LEB128 compressed number that is stored at addr, and
    /// more addr forward by the number of bytes that were used to store the
    /// compressed number (which varies).
    ///
    /// @param addr the address of the compressed number
    /// @return the resulting decompressed number.
    ///
    static uint64_t decode_uleb128(char **addr);

    /// Unwind the Stack
    ///
    /// Given information stored in a Frame Description Entry (FDE), and
    /// the current state of the register, this function unwinds the stack,
    /// storing the resulting instruction pointer, stack pointer, and restored
    /// register state, back into the state variable. If this FDE describes
    /// the CFA that contains the "catch" block that we care about, this new
    /// state can be used to "jump" back.
    ///
    /// @param fde the FDE that describes the CFA pointed to in the state
    /// @param state the current state of the registers
    ///
    static void unwind(const fd_entry &fde, register_state *state = nullptr);

    /// Find a function name given an address
    ///
    /// Given pointers to relevant .debug_* sections, this function will walk
    /// through the DIEs in .debug_info, with format information stored in
    /// .debug_abbrev, and return a string either in .debug_str or .debug_info
    /// that corresponds to the address given by `addr`.
    ///
    /// @param debug_info the address of .debug_info
    /// @param debug_info_len the size of .debug_info
    /// @param debug_abbrev the address of .debug_abbrev
    /// @param debug_str the address of .debug_str
    /// @param addr the pre-ASLR offset of the instruction address you wish to
    ///             associate to a function name
    ///
    /// @return a nonzero pointer if a name was found and `nullptr` otherwise
    static const char *find_function_name(
        void *debug_info, uint64_t debug_info_len, void *debug_abbrev, void *debug_str, uint64_t addr);
};

#endif
