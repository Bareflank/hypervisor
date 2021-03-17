/**
 * @copyright
 * Copyright (C) 2020 Assured Information Security, Inc.
 *
 * @copyright
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * @copyright
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * @copyright
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#ifndef EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL_H
#define EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL_H

#include "efi_simple_text_output_mode.h"
#include "efi_status.h"
#include "efi_types.h"

/** @brief prototype for _EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL */
struct _EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL;

/** @brief prototype for EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL */
typedef struct _EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL;

/**
 * <!-- description -->
 *   @brief The Reset() function resets the text output device hardware. The
 *     cursor position is set to (0, 0), and the screen is cleared to the
 *     default background color for the output device.
 *
 *     As part of initialization process, the firmware/device will make a
 *     quick but reasonable attempt to verify that the device is functioning.
 *     If the ExtendedVerification flag is TRUE the firmware may take an
 *     extended amount of time to verify the device is operating on reset.
 *     Otherwise the reset operation is to occur as quickly as possible.
 *
 *     The hardware verification process is not defined by this specification
 *     and is left up to the platform firmware or driver to implement.
 *
 * <!-- inputs/outputs -->
 *   @param This A pointer to the EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL instance.
 *   @param ExtendedVerification Indicates that the driver may perform a more
 *     exhaustive verification operation of the device during reset.
 *   @return Returns an EFI_STATUS
 */
typedef EFI_STATUS(EFIAPI *EFI_TEXT_RESET)(
    IN EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *This, IN BOOLEAN ExtendedVerification);

/**
 * <!-- description -->
 *   @brief Writes a string to the output device.
 *
 * <!-- inputs/outputs -->
 *   @param This A pointer to the EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL instance.
 *   @param String The Null-terminated string to be displayed on the output
 *     device(s). All output devices must also support the Unicode drawing
 *     character codes defined in “Related Definitions.
 *   @return Returns an EFI_STATUS
 */
typedef EFI_STATUS(EFIAPI *EFI_TEXT_STRING)(
    IN EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *This, IN CHAR16 *String);

/**
 * <!-- description -->
 *   @brief Verifies that all characters in a string can be output to the
 *     target device.
 *
 * <!-- inputs/outputs -->
 *   @param This A pointer to the EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL instance.
 *   @param String The Null-terminated string to be examined for the output
 *     device(s).
 *   @return Returns an EFI_STATUS
 */
typedef EFI_STATUS(EFIAPI *EFI_TEXT_TEST_STRING)(
    IN EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *This, IN CHAR16 *String);

/**
 * <!-- description -->
 *   @brief Returns information for an available text mode that the output
 *     device(s) supports.
 *
 * <!-- inputs/outputs -->
 *   @param This A pointer to the EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL instance.
 *   @param ModeNumber The mode number to return information on.
 *   @param Columns Returns the geometry of the text output device for the
 *     request ModeNumber.
 *   @param Rows Returns the geometry of the text output device for the
 *     request ModeNumber.
 *   @return Returns an EFI_STATUS
 */
typedef EFI_STATUS(EFIAPI *EFI_TEXT_QUERY_MODE)(
    IN EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *This,
    IN UINTN ModeNumber,
    OUT UINTN *Columns,
    OUT UINTN *Rows);

/**
 * <!-- description -->
 *   @brief Sets the output device(s) to a specified mode.
 *
 * <!-- inputs/outputs -->
 *   @param This A pointer to the EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL instance.
 *   @param ModeNumber The text mode to set.
 *   @return Returns an EFI_STATUS
 */
typedef EFI_STATUS (*EFIAPI EFI_TEXT_SET_MODE)(
    IN EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *This, IN UINTN ModeNumber);

/**
 * <!-- description -->
 *   @brief Sets the background and foreground colors for theOutputString()
 *     and ClearScreen() functions.
 *
 * <!-- inputs/outputs -->
 *   @param This A pointer to the EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL instance.
 *   @param Attribute The attribute to set. Bits 0..3 are the foreground color,
 *     and bits 4..6 are the background color. All other bits are reserved.
 *     See “Related Definitions” below.
 *   @return Returns an EFI_STATUS
 */
typedef EFI_STATUS(EFIAPI *EFI_TEXT_SET_ATTRIBUTE)(
    IN EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *This, IN UINTN Attribute);

/**
 * <!-- description -->
 *   @brief Clears the output device(s) display to the currently selected
 *     background color.
 *
 * <!-- inputs/outputs -->
 *   @param This A pointer to the EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL instance.
 *   @return Returns an EFI_STATUS
 */
typedef EFI_STATUS(EFIAPI *EFI_TEXT_CLEAR_SCREEN)(IN EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *This);

/**
 * <!-- description -->
 *   @brief Sets the current coordinates of the cursor position.
 *
 * <!-- inputs/outputs -->
 *   @param This A pointer to the EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL instance.
 *   @param Column The position to set the cursor to. Must greater than or
 *     equal to zero and less than the number of columns and rows returned
 *     by QueryMode().
 *   @param Row The position to set the cursor to. Must greater than or
 *     equal to zero and less than the number of columns and rows returned
 *     by QueryMode().
 *   @return Returns an EFI_STATUS
 */
typedef EFI_STATUS(EFIAPI *EFI_TEXT_SET_CURSOR_POSITION)(
    IN EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *This, IN UINTN Column, IN UINTN Row);

/**
 * <!-- description -->
 *   @brief Makes the cursor visible or invisible.
 *
 * <!-- inputs/outputs -->
 *   @param This A pointer to the EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL instance.
 *   @param Visible If TRUE, the cursor is set to be visible. If FALSE, the
 *     cursor is set to be invisible.
 *   @return Returns an EFI_STATUS
 */
typedef EFI_STATUS(EFIAPI *EFI_TEXT_ENABLE_CURSOR)(
    IN EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *This, IN BOOLEAN Visible);

/**
 * @struct EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL
 *
 * <!-- description -->
 *   @brief Defines the layout of the EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL struct:
 *     https://uefi.org/sites/default/files/resources/UEFI_Spec_2_8_final.pdf
 */
typedef struct _EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL
{
    /**
     * @brief Reset the ConsoleOut device. See Reset().
     */
    EFI_TEXT_RESET Reset;

    /**
     * @brief Displays the string on the device at the current cursor location.
     *   See OutputString().
     */
    EFI_TEXT_STRING OutputString;

    /**
     * @brief Tests to see if the ConsoleOut device supports this string. See
     *   TestString().
     */
    EFI_TEXT_TEST_STRING TestString;

    /**
     * @brief Queries information concerning the output device’s supported text
     *   mode. See QueryMode().
     */
    EFI_TEXT_QUERY_MODE QueryMode;

    /**
     * @brief Sets the current mode of the output device. See SetMode().
     */
    EFI_TEXT_SET_MODE SetMode;

    /**
     * @brief Sets the foreground and background color of the text that is
     *   output. See SetAttribute().
     */
    EFI_TEXT_SET_ATTRIBUTE SetAttribute;

    /**
     * @brief Clears the screen with the currently set background color. See
     *   ClearScreen().
     */
    EFI_TEXT_CLEAR_SCREEN ClearScreen;

    /**
     * @brief Sets the current cursor position. See SetCursorPosition().
     */
    EFI_TEXT_SET_CURSOR_POSITION SetCursorPosition;

    /**
     * @brief Turns the visibility of the cursor on/off. See EnableCursor().
     */
    EFI_TEXT_ENABLE_CURSOR EnableCursor;

    /**
     * @brief Pointer to SIMPLE_TEXT_OUTPUT_MODE data.
     */
    SIMPLE_TEXT_OUTPUT_MODE *Mode;

} EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL;

#endif
