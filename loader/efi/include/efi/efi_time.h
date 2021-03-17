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

#ifndef EFI_TIME_H
#define EFI_TIME_H

/**
 * @struct EFI_TIME
 *
 * <!-- description -->
 *   @brief Defines the layout of the EFI_TIME struct:
 *     https://uefi.org/sites/default/files/resources/UEFI_Spec_2_8_final.pdf
 */
typedef struct
{
    /**
     * @brief The current local date.
     */
    UINT16 Year;

    /**
     * @brief The current local date.
     */
    UINT8 Month;

    /**
     * @brief The current local date.
     */
    UINT8 Day;

    /**
     * @brief The current local time. Nanoseconds report the current
     *   fraction of a second in the device. The format of the time is
     *   hh:mm:ss.nnnnnnnnn. A battery backed real time clock device
     *   maintains the date and time.
     */
    UINT8 Hour;

    /**
     * @brief The current local time. Nanoseconds report the current
     *   fraction of a second in the device. The format of the time is
     *   hh:mm:ss.nnnnnnnnn. A battery backed real time clock device
     *   maintains the date and time.
     */
    UINT8 Minute;

    /**
     * @brief The current local time. Nanoseconds report the current
     *   fraction of a second in the device. The format of the time is
     *   hh:mm:ss.nnnnnnnnn. A battery backed real time clock device
     *   maintains the date and time.
     */
    UINT8 Second;

    /**
     * @brief n/a
     */
    UINT8 Pad1;

    /**
     * @brief The current local time. Nanoseconds report the current
     *   fraction of a second in the device. The format of the time is
     *   hh:mm:ss.nnnnnnnnn. A battery backed real time clock device
     *   maintains the date and time.
     */
    UINT32 Nanosecond;

    /**
     * @brief The time's offset in minutes from UTC. If the value is
     *   EFI_UNSPECIFIED_TIMEZONE, then the time is interpreted as a
     *   local time. The TimeZone is the number of minutes that the
     *   local time is relative to UTC. To calculate the TimeZone value,
     *   follow this equation: Localtime = UTC - TimeZone.
     */
    INT16 TimeZone;

    /**
     * @brief A bitmask containing the daylight savings time information for
     *   the time.
     */
    UINT8 Daylight;

    /**
     * @brief n/a
     */
    UINT8 Pad2;

} EFI_TIME;

#endif
