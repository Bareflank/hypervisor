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

#ifndef EFI_MP_SERVICES_PROTOCOL_H
#define EFI_MP_SERVICES_PROTOCOL_H

#include "efi_processor_information.h"
#include "efi_types.h"

/** @brief defines the GUID for EFI_MP_SERVICES_PROTOCOL_GUID */
#define EFI_MP_SERVICES_PROTOCOL_GUID                                                              \
    {                                                                                              \
        0x3fdda605, 0xa76e, 0x4f46,                                                                \
        {                                                                                          \
            0xad, 0x29, 0x12, 0xf4, 0x53, 0x1b, 0x3d, 0x08                                         \
        }                                                                                          \
    }

/** @brief prototype for _EFI_MP_SERVICES_PROTOCOL */
struct _EFI_MP_SERVICES_PROTOCOL;

/** @brief prototype for EFI_MP_SERVICES_PROTOCOL */
typedef struct _EFI_MP_SERVICES_PROTOCOL EFI_MP_SERVICES_PROTOCOL;

/**
 * <!-- description -->
 *   @brief This service retrieves the number of logical processor in the
 *     platform and the number of those logical processors that are currently
 *     enabled. This service may only be called from the BSP.
 *
 * <!-- inputs/outputs -->
 *   @param This A pointer to the EFI_MP_SERVICES_PROTOCOL instance.
 *   @param NumberOfProcessors Pointer to the total number of logical
 *     processors in the system, including the BSP and all enabled and
 *     disabled APs.
 *   @param NumberOfEnabledProcessors Pointer to the number of logical
 *     processors in the platform including the BSP that are currently
 *     enabled.
 *   @return Returns an EFI_STATUS
 */
typedef EFI_STATUS(EFIAPI *EFI_MP_SERVICES_GET_NUMBER_OF_PROCESSORS)(
    IN EFI_MP_SERVICES_PROTOCOL *This,
    OUT UINTN *NumberOfProcessors,
    OUT UINTN *NumberOfEnabledProcessors);

/**
 * <!-- description -->
 *   @brief Gets detailed MP-related information on the requested processor at
 *     the instant this call is made. This service may only be called from
 *     the BSP.
 *
 * <!-- inputs/outputs -->
 *   @param This A pointer to the EFI_MP_SERVICES_PROTOCOL instance.
 *   @param ProcessorNumber The handle number of processor. The range is from
 *     0 to the total number of logical processors minus 1. The total number
 *     of logical processors can be retrieved by
 *     EFI_MP_SERVICES_PROTOCOL.GetNumberOfProcessors().
 *   @param ProcessorInfoBuffer A pointer to the buffer where information for
 *     the requested processor is deposited. The buffer is allocated by the
 *     caller.
 *   @return Returns an EFI_STATUS
 */
typedef EFI_STATUS(EFIAPI *EFI_MP_SERVICES_GET_PROCESSOR_INFO)(
    IN EFI_MP_SERVICES_PROTOCOL *This,
    IN UINTN ProcessorNumber,
    OUT EFI_PROCESSOR_INFORMATION *ProcessorInfoBuffer);

/** Defined in EFI_MP_SERVICES_PROTOCOL.StartupAllAPs() */
#define END_OF_CPU_LIST 0xffffffff

/**
 * <!-- description -->
 *   @brief Defined in EFI_MP_SERVICES_PROTOCOL.StartupAllAPs()
 *
 * <!-- inputs/outputs -->
 *   @param ProcedureArgument Pointer to the procedure’s argument
 */
typedef VOID(EFIAPI *EFI_AP_PROCEDURE)(IN VOID *ProcedureArgument);

/**
 * <!-- description -->
 *   @brief This service executes a caller provided function on all enabled
 *     APs. APs can run either simultaneously or one at a time in sequence.
 *     This service supports both blocking and non-blocking requests. The
 *     non-blocking requests use EFI events so the BSP can detect when the
 *     APs have finished.
 *
 * <!-- inputs/outputs -->
 *   @param This A pointer to the EFI_MP_SERVICES_PROTOCOL instance.
 *   @param Procedure A pointer to the function to be run on enabled APs of the
 *     system.
 *   @param SingleThread If TRUE, then all the enabled APs execute the function
 *     specified by Procedure one by one, in ascending order of processor
 *     handle number. If FALSE, then all the enabled APs execute the function
 *     specified by Procedure simultaneously.
 *   @param WaitEvent The event created by the caller with CreateEvent()
 *     service. If it is NULL, then execute in blocking mode. BSP waits until
 *     all APs finish or TimeoutInMicroSeconds expires. If it’s not NULL, then
 *     execute in non-blocking mode. BSP requests the function specified by
 *     Procedure to be started on all the enabled APs, and go on executing
 *     immediately. If all return from Procedure or TimeoutInMicroSeconds
 *     expires, this event is signaled. The BSP can use the CheckEvent() or
 *     WaitForEvent() services to check the state of event. Type EFI_EVENT is
 *     defined in CreateEvent() in the Unified Extensible Firmware Interface
 *     Specification (Version 2.0).
 *   @param TimeoutInMicroSeconds Indicates the time limit in microseconds for
 *     APs to return from Procedure, either for blocking or non-blocking mode.
 *     Zero means infinity. If the timeout expires before all APs return from
 *     Procedure, then Procedure on the failed APs is terminated. All enabled
 *     APs are available for next function assigned by
 *     EFI_MP_SERVICES_PROTOCOL.StartupAllAPs() or
 *     EFI_MP_SERVICES_PROTOCOL.StartupThisAP(). If the timeout expires in
 *     blocking mode, BSP returns EFI_TIMEOUT. If the timeout expires in
 *     non-blocking mode, WaitEvent is signaled with SignalEvent().
 *   @param ProcedureArgument The parameter passed into Procedure for all APs.
 *   @param FailedCpuList If NULL, this parameter is ignored. Otherwise, if all
 *     APs finish successfully, then its content is set to NULL. If not all APs
 *     finish before timeout expires, then its content is set to address of the
 *     buffer holding handle numbers of the failed APs. The buffer is allocated
 *     by MP Service Protocol, and it’s the caller’s responsibility to free the
 *     buffer with FreePool() service. In blocking mode, it is ready for
 *     consumption when the call returns. In non-blocking mode, it is ready
 *     when WaitEvent is signaled. The list of failed CPU is terminated by
 *     END_OF_CPU_LIST.
 *   @return Returns an EFI_STATUS
 */
typedef EFI_STATUS(EFIAPI *EFI_MP_SERVICES_STARTUP_ALL_APS)(
    IN EFI_MP_SERVICES_PROTOCOL *This,
    IN EFI_AP_PROCEDURE Procedure,
    IN BOOLEAN SingleThread,
    IN EFI_EVENT WaitEvent OPTIONAL,
    IN UINTN TimeoutInMicroSeconds,
    IN VOID *ProcedureArgument OPTIONAL,
    OUT UINTN **FailedCpuList OPTIONAL);

/**
 * <!-- description -->
 *   @brief This service lets the caller get one enabled AP to execute a
 *     caller-provided function. The caller can request the BSP to either wait
 *     for the completion of the AP or just proceed with the next task by using
 *     the EFI event mechanism.
 *
 * <!-- inputs/outputs -->
 *   @param This A pointer to the EFI_MP_SERVICES_PROTOCOL instance.
 *   @param Procedure A pointer to the function to be run on the designated AP.
 *     Type EFI_AP_PROCEDURE is defined in
 *     EFI_MP_SERVICES_PROTOCOL.StartupAllAPs().
 *   @param ProcessorNumber The handle number of the AP. The range is from 0
 *     to the total number of logical processors minus 1. The total number of
 *     logical processors can be retrieved by
 *     EFI_MP_SERVICES_PROTOCOL.GetNumberOfProcessors().
 *   @param WaitEvent The event created by the caller with CreateEvent()
 *     service. If it is NULL, then execute in blocking mode. BSP waits until
 *     this AP finishes or TimeoutInMicroSeconds expires. If it’s not NULL,
 *     then execute in non-blocking mode. BSP requests the function specified
 *     by Procedure to be started on the AP, and go on executing immediately.
 *     If this AP finishes or TimeoutInMicroSeconds expires, this event is
 *     signaled. BSP can use the CheckEvent() and WaitForEvent() services to
 *     check the state of event. Type EFI_EVENT is defined in CreateEvent() in
 *     the Unified Extensible Firmware Interface Specification (Version 2.0)
 *   @param TimeoutInMicroseconds Indicates the time limit in microseconds
 *     for this AP to finish the function, either for blocking or non-blocking
 *     mode. Zero means infinity. If the timeout expires before this AP returns
 *     from Procedure, then Procedure on the AP is terminated. The AP is
 *     available for subsequent calls to
 *     EFI_MP_SERVICES_PROTOCOL.StartupAllAPs() and
 *     EFI_MP_SERVICES_PROTOCOL.StartupThisAP(). If the timeout expires in
 *     blocking mode, BSP returns EFI_TIMEOUT. If the timeout expires in
 *     non-blocking mode, WaitEvent is signaled with SignalEvent().
 *   @param ProcedureArgument The parameter passed into Procedure on the
 *     specified AP.
 *   @param Finished If NULL, this parameter is ignored. In blocking mode, this
 *     parameter is ignored. In non-blocking mode, if AP returns from Procedure
 *     before the timeout expires, its content is set to TRUE. Otherwise, the
 *     value is set to FALSE. The caller can determine if the AP returned from
 *     Procedure by evaluating this value.
 *   @return Returns an EFI_STATUS
 */
typedef EFI_STATUS(EFIAPI *EFI_MP_SERVICES_STARTUP_THIS_AP)(
    IN EFI_MP_SERVICES_PROTOCOL *This,
    IN EFI_AP_PROCEDURE Procedure,
    IN UINTN ProcessorNumber,
    IN EFI_EVENT WaitEvent OPTIONAL,
    IN UINTN TimeoutInMicroseconds,
    IN VOID *ProcedureArgument OPTIONAL,
    OUT BOOLEAN *Finished OPTIONAL);

/**
 * <!-- description -->
 *   @brief This service switches the requested AP to be the BSP from that
 *     point onward. This service changes the BSP for all purposes. This
 *     service may only be called from the current BSP.
 *
 * <!-- inputs/outputs -->
 *   @param This A pointer to the EFI_MP_SERVICES_PROTOCOL instance.
 *   @param ProcessorNumber The handle number of AP that is to become the new
 *     BSP. The range is from 0 to the total number of logical processors
 *     minus 1. The total number of logical processors can be retrieved by
 *     EFI_MP_SERVICES_PROTOCOL.GetNumberOfProcessors().
 *   @param EnableOldBSP If TRUE, then the old BSP will be listed as an enabled
 *     AP. Otherwise, it will be disabled.
 *   @return Returns an EFI_STATUS
 */
typedef EFI_STATUS(EFIAPI *EFI_MP_SERVICES_SWITCH_BSP)(
    IN EFI_MP_SERVICES_PROTOCOL *This, IN UINTN ProcessorNumber, IN BOOLEAN EnableOldBSP);

/**
 * <!-- description -->
 *   @brief This service lets the caller enable or disable an AP from this
 *     point onward. This service may only be called from the BSP.
 *
 * <!-- inputs/outputs -->
 *   @param This A pointer to the EFI_MP_SERVICES_PROTOCOL instance.
 *   @param ProcessorNumber The handle number of AP. The range is from 0 to
 *     the total number of logical processors minus 1. The total number of
 *     logical processors can be retrieved by
 *     EFI_MP_SERVICES_PROTOCOL.GetNumberOfProcessors().
 *   @param EnableAP Specifies the new state for the processor specified by
 *     ProcessorNumber. TRUE for enabled, FALSE for disabled.
 *   @param HealthFlag If not NULL, a pointer to a value that specifies the new
 *     health status of the AP. This flag corresponds to StatusFlag defined in
 *     EFI_MP_SERVICES_PROTOCOL.GetProcessorInfo(). Only the
 *     PROCESSOR_HEALTH_STATUS_BIT is used. All other bits are ignored. If it
 *     is NULL, this parameter is ignored.
 *   @return Returns an EFI_STATUS
 */
typedef EFI_STATUS(EFIAPI *EFI_MP_SERVICES_ENABLEDISABLEAP)(
    IN EFI_MP_SERVICES_PROTOCOL *This,
    IN UINTN ProcessorNumber,
    IN BOOLEAN EnableAP,
    IN UINT32 *HealthFlag OPTIONAL);

/**
 * <!-- description -->
 *   @brief This return the handle number for the calling processor. This
 *     service may be called from the BSP and APs.
 *
 * <!-- inputs/outputs -->
 *   @param This A pointer to the EFI_MP_SERVICES_PROTOCOL instance.
 *   @param ProcessorNumber Pointer to the handle number of AP. The range is
 *     from 0 to the total number of logical processors minus 1. The total
 *     number of logical processors can be retrieved by
 *     EFI_MP_SERVICES_PROTOCOL.GetNumberOfProcessors().
 *   @return Returns an EFI_STATUS
 */
typedef EFI_STATUS(EFIAPI *EFI_MP_SERVICES_WHOAMI)(
    IN EFI_MP_SERVICES_PROTOCOL *This, OUT UINTN *ProcessorNumber);

/**
 * @struct EFI_MP_SERVICES_PROTOCOL
 *
 * <!-- description -->
 *   @brief Defines the layout of the EFI_MP_SERVICES_PROTOCOL struct:
 *     https://uefi.org/sites/default/files/resources/PI_Spec_1_7_A_final_May1.pdf
 */
typedef struct _EFI_MP_SERVICES_PROTOCOL
{
    /**
     * @brief Gets the number of logical processors and the number of enabled
     *   logical processors in the system.
     */
    EFI_MP_SERVICES_GET_NUMBER_OF_PROCESSORS GetNumberOfProcessors;

    /**
     * @brief Gets detailed information on the requested processor at the
     *   instant this call is made.
     */
    EFI_MP_SERVICES_GET_PROCESSOR_INFO GetProcessorInfo;

    /**
     * @brief Starts up all the enabled APs in the system to run the function
     *   provided by the caller.
     */
    EFI_MP_SERVICES_STARTUP_ALL_APS StartupAllAPs;

    /**
     * @brief Starts up the requested AP to run the function provided by the
     *   caller.
     */
    EFI_MP_SERVICES_STARTUP_THIS_AP StartupThisAP;

    /**
     * @brief Switches the requested AP to be the BSP from that point onward.
     *   This service changes the BSP for all purposes.
     */
    EFI_MP_SERVICES_SWITCH_BSP SwitchBSP;

    /**
     * @brief Enables and disables the given AP from that point onward.
     */
    EFI_MP_SERVICES_ENABLEDISABLEAP EnableDisableAP;

    /**
     * @brief Gets the handle number of the caller processor.
     */
    EFI_MP_SERVICES_WHOAMI WhoAmI;

} EFI_MP_SERVICES_PROTOCOL;

/** @brief defines the global pointer to the EFI_MP_SERVICES_PROTOCOL */
extern EFI_MP_SERVICES_PROTOCOL *g_mp_services_protocol;

#endif
