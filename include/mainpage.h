/// @mainpage Bareflank APIs (version 1.0.0)
/// @section pageTOC Content
///     -# @ref description
///     -# @ref license
///     -# @ref unit_tests
///     -# @ref extending_bareflank
///     -# @ref vmm_reference
///     -# @ref serial
///
/// @section description Description
///
/// The Bareflank Hypervisor is an open source, lightweight hypervisor, lead by
/// Assured Information Security, Inc. that provides the scaffolding needed to
/// rapidly prototype new hypervisors. To ease development, Bareflank
/// is written in C++, and includes support for exceptions and the C++ Standard
/// Template Library (STL) via libc++. With the C++ STL, users can leverage
/// shared pointers, complex data structures (e.g. hash tables, maps, lists,
/// etc…), and several other modern C++ features. Existing open source
/// hypervisors that are written in C are difficult to modify, and spend a
/// considerable amount of time re-writing similar functionality instead of
/// focusing on what matters most: hypervisor technologies. Furthermore, users
/// can leverage inheritance to extend every part of the hypervisor to provide
/// additional functionality above and beyond what is already provided.
///
/// To this end, Bareflank's primary goal is to remain simple, and
/// minimalistic, providing only the scaffolding needed
/// to construct more complete/complicated hypervisors including:
/// - Type 1 Hypervisors (like Xen)
/// - Type 2 Hypervisors (like VirtualBox)
/// - Host-Only Hypervisors (commonly used by anti-virus and rootkits)
///
/// The core business logic will remain in the hypervisors that extend
/// Bareflank, and not in Bareflank itself.
///
/// @section license License
///
/// To support Bareflank's design approach, the entire project is licensed
/// under the GNU Lesser General Public License v2.1 (LGPL), specifically
/// enabling users of the project to both contribute back to the project, but
/// also create proprietary extensions if so desired. For more information
/// please see:
///
/// <a href="http://www.gnu.org/licenses/old-licenses/lgpl-2.1.en.html">GNU Lesser General Public License, version 2.1</a>
///
/// @section unit_tests Unit Tests
///
/// In addition to Bareflank’s lightweight, modular design, the entire
/// hypervisor has been written using test driven development. As such, all
/// of Bareflank’s code comes complete with a set of unit tests to validate
/// that the provided code works as expected.
///
/// To execute the unit tests, run:
/// @code
/// make
/// make unittest
/// @endcode
///
/// Bareflank uses Hippomocks for mocking C/C++ functionality in the unit
/// tests when needed. As such, Bareflank includes a version of Hippomocks
/// that can be used by Bareflank extensions. For more information on how
/// to use Hippomocks, checkout some of the existing unit tests in the bfvmm,
/// as well as the following:
///
/// <a href="http://hippomocks.com/Main_Page">Hippomocks</a>
///
/// @section extending_bareflank Extending Bareflank
///
/// Bareflank's VMM is written as a set of ELF modules. Extending the VMM
/// is as simple as adding / replacing the existing modules with new
/// functionality. For example, suppose you want to prototype a new memory
/// management algorithm for your hypervisor. Doing so is as simple as
/// replacing the memory_manager_x64 module with your own.
///
/// In most cases, your likely to be more interested in modifying the
/// virtualization extension logic. Currently Bareflank supports Intel, but
/// ARM and AMD are planned for future releases. The VMM is broken up into
/// the following major components:
///
/// - Support Logic (memory manager, serial, libc++, etc...)
/// - Virtual CPU Management
/// - Virtualization Extension Logic
///
/// The support logic enables the VMM environment. For example, libc++
/// provides std::cout for debugging which uses the memory_manager_x64 to
/// allocate memory, and the serial_port_intel_x64 / debug_ring to output
/// the resulting text to. The virtualization extension logic is responsible
/// for setting up, and enabling virtualization. This logic is specific to
/// the architecture your using. On Intel, this consists of the VMXON, VMCS,
/// exit handler, and intrinsics logic.
///
/// To encapsulate the architectural specific logic, each architecture
/// has its own vCPU (for Intel this is vcpu_intel_x64) that subclasses a
/// generic vCPU (@ref vcpu) used by the vcpu_manager, and created by the
/// vcpu_factory. The vcpu_factory is in its own module, specifically so
/// that users of Bareflank can replace this module with their own factory.
///
/// The process of extending Bareflank with custom virtualization logic,
/// starts by subclassing the code you wish to extend. In this example we
/// will extend the exit_handler_intel_x64 to count the number of
/// CPUIDs that have been executed, but you can subclass anything including
/// the vmxon_intel_x64, vmcs_intel_x64, intrinsics_intel_x64 logic, etc...
/// Worst case, you can always outright provide your own modules for this same
/// logic. Subclassing the code that Bareflank
/// already provides allows you to leverage the existing scaffolding that
/// Bareflank has, likely saving you some additional time.
///
/// @code
/// class exit_handler_cpuidcount : public exit_handler_intel_x64
/// {
/// public:
///     exit_handler_cpuidcount() :
///         m_count(0)
///     { }

///     virtual ~exit_handler_cpuidcount()
///     { bfdebug << "cpuid count = " << m_count << bfendl; }

///     virtual void handle_cpuid()
///     {
///         m_count++;
///         exit_handler_intel_x64::handle_cpuid();
///     }

/// private:
///     int64_t m_count;
/// };
/// @endcode
///
/// In this example, when the exit handler is first created, a "count"
/// variable is created with an initial value of 0, and when the exit handler
/// is destroyed, the exit handler prints out the count variable using
/// Bareflank's std::cout shortcut "bfdebug" (which also adds some additional
/// text and color for the developer). When the default exit handler's
/// dispatch function is called, it will call "handle_cpuid" each time a
/// CPUID instruction needs to be emulated. In this example, we overload this
/// function and increment the count variable each time this function is
/// called. Finally, we call the original handle_cpuid which provides the
/// CPUID emulation for us. Note that you could also leave this last part out
/// and emulate the CPUID instruction yourself.
///
/// The next step is to tell the VMM how to create your exit handler instead
/// of the default one. To do this, you need to provide a new vcpu_factory.
/// The vcpu_manager uses the vcpu_factory to create vCPUs. Thus providing a
/// custom factory provides a means to provide custom logic here (and also
/// provides a simple means for unit testing).
///
/// @code
/// std::shared_ptr<vcpu>
/// vcpu_factory::make_vcpu(uint64_t vcpuid)
/// {
///     return std::make_shared<vcpu_intel_x64>(vcpuid,
///                                             nullptr,
///                                             nullptr,
///                                             nullptr,
///                                             std::make_shared<exit_handler_cpuidcount>(),
///                                             nullptr);
/// }
/// @endcode
///
/// In this example, we leave all of the inputs to the vCPU as null except for
/// our new exit handler. When the vCPU is created, the vcpu creates default
/// objects for all arguments that are left null, and uses the arguments that
/// are provided. Note that we use the existing vcpu_intel_x64, but you could
/// subclass this vCPU class and provide your own custom logic here too.
/// It's entirely up to the developer on how much you wish to reuse vs.
/// replace.
///
/// Finally, we must provide a new list of modules to BFM when starting the
/// hypervisor. In this example, we simply need to replace the old vcpu_factory
/// with our new one, but you could add as many new modules as you wish here.
/// Note that we use the BUILD_ABS macro to simplify pathing. If you use the
/// make shortcuts, Bareflank will convert these for you. If you run bfm
/// manually, you will need to run the build_scripts/filter_module_file.sh
/// script to convert the macros, or use absolute / relative pathing in your
/// module file.
///
/// @code
/// # Default Modules
/// #
/// # Note: The existing vcpu_factory module is commented out as we will be
/// # providing our own.
/// %BUILD_ABS%/sysroot/x86_64-elf/lib/libc++.so
/// %BUILD_ABS%/makefiles/bfvmm/src/debug_ring/bin/cross/libdebug_ring.so
/// %BUILD_ABS%/makefiles/bfvmm/src/entry/bin/cross/libentry.so
/// %BUILD_ABS%/makefiles/bfvmm/src/exit_handler/bin/cross/libexit_handler.so
/// %BUILD_ABS%/makefiles/bfvmm/src/intrinsics/bin/cross/libintrinsics.so
/// %BUILD_ABS%/makefiles/bfvmm/src/memory_manager_x64/bin/cross/libmemory_manager_x64.so
/// %BUILD_ABS%/makefiles/bfvmm/src/misc/bin/cross/libmisc.so
/// %BUILD_ABS%/makefiles/bfvmm/src/serial/bin/cross/libserial.so
/// %BUILD_ABS%/makefiles/bfvmm/src/vcpu/bin/cross/libvcpu.so
/// #    %BUILD_ABS%/makefiles/bfvmm/src/vcpu_factory/bin/cross/libvcpu_factory.so
/// %BUILD_ABS%/makefiles/bfvmm/src/vmcs/bin/cross/libvmcs.so
/// %BUILD_ABS%/makefiles/bfvmm/src/vmxon/bin/cross/libvmxon.so

/// # Custom Modules
/// #
/// # Note: This is where we provide our own vcpu_factory.
/// %BUILD_ABS%/makefiles/hypervisor_example_cpuidcount/vcpu_factory_cpuidcount/bin/cross/libvcpu_factory_cpuidcount.so
/// @endcode
///
/// Currently, Bareflank supports both in-tree and out-of-tree compilation.
/// To use in-tree, simply place your code in a folder at Bareflank's root
/// starting with hypervisor_* or src_* and run make. To perform out-of-tree
/// compilation, please see one of the examples as this process is fully
/// documented there. Also, these examples demonstrate how to code, compile
/// and run an extension.
///
/// <a href="https://github.com/Bareflank/hypervisor_example_vpid">Bareflank Hypervisor VPID Example</a>
/// <br>
/// <a href="https://github.com/Bareflank/hypervisor_example_cpuidcount">Bareflank Hypervisor CPUID Count Example</a>
/// <br>
/// <a href="https://github.com/Bareflank/hypervisor_example_msr_bitmap">Bareflank Hypervisor MSR Bitmaps Example</a>
///
/// @section vmm_reference VMM Reference
///
/// Bareflank's VMM is made up of the following components:
///
/// @subsection General
///
/// @ref start_vmm <br>
/// @ref stop_vmm <br>
/// @ref vcpu <br>
/// @ref vcpu_factory <br>
/// @ref vcpu_manager <br>
/// @ref memory_manager_x64 <br>
///
/// @subsection Intel x86_64 Specific
///
/// @ref vmxon_intel_x64 <br>
/// @ref exit_handler_intel_x64 <br>
/// @ref vmcs_intel_x64 <br>
/// @ref vmcs_intel_x64_state <br>
/// @ref vcpu_intel_x64 <br>
///
/// @subsection Unit Testing
///
/// @ref unittest <br>
/// @ref bfn::mock_shared <br>
/// @ref expect_true <br>
/// @ref expect_false <br>
/// @ref expect_exception <br>
/// @ref expect_no_exception <br>
/// @ref ASSERT_TRUE <br>
/// @ref ASSERT_FALSE <br>
/// @ref ASSERT_EXCEPTION <br>
/// @ref ASSERT_NO_EXCEPTION <br>
/// @ref RUN_UNITTEST_WITH_MOCKS <br>
/// @ref RUN_ALL_TESTS <br>
///
/// @subsection Debugging
///
/// @ref bfinfo <br>
/// @ref bfdebug <br>
/// @ref bfwarning <br>
/// @ref bferror <br>
/// @ref bffatal <br>
/// @ref bfendl <br>
/// @ref debug_ring <br>
/// @ref serial_port_intel_x64 <br>
///
/// @section serial Serial Setup
///
/// With VMWare, Bareflank will use serial0 to output bfxxx / std::cout /
/// std::cerr by default. On some VMWare systems, the printer uses serial0,
/// so you might have to remove (disabling is not enough) the printer prior
/// to adding the serial device. Worst case, you can modify the .vmx file
/// manually to setup serial0.
///
/// On physical hardware however, you might have to define the serial port
/// during compilation to something other than the default (or if you
/// want to use a different VMWare serial port). To tell Bareflank to use
/// a different port, you need to define the default port prior to
/// compiling Bareflank.
///
/// export CROSS_CXXFLAGS="-DDEFAULT_COM_PORT=0x<port #>"
///
/// By default this is set to "COM1_PORT" or "0x3f8". You can set this to
/// any of the following:
/// - COM1_PORT
/// - COM2_PORT
/// - COM3_PORT
/// - COM4_PORT
/// - 0x<port #>
///
/// On some Intel systems with PCI serial devices the port numbers are:
/// - 0xe000
/// - 0xe010
///
/// You can use the above method to define all of the parameters for serial
/// as well. The default values are listed below, and you can change them
/// to anything you wish:
/// - DEFAULT_COM_PORT=COM1_PORT
/// - DEFAULT_BAUD_RATE=baud_rate_115200
/// - DEFAULT_DATA_BITS=char_length_8
/// - DEFAULT_STOP_BITS=stop_bits_1
/// - DEFAULT_PARITY_BITS=parity_none
///
/// For more information, please see serial_port_intel_x64.h
///
