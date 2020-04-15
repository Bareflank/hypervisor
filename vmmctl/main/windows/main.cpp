#include <bsl/exit_code.hpp>
#include <bsl/cstr_type.hpp>

#include <app.hpp>
#include <composite_concrete.hpp>
#include <windows/windows_vmm_info.hpp>
#include <windows/windows_vmm_loader.hpp>

/// @brief Provides the vmmctl main function
///
/// @param argc the total number of arguments passed to the app
/// @param argv the arguments passed to the app
/// @return 0 on success, non-0 on failure
bsl::exit_code
main(bsl::int32 const argc, bsl::cstr_type const *const argv) noexcept
{
    if ((0 == argc) || (nullptr == argv)) {
        return bsl::exit_failure;
    }

    // Example 1: Implement all interface requirements by combining individual
    // concrete types into a composite concrete class
    vmmctl::composite_concrete<
        vmmctl::windows_vmm_info,
        vmmctl::windows_vmm_loader
    > my_composite{};

    my_composite.dump();
    my_composite.status();
    my_composite.load();
    my_composite.start();
    my_composite.stop();
    my_composite.unload();

    // Example 2: Implement all interface requirements by injecting individual
    // concrete types into a business logic container
    vmmctl::app<
        vmmctl::windows_vmm_info,
        vmmctl::windows_vmm_loader
    > const myapp{};

    return myapp.run();
}
