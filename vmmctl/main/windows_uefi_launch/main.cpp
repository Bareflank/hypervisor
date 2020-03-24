#include <bsl/exit_code.hpp>
#include <bsl/cstr_type.hpp>

#include <app.hpp>
#include <windows/windows_vmm_info.hpp>
#include <unsupported/unsupported_vmm_loader.hpp>

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

    vmmctl::app<
        vmmctl::windows_vmm_info,
        vmmctl::unsupported_vmm_loader
    > const myapp{};

    return myapp.run();
}
