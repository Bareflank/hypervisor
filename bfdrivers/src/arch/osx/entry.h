#include <IOKit/IOLib.h>
#include <IOKit/IOKitKeys.h>
#include <IOKit/IOService.h>
#include <IOKit/IOUserClient.h>

#include <sys/types.h>
#include <sys/systm.h>

extern "C"
{

#include <common.h>

}

class org_bareflank_osx : public IOUserClient
{
    OSDeclareDefaultStructors(org_bareflank_osx)
public:

    // IOKit Base Functions
    virtual bool init(OSDictionary *dictionary = 0) override;
    virtual bool start(IOService *provider) override;
    virtual void stop(IOService *provider) override;
    virtual void free(void) override;
    virtual IOReturn externalMethod(uint32_t selector, IOExternalMethodArguments *arguments, IOExternalMethodDispatch *dispatch, OSObject *target, void *reference) override;

    // Custom Functions
    virtual IOReturn methodCommand(bf_ioctl_t *in_ioctl, bf_ioctl_t *out_ioctl, uint32_t inStructSize, uint32_t *outStructSize);
};