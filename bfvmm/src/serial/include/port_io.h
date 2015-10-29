#ifndef PORT_IO__H
#define PORT_IO__H

#include <stdint.h>

class port_io
{

public:
    port_io(void) {}
    virtual ~port_io(void) {}

    virtual void port_write_8(uint16_t port, uint8_t value)  {}
    virtual void port_write_16(uint16_t port, uint16_t value) {}
    virtual uint8_t port_read_8(uint16_t port) { return 0; }
    virtual uint16_t port_read_16(uint16_t port) { return 0; }
};

#endif // PORT_IO__H
