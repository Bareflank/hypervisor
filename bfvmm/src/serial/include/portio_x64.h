#ifndef PORTIO_X64__H
#define PORTIO_X64__H

#include <port_io.h>

class portio_x64 : public port_io
{
public:

    portio_x64();
    ~portio_x64();

    void port_write_8(uint16_t port, uint8_t value);
    void port_write_16(uint16_t port, uint16_t value);

    uint8_t port_read_8(uint16_t port);
    uint16_t port_read_16(uint16_t port);
};

#endif