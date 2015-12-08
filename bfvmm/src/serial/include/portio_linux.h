#ifndef PORTIO_LINUX__H
#define PORTIO_LINUX__H

#include <port_io.h>

class portio_linux : public port_io
{
public:

    portio_linux();
    ~portio_linux();

    void port_write_8(uint16_t port, uint8_t value);
    void port_write_16(uint16_t port, uint16_t value);

    uint8_t port_read_8(uint16_t port);
    uint16_t port_read_16(uint16_t port);
};

#endif