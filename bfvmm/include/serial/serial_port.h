#ifndef SERIAL_PORT__H
#define SERIAL_PORT__H

#define STRINGIFY(x) (#x)
#include <stdint.h>

namespace serial
{
    enum err
    {
        SUCCESS,
        GENERAL_ERROR,
        INVALID_PARITY,
        INVALID_BAUD,
        INVALID_STOP_BITS,
        INVALID_INTERRUPT_MODE,
        UNIMPLEMENTED,
    };

    //    const char *toString[] =
    //{
    //    STRINGIFY(SUCCESS),
    //    STRINGIFY(GENERAL_ERROR),
    //    STRINGIFY(INVALID_PARITY),
    //    STRINGIFY(INVALID_BAUD),
    //    STRINGIFY(INVALID_STOP_BITS),
    //    STRINGIFY(INVALID_INTERRUPT_MODE),
    //    STRINGIFY(UNIMPLEMENTED),
    //};
}

typedef enum
{
    NONE,
    ODD,
    EVEN,
    MARK,
    SPACE,
    PARITY_MAX
} PARITY_MODE;

#define DEFAULT_BAUD_RATE 9600

class serial_port
{
public:
    serial_port(uint32_t baud = DEFAULT_BAUD_RATE, uint8_t data_bits = 8,
                PARITY_MODE parity = NONE, uint8_t stop_bits = 1) {}
    virtual ~serial_port(void) {}

    virtual serial::err
    open(void) { return serial::UNIMPLEMENTED; }

    virtual serial::err
    close(void)  { return serial::UNIMPLEMENTED; }

    virtual serial::err
    set_baud_rate(uint32_t baud) { return serial::UNIMPLEMENTED; }

    virtual uint32_t
    baud_rate(void) { return 0; }

    virtual serial::err
    set_parity_mode(PARITY_MODE parity) { return serial::UNIMPLEMENTED; }
    virtual uint8_t parity_mode(void) { return 0; }

    virtual serial::err set_data_size(uint8_t bits)  { return serial::UNIMPLEMENTED; }
    virtual uint8_t data_size(void)  { return 0; }

    virtual serial::err set_stop_bits(uint8_t bits)  { return serial::UNIMPLEMENTED; }
    virtual uint8_t stop_bits(void)  { return 0; }

    virtual serial::err enable_interrupt_mode(uint8_t mode)  { return serial::UNIMPLEMENTED; }
    virtual void disable_interrupt_mode(void) {}
    virtual uint8_t interrupt_mode(void)  { return 0; }

    virtual serial::err enable_fifo(void)  { return serial::UNIMPLEMENTED; }
    virtual void disable_fifo(void) {}
    virtual bool fifo(void)  { return false; }

    virtual void write(uint8_t) {}
    virtual void write(int8_t *bytes) {}
    virtual uint8_t read(void) { return 0; }

    virtual bool data_ready(void) { return false; }
    virtual bool overrun_error(void) { return false; }
    virtual bool parity_error(void) { return false; }
    virtual bool framing_error(void) { return false; }
    virtual bool break_indicator(void) { return false; }
    virtual bool transmit_hold_register_empty(void) { return false; }
    virtual bool transmitter_empty(void) { return false; }
    virtual bool error_byte_rx_fifo(void) { return false; }

    virtual serial_port &operator<<(uint8_t value) { return *this; }

protected:
    // Get appropriate divisor for desired baud
    virtual uint8_t baud_to_lo_divisor(uint32_t baud) { return 0; }
    virtual uint8_t baud_to_hi_divisor(uint32_t baud) { return 0; }

    uint32_t m_baud;
    PARITY_MODE m_parity;
    uint8_t m_data_size;
    uint8_t m_stop_bits;
    uint8_t m_interrupt_mode;
    bool m_fifo_enabled;
};

#endif // SERIAL_PORT__H
