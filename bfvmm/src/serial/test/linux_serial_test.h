#ifndef LINUX_SERIAL_TEST__H
#define LINUX_SERIAL_TEST__H

class linux_serial_test_harness
{

public:
    linux_serial_test_harness() {}
    ~linux_serial_test_harness() {}

private:
    uint8_t register_file[8];

};

#endif // LINUX_SERIAL_TEST__H