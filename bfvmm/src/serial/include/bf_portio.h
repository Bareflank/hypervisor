#ifndef BF_PORTIO__H
#define BF_PORTIO__H

#ifdef __cplusplus
extern "C" {
#endif
uint8_t bf_inb(uint16_t port);
uint16_t bf_inw(uint16_t port);

void bf_outb(uint8_t value, uint16_t port);
void bf_outw(uint16_t value, uint16_t port);
#ifdef __cplusplus
};
#endif

#endif //BF_PORTIO__H
