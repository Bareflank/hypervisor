section .text

global bf_outb
global bf_inb
global bf_outw
global bf_inw


bf_outb:
	mov ax, di
	mov dx, si
	out dx, al
	ret

bf_inb:
	mov al, 0
	mov dx, di
	in al, dx
	ret

bf_outw:
	mov ax, di
	mov dx, si
	out dx, ax
	ret

bf_inw:
	mov eax, 0
	mov edx, edi
	in ax, dx
	ret
