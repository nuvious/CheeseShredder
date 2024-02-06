[BITS 32]

	push ebp
	push edi
	retn

my_label:
	mov [eax], edi
	push ebp
	push edi
	push ebp
	jmp my_label
