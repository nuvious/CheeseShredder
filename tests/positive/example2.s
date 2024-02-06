[ BITS 32 ]

; nasm example2.S -o example2.o
; ndisasm -u example2.o

    push    ebp
    mov     ebp, esp
    push    edx
    push    ecx
    cmp     ecx, edx
    jz      label_error
    mov     eax, 041424344h
    mov     edx, dword [ byte ebp + 08h]    ; By default, the assembler will 
                                            ; likely make 0x08 a byte, but the
                                            ; byte qualifier guarantees it.
    mov     ecx, dword [ byte ebp + 0ch]    ; By default, the assembler will 
                                            ; likely make 0x0c a byte, but the
                                            ; byte qualifier guarantees it.
    add     ecx, edx
    mov     eax, ecx

label_error:
    pop     edx
    pop     ecx
    pop     ebp
    retn    08h
