[BITS 32]

; clflush esi 
db 0x0f
db 0xae
db 0xfe

; expected disassmebler ouput
; 00000000:  0F                db 0x0f
; 00000001:  AE                db 0xae
; 00000002:  FE                db 0xfe