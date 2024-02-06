[BITS 32]

db 0xe8
db 0xff
db 0xff
db 0xff
db 0xff

nop

; expected disassembler output :
; 00000000:  E8 FF FF FF FF        call offset_00000004h
; 00000005:  90                    nop
