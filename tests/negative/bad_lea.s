[BITS 32]

; lea edi, ecx (invalid so need to emit)
db 0x8d
db 0xf9

; expected output of disassembler:
;00000000:  8d   db 0x8d
;00000001:  f9   db 0xf9