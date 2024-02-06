[BITS 32]

mov dword [ byte esi - 4 ], edi

; expected output in disassembler
; 00000000:  89 7E FC            mov [esi-0x4],edi
;  -OR-
; 00000000:  89 7E FC            mov [esi + 0xfffffffc],edi