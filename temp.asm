bits 64
mov eax, 4        ; reg write (32-bit)
mov [rsp], eax    ; mem write (32-bit)
mov ebx, [rsp+4]  ; mem read (32-bit)
add eax, ebx      ; reg read/write
mov [rsp+8], rax  ; mem write (64-bit)
int3
