; This shellcode uses the PEB method to pop a MessageBox.
BITS 64;

section .text
global _WinMain@16

; vars:
; [@rbp-0x100]  the system directory name
and rsp, 0ffffffffffffff00h
_WinMain@16:
call getrip
getrip:
pop r15

mov rcx, 0d4e88h    ; hash("kernel32.dll")
call findmod
mov r12, rax

mov rcx, 069bb2e6h  ; hash("GetSystemDirectoryA")
mov rdx, r12
call findproc

lea rcx, [r15+BUF-getrip]
mov rdx, 0f0h
call rax            ; GetSystemDirectoryA(BUF, 240)

mov byte [r15+rax+BUF-getrip], 05ch ; Add a '\\' to the end of the path
mov rbx, 0642e323372657375h
mov qword [r15+rax+BUF-getrip+1], rbx    ; "user32.d"
mov dword [r15+rax+BUF-getrip+9], 06c6ch ; "ll\0\0"

mov rcx, 0d5786h    ; hash("LoadLibraryA")
mov rdx, r12
call findproc

lea rcx, [r15+BUF-getrip]
call rax            ; LoadLibraryA("user32.dll")

mov rcx, 06b81ah    ; hash("MessageBoxA")
mov rdx, rax
call findproc

xor rcx, rcx
lea rdx, [r15+MSG-getrip]
xor r8, r8
xor r9, r9
call rax            ; MessageBoxA(NULL, "Pwned", NULL, 0)

jmp END

; compares two hashes.
; !!!   this function does not change rcx
; !!!   this function does not change r9
; !!!   this function does not change r11
; args:
; @rcx  the hash to compare against
; @rdx  the address of the buffer
; @r8   the length of the buffer
; @r9   the increment (1-ascii, 2-unicode)
hashcmp:
push rbp
mov rbp, rsp
xor r10, r10    ; this register will hold the hash
xor rax, rax

hashcmp_cond:
test r8, r8     ; is the remaining length 0? 
jz hashcmp_done
mov al, [rdx]   ; take a char
test rax, rax   ; is the current char NUL?
jz hashcmp_done

or al, 0x60     ; to uppercase
add r10, rax
shl r10, 1
sub r8, r9      ; decrement the length counter
add rdx, r9     ; increment the data pointer
jmp hashcmp_cond

hashcmp_done:
xor rax, rax    ; by default, return false
cmp r10, rcx
jnz hashcmp_ret
inc rax         ; return true

hashcmp_ret:
leave
ret

; find a loaded module by name-hash from the peb. 
; args:
; @rcx  the hash of the name of the module
findmod:
push rbp
mov rbp, rsp
mov r11, [gs:60h]   ; Fetch the PEB from TEB->ProcessEnvironmentBlock
mov r11, [r11+18h]  ; PEB->Ldr
mov r11, [r11+20h]  ; Ldr->InMemoryOrderModuleList.Flink (first - the executable)
mov r9, 2

findmod_next:
mov r11, [r11]      ; next. (_LIST_ENTRY)->Flink
mov rdx, [r11+50h]  ; (_LDR_DATA_TABLE_ENTRY)->BaseDllName.Buffer
movzx r8, WORD [r11+48h]    ; (_LDR_DATA_TABLE_ENTRY)->BaseDllName.Length
call hashcmp
test rax, rax
jz findmod_next
mov rax, [r11+20h]  ; (_LDR_DATA_TABLE_ENTRY)->DllBase

leave
ret

; find the address of a symbol in a loaded module.
; args:
; @rcx  the hash of the symbol name
; @rdx  the base of the module
; vars:
; [@rbp-0x20]   the base of the module
; [@rbp-0x18]   the AddressOfFunctions array
; [@rbp-0x10]   the AddressOfNames array
; [@rbp-0x8]    the AddressOfNameOrdinals array

findproc:
push rbp
mov rbp, rsp
sub rsp, 20h

movzx r11, word [rdx+3ch]   ; (IMAGE_DOS_HEADER)->e_lfanew
mov r11d, [r11+rdx+88h]     ; IMAGE_NT_HEADER.OptionalHeader.DataDirectory[EXPORT_DATA_DIRECTORY]
add r11, rdx        ; RVA -> VA
mov eax, [r11+1ch]  ; AddressOfFunctions
add rax, rdx        ; RVA -> VA
mov [rbp-18h], rax
mov eax, [r11+20h]  ; AddressOfNames
add rax, rdx        ; RVA -> VA
mov [rbp-10h], rax
mov eax, [r11+24h]  ; AddressOfNameOrdinals
add rax, rdx        ; RVA -> VA
mov [rbp-8h], rax
mov [rbp-20h], rdx  ; ImageBase

mov r9, 1           ; ascii

findproc_next:
mov rax, [rbp-10h]
mov edx, [rax]      ; take name RVA (apparnetly zeros the higher bits of rdx)
add rdx, [rbp-20h]  ; RVA -> VA
mov r8, -1          ; max length
call hashcmp
test rax, rax
jnz findproc_done
add qword [rbp-10h], 4    ; continue to the next RVA
add qword [rbp-8h], 2     ; continue to the next ordinal
jmp findproc_next

findproc_done:
mov rax, [rbp-8h]

movzx rax, word [rax]   ; NameOrdinals[i]
shl rax, 2          ; *= sizeof(DWORD)
add rax, [rbp-18h]  ; Functions[NameOrdinals[i]]
mov eax, [rax]
add rax, [rbp-20h]

add rsp, 20h
leave
ret

BUF:
times 256 db 0
MSG:
db "Pwned", 0
END: