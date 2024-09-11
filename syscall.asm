; Basic Direct Syscall Example

.code
CustomNtCreateFile PROC
	mov r10, rcx
	mov eax, 55h
	syscall
	ret
CustomNtCreateFile ENDP

end