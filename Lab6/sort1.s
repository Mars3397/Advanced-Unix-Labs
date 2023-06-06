sort_funcptr_t:
	sub	rsp, 8
	lea	edx, -1[rsi]
	mov	esi, 0
	call	quicksort
	add	rsp, 8
	ret

quicksort:
	cmp	esi, edx
	jge	.L7
	push	r12
	push	rbp
	push	rbx
	mov	rbp, rdi
	mov	r12d, edx
	movsx	rax, edx
	lea	r10, [rdi+rax*8]
	mov	r8, QWORD PTR [r10]
	lea	ebx, -1[rsi]
	movsx	rcx, esi
	lea	rax, [rdi+rcx*8]
	lea	edx, -1[rdx]
	sub	edx, esi
	add	rdx, rcx
	lea	rdi, 8[rdi+rdx*8]
	jmp	.L4
.L3:
	add	rax, 8
	cmp	rax, rdi
	je	.L10
.L4:
	mov	rdx, QWORD PTR [rax]
	cmp	rdx, r8
	jge	.L3
	add	ebx, 1
	movsx	rcx, ebx
	lea	rcx, 0[rbp+rcx*8]
	mov	r9, QWORD PTR [rcx]
	mov	QWORD PTR [rcx], rdx
	mov	QWORD PTR [rax], r9
	jmp	.L3
.L10:
	movsx	rax, ebx
	lea	rax, 8[rbp+rax*8]
	mov	rdx, QWORD PTR [rax]
	mov	rcx, QWORD PTR [r10]
	mov	QWORD PTR [rax], rcx
	mov	QWORD PTR [r10], rdx
	mov	edx, ebx
	mov	rdi, rbp
	call	quicksort
	lea	esi, 2[rbx]
	mov	edx, r12d
	mov	rdi, rbp
	call	quicksort
	pop	rbx
	pop	rbp
	pop	r12
	ret
.L7:
	ret