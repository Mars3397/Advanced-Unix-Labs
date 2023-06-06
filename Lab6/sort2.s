sort_funcptr_t:
	endbr64
	cmp	esi, 119
	jg	.L14
	lea	r9d, -1[rsi]
	xor	r8d, r8d
	cmp	esi, 1
	jle	.L13
.L20:
	movsx	rsi, DWORD PTR 8[rdi+r8*8]
	mov	rax, r8
.L17:
	mov	rdx, QWORD PTR [rdi+rax*8]
	mov	ecx, eax
	cmp	rdx, rsi
	jle	.L25
	mov	QWORD PTR 8[rdi+rax*8], rdx
	sub	rax, 1
	cmp	eax, -1
	jne	.L17
	mov	rax, rdi
.L18:
	add	r8, 1
	mov	QWORD PTR [rax], rsi
	cmp	r9, r8
	jne	.L20
	ret
.L25:
	add	ecx, 1
	movsx	rcx, ecx
	lea	rax, [rdi+rcx*8]
	jmp	.L18
.L13:
	ret
.L14:
	lea	edx, -1[rsi]
	xor	esi, esi
	jmp	quicksort

quicksort:
	endbr64
	cmp	esi, edx
	jge	.L9
	push	r13
	movsx	rax, edx
	mov	r8d, esi
	push	r12
	lea	r13, [rdi+rax*8]
	mov	r12d, edx
	push	rbp
	push	rbx
	mov	rbx, rdi
	sub	rsp, 8
.L5:
	mov	rsi, QWORD PTR 0[r13]
	lea	ebp, -1[r8]
	movsx	rax, r8d
.L4:
	mov	rdx, QWORD PTR [rbx+rax*8]
	cmp	rdx, rsi
	jge	.L3
	add	ebp, 1
	movsx	rcx, ebp
	lea	rcx, [rbx+rcx*8]
	mov	rdi, QWORD PTR [rcx]
	mov	QWORD PTR [rcx], rdx
	mov	QWORD PTR [rbx+rax*8], rdi
.L3:
	add	rax, 1
	cmp	r12d, eax
	jg	.L4
	movsx	rax, ebp
	mov	rcx, QWORD PTR 0[r13]
	mov	esi, r8d
	mov	rdi, rbx
	lea	rax, 8[rbx+rax*8]
	mov	rdx, QWORD PTR [rax]
	mov	QWORD PTR [rax], rcx
	mov	QWORD PTR 0[r13], rdx
	mov	edx, ebp
	call	quicksort
	lea	r8d, 2[rbp]
	cmp	r8d, r12d
	jl	.L5
	add	rsp, 8
	pop	rbx
	pop	rbp
	pop	r12
	pop	r13
	ret
.L9:
	ret