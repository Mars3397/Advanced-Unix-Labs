sort_funcptr_t:
	push	rbp
	mov	rbp, rsp
	lea	edx, -1[rsi]
	mov	esi, 0
	call	quicksort
	nop
	leave
	ret

quicksort:
	push	rbp
	mov	rbp, rsp
	push	r15
	push	r14
	push	r13
	push	r12
	push	rbx
	sub	rsp, 8
	mov	r13, rdi
	mov	eax, esi
	mov	r12d, edx
	cmp	eax, r12d
	jge	.L6
	movsx	rdx, r12d
	sal	rdx, 3
	add	rdx, r13
	mov	rsi, QWORD PTR [rdx]
	lea	ebx, -1[rax]
	mov	r14d, eax
	jmp	.L3
.L5:
	movsx	rdx, r14d
	sal	rdx, 3
	add	rdx, r13
	mov	rdx, QWORD PTR [rdx]
	mov	rdi, rsi
	cmp	rdi, rdx
	jle	.L4
	add	ebx, 1
	movsx	rdx, ebx
	sal	rdx, 3
	add	rdx, r13
	mov	r15, QWORD PTR [rdx]
	movsx	rdx, r14d
	sal	rdx, 3
	add	rdx, r13
	movsx	rcx, ebx
	sal	rcx, 3
	add	rcx, r13
	mov	rdx, QWORD PTR [rdx]
	mov	QWORD PTR [rcx], rdx
	movsx	rdx, r14d
	sal	rdx, 3
	add	rdx, r13
	mov	QWORD PTR [rdx], r15
.L4:
	add	r14d, 1
.L3:
	cmp	r14d, r12d
	jl	.L5
	movsx	rdx, ebx
	add	rdx, 1
	sal	rdx, 3
	add	rdx, r13
	mov	r15, QWORD PTR [rdx]
	movsx	rdx, r12d
	sal	rdx, 3
	add	rdx, r13
	movsx	rcx, ebx
	add	rcx, 1
	sal	rcx, 3
	add	rcx, r13
	mov	rdx, QWORD PTR [rdx]
	mov	QWORD PTR [rcx], rdx
	movsx	rdx, r12d
	sal	rdx, 3
	add	rdx, r13
	mov	QWORD PTR [rdx], r15
	mov	edx, ebx
	mov	esi, eax
	mov	rdi, r13
	call	quicksort
	lea	eax, 2[rbx]
	mov	edx, r12d
	mov	esi, eax
	mov	rdi, r13
	call	quicksort
.L6:
	nop
	add	rsp, 8
	pop	rbx
	pop	r12
	pop	r13
	pop	r14
	pop	r15
	pop	rbp
	ret