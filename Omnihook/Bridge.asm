EXTERN MasterDispatcher : PROC

.code

SharedMidHookStub PROC
	
	pushfq

	push rax
	push rcx
	push rdx
	push rbx
	push rsi
	push rdi
	push rbp
	push r8
	push r9
	push r10
	push r11
	push r12
	push r13
	push r14
	push r15

	sub rsp, 100h ; allocate 16 * 16 bytes for XMM registers

	movdqu xmmword ptr [rsp + 000h], xmm0
    movdqu xmmword ptr [rsp + 010h], xmm1
    movdqu xmmword ptr [rsp + 020h], xmm2
    movdqu xmmword ptr [rsp + 030h], xmm3
    movdqu xmmword ptr [rsp + 040h], xmm4
    movdqu xmmword ptr [rsp + 050h], xmm5
    movdqu xmmword ptr [rsp + 060h], xmm6
    movdqu xmmword ptr [rsp + 070h], xmm7
    movdqu xmmword ptr [rsp + 080h], xmm8
    movdqu xmmword ptr [rsp + 090h], xmm9
    movdqu xmmword ptr [rsp + 0A0h], xmm10
    movdqu xmmword ptr [rsp + 0B0h], xmm11
    movdqu xmmword ptr [rsp + 0C0h], xmm12
    movdqu xmmword ptr [rsp + 0D0h], xmm13
    movdqu xmmword ptr [rsp + 0E0h], xmm14
    movdqu xmmword ptr [rsp + 0F0h], xmm15


	mov rbx, rsp ; save the unaligned stack pointer
	and rsp, -16 ; align stack pointer to 16 bytes

	mov rcx, [rbx + 180h] ; load hookId from stack into 1st arg
	mov rdx, rbx ; load RegisterContext into 2nd arg

	sub rsp, 32 ; shadow space
	call MasterDispatcher
	add rsp, 32

	mov rsp, rbx ; restore original stack

	movdqu xmm0,  xmmword ptr [rsp + 000h]
    movdqu xmm1,  xmmword ptr [rsp + 010h]
    movdqu xmm2,  xmmword ptr [rsp + 020h]
    movdqu xmm3,  xmmword ptr [rsp + 030h]
    movdqu xmm4,  xmmword ptr [rsp + 040h]
    movdqu xmm5,  xmmword ptr [rsp + 050h]
    movdqu xmm6,  xmmword ptr [rsp + 060h]
    movdqu xmm7,  xmmword ptr [rsp + 070h]
    movdqu xmm8,  xmmword ptr [rsp + 080h]
    movdqu xmm9,  xmmword ptr [rsp + 090h]
    movdqu xmm10, xmmword ptr [rsp + 0A0h]
    movdqu xmm11, xmmword ptr [rsp + 0B0h]
    movdqu xmm12, xmmword ptr [rsp + 0C0h]
    movdqu xmm13, xmmword ptr [rsp + 0D0h]
    movdqu xmm14, xmmword ptr [rsp + 0E0h]
    movdqu xmm15, xmmword ptr [rsp + 0F0h]

   
    add rsp, 100h ; free the allocated bytes for XMM registers


	pop r15
	pop r14
	pop r13
	pop r12
	pop r11
	pop r10
	pop r9
	pop r8
	pop rbp
	pop rdi
	pop rsi
	pop rbx
	pop rdx
	pop rcx
	pop rax

	popfq

	add rsp, 8
	jmp rax ; jump to what we set in MasterDispatcher



SharedMidHookStub ENDP

END