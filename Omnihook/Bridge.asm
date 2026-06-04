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

	sub rsp, 200h ; allocate 16 * 16 bytes for ymm registers

	vmovdqu ymmword ptr [rsp + 000h], ymm0
    vmovdqu ymmword ptr [rsp + 020h], ymm1
    vmovdqu ymmword ptr [rsp + 040h], ymm2
    vmovdqu ymmword ptr [rsp + 060h], ymm3
    vmovdqu ymmword ptr [rsp + 080h], ymm4
    vmovdqu ymmword ptr [rsp + 0A0h], ymm5
    vmovdqu ymmword ptr [rsp + 0C0h], ymm6
    vmovdqu ymmword ptr [rsp + 0E0h], ymm7
    vmovdqu ymmword ptr [rsp + 100h], ymm8
    vmovdqu ymmword ptr [rsp + 120h], ymm9
    vmovdqu ymmword ptr [rsp + 140h], ymm10
    vmovdqu ymmword ptr [rsp + 160h], ymm11
    vmovdqu ymmword ptr [rsp + 180h], ymm12
    vmovdqu ymmword ptr [rsp + 1A0h], ymm13
    vmovdqu ymmword ptr [rsp + 1C0h], ymm14
    vmovdqu ymmword ptr [rsp + 1E0h], ymm15


	mov rbx, rsp ; save the unaligned stack pointer
	and rsp, -16 ; align stack pointer to 16 bytes

	mov rcx, [rbx + 280h] ; load hookId from stack into 1st arg
	mov rdx, rbx ; load RegisterContext into 2nd arg

	sub rsp, 32 ; shadow space
	call MasterDispatcher
	add rsp, 32

	mov rsp, rbx ; restore original stack

	vmovdqu ymm0,  ymmword ptr [rsp + 000h]
    vmovdqu ymm1,  ymmword ptr [rsp + 020h]
    vmovdqu ymm2,  ymmword ptr [rsp + 040h]
    vmovdqu ymm3,  ymmword ptr [rsp + 060h]
    vmovdqu ymm4,  ymmword ptr [rsp + 080h]
    vmovdqu ymm5,  ymmword ptr [rsp + 0A0h]
    vmovdqu ymm6,  ymmword ptr [rsp + 0C0h]
    vmovdqu ymm7,  ymmword ptr [rsp + 0E0h]
    vmovdqu ymm8,  ymmword ptr [rsp + 100h]
    vmovdqu ymm9,  ymmword ptr [rsp + 120h]
    vmovdqu ymm10, ymmword ptr [rsp + 140h]
    vmovdqu ymm11, ymmword ptr [rsp + 160h]
    vmovdqu ymm12, ymmword ptr [rsp + 180h]
    vmovdqu ymm13, ymmword ptr [rsp + 1A0h]
    vmovdqu ymm14, ymmword ptr [rsp + 1C0h]
    vmovdqu ymm15, ymmword ptr [rsp + 1E0h]

   
    add rsp, 200h ; free the allocated bytes for ymm registers


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