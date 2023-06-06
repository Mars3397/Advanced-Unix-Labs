
solver:     file format elf64-x86-64


Disassembly of section .interp:

0000000000000318 <.interp>:
 318:	2f                   	(bad)  
 319:	6c                   	ins    BYTE PTR es:[rdi],dx
 31a:	69 62 36 34 2f 6c 64 	imul   esp,DWORD PTR [rdx+0x36],0x646c2f34
 321:	2d 6c 69 6e 75       	sub    eax,0x756e696c
 326:	78 2d                	js     355 <__abi_tag-0x37>
 328:	78 38                	js     362 <__abi_tag-0x2a>
 32a:	36 2d 36 34 2e 73    	ss sub eax,0x732e3436
 330:	6f                   	outs   dx,DWORD PTR ds:[rsi]
 331:	2e 32 00             	cs xor al,BYTE PTR [rax]

Disassembly of section .note.gnu.property:

0000000000000338 <.note.gnu.property>:
 338:	04 00                	add    al,0x0
 33a:	00 00                	add    BYTE PTR [rax],al
 33c:	20 00                	and    BYTE PTR [rax],al
 33e:	00 00                	add    BYTE PTR [rax],al
 340:	05 00 00 00 47       	add    eax,0x47000000
 345:	4e 55                	rex.WRX push rbp
 347:	00 02                	add    BYTE PTR [rdx],al
 349:	00 00                	add    BYTE PTR [rax],al
 34b:	c0 04 00 00          	rol    BYTE PTR [rax+rax*1],0x0
 34f:	00 03                	add    BYTE PTR [rbx],al
 351:	00 00                	add    BYTE PTR [rax],al
 353:	00 00                	add    BYTE PTR [rax],al
 355:	00 00                	add    BYTE PTR [rax],al
 357:	00 02                	add    BYTE PTR [rdx],al
 359:	80 00 c0             	add    BYTE PTR [rax],0xc0
 35c:	04 00                	add    al,0x0
 35e:	00 00                	add    BYTE PTR [rax],al
 360:	01 00                	add    DWORD PTR [rax],eax
 362:	00 00                	add    BYTE PTR [rax],al
 364:	00 00                	add    BYTE PTR [rax],al
	...

Disassembly of section .note.gnu.build-id:

0000000000000368 <.note.gnu.build-id>:
 368:	04 00                	add    al,0x0
 36a:	00 00                	add    BYTE PTR [rax],al
 36c:	14 00                	adc    al,0x0
 36e:	00 00                	add    BYTE PTR [rax],al
 370:	03 00                	add    eax,DWORD PTR [rax]
 372:	00 00                	add    BYTE PTR [rax],al
 374:	47                   	rex.RXB
 375:	4e 55                	rex.WRX push rbp
 377:	00 dc                	add    ah,bl
 379:	c5 4c da             	(bad)
 37c:	f2 82                	repnz (bad) 
 37e:	4c d3 81 34 76 45 90 	rex.WR rol QWORD PTR [rcx-0x6fba89cc],cl
 385:	b6 fd                	mov    dh,0xfd
 387:	0a                   	.byte 0xa
 388:	15                   	.byte 0x15
 389:	e0 fd                	loopne 388 <__abi_tag-0x4>
 38b:	af                   	scas   eax,DWORD PTR es:[rdi]

Disassembly of section .note.ABI-tag:

000000000000038c <__abi_tag>:
 38c:	04 00                	add    al,0x0
 38e:	00 00                	add    BYTE PTR [rax],al
 390:	10 00                	adc    BYTE PTR [rax],al
 392:	00 00                	add    BYTE PTR [rax],al
 394:	01 00                	add    DWORD PTR [rax],eax
 396:	00 00                	add    BYTE PTR [rax],al
 398:	47                   	rex.RXB
 399:	4e 55                	rex.WRX push rbp
 39b:	00 00                	add    BYTE PTR [rax],al
 39d:	00 00                	add    BYTE PTR [rax],al
 39f:	00 03                	add    BYTE PTR [rbx],al
 3a1:	00 00                	add    BYTE PTR [rax],al
 3a3:	00 02                	add    BYTE PTR [rdx],al
 3a5:	00 00                	add    BYTE PTR [rax],al
 3a7:	00 00                	add    BYTE PTR [rax],al
 3a9:	00 00                	add    BYTE PTR [rax],al
	...

Disassembly of section .gnu.hash:

00000000000003b0 <.gnu.hash>:
 3b0:	02 00                	add    al,BYTE PTR [rax]
 3b2:	00 00                	add    BYTE PTR [rax],al
 3b4:	06                   	(bad)  
 3b5:	00 00                	add    BYTE PTR [rax],al
 3b7:	00 01                	add    BYTE PTR [rcx],al
 3b9:	00 00                	add    BYTE PTR [rax],al
 3bb:	00 06                	add    BYTE PTR [rsi],al
 3bd:	00 00                	add    BYTE PTR [rax],al
 3bf:	00 00                	add    BYTE PTR [rax],al
 3c1:	00 81 00 00 40 00    	add    BYTE PTR [rcx+0x400000],al
 3c7:	01 06                	add    DWORD PTR [rsi],eax
 3c9:	00 00                	add    BYTE PTR [rax],al
 3cb:	00 00                	add    BYTE PTR [rax],al
 3cd:	00 00                	add    BYTE PTR [rax],al
 3cf:	00 b8 2b 6b 15 d1    	add    BYTE PTR [rax-0x2eea94d5],bh
 3d5:	65 ce                	gs (bad) 
 3d7:	6d                   	ins    DWORD PTR es:[rdi],dx

Disassembly of section .dynsym:

00000000000003d8 <.dynsym>:
	...
 3f0:	10 00                	adc    BYTE PTR [rax],al
 3f2:	00 00                	add    BYTE PTR [rax],al
 3f4:	12 00                	adc    al,BYTE PTR [rax]
	...
 406:	00 00                	add    BYTE PTR [rax],al
 408:	65 00 00             	add    BYTE PTR gs:[rax],al
 40b:	00 20                	add    BYTE PTR [rax],ah
	...
 41d:	00 00                	add    BYTE PTR [rax],al
 41f:	00 22                	add    BYTE PTR [rdx],ah
 421:	00 00                	add    BYTE PTR [rax],al
 423:	00 12                	add    BYTE PTR [rdx],dl
	...
 435:	00 00                	add    BYTE PTR [rax],al
 437:	00 81 00 00 00 20    	add    BYTE PTR [rcx+0x20000000],al
	...
 44d:	00 00                	add    BYTE PTR [rax],al
 44f:	00 90 00 00 00 20    	add    BYTE PTR [rax+0x20000000],dl
	...
 465:	00 00                	add    BYTE PTR [rax],al
 467:	00 33                	add    BYTE PTR [rbx],dh
 469:	00 00                	add    BYTE PTR [rax],al
 46b:	00 12                	add    BYTE PTR [rdx],dl
	...
 47d:	00 00                	add    BYTE PTR [rax],al
 47f:	00 01                	add    BYTE PTR [rcx],al
 481:	00 00                	add    BYTE PTR [rax],al
 483:	00 22                	add    BYTE PTR [rdx],ah
	...

Disassembly of section .dynstr:

0000000000000498 <.dynstr>:
 498:	00 5f 5f             	add    BYTE PTR [rdi+0x5f],bl
 49b:	63 78 61             	movsxd edi,DWORD PTR [rax+0x61]
 49e:	5f                   	pop    rdi
 49f:	66 69 6e 61 6c 69    	imul   bp,WORD PTR [rsi+0x61],0x696c
 4a5:	7a 65                	jp     50c <__abi_tag+0x180>
 4a7:	00 5f 5f             	add    BYTE PTR [rdi+0x5f],bl
 4aa:	6c                   	ins    BYTE PTR es:[rdi],dx
 4ab:	69 62 63 5f 73 74 61 	imul   esp,DWORD PTR [rdx+0x63],0x6174735f
 4b2:	72 74                	jb     528 <__abi_tag+0x19c>
 4b4:	5f                   	pop    rdi
 4b5:	6d                   	ins    DWORD PTR es:[rdi],dx
 4b6:	61                   	(bad)  
 4b7:	69 6e 00 5f 5f 73 74 	imul   ebp,DWORD PTR [rsi+0x0],0x74735f5f
 4be:	61                   	(bad)  
 4bf:	63 6b 5f             	movsxd ebp,DWORD PTR [rbx+0x5f]
 4c2:	63 68 6b             	movsxd ebp,DWORD PTR [rax+0x6b]
 4c5:	5f                   	pop    rdi
 4c6:	66 61                	data16 (bad) 
 4c8:	69 6c 00 70 72 69 6e 	imul   ebp,DWORD PTR [rax+rax*1+0x70],0x746e6972
 4cf:	74 
 4d0:	66 00 6c 69 62       	data16 add BYTE PTR [rcx+rbp*2+0x62],ch
 4d5:	63 2e                	movsxd ebp,DWORD PTR [rsi]
 4d7:	73 6f                	jae    548 <__abi_tag+0x1bc>
 4d9:	2e 36 00 47 4c       	cs ss add BYTE PTR [rdi+0x4c],al
 4de:	49                   	rex.WB
 4df:	42                   	rex.X
 4e0:	43 5f                	rex.XB pop r15
 4e2:	32 2e                	xor    ch,BYTE PTR [rsi]
 4e4:	32 2e                	xor    ch,BYTE PTR [rsi]
 4e6:	35 00 47 4c 49       	xor    eax,0x494c4700
 4eb:	42                   	rex.X
 4ec:	43 5f                	rex.XB pop r15
 4ee:	32 2e                	xor    ch,BYTE PTR [rsi]
 4f0:	34 00                	xor    al,0x0
 4f2:	47                   	rex.RXB
 4f3:	4c                   	rex.WR
 4f4:	49                   	rex.WB
 4f5:	42                   	rex.X
 4f6:	43 5f                	rex.XB pop r15
 4f8:	32 2e                	xor    ch,BYTE PTR [rsi]
 4fa:	33 34 00             	xor    esi,DWORD PTR [rax+rax*1]
 4fd:	5f                   	pop    rdi
 4fe:	49 54                	rex.WB push r12
 500:	4d 5f                	rex.WRB pop r15
 502:	64 65 72 65          	fs gs jb 56b <__abi_tag+0x1df>
 506:	67 69 73 74 65 72 54 	imul   esi,DWORD PTR [ebx+0x74],0x4d547265
 50d:	4d 
 50e:	43 6c                	rex.XB ins BYTE PTR es:[rdi],dx
 510:	6f                   	outs   dx,DWORD PTR ds:[rsi]
 511:	6e                   	outs   dx,BYTE PTR ds:[rsi]
 512:	65 54                	gs push rsp
 514:	61                   	(bad)  
 515:	62                   	(bad)  
 516:	6c                   	ins    BYTE PTR es:[rdi],dx
 517:	65 00 5f 5f          	add    BYTE PTR gs:[rdi+0x5f],bl
 51b:	67 6d                	ins    DWORD PTR es:[edi],dx
 51d:	6f                   	outs   dx,DWORD PTR ds:[rsi]
 51e:	6e                   	outs   dx,BYTE PTR ds:[rsi]
 51f:	5f                   	pop    rdi
 520:	73 74                	jae    596 <__abi_tag+0x20a>
 522:	61                   	(bad)  
 523:	72 74                	jb     599 <__abi_tag+0x20d>
 525:	5f                   	pop    rdi
 526:	5f                   	pop    rdi
 527:	00 5f 49             	add    BYTE PTR [rdi+0x49],bl
 52a:	54                   	push   rsp
 52b:	4d 5f                	rex.WRB pop r15
 52d:	72 65                	jb     594 <__abi_tag+0x208>
 52f:	67 69 73 74 65 72 54 	imul   esi,DWORD PTR [ebx+0x74],0x4d547265
 536:	4d 
 537:	43 6c                	rex.XB ins BYTE PTR es:[rdi],dx
 539:	6f                   	outs   dx,DWORD PTR ds:[rsi]
 53a:	6e                   	outs   dx,BYTE PTR ds:[rsi]
 53b:	65 54                	gs push rsp
 53d:	61                   	(bad)  
 53e:	62                   	.byte 0x62
 53f:	6c                   	ins    BYTE PTR es:[rdi],dx
 540:	65                   	gs
	...

Disassembly of section .gnu.version:

0000000000000542 <.gnu.version>:
 542:	00 00                	add    BYTE PTR [rax],al
 544:	02 00                	add    al,BYTE PTR [rax]
 546:	01 00                	add    DWORD PTR [rax],eax
 548:	03 00                	add    eax,DWORD PTR [rax]
 54a:	01 00                	add    DWORD PTR [rax],eax
 54c:	01 00                	add    DWORD PTR [rax],eax
 54e:	04 00                	add    al,0x0
 550:	04 00                	add    al,0x0

Disassembly of section .gnu.version_r:

0000000000000558 <.gnu.version_r>:
 558:	01 00                	add    DWORD PTR [rax],eax
 55a:	03 00                	add    eax,DWORD PTR [rax]
 55c:	3a 00                	cmp    al,BYTE PTR [rax]
 55e:	00 00                	add    BYTE PTR [rax],al
 560:	10 00                	adc    BYTE PTR [rax],al
 562:	00 00                	add    BYTE PTR [rax],al
 564:	00 00                	add    BYTE PTR [rax],al
 566:	00 00                	add    BYTE PTR [rax],al
 568:	75 1a                	jne    584 <__abi_tag+0x1f8>
 56a:	69 09 00 00 04 00    	imul   ecx,DWORD PTR [rcx],0x40000
 570:	44 00 00             	add    BYTE PTR [rax],r8b
 573:	00 10                	add    BYTE PTR [rax],dl
 575:	00 00                	add    BYTE PTR [rax],al
 577:	00 14 69             	add    BYTE PTR [rcx+rbp*2],dl
 57a:	69 0d 00 00 03 00 50 	imul   ecx,DWORD PTR [rip+0x30000],0x50        # 30584 <_end+0x2c56c>
 581:	00 00 00 
 584:	10 00                	adc    BYTE PTR [rax],al
 586:	00 00                	add    BYTE PTR [rax],al
 588:	b4 91                	mov    ah,0x91
 58a:	96                   	xchg   esi,eax
 58b:	06                   	(bad)  
 58c:	00 00                	add    BYTE PTR [rax],al
 58e:	02 00                	add    al,BYTE PTR [rax]
 590:	5a                   	pop    rdx
 591:	00 00                	add    BYTE PTR [rax],al
 593:	00 00                	add    BYTE PTR [rax],al
 595:	00 00                	add    BYTE PTR [rax],al
	...

Disassembly of section .rela.dyn:

0000000000000598 <.rela.dyn>:
 598:	b0 3d                	mov    al,0x3d
 59a:	00 00                	add    BYTE PTR [rax],al
 59c:	00 00                	add    BYTE PTR [rax],al
 59e:	00 00                	add    BYTE PTR [rax],al
 5a0:	08 00                	or     BYTE PTR [rax],al
 5a2:	00 00                	add    BYTE PTR [rax],al
 5a4:	00 00                	add    BYTE PTR [rax],al
 5a6:	00 00                	add    BYTE PTR [rax],al
 5a8:	50                   	push   rax
 5a9:	11 00                	adc    DWORD PTR [rax],eax
 5ab:	00 00                	add    BYTE PTR [rax],al
 5ad:	00 00                	add    BYTE PTR [rax],al
 5af:	00 b8 3d 00 00 00    	add    BYTE PTR [rax+0x3d],bh
 5b5:	00 00                	add    BYTE PTR [rax],al
 5b7:	00 08                	add    BYTE PTR [rax],cl
 5b9:	00 00                	add    BYTE PTR [rax],al
 5bb:	00 00                	add    BYTE PTR [rax],al
 5bd:	00 00                	add    BYTE PTR [rax],al
 5bf:	00 10                	add    BYTE PTR [rax],dl
 5c1:	11 00                	adc    DWORD PTR [rax],eax
 5c3:	00 00                	add    BYTE PTR [rax],al
 5c5:	00 00                	add    BYTE PTR [rax],al
 5c7:	00 08                	add    BYTE PTR [rax],cl
 5c9:	40 00 00             	rex add BYTE PTR [rax],al
 5cc:	00 00                	add    BYTE PTR [rax],al
 5ce:	00 00                	add    BYTE PTR [rax],al
 5d0:	08 00                	or     BYTE PTR [rax],al
 5d2:	00 00                	add    BYTE PTR [rax],al
 5d4:	00 00                	add    BYTE PTR [rax],al
 5d6:	00 00                	add    BYTE PTR [rax],al
 5d8:	08 40 00             	or     BYTE PTR [rax+0x0],al
 5db:	00 00                	add    BYTE PTR [rax],al
 5dd:	00 00                	add    BYTE PTR [rax],al
 5df:	00 d0                	add    al,dl
 5e1:	3f                   	(bad)  
 5e2:	00 00                	add    BYTE PTR [rax],al
 5e4:	00 00                	add    BYTE PTR [rax],al
 5e6:	00 00                	add    BYTE PTR [rax],al
 5e8:	06                   	(bad)  
 5e9:	00 00                	add    BYTE PTR [rax],al
 5eb:	00 01                	add    BYTE PTR [rcx],al
	...
 5f5:	00 00                	add    BYTE PTR [rax],al
 5f7:	00 d8                	add    al,bl
 5f9:	3f                   	(bad)  
 5fa:	00 00                	add    BYTE PTR [rax],al
 5fc:	00 00                	add    BYTE PTR [rax],al
 5fe:	00 00                	add    BYTE PTR [rax],al
 600:	06                   	(bad)  
 601:	00 00                	add    BYTE PTR [rax],al
 603:	00 02                	add    BYTE PTR [rdx],al
	...
 60d:	00 00                	add    BYTE PTR [rax],al
 60f:	00 e0                	add    al,ah
 611:	3f                   	(bad)  
 612:	00 00                	add    BYTE PTR [rax],al
 614:	00 00                	add    BYTE PTR [rax],al
 616:	00 00                	add    BYTE PTR [rax],al
 618:	06                   	(bad)  
 619:	00 00                	add    BYTE PTR [rax],al
 61b:	00 06                	add    BYTE PTR [rsi],al
	...
 625:	00 00                	add    BYTE PTR [rax],al
 627:	00 e8                	add    al,ch
 629:	3f                   	(bad)  
 62a:	00 00                	add    BYTE PTR [rax],al
 62c:	00 00                	add    BYTE PTR [rax],al
 62e:	00 00                	add    BYTE PTR [rax],al
 630:	06                   	(bad)  
 631:	00 00                	add    BYTE PTR [rax],al
 633:	00 04 00             	add    BYTE PTR [rax+rax*1],al
	...
 63e:	00 00                	add    BYTE PTR [rax],al
 640:	f0 3f                	lock (bad) 
 642:	00 00                	add    BYTE PTR [rax],al
 644:	00 00                	add    BYTE PTR [rax],al
 646:	00 00                	add    BYTE PTR [rax],al
 648:	06                   	(bad)  
 649:	00 00                	add    BYTE PTR [rax],al
 64b:	00 05 00 00 00 00    	add    BYTE PTR [rip+0x0],al        # 651 <__abi_tag+0x2c5>
 651:	00 00                	add    BYTE PTR [rax],al
 653:	00 00                	add    BYTE PTR [rax],al
 655:	00 00                	add    BYTE PTR [rax],al
 657:	00 f8                	add    al,bh
 659:	3f                   	(bad)  
 65a:	00 00                	add    BYTE PTR [rax],al
 65c:	00 00                	add    BYTE PTR [rax],al
 65e:	00 00                	add    BYTE PTR [rax],al
 660:	06                   	(bad)  
 661:	00 00                	add    BYTE PTR [rax],al
 663:	00 07                	add    BYTE PTR [rdi],al
	...

Disassembly of section .rela.plt:

0000000000000670 <.rela.plt>:
 670:	c8 3f 00 00          	enter  0x3f,0x0
 674:	00 00                	add    BYTE PTR [rax],al
 676:	00 00                	add    BYTE PTR [rax],al
 678:	07                   	(bad)  
 679:	00 00                	add    BYTE PTR [rax],al
 67b:	00 03                	add    BYTE PTR [rbx],al
	...

Disassembly of section .init:

0000000000001000 <_init>:
    1000:	f3 0f 1e fa          	endbr64 
    1004:	48 83 ec 08          	sub    rsp,0x8
    1008:	48 8b 05 d9 2f 00 00 	mov    rax,QWORD PTR [rip+0x2fd9]        # 3fe8 <__gmon_start__@Base>
    100f:	48 85 c0             	test   rax,rax
    1012:	74 02                	je     1016 <_init+0x16>
    1014:	ff d0                	call   rax
    1016:	48 83 c4 08          	add    rsp,0x8
    101a:	c3                   	ret    

Disassembly of section .plt:

0000000000001020 <.plt>:
    1020:	ff 35 92 2f 00 00    	push   QWORD PTR [rip+0x2f92]        # 3fb8 <_GLOBAL_OFFSET_TABLE_+0x8>
    1026:	f2 ff 25 93 2f 00 00 	bnd jmp QWORD PTR [rip+0x2f93]        # 3fc0 <_GLOBAL_OFFSET_TABLE_+0x10>
    102d:	0f 1f 00             	nop    DWORD PTR [rax]
    1030:	f3 0f 1e fa          	endbr64 
    1034:	68 00 00 00 00       	push   0x0
    1039:	f2 e9 e1 ff ff ff    	bnd jmp 1020 <_init+0x20>
    103f:	90                   	nop

Disassembly of section .plt.got:

0000000000001040 <printf@plt>:
    1040:	f3 0f 1e fa          	endbr64 
    1044:	f2 ff 25 95 2f 00 00 	bnd jmp QWORD PTR [rip+0x2f95]        # 3fe0 <printf@GLIBC_2.2.5>
    104b:	0f 1f 44 00 00       	nop    DWORD PTR [rax+rax*1+0x0]

0000000000001050 <__cxa_finalize@plt>:
    1050:	f3 0f 1e fa          	endbr64 
    1054:	f2 ff 25 9d 2f 00 00 	bnd jmp QWORD PTR [rip+0x2f9d]        # 3ff8 <__cxa_finalize@GLIBC_2.2.5>
    105b:	0f 1f 44 00 00       	nop    DWORD PTR [rax+rax*1+0x0]

Disassembly of section .plt.sec:

0000000000001060 <__stack_chk_fail@plt>:
    1060:	f3 0f 1e fa          	endbr64 
    1064:	f2 ff 25 5d 2f 00 00 	bnd jmp QWORD PTR [rip+0x2f5d]        # 3fc8 <__stack_chk_fail@GLIBC_2.4>
    106b:	0f 1f 44 00 00       	nop    DWORD PTR [rax+rax*1+0x0]

Disassembly of section .text:

0000000000001070 <_start>:
    1070:	f3 0f 1e fa          	endbr64 
    1074:	31 ed                	xor    ebp,ebp
    1076:	49 89 d1             	mov    r9,rdx
    1079:	5e                   	pop    rsi
    107a:	48 89 e2             	mov    rdx,rsp
    107d:	48 83 e4 f0          	and    rsp,0xfffffffffffffff0
    1081:	50                   	push   rax
    1082:	54                   	push   rsp
    1083:	45 31 c0             	xor    r8d,r8d
    1086:	31 c9                	xor    ecx,ecx
    1088:	48 8d 3d 56 01 00 00 	lea    rdi,[rip+0x156]        # 11e5 <main>
    108f:	ff 15 3b 2f 00 00    	call   QWORD PTR [rip+0x2f3b]        # 3fd0 <__libc_start_main@GLIBC_2.34>
    1095:	f4                   	hlt    
    1096:	66 2e 0f 1f 84 00 00 	cs nop WORD PTR [rax+rax*1+0x0]
    109d:	00 00 00 

00000000000010a0 <deregister_tm_clones>:
    10a0:	48 8d 3d 69 2f 00 00 	lea    rdi,[rip+0x2f69]        # 4010 <__TMC_END__>
    10a7:	48 8d 05 62 2f 00 00 	lea    rax,[rip+0x2f62]        # 4010 <__TMC_END__>
    10ae:	48 39 f8             	cmp    rax,rdi
    10b1:	74 15                	je     10c8 <deregister_tm_clones+0x28>
    10b3:	48 8b 05 1e 2f 00 00 	mov    rax,QWORD PTR [rip+0x2f1e]        # 3fd8 <_ITM_deregisterTMCloneTable@Base>
    10ba:	48 85 c0             	test   rax,rax
    10bd:	74 09                	je     10c8 <deregister_tm_clones+0x28>
    10bf:	ff e0                	jmp    rax
    10c1:	0f 1f 80 00 00 00 00 	nop    DWORD PTR [rax+0x0]
    10c8:	c3                   	ret    
    10c9:	0f 1f 80 00 00 00 00 	nop    DWORD PTR [rax+0x0]

00000000000010d0 <register_tm_clones>:
    10d0:	48 8d 3d 39 2f 00 00 	lea    rdi,[rip+0x2f39]        # 4010 <__TMC_END__>
    10d7:	48 8d 35 32 2f 00 00 	lea    rsi,[rip+0x2f32]        # 4010 <__TMC_END__>
    10de:	48 29 fe             	sub    rsi,rdi
    10e1:	48 89 f0             	mov    rax,rsi
    10e4:	48 c1 ee 3f          	shr    rsi,0x3f
    10e8:	48 c1 f8 03          	sar    rax,0x3
    10ec:	48 01 c6             	add    rsi,rax
    10ef:	48 d1 fe             	sar    rsi,1
    10f2:	74 14                	je     1108 <register_tm_clones+0x38>
    10f4:	48 8b 05 f5 2e 00 00 	mov    rax,QWORD PTR [rip+0x2ef5]        # 3ff0 <_ITM_registerTMCloneTable@Base>
    10fb:	48 85 c0             	test   rax,rax
    10fe:	74 08                	je     1108 <register_tm_clones+0x38>
    1100:	ff e0                	jmp    rax
    1102:	66 0f 1f 44 00 00    	nop    WORD PTR [rax+rax*1+0x0]
    1108:	c3                   	ret    
    1109:	0f 1f 80 00 00 00 00 	nop    DWORD PTR [rax+0x0]

0000000000001110 <__do_global_dtors_aux>:
    1110:	f3 0f 1e fa          	endbr64 
    1114:	80 3d f5 2e 00 00 00 	cmp    BYTE PTR [rip+0x2ef5],0x0        # 4010 <__TMC_END__>
    111b:	75 2b                	jne    1148 <__do_global_dtors_aux+0x38>
    111d:	55                   	push   rbp
    111e:	48 83 3d d2 2e 00 00 	cmp    QWORD PTR [rip+0x2ed2],0x0        # 3ff8 <__cxa_finalize@GLIBC_2.2.5>
    1125:	00 
    1126:	48 89 e5             	mov    rbp,rsp
    1129:	74 0c                	je     1137 <__do_global_dtors_aux+0x27>
    112b:	48 8b 3d d6 2e 00 00 	mov    rdi,QWORD PTR [rip+0x2ed6]        # 4008 <__dso_handle>
    1132:	e8 19 ff ff ff       	call   1050 <__cxa_finalize@plt>
    1137:	e8 64 ff ff ff       	call   10a0 <deregister_tm_clones>
    113c:	c6 05 cd 2e 00 00 01 	mov    BYTE PTR [rip+0x2ecd],0x1        # 4010 <__TMC_END__>
    1143:	5d                   	pop    rbp
    1144:	c3                   	ret    
    1145:	0f 1f 00             	nop    DWORD PTR [rax]
    1148:	c3                   	ret    
    1149:	0f 1f 80 00 00 00 00 	nop    DWORD PTR [rax+0x0]

0000000000001150 <frame_dummy>:
    1150:	f3 0f 1e fa          	endbr64 
    1154:	e9 77 ff ff ff       	jmp    10d0 <register_tm_clones>

0000000000001159 <solver>:
    1159:	f3 0f 1e fa          	endbr64 
    115d:	55                   	push   rbp
    115e:	48 89 e5             	mov    rbp,rsp
    1161:	48 83 ec 40          	sub    rsp,0x40
    1165:	48 89 7d c8          	mov    QWORD PTR [rbp-0x38],rdi
    1169:	64 48 8b 04 25 28 00 	mov    rax,QWORD PTR fs:0x28
    1170:	00 00 
    1172:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
    1176:	31 c0                	xor    eax,eax
    1178:	48 b8 68 65 6c 6c 6f 	movabs rax,0x77202c6f6c6c6568
    117f:	2c 20 77 
    1182:	48 ba 6f 72 6c 64 21 	movabs rdx,0x21646c726f
    1189:	00 00 00 
    118c:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
    1190:	48 89 55 e8          	mov    QWORD PTR [rbp-0x18],rdx
    1194:	c7 45 dc 18 00 00 00 	mov    DWORD PTR [rbp-0x24],0x18
    119b:	eb 2b                	jmp    11c8 <solver+0x6f>
    119d:	48 8d 55 e0          	lea    rdx,[rbp-0x20]
    11a1:	8b 45 dc             	mov    eax,DWORD PTR [rbp-0x24]
    11a4:	48 98                	cdqe   
    11a6:	48 01 d0             	add    rax,rdx
    11a9:	48 8b 00             	mov    rax,QWORD PTR [rax]
    11ac:	48 8b 55 c8          	mov    rdx,QWORD PTR [rbp-0x38]
    11b0:	48 89 c6             	mov    rsi,rax
    11b3:	48 8d 05 4a 0e 00 00 	lea    rax,[rip+0xe4a]        # 2004 <_IO_stdin_used+0x4>
    11ba:	48 89 c7             	mov    rdi,rax
    11bd:	b8 00 00 00 00       	mov    eax,0x0
    11c2:	ff d2                	call   rdx
    11c4:	83 45 dc 08          	add    DWORD PTR [rbp-0x24],0x8
    11c8:	83 7d dc 30          	cmp    DWORD PTR [rbp-0x24],0x30
    11cc:	7e cf                	jle    119d <solver+0x44>
    11ce:	90                   	nop
    11cf:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
    11d3:	64 48 2b 04 25 28 00 	sub    rax,QWORD PTR fs:0x28
    11da:	00 00 
    11dc:	74 05                	je     11e3 <solver+0x8a>
    11de:	e8 7d fe ff ff       	call   1060 <__stack_chk_fail@plt>
    11e3:	c9                   	leave  
    11e4:	c3                   	ret    

00000000000011e5 <main>:
    11e5:	f3 0f 1e fa          	endbr64 
    11e9:	55                   	push   rbp
    11ea:	48 89 e5             	mov    rbp,rsp
    11ed:	48 83 ec 20          	sub    rsp,0x20
    11f1:	64 48 8b 04 25 28 00 	mov    rax,QWORD PTR fs:0x28
    11f8:	00 00 
    11fa:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
    11fe:	31 c0                	xor    eax,eax
    1200:	48 b8 2a 2a 20 6d 61 	movabs rax,0x206e69616d202a2a
    1207:	69 6e 20 
    120a:	48 ba 3d 20 25 70 0a 	movabs rdx,0xa7025203d
    1211:	00 00 00 
    1214:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
    1218:	48 89 55 e8          	mov    QWORD PTR [rbp-0x18],rdx
    121c:	48 8d 45 e0          	lea    rax,[rbp-0x20]
    1220:	48 8d 15 be ff ff ff 	lea    rdx,[rip+0xffffffffffffffbe]        # 11e5 <main>
    1227:	48 89 d6             	mov    rsi,rdx
    122a:	48 89 c7             	mov    rdi,rax
    122d:	b8 00 00 00 00       	mov    eax,0x0
    1232:	e8 09 fe ff ff       	call   1040 <printf@plt>
    1237:	48 8b 05 a2 2d 00 00 	mov    rax,QWORD PTR [rip+0x2da2]        # 3fe0 <printf@GLIBC_2.2.5>
    123e:	48 89 c7             	mov    rdi,rax
    1241:	e8 13 ff ff ff       	call   1159 <solver>
    1246:	b8 00 00 00 00       	mov    eax,0x0
    124b:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
    124f:	64 48 2b 14 25 28 00 	sub    rdx,QWORD PTR fs:0x28
    1256:	00 00 
    1258:	74 05                	je     125f <main+0x7a>
    125a:	e8 01 fe ff ff       	call   1060 <__stack_chk_fail@plt>
    125f:	c9                   	leave  
    1260:	c3                   	ret    

Disassembly of section .fini:

0000000000001264 <_fini>:
    1264:	f3 0f 1e fa          	endbr64 
    1268:	48 83 ec 08          	sub    rsp,0x8
    126c:	48 83 c4 08          	add    rsp,0x8
    1270:	c3                   	ret    

Disassembly of section .rodata:

0000000000002000 <_IO_stdin_used>:
    2000:	01 00                	add    DWORD PTR [rax],eax
    2002:	02 00                	add    al,BYTE PTR [rax]
    2004:	25 30 31 36 6c       	and    eax,0x6c363130
    2009:	78 0a                	js     2015 <__GNU_EH_FRAME_HDR+0x9>
	...

Disassembly of section .eh_frame_hdr:

000000000000200c <__GNU_EH_FRAME_HDR>:
    200c:	01 1b                	add    DWORD PTR [rbx],ebx
    200e:	03 3b                	add    edi,DWORD PTR [rbx]
    2010:	38 00                	cmp    BYTE PTR [rax],al
    2012:	00 00                	add    BYTE PTR [rax],al
    2014:	06                   	(bad)  
    2015:	00 00                	add    BYTE PTR [rax],al
    2017:	00 14 f0             	add    BYTE PTR [rax+rsi*8],dl
    201a:	ff                   	(bad)  
    201b:	ff 6c 00 00          	jmp    FWORD PTR [rax+rax*1+0x0]
    201f:	00 34 f0             	add    BYTE PTR [rax+rsi*8],dh
    2022:	ff                   	(bad)  
    2023:	ff 94 00 00 00 54 f0 	call   QWORD PTR [rax+rax*1-0xfac0000]
    202a:	ff                   	(bad)  
    202b:	ff ac 00 00 00 64 f0 	jmp    FWORD PTR [rax+rax*1-0xf9c0000]
    2032:	ff                   	(bad)  
    2033:	ff 54 00 00          	call   QWORD PTR [rax+rax*1+0x0]
    2037:	00 4d f1             	add    BYTE PTR [rbp-0xf],cl
    203a:	ff                   	(bad)  
    203b:	ff c4                	inc    esp
    203d:	00 00                	add    BYTE PTR [rax],al
    203f:	00 d9                	add    cl,bl
    2041:	f1                   	int1   
    2042:	ff                   	(bad)  
    2043:	ff e4                	jmp    rsp
    2045:	00 00                	add    BYTE PTR [rax],al
	...

Disassembly of section .eh_frame:

0000000000002048 <__FRAME_END__-0xc8>:
    2048:	14 00                	adc    al,0x0
    204a:	00 00                	add    BYTE PTR [rax],al
    204c:	00 00                	add    BYTE PTR [rax],al
    204e:	00 00                	add    BYTE PTR [rax],al
    2050:	01 7a 52             	add    DWORD PTR [rdx+0x52],edi
    2053:	00 01                	add    BYTE PTR [rcx],al
    2055:	78 10                	js     2067 <__GNU_EH_FRAME_HDR+0x5b>
    2057:	01 1b                	add    DWORD PTR [rbx],ebx
    2059:	0c 07                	or     al,0x7
    205b:	08 90 01 00 00 14    	or     BYTE PTR [rax+0x14000001],dl
    2061:	00 00                	add    BYTE PTR [rax],al
    2063:	00 1c 00             	add    BYTE PTR [rax+rax*1],bl
    2066:	00 00                	add    BYTE PTR [rax],al
    2068:	08 f0                	or     al,dh
    206a:	ff                   	(bad)  
    206b:	ff 26                	jmp    QWORD PTR [rsi]
    206d:	00 00                	add    BYTE PTR [rax],al
    206f:	00 00                	add    BYTE PTR [rax],al
    2071:	44 07                	rex.R (bad) 
    2073:	10 00                	adc    BYTE PTR [rax],al
    2075:	00 00                	add    BYTE PTR [rax],al
    2077:	00 24 00             	add    BYTE PTR [rax+rax*1],ah
    207a:	00 00                	add    BYTE PTR [rax],al
    207c:	34 00                	xor    al,0x0
    207e:	00 00                	add    BYTE PTR [rax],al
    2080:	a0 ef ff ff 20 00 00 	movabs al,ds:0x20ffffef
    2087:	00 00 
    2089:	0e                   	(bad)  
    208a:	10 46 0e             	adc    BYTE PTR [rsi+0xe],al
    208d:	18 4a 0f             	sbb    BYTE PTR [rdx+0xf],cl
    2090:	0b 77 08             	or     esi,DWORD PTR [rdi+0x8]
    2093:	80 00 3f             	add    BYTE PTR [rax],0x3f
    2096:	1a 3a                	sbb    bh,BYTE PTR [rdx]
    2098:	2a 33                	sub    dh,BYTE PTR [rbx]
    209a:	24 22                	and    al,0x22
    209c:	00 00                	add    BYTE PTR [rax],al
    209e:	00 00                	add    BYTE PTR [rax],al
    20a0:	14 00                	adc    al,0x0
    20a2:	00 00                	add    BYTE PTR [rax],al
    20a4:	5c                   	pop    rsp
    20a5:	00 00                	add    BYTE PTR [rax],al
    20a7:	00 98 ef ff ff 20    	add    BYTE PTR [rax+0x20ffffef],bl
	...
    20b5:	00 00                	add    BYTE PTR [rax],al
    20b7:	00 14 00             	add    BYTE PTR [rax+rax*1],dl
    20ba:	00 00                	add    BYTE PTR [rax],al
    20bc:	74 00                	je     20be <__GNU_EH_FRAME_HDR+0xb2>
    20be:	00 00                	add    BYTE PTR [rax],al
    20c0:	a0 ef ff ff 10 00 00 	movabs al,ds:0x10ffffef
    20c7:	00 00 
    20c9:	00 00                	add    BYTE PTR [rax],al
    20cb:	00 00                	add    BYTE PTR [rax],al
    20cd:	00 00                	add    BYTE PTR [rax],al
    20cf:	00 1c 00             	add    BYTE PTR [rax+rax*1],bl
    20d2:	00 00                	add    BYTE PTR [rax],al
    20d4:	8c 00                	mov    WORD PTR [rax],es
    20d6:	00 00                	add    BYTE PTR [rax],al
    20d8:	81 f0 ff ff 8c 00    	xor    eax,0x8cffff
    20de:	00 00                	add    BYTE PTR [rax],al
    20e0:	00 45 0e             	add    BYTE PTR [rbp+0xe],al
    20e3:	10 86 02 43 0d 06    	adc    BYTE PTR [rsi+0x60d4302],al
    20e9:	02 83 0c 07 08 00    	add    al,BYTE PTR [rbx+0x8070c]
    20ef:	00 1c 00             	add    BYTE PTR [rax+rax*1],bl
    20f2:	00 00                	add    BYTE PTR [rax],al
    20f4:	ac                   	lods   al,BYTE PTR ds:[rsi]
    20f5:	00 00                	add    BYTE PTR [rax],al
    20f7:	00 ed                	add    ch,ch
    20f9:	f0 ff                	lock (bad) 
    20fb:	ff                   	(bad)  
    20fc:	7c 00                	jl     20fe <__GNU_EH_FRAME_HDR+0xf2>
    20fe:	00 00                	add    BYTE PTR [rax],al
    2100:	00 45 0e             	add    BYTE PTR [rbp+0xe],al
    2103:	10 86 02 43 0d 06    	adc    BYTE PTR [rsi+0x60d4302],al
    2109:	02 73 0c             	add    dh,BYTE PTR [rbx+0xc]
    210c:	07                   	(bad)  
    210d:	08 00                	or     BYTE PTR [rax],al
	...

0000000000002110 <__FRAME_END__>:
    2110:	00 00                	add    BYTE PTR [rax],al
	...

Disassembly of section .init_array:

0000000000003db0 <__frame_dummy_init_array_entry>:
    3db0:	50                   	push   rax
    3db1:	11 00                	adc    DWORD PTR [rax],eax
    3db3:	00 00                	add    BYTE PTR [rax],al
    3db5:	00 00                	add    BYTE PTR [rax],al
	...

Disassembly of section .fini_array:

0000000000003db8 <__do_global_dtors_aux_fini_array_entry>:
    3db8:	10 11                	adc    BYTE PTR [rcx],dl
    3dba:	00 00                	add    BYTE PTR [rax],al
    3dbc:	00 00                	add    BYTE PTR [rax],al
	...

Disassembly of section .dynamic:

0000000000003dc0 <_DYNAMIC>:
    3dc0:	01 00                	add    DWORD PTR [rax],eax
    3dc2:	00 00                	add    BYTE PTR [rax],al
    3dc4:	00 00                	add    BYTE PTR [rax],al
    3dc6:	00 00                	add    BYTE PTR [rax],al
    3dc8:	3a 00                	cmp    al,BYTE PTR [rax]
    3dca:	00 00                	add    BYTE PTR [rax],al
    3dcc:	00 00                	add    BYTE PTR [rax],al
    3dce:	00 00                	add    BYTE PTR [rax],al
    3dd0:	0c 00                	or     al,0x0
    3dd2:	00 00                	add    BYTE PTR [rax],al
    3dd4:	00 00                	add    BYTE PTR [rax],al
    3dd6:	00 00                	add    BYTE PTR [rax],al
    3dd8:	00 10                	add    BYTE PTR [rax],dl
    3dda:	00 00                	add    BYTE PTR [rax],al
    3ddc:	00 00                	add    BYTE PTR [rax],al
    3dde:	00 00                	add    BYTE PTR [rax],al
    3de0:	0d 00 00 00 00       	or     eax,0x0
    3de5:	00 00                	add    BYTE PTR [rax],al
    3de7:	00 64 12 00          	add    BYTE PTR [rdx+rdx*1+0x0],ah
    3deb:	00 00                	add    BYTE PTR [rax],al
    3ded:	00 00                	add    BYTE PTR [rax],al
    3def:	00 19                	add    BYTE PTR [rcx],bl
    3df1:	00 00                	add    BYTE PTR [rax],al
    3df3:	00 00                	add    BYTE PTR [rax],al
    3df5:	00 00                	add    BYTE PTR [rax],al
    3df7:	00 b0 3d 00 00 00    	add    BYTE PTR [rax+0x3d],dh
    3dfd:	00 00                	add    BYTE PTR [rax],al
    3dff:	00 1b                	add    BYTE PTR [rbx],bl
    3e01:	00 00                	add    BYTE PTR [rax],al
    3e03:	00 00                	add    BYTE PTR [rax],al
    3e05:	00 00                	add    BYTE PTR [rax],al
    3e07:	00 08                	add    BYTE PTR [rax],cl
    3e09:	00 00                	add    BYTE PTR [rax],al
    3e0b:	00 00                	add    BYTE PTR [rax],al
    3e0d:	00 00                	add    BYTE PTR [rax],al
    3e0f:	00 1a                	add    BYTE PTR [rdx],bl
    3e11:	00 00                	add    BYTE PTR [rax],al
    3e13:	00 00                	add    BYTE PTR [rax],al
    3e15:	00 00                	add    BYTE PTR [rax],al
    3e17:	00 b8 3d 00 00 00    	add    BYTE PTR [rax+0x3d],bh
    3e1d:	00 00                	add    BYTE PTR [rax],al
    3e1f:	00 1c 00             	add    BYTE PTR [rax+rax*1],bl
    3e22:	00 00                	add    BYTE PTR [rax],al
    3e24:	00 00                	add    BYTE PTR [rax],al
    3e26:	00 00                	add    BYTE PTR [rax],al
    3e28:	08 00                	or     BYTE PTR [rax],al
    3e2a:	00 00                	add    BYTE PTR [rax],al
    3e2c:	00 00                	add    BYTE PTR [rax],al
    3e2e:	00 00                	add    BYTE PTR [rax],al
    3e30:	f5                   	cmc    
    3e31:	fe                   	(bad)  
    3e32:	ff 6f 00             	jmp    FWORD PTR [rdi+0x0]
    3e35:	00 00                	add    BYTE PTR [rax],al
    3e37:	00 b0 03 00 00 00    	add    BYTE PTR [rax+0x3],dh
    3e3d:	00 00                	add    BYTE PTR [rax],al
    3e3f:	00 05 00 00 00 00    	add    BYTE PTR [rip+0x0],al        # 3e45 <_DYNAMIC+0x85>
    3e45:	00 00                	add    BYTE PTR [rax],al
    3e47:	00 98 04 00 00 00    	add    BYTE PTR [rax+0x4],bl
    3e4d:	00 00                	add    BYTE PTR [rax],al
    3e4f:	00 06                	add    BYTE PTR [rsi],al
    3e51:	00 00                	add    BYTE PTR [rax],al
    3e53:	00 00                	add    BYTE PTR [rax],al
    3e55:	00 00                	add    BYTE PTR [rax],al
    3e57:	00 d8                	add    al,bl
    3e59:	03 00                	add    eax,DWORD PTR [rax]
    3e5b:	00 00                	add    BYTE PTR [rax],al
    3e5d:	00 00                	add    BYTE PTR [rax],al
    3e5f:	00 0a                	add    BYTE PTR [rdx],cl
    3e61:	00 00                	add    BYTE PTR [rax],al
    3e63:	00 00                	add    BYTE PTR [rax],al
    3e65:	00 00                	add    BYTE PTR [rax],al
    3e67:	00 aa 00 00 00 00    	add    BYTE PTR [rdx+0x0],ch
    3e6d:	00 00                	add    BYTE PTR [rax],al
    3e6f:	00 0b                	add    BYTE PTR [rbx],cl
    3e71:	00 00                	add    BYTE PTR [rax],al
    3e73:	00 00                	add    BYTE PTR [rax],al
    3e75:	00 00                	add    BYTE PTR [rax],al
    3e77:	00 18                	add    BYTE PTR [rax],bl
    3e79:	00 00                	add    BYTE PTR [rax],al
    3e7b:	00 00                	add    BYTE PTR [rax],al
    3e7d:	00 00                	add    BYTE PTR [rax],al
    3e7f:	00 15 00 00 00 00    	add    BYTE PTR [rip+0x0],dl        # 3e85 <_DYNAMIC+0xc5>
	...
    3e8d:	00 00                	add    BYTE PTR [rax],al
    3e8f:	00 03                	add    BYTE PTR [rbx],al
    3e91:	00 00                	add    BYTE PTR [rax],al
    3e93:	00 00                	add    BYTE PTR [rax],al
    3e95:	00 00                	add    BYTE PTR [rax],al
    3e97:	00 b0 3f 00 00 00    	add    BYTE PTR [rax+0x3f],dh
    3e9d:	00 00                	add    BYTE PTR [rax],al
    3e9f:	00 02                	add    BYTE PTR [rdx],al
    3ea1:	00 00                	add    BYTE PTR [rax],al
    3ea3:	00 00                	add    BYTE PTR [rax],al
    3ea5:	00 00                	add    BYTE PTR [rax],al
    3ea7:	00 18                	add    BYTE PTR [rax],bl
    3ea9:	00 00                	add    BYTE PTR [rax],al
    3eab:	00 00                	add    BYTE PTR [rax],al
    3ead:	00 00                	add    BYTE PTR [rax],al
    3eaf:	00 14 00             	add    BYTE PTR [rax+rax*1],dl
    3eb2:	00 00                	add    BYTE PTR [rax],al
    3eb4:	00 00                	add    BYTE PTR [rax],al
    3eb6:	00 00                	add    BYTE PTR [rax],al
    3eb8:	07                   	(bad)  
    3eb9:	00 00                	add    BYTE PTR [rax],al
    3ebb:	00 00                	add    BYTE PTR [rax],al
    3ebd:	00 00                	add    BYTE PTR [rax],al
    3ebf:	00 17                	add    BYTE PTR [rdi],dl
    3ec1:	00 00                	add    BYTE PTR [rax],al
    3ec3:	00 00                	add    BYTE PTR [rax],al
    3ec5:	00 00                	add    BYTE PTR [rax],al
    3ec7:	00 70 06             	add    BYTE PTR [rax+0x6],dh
    3eca:	00 00                	add    BYTE PTR [rax],al
    3ecc:	00 00                	add    BYTE PTR [rax],al
    3ece:	00 00                	add    BYTE PTR [rax],al
    3ed0:	07                   	(bad)  
    3ed1:	00 00                	add    BYTE PTR [rax],al
    3ed3:	00 00                	add    BYTE PTR [rax],al
    3ed5:	00 00                	add    BYTE PTR [rax],al
    3ed7:	00 98 05 00 00 00    	add    BYTE PTR [rax+0x5],bl
    3edd:	00 00                	add    BYTE PTR [rax],al
    3edf:	00 08                	add    BYTE PTR [rax],cl
    3ee1:	00 00                	add    BYTE PTR [rax],al
    3ee3:	00 00                	add    BYTE PTR [rax],al
    3ee5:	00 00                	add    BYTE PTR [rax],al
    3ee7:	00 d8                	add    al,bl
    3ee9:	00 00                	add    BYTE PTR [rax],al
    3eeb:	00 00                	add    BYTE PTR [rax],al
    3eed:	00 00                	add    BYTE PTR [rax],al
    3eef:	00 09                	add    BYTE PTR [rcx],cl
    3ef1:	00 00                	add    BYTE PTR [rax],al
    3ef3:	00 00                	add    BYTE PTR [rax],al
    3ef5:	00 00                	add    BYTE PTR [rax],al
    3ef7:	00 18                	add    BYTE PTR [rax],bl
    3ef9:	00 00                	add    BYTE PTR [rax],al
    3efb:	00 00                	add    BYTE PTR [rax],al
    3efd:	00 00                	add    BYTE PTR [rax],al
    3eff:	00 1e                	add    BYTE PTR [rsi],bl
    3f01:	00 00                	add    BYTE PTR [rax],al
    3f03:	00 00                	add    BYTE PTR [rax],al
    3f05:	00 00                	add    BYTE PTR [rax],al
    3f07:	00 08                	add    BYTE PTR [rax],cl
    3f09:	00 00                	add    BYTE PTR [rax],al
    3f0b:	00 00                	add    BYTE PTR [rax],al
    3f0d:	00 00                	add    BYTE PTR [rax],al
    3f0f:	00 fb                	add    bl,bh
    3f11:	ff                   	(bad)  
    3f12:	ff 6f 00             	jmp    FWORD PTR [rdi+0x0]
    3f15:	00 00                	add    BYTE PTR [rax],al
    3f17:	00 01                	add    BYTE PTR [rcx],al
    3f19:	00 00                	add    BYTE PTR [rax],al
    3f1b:	08 00                	or     BYTE PTR [rax],al
    3f1d:	00 00                	add    BYTE PTR [rax],al
    3f1f:	00 fe                	add    dh,bh
    3f21:	ff                   	(bad)  
    3f22:	ff 6f 00             	jmp    FWORD PTR [rdi+0x0]
    3f25:	00 00                	add    BYTE PTR [rax],al
    3f27:	00 58 05             	add    BYTE PTR [rax+0x5],bl
    3f2a:	00 00                	add    BYTE PTR [rax],al
    3f2c:	00 00                	add    BYTE PTR [rax],al
    3f2e:	00 00                	add    BYTE PTR [rax],al
    3f30:	ff                   	(bad)  
    3f31:	ff                   	(bad)  
    3f32:	ff 6f 00             	jmp    FWORD PTR [rdi+0x0]
    3f35:	00 00                	add    BYTE PTR [rax],al
    3f37:	00 01                	add    BYTE PTR [rcx],al
    3f39:	00 00                	add    BYTE PTR [rax],al
    3f3b:	00 00                	add    BYTE PTR [rax],al
    3f3d:	00 00                	add    BYTE PTR [rax],al
    3f3f:	00 f0                	add    al,dh
    3f41:	ff                   	(bad)  
    3f42:	ff 6f 00             	jmp    FWORD PTR [rdi+0x0]
    3f45:	00 00                	add    BYTE PTR [rax],al
    3f47:	00 42 05             	add    BYTE PTR [rdx+0x5],al
    3f4a:	00 00                	add    BYTE PTR [rax],al
    3f4c:	00 00                	add    BYTE PTR [rax],al
    3f4e:	00 00                	add    BYTE PTR [rax],al
    3f50:	f9                   	stc    
    3f51:	ff                   	(bad)  
    3f52:	ff 6f 00             	jmp    FWORD PTR [rdi+0x0]
    3f55:	00 00                	add    BYTE PTR [rax],al
    3f57:	00 03                	add    BYTE PTR [rbx],al
	...

Disassembly of section .got:

0000000000003fb0 <_GLOBAL_OFFSET_TABLE_>:
    3fb0:	c0 3d 00 00 00 00 00 	sar    BYTE PTR [rip+0x0],0x0        # 3fb7 <_GLOBAL_OFFSET_TABLE_+0x7>
	...
    3fc7:	00 30                	add    BYTE PTR [rax],dh
    3fc9:	10 00                	adc    BYTE PTR [rax],al
	...

Disassembly of section .data:

0000000000004000 <__data_start>:
	...

0000000000004008 <__dso_handle>:
    4008:	08 40 00             	or     BYTE PTR [rax+0x0],al
    400b:	00 00                	add    BYTE PTR [rax],al
    400d:	00 00                	add    BYTE PTR [rax],al
	...

Disassembly of section .bss:

0000000000004010 <completed.0>:
	...

Disassembly of section .comment:

0000000000000000 <.comment>:
   0:	47                   	rex.RXB
   1:	43                   	rex.XB
   2:	43 3a 20             	rex.XB cmp spl,BYTE PTR [r8]
   5:	28 55 62             	sub    BYTE PTR [rbp+0x62],dl
   8:	75 6e                	jne    78 <__abi_tag-0x314>
   a:	74 75                	je     81 <__abi_tag-0x30b>
   c:	20 31                	and    BYTE PTR [rcx],dh
   e:	31 2e                	xor    DWORD PTR [rsi],ebp
  10:	33 2e                	xor    ebp,DWORD PTR [rsi]
  12:	30 2d 31 75 62 75    	xor    BYTE PTR [rip+0x75627531],ch        # 75627549 <_end+0x75623531>
  18:	6e                   	outs   dx,BYTE PTR ds:[rsi]
  19:	74 75                	je     90 <__abi_tag-0x2fc>
  1b:	31 7e 32             	xor    DWORD PTR [rsi+0x32],edi
  1e:	32 2e                	xor    ch,BYTE PTR [rsi]
  20:	30 34 29             	xor    BYTE PTR [rcx+rbp*1],dh
  23:	20 31                	and    BYTE PTR [rcx],dh
  25:	31 2e                	xor    DWORD PTR [rsi],ebp
  27:	33 2e                	xor    ebp,DWORD PTR [rsi]
  29:	30 00                	xor    BYTE PTR [rax],al
