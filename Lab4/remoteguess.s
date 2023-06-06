
remoteguess:     file format elf64-x86-64


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
 377:	00 5c f1 af          	add    BYTE PTR [rcx+rsi*8-0x51],bl
 37b:	09 f8                	or     eax,edi
 37d:	f6 fe                	idiv   dh
 37f:	bf 54 07 10 70       	mov    edi,0x70100754
 384:	ae                   	scas   al,BYTE PTR es:[rdi]
 385:	08 c3                	or     bl,al
 387:	00                   	.byte 0x0
 388:	8c                   	.byte 0x8c
 389:	91                   	xchg   ecx,eax
 38a:	5b                   	pop    rbx
 38b:	67                   	addr32

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
 3b0:	03 00                	add    eax,DWORD PTR [rax]
 3b2:	00 00                	add    BYTE PTR [rax],al
 3b4:	16                   	(bad)  
 3b5:	00 00                	add    BYTE PTR [rax],al
 3b7:	00 01                	add    BYTE PTR [rcx],al
 3b9:	00 00                	add    BYTE PTR [rax],al
 3bb:	00 06                	add    BYTE PTR [rsi],al
 3bd:	00 00                	add    BYTE PTR [rax],al
 3bf:	00 00                	add    BYTE PTR [rax],al
 3c1:	01 a1 00 80 41 10    	add    DWORD PTR [rcx+0x10418000],esp
 3c7:	03 16                	add    edx,DWORD PTR [rsi]
 3c9:	00 00                	add    BYTE PTR [rax],al
 3cb:	00 18                	add    BYTE PTR [rax],bl
 3cd:	00 00                	add    BYTE PTR [rax],al
 3cf:	00 00                	add    BYTE PTR [rax],al
 3d1:	00 00                	add    BYTE PTR [rax],al
 3d3:	00 28                	add    BYTE PTR [rax],ch
 3d5:	1d 8c 1c d1 65       	sbb    eax,0x65d11c8c
 3da:	ce                   	(bad)  
 3db:	6d                   	ins    DWORD PTR es:[rdi],dx
 3dc:	66 55                	push   bp
 3de:	61                   	(bad)  
 3df:	10 b8 2b 6b 15 39    	adc    BYTE PTR [rax+0x39156b2b],bh
 3e5:	f2                   	repnz
 3e6:	8b                   	.byte 0x8b
 3e7:	1c                   	.byte 0x1c

Disassembly of section .dynsym:

00000000000003e8 <.dynsym>:
	...
 400:	82                   	(bad)  
 401:	00 00                	add    BYTE PTR [rax],al
 403:	00 12                	add    BYTE PTR [rdx],dl
	...
 415:	00 00                	add    BYTE PTR [rax],al
 417:	00 2b                	add    BYTE PTR [rbx],ch
 419:	00 00                	add    BYTE PTR [rax],al
 41b:	00 12                	add    BYTE PTR [rdx],dl
	...
 42d:	00 00                	add    BYTE PTR [rax],al
 42f:	00 ff                	add    bh,bh
 431:	00 00                	add    BYTE PTR [rax],al
 433:	00 20                	add    BYTE PTR [rax],ah
	...
 445:	00 00                	add    BYTE PTR [rax],al
 447:	00 7c 00 00          	add    BYTE PTR [rax+rax*1+0x0],bh
 44b:	00 12                	add    BYTE PTR [rdx],dl
	...
 45d:	00 00                	add    BYTE PTR [rax],al
 45f:	00 53 00             	add    BYTE PTR [rbx+0x0],dl
 462:	00 00                	add    BYTE PTR [rax],al
 464:	12 00                	adc    al,BYTE PTR [rax]
	...
 476:	00 00                	add    BYTE PTR [rax],al
 478:	25 00 00 00 12       	and    eax,0x12000000
	...
 48d:	00 00                	add    BYTE PTR [rax],al
 48f:	00 a2 00 00 00 12    	add    BYTE PTR [rdx+0x12000000],ah
	...
 4a5:	00 00                	add    BYTE PTR [rax],al
 4a7:	00 ba 00 00 00 12    	add    BYTE PTR [rdx+0x12000000],bh
	...
 4bd:	00 00                	add    BYTE PTR [rax],al
 4bf:	00 58 00             	add    BYTE PTR [rax+0x0],bl
 4c2:	00 00                	add    BYTE PTR [rax],al
 4c4:	12 00                	adc    al,BYTE PTR [rax]
	...
 4d6:	00 00                	add    BYTE PTR [rax],al
 4d8:	20 00                	and    BYTE PTR [rax],al
 4da:	00 00                	add    BYTE PTR [rax],al
 4dc:	12 00                	adc    al,BYTE PTR [rax]
	...
 4ee:	00 00                	add    BYTE PTR [rax],al
 4f0:	1a 00                	sbb    al,BYTE PTR [rax]
 4f2:	00 00                	add    BYTE PTR [rax],al
 4f4:	12 00                	adc    al,BYTE PTR [rax]
	...
 506:	00 00                	add    BYTE PTR [rax],al
 508:	1b 01                	sbb    eax,DWORD PTR [rcx]
 50a:	00 00                	add    BYTE PTR [rax],al
 50c:	20 00                	and    BYTE PTR [rax],al
	...
 51e:	00 00                	add    BYTE PTR [rax],al
 520:	3d 00 00 00 12       	cmp    eax,0x12000000
	...
 535:	00 00                	add    BYTE PTR [rax],al
 537:	00 8a 00 00 00 12    	add    BYTE PTR [rdx+0x12000000],cl
	...
 54d:	00 00                	add    BYTE PTR [rax],al
 54f:	00 44 00 00          	add    BYTE PTR [rax+rax*1+0x0],al
 553:	00 12                	add    BYTE PTR [rdx],dl
	...
 565:	00 00                	add    BYTE PTR [rax],al
 567:	00 9a 00 00 00 12    	add    BYTE PTR [rdx+0x12000000],bl
	...
 57d:	00 00                	add    BYTE PTR [rax],al
 57f:	00 5e 00             	add    BYTE PTR [rsi+0x0],bl
 582:	00 00                	add    BYTE PTR [rax],al
 584:	12 00                	adc    al,BYTE PTR [rax]
	...
 596:	00 00                	add    BYTE PTR [rax],al
 598:	75 00                	jne    59a <__abi_tag+0x20e>
 59a:	00 00                	add    BYTE PTR [rax],al
 59c:	12 00                	adc    al,BYTE PTR [rax]
	...
 5ae:	00 00                	add    BYTE PTR [rax],al
 5b0:	2a 01                	sub    al,BYTE PTR [rcx]
 5b2:	00 00                	add    BYTE PTR [rax],al
 5b4:	20 00                	and    BYTE PTR [rax],al
	...
 5c6:	00 00                	add    BYTE PTR [rax],al
 5c8:	01 00                	add    DWORD PTR [rax],eax
 5ca:	00 00                	add    BYTE PTR [rax],al
 5cc:	12 00                	adc    al,BYTE PTR [rax]
	...
 5de:	00 00                	add    BYTE PTR [rax],al
 5e0:	69 00 00 00 12 00    	imul   eax,DWORD PTR [rax],0x120000
	...
 5f6:	00 00                	add    BYTE PTR [rax],al
 5f8:	4c 00 00             	rex.WR add BYTE PTR [rax],r8b
 5fb:	00 11                	add    BYTE PTR [rcx],dl
 5fd:	00 1a                	add    BYTE PTR [rdx],bl
 5ff:	00 20                	add    BYTE PTR [rax],ah
 601:	40 00 00             	rex add BYTE PTR [rax],al
 604:	00 00                	add    BYTE PTR [rax],al
 606:	00 00                	add    BYTE PTR [rax],al
 608:	08 00                	or     BYTE PTR [rax],al
 60a:	00 00                	add    BYTE PTR [rax],al
 60c:	00 00                	add    BYTE PTR [rax],al
 60e:	00 00                	add    BYTE PTR [rax],al
 610:	0b 00                	or     eax,DWORD PTR [rax]
 612:	00 00                	add    BYTE PTR [rax],al
 614:	22 00                	and    al,BYTE PTR [rax]
	...
 626:	00 00                	add    BYTE PTR [rax],al
 628:	63 00                	movsxd eax,DWORD PTR [rax]
 62a:	00 00                	add    BYTE PTR [rax],al
 62c:	11 00                	adc    DWORD PTR [rax],eax
 62e:	1a 00                	sbb    al,BYTE PTR [rax]
 630:	30 40 00             	xor    BYTE PTR [rax+0x0],al
 633:	00 00                	add    BYTE PTR [rax],al
 635:	00 00                	add    BYTE PTR [rax],al
 637:	00 08                	add    BYTE PTR [rax],cl
 639:	00 00                	add    BYTE PTR [rax],al
 63b:	00 00                	add    BYTE PTR [rax],al
 63d:	00 00                	add    BYTE PTR [rax],al
 63f:	00 b3 00 00 00 12    	add    BYTE PTR [rbx+0x12000000],dh
	...
 655:	00 00                	add    BYTE PTR [rax],al
 657:	00 6e 00             	add    BYTE PTR [rsi+0x0],ch
 65a:	00 00                	add    BYTE PTR [rax],al
 65c:	11 00                	adc    DWORD PTR [rax],eax
 65e:	1a 00                	sbb    al,BYTE PTR [rax]
 660:	40                   	rex
 661:	40 00 00             	rex add BYTE PTR [rax],al
 664:	00 00                	add    BYTE PTR [rax],al
 666:	00 00                	add    BYTE PTR [rax],al
 668:	08 00                	or     BYTE PTR [rax],al
 66a:	00 00                	add    BYTE PTR [rax],al
 66c:	00 00                	add    BYTE PTR [rax],al
	...

Disassembly of section .dynstr:

0000000000000670 <.dynstr>:
 670:	00 67 65             	add    BYTE PTR [rdi+0x65],ah
 673:	74 72                	je     6e7 <__abi_tag+0x35b>
 675:	61                   	(bad)  
 676:	6e                   	outs   dx,BYTE PTR ds:[rsi]
 677:	64 6f                	outs   dx,DWORD PTR fs:[rsi]
 679:	6d                   	ins    DWORD PTR es:[rdi],dx
 67a:	00 5f 5f             	add    BYTE PTR [rdi+0x5f],bl
 67d:	63 78 61             	movsxd edi,DWORD PTR [rax+0x61]
 680:	5f                   	pop    rdi
 681:	66 69 6e 61 6c 69    	imul   bp,WORD PTR [rsi+0x61],0x696c
 687:	7a 65                	jp     6ee <__abi_tag+0x362>
 689:	00 66 67             	add    BYTE PTR [rsi+0x67],ah
 68c:	65 74 73             	gs je  702 <__abi_tag+0x376>
 68f:	00 72 65             	add    BYTE PTR [rdx+0x65],dh
 692:	61                   	(bad)  
 693:	64 00 77 72          	add    BYTE PTR fs:[rdi+0x72],dh
 697:	69 74 65 00 5f 5f 6c 	imul   esi,DWORD PTR [rbp+riz*2+0x0],0x696c5f5f
 69e:	69 
 69f:	62 63 5f 73 74       	(bad)
 6a4:	61                   	(bad)  
 6a5:	72 74                	jb     71b <__abi_tag+0x38f>
 6a7:	5f                   	pop    rdi
 6a8:	6d                   	ins    DWORD PTR es:[rdi],dx
 6a9:	61                   	(bad)  
 6aa:	69 6e 00 73 74 72 74 	imul   ebp,DWORD PTR [rsi+0x0],0x74727473
 6b1:	6f                   	outs   dx,DWORD PTR ds:[rsi]
 6b2:	6c                   	ins    BYTE PTR es:[rdi],dx
 6b3:	00 73 65             	add    BYTE PTR [rbx+0x65],dh
 6b6:	74 76                	je     72e <__abi_tag+0x3a2>
 6b8:	62 75 66 00 73       	(bad)
 6bd:	74 64                	je     723 <__abi_tag+0x397>
 6bf:	6f                   	outs   dx,DWORD PTR ds:[rsi]
 6c0:	75 74                	jne    736 <__abi_tag+0x3aa>
 6c2:	00 70 75             	add    BYTE PTR [rax+0x75],dh
 6c5:	74 73                	je     73a <__abi_tag+0x3ae>
 6c7:	00 63 6c             	add    BYTE PTR [rbx+0x6c],ah
 6ca:	6f                   	outs   dx,DWORD PTR ds:[rsi]
 6cb:	73 65                	jae    732 <__abi_tag+0x3a6>
 6cd:	00 6f 70             	add    BYTE PTR [rdi+0x70],ch
 6d0:	65 6e                	outs   dx,BYTE PTR gs:[rsi]
 6d2:	00 73 74             	add    BYTE PTR [rbx+0x74],dh
 6d5:	64 69 6e 00 66 6f 72 	imul   ebp,DWORD PTR fs:[rsi+0x0],0x6b726f66
 6dc:	6b 
 6dd:	00 73 74             	add    BYTE PTR [rbx+0x74],dh
 6e0:	64 65 72 72          	fs gs jb 756 <__abi_tag+0x3ca>
 6e4:	00 70 65             	add    BYTE PTR [rax+0x65],dh
 6e7:	72 72                	jb     75b <__abi_tag+0x3cf>
 6e9:	6f                   	outs   dx,DWORD PTR ds:[rsi]
 6ea:	72 00                	jb     6ec <__abi_tag+0x360>
 6ec:	5f                   	pop    rdi
 6ed:	65 78 69             	gs js  759 <__abi_tag+0x3cd>
 6f0:	74 00                	je     6f2 <__abi_tag+0x366>
 6f2:	70 75                	jo     769 <__abi_tag+0x3dd>
 6f4:	74 63                	je     759 <__abi_tag+0x3cd>
 6f6:	68 61 72 00 5f       	push   0x5f007261
 6fb:	5f                   	pop    rdi
 6fc:	69 73 6f 63 39 39 5f 	imul   esi,DWORD PTR [rbx+0x6f],0x5f393963
 703:	73 73                	jae    778 <__abi_tag+0x3ec>
 705:	63 61 6e             	movsxd esp,DWORD PTR [rcx+0x6e]
 708:	66 00 77 61          	data16 add BYTE PTR [rdi+0x61],dh
 70c:	69 74 70 69 64 00 5f 	imul   esi,DWORD PTR [rax+rsi*2+0x69],0x5f5f0064
 713:	5f 
 714:	73 74                	jae    78a <__abi_tag+0x3fe>
 716:	61                   	(bad)  
 717:	63 6b 5f             	movsxd ebp,DWORD PTR [rbx+0x5f]
 71a:	63 68 6b             	movsxd ebp,DWORD PTR [rax+0x6b]
 71d:	5f                   	pop    rdi
 71e:	66 61                	data16 (bad) 
 720:	69 6c 00 70 72 69 6e 	imul   ebp,DWORD PTR [rax+rax*1+0x70],0x746e6972
 727:	74 
 728:	66 00 6d 6d          	data16 add BYTE PTR [rbp+0x6d],ch
 72c:	61                   	(bad)  
 72d:	70 00                	jo     72f <__abi_tag+0x3a3>
 72f:	6c                   	ins    BYTE PTR es:[rdi],dx
 730:	69 62 63 2e 73 6f 2e 	imul   esp,DWORD PTR [rdx+0x63],0x2e6f732e
 737:	36 00 47 4c          	ss add BYTE PTR [rdi+0x4c],al
 73b:	49                   	rex.WB
 73c:	42                   	rex.X
 73d:	43 5f                	rex.XB pop r15
 73f:	32 2e                	xor    ch,BYTE PTR [rsi]
 741:	32 35 00 47 4c 49    	xor    dh,BYTE PTR [rip+0x494c4700]        # 494c4e47 <_end+0x494c0df7>
 747:	42                   	rex.X
 748:	43 5f                	rex.XB pop r15
 74a:	32 2e                	xor    ch,BYTE PTR [rsi]
 74c:	37                   	(bad)  
 74d:	00 47 4c             	add    BYTE PTR [rdi+0x4c],al
 750:	49                   	rex.WB
 751:	42                   	rex.X
 752:	43 5f                	rex.XB pop r15
 754:	32 2e                	xor    ch,BYTE PTR [rsi]
 756:	34 00                	xor    al,0x0
 758:	47                   	rex.RXB
 759:	4c                   	rex.WR
 75a:	49                   	rex.WB
 75b:	42                   	rex.X
 75c:	43 5f                	rex.XB pop r15
 75e:	32 2e                	xor    ch,BYTE PTR [rsi]
 760:	33 34 00             	xor    esi,DWORD PTR [rax+rax*1]
 763:	47                   	rex.RXB
 764:	4c                   	rex.WR
 765:	49                   	rex.WB
 766:	42                   	rex.X
 767:	43 5f                	rex.XB pop r15
 769:	32 2e                	xor    ch,BYTE PTR [rsi]
 76b:	32 2e                	xor    ch,BYTE PTR [rsi]
 76d:	35 00 5f 49 54       	xor    eax,0x54495f00
 772:	4d 5f                	rex.WRB pop r15
 774:	64 65 72 65          	fs gs jb 7dd <__abi_tag+0x451>
 778:	67 69 73 74 65 72 54 	imul   esi,DWORD PTR [ebx+0x74],0x4d547265
 77f:	4d 
 780:	43 6c                	rex.XB ins BYTE PTR es:[rdi],dx
 782:	6f                   	outs   dx,DWORD PTR ds:[rsi]
 783:	6e                   	outs   dx,BYTE PTR ds:[rsi]
 784:	65 54                	gs push rsp
 786:	61                   	(bad)  
 787:	62                   	(bad)  
 788:	6c                   	ins    BYTE PTR es:[rdi],dx
 789:	65 00 5f 5f          	add    BYTE PTR gs:[rdi+0x5f],bl
 78d:	67 6d                	ins    DWORD PTR es:[edi],dx
 78f:	6f                   	outs   dx,DWORD PTR ds:[rsi]
 790:	6e                   	outs   dx,BYTE PTR ds:[rsi]
 791:	5f                   	pop    rdi
 792:	73 74                	jae    808 <__abi_tag+0x47c>
 794:	61                   	(bad)  
 795:	72 74                	jb     80b <__abi_tag+0x47f>
 797:	5f                   	pop    rdi
 798:	5f                   	pop    rdi
 799:	00 5f 49             	add    BYTE PTR [rdi+0x49],bl
 79c:	54                   	push   rsp
 79d:	4d 5f                	rex.WRB pop r15
 79f:	72 65                	jb     806 <__abi_tag+0x47a>
 7a1:	67 69 73 74 65 72 54 	imul   esi,DWORD PTR [ebx+0x74],0x4d547265
 7a8:	4d 
 7a9:	43 6c                	rex.XB ins BYTE PTR es:[rdi],dx
 7ab:	6f                   	outs   dx,DWORD PTR ds:[rsi]
 7ac:	6e                   	outs   dx,BYTE PTR ds:[rsi]
 7ad:	65 54                	gs push rsp
 7af:	61                   	(bad)  
 7b0:	62                   	.byte 0x62
 7b1:	6c                   	ins    BYTE PTR es:[rdi],dx
 7b2:	65                   	gs
	...

Disassembly of section .gnu.version:

00000000000007b4 <.gnu.version>:
 7b4:	00 00                	add    BYTE PTR [rax],al
 7b6:	02 00                	add    al,BYTE PTR [rax]
 7b8:	03 00                	add    eax,DWORD PTR [rax]
 7ba:	01 00                	add    DWORD PTR [rax],eax
 7bc:	02 00                	add    al,BYTE PTR [rax]
 7be:	02 00                	add    al,BYTE PTR [rax]
 7c0:	02 00                	add    al,BYTE PTR [rax]
 7c2:	04 00                	add    al,0x0
 7c4:	02 00                	add    al,BYTE PTR [rax]
 7c6:	02 00                	add    al,BYTE PTR [rax]
 7c8:	02 00                	add    al,BYTE PTR [rax]
 7ca:	02 00                	add    al,BYTE PTR [rax]
 7cc:	01 00                	add    DWORD PTR [rax],eax
 7ce:	02 00                	add    al,BYTE PTR [rax]
 7d0:	05 00 02 00 02       	add    eax,0x2000200
 7d5:	00 02                	add    BYTE PTR [rdx],al
 7d7:	00 02                	add    BYTE PTR [rdx],al
 7d9:	00 01                	add    BYTE PTR [rcx],al
 7db:	00 06                	add    BYTE PTR [rsi],al
 7dd:	00 02                	add    BYTE PTR [rdx],al
 7df:	00 02                	add    BYTE PTR [rdx],al
 7e1:	00 02                	add    BYTE PTR [rdx],al
 7e3:	00 02                	add    BYTE PTR [rdx],al
 7e5:	00 02                	add    BYTE PTR [rdx],al
 7e7:	00 02                	add    BYTE PTR [rdx],al
	...

Disassembly of section .gnu.version_r:

00000000000007f0 <.gnu.version_r>:
 7f0:	01 00                	add    DWORD PTR [rax],eax
 7f2:	05 00 bf 00 00       	add    eax,0xbf00
 7f7:	00 10                	add    BYTE PTR [rax],dl
 7f9:	00 00                	add    BYTE PTR [rax],al
 7fb:	00 00                	add    BYTE PTR [rax],al
 7fd:	00 00                	add    BYTE PTR [rax],al
 7ff:	00 85 91 96 06 00    	add    BYTE PTR [rbp+0x69691],al
 805:	00 06                	add    BYTE PTR [rsi],al
 807:	00 c9                	add    cl,cl
 809:	00 00                	add    BYTE PTR [rax],al
 80b:	00 10                	add    BYTE PTR [rax],dl
 80d:	00 00                	add    BYTE PTR [rax],al
 80f:	00 17                	add    BYTE PTR [rdi],dl
 811:	69 69 0d 00 00 05 00 	imul   ebp,DWORD PTR [rcx+0xd],0x50000
 818:	d4                   	(bad)  
 819:	00 00                	add    BYTE PTR [rax],al
 81b:	00 10                	add    BYTE PTR [rax],dl
 81d:	00 00                	add    BYTE PTR [rax],al
 81f:	00 14 69             	add    BYTE PTR [rcx+rbp*2],dl
 822:	69 0d 00 00 04 00 de 	imul   ecx,DWORD PTR [rip+0x40000],0xde        # 4082c <_end+0x3c7dc>
 829:	00 00 00 
 82c:	10 00                	adc    BYTE PTR [rax],al
 82e:	00 00                	add    BYTE PTR [rax],al
 830:	b4 91                	mov    ah,0x91
 832:	96                   	xchg   esi,eax
 833:	06                   	(bad)  
 834:	00 00                	add    BYTE PTR [rax],al
 836:	03 00                	add    eax,DWORD PTR [rax]
 838:	e8 00 00 00 10       	call   1000083d <_end+0xfffc7ed>
 83d:	00 00                	add    BYTE PTR [rax],al
 83f:	00 75 1a             	add    BYTE PTR [rbp+0x1a],dh
 842:	69 09 00 00 02 00    	imul   ecx,DWORD PTR [rcx],0x20000
 848:	f3 00 00             	repz add BYTE PTR [rax],al
 84b:	00 00                	add    BYTE PTR [rax],al
 84d:	00 00                	add    BYTE PTR [rax],al
	...

Disassembly of section .rela.dyn:

0000000000000850 <.rela.dyn>:
 850:	30 3d 00 00 00 00    	xor    BYTE PTR [rip+0x0],bh        # 856 <__abi_tag+0x4ca>
 856:	00 00                	add    BYTE PTR [rax],al
 858:	08 00                	or     BYTE PTR [rax],al
 85a:	00 00                	add    BYTE PTR [rax],al
 85c:	00 00                	add    BYTE PTR [rax],al
 85e:	00 00                	add    BYTE PTR [rax],al
 860:	50                   	push   rax
 861:	13 00                	adc    eax,DWORD PTR [rax]
 863:	00 00                	add    BYTE PTR [rax],al
 865:	00 00                	add    BYTE PTR [rax],al
 867:	00 38                	add    BYTE PTR [rax],bh
 869:	3d 00 00 00 00       	cmp    eax,0x0
 86e:	00 00                	add    BYTE PTR [rax],al
 870:	08 00                	or     BYTE PTR [rax],al
 872:	00 00                	add    BYTE PTR [rax],al
 874:	00 00                	add    BYTE PTR [rax],al
 876:	00 00                	add    BYTE PTR [rax],al
 878:	10 13                	adc    BYTE PTR [rbx],dl
 87a:	00 00                	add    BYTE PTR [rax],al
 87c:	00 00                	add    BYTE PTR [rax],al
 87e:	00 00                	add    BYTE PTR [rax],al
 880:	08 40 00             	or     BYTE PTR [rax+0x0],al
 883:	00 00                	add    BYTE PTR [rax],al
 885:	00 00                	add    BYTE PTR [rax],al
 887:	00 08                	add    BYTE PTR [rax],cl
 889:	00 00                	add    BYTE PTR [rax],al
 88b:	00 00                	add    BYTE PTR [rax],al
 88d:	00 00                	add    BYTE PTR [rax],al
 88f:	00 08                	add    BYTE PTR [rax],cl
 891:	40 00 00             	rex add BYTE PTR [rax],al
 894:	00 00                	add    BYTE PTR [rax],al
 896:	00 00                	add    BYTE PTR [rax],al
 898:	d0 3f                	sar    BYTE PTR [rdi],1
 89a:	00 00                	add    BYTE PTR [rax],al
 89c:	00 00                	add    BYTE PTR [rax],al
 89e:	00 00                	add    BYTE PTR [rax],al
 8a0:	06                   	(bad)  
 8a1:	00 00                	add    BYTE PTR [rax],al
 8a3:	00 02                	add    BYTE PTR [rdx],al
	...
 8ad:	00 00                	add    BYTE PTR [rax],al
 8af:	00 d8                	add    al,bl
 8b1:	3f                   	(bad)  
 8b2:	00 00                	add    BYTE PTR [rax],al
 8b4:	00 00                	add    BYTE PTR [rax],al
 8b6:	00 00                	add    BYTE PTR [rax],al
 8b8:	06                   	(bad)  
 8b9:	00 00                	add    BYTE PTR [rax],al
 8bb:	00 03                	add    BYTE PTR [rbx],al
	...
 8c5:	00 00                	add    BYTE PTR [rax],al
 8c7:	00 e0                	add    al,ah
 8c9:	3f                   	(bad)  
 8ca:	00 00                	add    BYTE PTR [rax],al
 8cc:	00 00                	add    BYTE PTR [rax],al
 8ce:	00 00                	add    BYTE PTR [rax],al
 8d0:	06                   	(bad)  
 8d1:	00 00                	add    BYTE PTR [rax],al
 8d3:	00 19                	add    BYTE PTR [rcx],bl
	...
 8dd:	00 00                	add    BYTE PTR [rax],al
 8df:	00 e8                	add    al,ch
 8e1:	3f                   	(bad)  
 8e2:	00 00                	add    BYTE PTR [rax],al
 8e4:	00 00                	add    BYTE PTR [rax],al
 8e6:	00 00                	add    BYTE PTR [rax],al
 8e8:	06                   	(bad)  
 8e9:	00 00                	add    BYTE PTR [rax],al
 8eb:	00 0c 00             	add    BYTE PTR [rax+rax*1],cl
	...
 8f6:	00 00                	add    BYTE PTR [rax],al
 8f8:	f0 3f                	lock (bad) 
 8fa:	00 00                	add    BYTE PTR [rax],al
 8fc:	00 00                	add    BYTE PTR [rax],al
 8fe:	00 00                	add    BYTE PTR [rax],al
 900:	06                   	(bad)  
 901:	00 00                	add    BYTE PTR [rax],al
 903:	00 13                	add    BYTE PTR [rbx],dl
	...
 90d:	00 00                	add    BYTE PTR [rax],al
 90f:	00 f8                	add    al,bh
 911:	3f                   	(bad)  
 912:	00 00                	add    BYTE PTR [rax],al
 914:	00 00                	add    BYTE PTR [rax],al
 916:	00 00                	add    BYTE PTR [rax],al
 918:	06                   	(bad)  
 919:	00 00                	add    BYTE PTR [rax],al
 91b:	00 17                	add    BYTE PTR [rdi],dl
	...
 925:	00 00                	add    BYTE PTR [rax],al
 927:	00 20                	add    BYTE PTR [rax],ah
 929:	40 00 00             	rex add BYTE PTR [rax],al
 92c:	00 00                	add    BYTE PTR [rax],al
 92e:	00 00                	add    BYTE PTR [rax],al
 930:	05 00 00 00 16       	add    eax,0x16000000
	...
 93d:	00 00                	add    BYTE PTR [rax],al
 93f:	00 30                	add    BYTE PTR [rax],dh
 941:	40 00 00             	rex add BYTE PTR [rax],al
 944:	00 00                	add    BYTE PTR [rax],al
 946:	00 00                	add    BYTE PTR [rax],al
 948:	05 00 00 00 18       	add    eax,0x18000000
	...
 955:	00 00                	add    BYTE PTR [rax],al
 957:	00 40 40             	add    BYTE PTR [rax+0x40],al
 95a:	00 00                	add    BYTE PTR [rax],al
 95c:	00 00                	add    BYTE PTR [rax],al
 95e:	00 00                	add    BYTE PTR [rax],al
 960:	05 00 00 00 1a       	add    eax,0x1a000000
	...

Disassembly of section .rela.plt:

0000000000000970 <.rela.plt>:
 970:	48 3f                	rex.W (bad) 
 972:	00 00                	add    BYTE PTR [rax],al
 974:	00 00                	add    BYTE PTR [rax],al
 976:	00 00                	add    BYTE PTR [rax],al
 978:	07                   	(bad)  
 979:	00 00                	add    BYTE PTR [rax],al
 97b:	00 01                	add    BYTE PTR [rcx],al
	...
 985:	00 00                	add    BYTE PTR [rax],al
 987:	00 50 3f             	add    BYTE PTR [rax+0x3f],dl
 98a:	00 00                	add    BYTE PTR [rax],al
 98c:	00 00                	add    BYTE PTR [rax],al
 98e:	00 00                	add    BYTE PTR [rax],al
 990:	07                   	(bad)  
 991:	00 00                	add    BYTE PTR [rax],al
 993:	00 04 00             	add    BYTE PTR [rax+rax*1],al
	...
 99e:	00 00                	add    BYTE PTR [rax],al
 9a0:	58                   	pop    rax
 9a1:	3f                   	(bad)  
 9a2:	00 00                	add    BYTE PTR [rax],al
 9a4:	00 00                	add    BYTE PTR [rax],al
 9a6:	00 00                	add    BYTE PTR [rax],al
 9a8:	07                   	(bad)  
 9a9:	00 00                	add    BYTE PTR [rax],al
 9ab:	00 05 00 00 00 00    	add    BYTE PTR [rip+0x0],al        # 9b1 <__abi_tag+0x625>
 9b1:	00 00                	add    BYTE PTR [rax],al
 9b3:	00 00                	add    BYTE PTR [rax],al
 9b5:	00 00                	add    BYTE PTR [rax],al
 9b7:	00 60 3f             	add    BYTE PTR [rax+0x3f],ah
 9ba:	00 00                	add    BYTE PTR [rax],al
 9bc:	00 00                	add    BYTE PTR [rax],al
 9be:	00 00                	add    BYTE PTR [rax],al
 9c0:	07                   	(bad)  
 9c1:	00 00                	add    BYTE PTR [rax],al
 9c3:	00 06                	add    BYTE PTR [rsi],al
	...
 9cd:	00 00                	add    BYTE PTR [rax],al
 9cf:	00 68 3f             	add    BYTE PTR [rax+0x3f],ch
 9d2:	00 00                	add    BYTE PTR [rax],al
 9d4:	00 00                	add    BYTE PTR [rax],al
 9d6:	00 00                	add    BYTE PTR [rax],al
 9d8:	07                   	(bad)  
 9d9:	00 00                	add    BYTE PTR [rax],al
 9db:	00 07                	add    BYTE PTR [rdi],al
	...
 9e5:	00 00                	add    BYTE PTR [rax],al
 9e7:	00 70 3f             	add    BYTE PTR [rax+0x3f],dh
 9ea:	00 00                	add    BYTE PTR [rax],al
 9ec:	00 00                	add    BYTE PTR [rax],al
 9ee:	00 00                	add    BYTE PTR [rax],al
 9f0:	07                   	(bad)  
 9f1:	00 00                	add    BYTE PTR [rax],al
 9f3:	00 08                	add    BYTE PTR [rax],cl
	...
 9fd:	00 00                	add    BYTE PTR [rax],al
 9ff:	00 78 3f             	add    BYTE PTR [rax+0x3f],bh
 a02:	00 00                	add    BYTE PTR [rax],al
 a04:	00 00                	add    BYTE PTR [rax],al
 a06:	00 00                	add    BYTE PTR [rax],al
 a08:	07                   	(bad)  
 a09:	00 00                	add    BYTE PTR [rax],al
 a0b:	00 09                	add    BYTE PTR [rcx],cl
	...
 a15:	00 00                	add    BYTE PTR [rax],al
 a17:	00 80 3f 00 00 00    	add    BYTE PTR [rax+0x3f],al
 a1d:	00 00                	add    BYTE PTR [rax],al
 a1f:	00 07                	add    BYTE PTR [rdi],al
 a21:	00 00                	add    BYTE PTR [rax],al
 a23:	00 0a                	add    BYTE PTR [rdx],cl
	...
 a2d:	00 00                	add    BYTE PTR [rax],al
 a2f:	00 88 3f 00 00 00    	add    BYTE PTR [rax+0x3f],cl
 a35:	00 00                	add    BYTE PTR [rax],al
 a37:	00 07                	add    BYTE PTR [rdi],al
 a39:	00 00                	add    BYTE PTR [rax],al
 a3b:	00 0b                	add    BYTE PTR [rbx],cl
	...
 a45:	00 00                	add    BYTE PTR [rax],al
 a47:	00 90 3f 00 00 00    	add    BYTE PTR [rax+0x3f],dl
 a4d:	00 00                	add    BYTE PTR [rax],al
 a4f:	00 07                	add    BYTE PTR [rdi],al
 a51:	00 00                	add    BYTE PTR [rax],al
 a53:	00 0d 00 00 00 00    	add    BYTE PTR [rip+0x0],cl        # a59 <__abi_tag+0x6cd>
 a59:	00 00                	add    BYTE PTR [rax],al
 a5b:	00 00                	add    BYTE PTR [rax],al
 a5d:	00 00                	add    BYTE PTR [rax],al
 a5f:	00 98 3f 00 00 00    	add    BYTE PTR [rax+0x3f],bl
 a65:	00 00                	add    BYTE PTR [rax],al
 a67:	00 07                	add    BYTE PTR [rdi],al
 a69:	00 00                	add    BYTE PTR [rax],al
 a6b:	00 0e                	add    BYTE PTR [rsi],cl
	...
 a75:	00 00                	add    BYTE PTR [rax],al
 a77:	00 a0 3f 00 00 00    	add    BYTE PTR [rax+0x3f],ah
 a7d:	00 00                	add    BYTE PTR [rax],al
 a7f:	00 07                	add    BYTE PTR [rdi],al
 a81:	00 00                	add    BYTE PTR [rax],al
 a83:	00 0f                	add    BYTE PTR [rdi],cl
	...
 a8d:	00 00                	add    BYTE PTR [rax],al
 a8f:	00 a8 3f 00 00 00    	add    BYTE PTR [rax+0x3f],ch
 a95:	00 00                	add    BYTE PTR [rax],al
 a97:	00 07                	add    BYTE PTR [rdi],al
 a99:	00 00                	add    BYTE PTR [rax],al
 a9b:	00 10                	add    BYTE PTR [rax],dl
	...
 aa5:	00 00                	add    BYTE PTR [rax],al
 aa7:	00 b0 3f 00 00 00    	add    BYTE PTR [rax+0x3f],dh
 aad:	00 00                	add    BYTE PTR [rax],al
 aaf:	00 07                	add    BYTE PTR [rdi],al
 ab1:	00 00                	add    BYTE PTR [rax],al
 ab3:	00 11                	add    BYTE PTR [rcx],dl
	...
 abd:	00 00                	add    BYTE PTR [rax],al
 abf:	00 b8 3f 00 00 00    	add    BYTE PTR [rax+0x3f],bh
 ac5:	00 00                	add    BYTE PTR [rax],al
 ac7:	00 07                	add    BYTE PTR [rdi],al
 ac9:	00 00                	add    BYTE PTR [rax],al
 acb:	00 12                	add    BYTE PTR [rdx],dl
	...
 ad5:	00 00                	add    BYTE PTR [rax],al
 ad7:	00 c0                	add    al,al
 ad9:	3f                   	(bad)  
 ada:	00 00                	add    BYTE PTR [rax],al
 adc:	00 00                	add    BYTE PTR [rax],al
 ade:	00 00                	add    BYTE PTR [rax],al
 ae0:	07                   	(bad)  
 ae1:	00 00                	add    BYTE PTR [rax],al
 ae3:	00 14 00             	add    BYTE PTR [rax+rax*1],dl
	...
 aee:	00 00                	add    BYTE PTR [rax],al
 af0:	c8 3f 00 00          	enter  0x3f,0x0
 af4:	00 00                	add    BYTE PTR [rax],al
 af6:	00 00                	add    BYTE PTR [rax],al
 af8:	07                   	(bad)  
 af9:	00 00                	add    BYTE PTR [rax],al
 afb:	00 15 00 00 00 00    	add    BYTE PTR [rip+0x0],dl        # b01 <__abi_tag+0x775>
 b01:	00 00                	add    BYTE PTR [rax],al
 b03:	00 00                	add    BYTE PTR [rax],al
 b05:	00 00                	add    BYTE PTR [rax],al
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
    1020:	ff 35 12 2f 00 00    	push   QWORD PTR [rip+0x2f12]        # 3f38 <_GLOBAL_OFFSET_TABLE_+0x8>
    1026:	f2 ff 25 13 2f 00 00 	bnd jmp QWORD PTR [rip+0x2f13]        # 3f40 <_GLOBAL_OFFSET_TABLE_+0x10>
    102d:	0f 1f 00             	nop    DWORD PTR [rax]
    1030:	f3 0f 1e fa          	endbr64 
    1034:	68 00 00 00 00       	push   0x0
    1039:	f2 e9 e1 ff ff ff    	bnd jmp 1020 <_init+0x20>
    103f:	90                   	nop
    1040:	f3 0f 1e fa          	endbr64 
    1044:	68 01 00 00 00       	push   0x1
    1049:	f2 e9 d1 ff ff ff    	bnd jmp 1020 <_init+0x20>
    104f:	90                   	nop
    1050:	f3 0f 1e fa          	endbr64 
    1054:	68 02 00 00 00       	push   0x2
    1059:	f2 e9 c1 ff ff ff    	bnd jmp 1020 <_init+0x20>
    105f:	90                   	nop
    1060:	f3 0f 1e fa          	endbr64 
    1064:	68 03 00 00 00       	push   0x3
    1069:	f2 e9 b1 ff ff ff    	bnd jmp 1020 <_init+0x20>
    106f:	90                   	nop
    1070:	f3 0f 1e fa          	endbr64 
    1074:	68 04 00 00 00       	push   0x4
    1079:	f2 e9 a1 ff ff ff    	bnd jmp 1020 <_init+0x20>
    107f:	90                   	nop
    1080:	f3 0f 1e fa          	endbr64 
    1084:	68 05 00 00 00       	push   0x5
    1089:	f2 e9 91 ff ff ff    	bnd jmp 1020 <_init+0x20>
    108f:	90                   	nop
    1090:	f3 0f 1e fa          	endbr64 
    1094:	68 06 00 00 00       	push   0x6
    1099:	f2 e9 81 ff ff ff    	bnd jmp 1020 <_init+0x20>
    109f:	90                   	nop
    10a0:	f3 0f 1e fa          	endbr64 
    10a4:	68 07 00 00 00       	push   0x7
    10a9:	f2 e9 71 ff ff ff    	bnd jmp 1020 <_init+0x20>
    10af:	90                   	nop
    10b0:	f3 0f 1e fa          	endbr64 
    10b4:	68 08 00 00 00       	push   0x8
    10b9:	f2 e9 61 ff ff ff    	bnd jmp 1020 <_init+0x20>
    10bf:	90                   	nop
    10c0:	f3 0f 1e fa          	endbr64 
    10c4:	68 09 00 00 00       	push   0x9
    10c9:	f2 e9 51 ff ff ff    	bnd jmp 1020 <_init+0x20>
    10cf:	90                   	nop
    10d0:	f3 0f 1e fa          	endbr64 
    10d4:	68 0a 00 00 00       	push   0xa
    10d9:	f2 e9 41 ff ff ff    	bnd jmp 1020 <_init+0x20>
    10df:	90                   	nop
    10e0:	f3 0f 1e fa          	endbr64 
    10e4:	68 0b 00 00 00       	push   0xb
    10e9:	f2 e9 31 ff ff ff    	bnd jmp 1020 <_init+0x20>
    10ef:	90                   	nop
    10f0:	f3 0f 1e fa          	endbr64 
    10f4:	68 0c 00 00 00       	push   0xc
    10f9:	f2 e9 21 ff ff ff    	bnd jmp 1020 <_init+0x20>
    10ff:	90                   	nop
    1100:	f3 0f 1e fa          	endbr64 
    1104:	68 0d 00 00 00       	push   0xd
    1109:	f2 e9 11 ff ff ff    	bnd jmp 1020 <_init+0x20>
    110f:	90                   	nop
    1110:	f3 0f 1e fa          	endbr64 
    1114:	68 0e 00 00 00       	push   0xe
    1119:	f2 e9 01 ff ff ff    	bnd jmp 1020 <_init+0x20>
    111f:	90                   	nop
    1120:	f3 0f 1e fa          	endbr64 
    1124:	68 0f 00 00 00       	push   0xf
    1129:	f2 e9 f1 fe ff ff    	bnd jmp 1020 <_init+0x20>
    112f:	90                   	nop
    1130:	f3 0f 1e fa          	endbr64 
    1134:	68 10 00 00 00       	push   0x10
    1139:	f2 e9 e1 fe ff ff    	bnd jmp 1020 <_init+0x20>
    113f:	90                   	nop

Disassembly of section .plt.got:

0000000000001140 <printf@plt>:
    1140:	f3 0f 1e fa          	endbr64 
    1144:	f2 ff 25 95 2e 00 00 	bnd jmp QWORD PTR [rip+0x2e95]        # 3fe0 <printf@GLIBC_2.2.5>
    114b:	0f 1f 44 00 00       	nop    DWORD PTR [rax+rax*1+0x0]

0000000000001150 <__cxa_finalize@plt>:
    1150:	f3 0f 1e fa          	endbr64 
    1154:	f2 ff 25 9d 2e 00 00 	bnd jmp QWORD PTR [rip+0x2e9d]        # 3ff8 <__cxa_finalize@GLIBC_2.2.5>
    115b:	0f 1f 44 00 00       	nop    DWORD PTR [rax+rax*1+0x0]

Disassembly of section .plt.sec:

0000000000001160 <putchar@plt>:
    1160:	f3 0f 1e fa          	endbr64 
    1164:	f2 ff 25 dd 2d 00 00 	bnd jmp QWORD PTR [rip+0x2ddd]        # 3f48 <putchar@GLIBC_2.2.5>
    116b:	0f 1f 44 00 00       	nop    DWORD PTR [rax+rax*1+0x0]

0000000000001170 <_exit@plt>:
    1170:	f3 0f 1e fa          	endbr64 
    1174:	f2 ff 25 d5 2d 00 00 	bnd jmp QWORD PTR [rip+0x2dd5]        # 3f50 <_exit@GLIBC_2.2.5>
    117b:	0f 1f 44 00 00       	nop    DWORD PTR [rax+rax*1+0x0]

0000000000001180 <puts@plt>:
    1180:	f3 0f 1e fa          	endbr64 
    1184:	f2 ff 25 cd 2d 00 00 	bnd jmp QWORD PTR [rip+0x2dcd]        # 3f58 <puts@GLIBC_2.2.5>
    118b:	0f 1f 44 00 00       	nop    DWORD PTR [rax+rax*1+0x0]

0000000000001190 <write@plt>:
    1190:	f3 0f 1e fa          	endbr64 
    1194:	f2 ff 25 c5 2d 00 00 	bnd jmp QWORD PTR [rip+0x2dc5]        # 3f60 <write@GLIBC_2.2.5>
    119b:	0f 1f 44 00 00       	nop    DWORD PTR [rax+rax*1+0x0]

00000000000011a0 <__stack_chk_fail@plt>:
    11a0:	f3 0f 1e fa          	endbr64 
    11a4:	f2 ff 25 bd 2d 00 00 	bnd jmp QWORD PTR [rip+0x2dbd]        # 3f68 <__stack_chk_fail@GLIBC_2.4>
    11ab:	0f 1f 44 00 00       	nop    DWORD PTR [rax+rax*1+0x0]

00000000000011b0 <mmap@plt>:
    11b0:	f3 0f 1e fa          	endbr64 
    11b4:	f2 ff 25 b5 2d 00 00 	bnd jmp QWORD PTR [rip+0x2db5]        # 3f70 <mmap@GLIBC_2.2.5>
    11bb:	0f 1f 44 00 00       	nop    DWORD PTR [rax+rax*1+0x0]

00000000000011c0 <close@plt>:
    11c0:	f3 0f 1e fa          	endbr64 
    11c4:	f2 ff 25 ad 2d 00 00 	bnd jmp QWORD PTR [rip+0x2dad]        # 3f78 <close@GLIBC_2.2.5>
    11cb:	0f 1f 44 00 00       	nop    DWORD PTR [rax+rax*1+0x0]

00000000000011d0 <read@plt>:
    11d0:	f3 0f 1e fa          	endbr64 
    11d4:	f2 ff 25 a5 2d 00 00 	bnd jmp QWORD PTR [rip+0x2da5]        # 3f80 <read@GLIBC_2.2.5>
    11db:	0f 1f 44 00 00       	nop    DWORD PTR [rax+rax*1+0x0]

00000000000011e0 <fgets@plt>:
    11e0:	f3 0f 1e fa          	endbr64 
    11e4:	f2 ff 25 9d 2d 00 00 	bnd jmp QWORD PTR [rip+0x2d9d]        # 3f88 <fgets@GLIBC_2.2.5>
    11eb:	0f 1f 44 00 00       	nop    DWORD PTR [rax+rax*1+0x0]

00000000000011f0 <strtol@plt>:
    11f0:	f3 0f 1e fa          	endbr64 
    11f4:	f2 ff 25 95 2d 00 00 	bnd jmp QWORD PTR [rip+0x2d95]        # 3f90 <strtol@GLIBC_2.2.5>
    11fb:	0f 1f 44 00 00       	nop    DWORD PTR [rax+rax*1+0x0]

0000000000001200 <__isoc99_sscanf@plt>:
    1200:	f3 0f 1e fa          	endbr64 
    1204:	f2 ff 25 8d 2d 00 00 	bnd jmp QWORD PTR [rip+0x2d8d]        # 3f98 <__isoc99_sscanf@GLIBC_2.7>
    120b:	0f 1f 44 00 00       	nop    DWORD PTR [rax+rax*1+0x0]

0000000000001210 <setvbuf@plt>:
    1210:	f3 0f 1e fa          	endbr64 
    1214:	f2 ff 25 85 2d 00 00 	bnd jmp QWORD PTR [rip+0x2d85]        # 3fa0 <setvbuf@GLIBC_2.2.5>
    121b:	0f 1f 44 00 00       	nop    DWORD PTR [rax+rax*1+0x0]

0000000000001220 <waitpid@plt>:
    1220:	f3 0f 1e fa          	endbr64 
    1224:	f2 ff 25 7d 2d 00 00 	bnd jmp QWORD PTR [rip+0x2d7d]        # 3fa8 <waitpid@GLIBC_2.2.5>
    122b:	0f 1f 44 00 00       	nop    DWORD PTR [rax+rax*1+0x0]

0000000000001230 <open@plt>:
    1230:	f3 0f 1e fa          	endbr64 
    1234:	f2 ff 25 75 2d 00 00 	bnd jmp QWORD PTR [rip+0x2d75]        # 3fb0 <open@GLIBC_2.2.5>
    123b:	0f 1f 44 00 00       	nop    DWORD PTR [rax+rax*1+0x0]

0000000000001240 <perror@plt>:
    1240:	f3 0f 1e fa          	endbr64 
    1244:	f2 ff 25 6d 2d 00 00 	bnd jmp QWORD PTR [rip+0x2d6d]        # 3fb8 <perror@GLIBC_2.2.5>
    124b:	0f 1f 44 00 00       	nop    DWORD PTR [rax+rax*1+0x0]

0000000000001250 <getrandom@plt>:
    1250:	f3 0f 1e fa          	endbr64 
    1254:	f2 ff 25 65 2d 00 00 	bnd jmp QWORD PTR [rip+0x2d65]        # 3fc0 <getrandom@GLIBC_2.25>
    125b:	0f 1f 44 00 00       	nop    DWORD PTR [rax+rax*1+0x0]

0000000000001260 <fork@plt>:
    1260:	f3 0f 1e fa          	endbr64 
    1264:	f2 ff 25 5d 2d 00 00 	bnd jmp QWORD PTR [rip+0x2d5d]        # 3fc8 <fork@GLIBC_2.2.5>
    126b:	0f 1f 44 00 00       	nop    DWORD PTR [rax+rax*1+0x0]

Disassembly of section .text:

0000000000001270 <_start>:
    1270:	f3 0f 1e fa          	endbr64 
    1274:	31 ed                	xor    ebp,ebp
    1276:	49 89 d1             	mov    r9,rdx
    1279:	5e                   	pop    rsi
    127a:	48 89 e2             	mov    rdx,rsp
    127d:	48 83 e4 f0          	and    rsp,0xfffffffffffffff0
    1281:	50                   	push   rax
    1282:	54                   	push   rsp
    1283:	45 31 c0             	xor    r8d,r8d
    1286:	31 c9                	xor    ecx,ecx
    1288:	48 8d 3d a5 02 00 00 	lea    rdi,[rip+0x2a5]        # 1534 <main>
    128f:	ff 15 3b 2d 00 00    	call   QWORD PTR [rip+0x2d3b]        # 3fd0 <__libc_start_main@GLIBC_2.34>
    1295:	f4                   	hlt    
    1296:	66 2e 0f 1f 84 00 00 	cs nop WORD PTR [rax+rax*1+0x0]
    129d:	00 00 00 

00000000000012a0 <deregister_tm_clones>:
    12a0:	48 8d 3d 69 2d 00 00 	lea    rdi,[rip+0x2d69]        # 4010 <__TMC_END__>
    12a7:	48 8d 05 62 2d 00 00 	lea    rax,[rip+0x2d62]        # 4010 <__TMC_END__>
    12ae:	48 39 f8             	cmp    rax,rdi
    12b1:	74 15                	je     12c8 <deregister_tm_clones+0x28>
    12b3:	48 8b 05 1e 2d 00 00 	mov    rax,QWORD PTR [rip+0x2d1e]        # 3fd8 <_ITM_deregisterTMCloneTable@Base>
    12ba:	48 85 c0             	test   rax,rax
    12bd:	74 09                	je     12c8 <deregister_tm_clones+0x28>
    12bf:	ff e0                	jmp    rax
    12c1:	0f 1f 80 00 00 00 00 	nop    DWORD PTR [rax+0x0]
    12c8:	c3                   	ret    
    12c9:	0f 1f 80 00 00 00 00 	nop    DWORD PTR [rax+0x0]

00000000000012d0 <register_tm_clones>:
    12d0:	48 8d 3d 39 2d 00 00 	lea    rdi,[rip+0x2d39]        # 4010 <__TMC_END__>
    12d7:	48 8d 35 32 2d 00 00 	lea    rsi,[rip+0x2d32]        # 4010 <__TMC_END__>
    12de:	48 29 fe             	sub    rsi,rdi
    12e1:	48 89 f0             	mov    rax,rsi
    12e4:	48 c1 ee 3f          	shr    rsi,0x3f
    12e8:	48 c1 f8 03          	sar    rax,0x3
    12ec:	48 01 c6             	add    rsi,rax
    12ef:	48 d1 fe             	sar    rsi,1
    12f2:	74 14                	je     1308 <register_tm_clones+0x38>
    12f4:	48 8b 05 f5 2c 00 00 	mov    rax,QWORD PTR [rip+0x2cf5]        # 3ff0 <_ITM_registerTMCloneTable@Base>
    12fb:	48 85 c0             	test   rax,rax
    12fe:	74 08                	je     1308 <register_tm_clones+0x38>
    1300:	ff e0                	jmp    rax
    1302:	66 0f 1f 44 00 00    	nop    WORD PTR [rax+rax*1+0x0]
    1308:	c3                   	ret    
    1309:	0f 1f 80 00 00 00 00 	nop    DWORD PTR [rax+0x0]

0000000000001310 <__do_global_dtors_aux>:
    1310:	f3 0f 1e fa          	endbr64 
    1314:	80 3d 2d 2d 00 00 00 	cmp    BYTE PTR [rip+0x2d2d],0x0        # 4048 <completed.0>
    131b:	75 2b                	jne    1348 <__do_global_dtors_aux+0x38>
    131d:	55                   	push   rbp
    131e:	48 83 3d d2 2c 00 00 	cmp    QWORD PTR [rip+0x2cd2],0x0        # 3ff8 <__cxa_finalize@GLIBC_2.2.5>
    1325:	00 
    1326:	48 89 e5             	mov    rbp,rsp
    1329:	74 0c                	je     1337 <__do_global_dtors_aux+0x27>
    132b:	48 8b 3d d6 2c 00 00 	mov    rdi,QWORD PTR [rip+0x2cd6]        # 4008 <__dso_handle>
    1332:	e8 19 fe ff ff       	call   1150 <__cxa_finalize@plt>
    1337:	e8 64 ff ff ff       	call   12a0 <deregister_tm_clones>
    133c:	c6 05 05 2d 00 00 01 	mov    BYTE PTR [rip+0x2d05],0x1        # 4048 <completed.0>
    1343:	5d                   	pop    rbp
    1344:	c3                   	ret    
    1345:	0f 1f 00             	nop    DWORD PTR [rax]
    1348:	c3                   	ret    
    1349:	0f 1f 80 00 00 00 00 	nop    DWORD PTR [rax+0x0]

0000000000001350 <frame_dummy>:
    1350:	f3 0f 1e fa          	endbr64 
    1354:	e9 77 ff ff ff       	jmp    12d0 <register_tm_clones>

0000000000001359 <os_urandom>:
    1359:	f3 0f 1e fa          	endbr64 
    135d:	55                   	push   rbp
    135e:	48 89 e5             	mov    rbp,rsp
    1361:	48 83 ec 10          	sub    rsp,0x10
    1365:	64 48 8b 04 25 28 00 	mov    rax,QWORD PTR fs:0x28
    136c:	00 00 
    136e:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
    1372:	31 c0                	xor    eax,eax
    1374:	48 8d 45 f4          	lea    rax,[rbp-0xc]
    1378:	ba 00 00 00 00       	mov    edx,0x0
    137d:	be 04 00 00 00       	mov    esi,0x4
    1382:	48 89 c7             	mov    rdi,rax
    1385:	e8 c6 fe ff ff       	call   1250 <getrandom@plt>
    138a:	48 85 c0             	test   rax,rax
    138d:	79 19                	jns    13a8 <os_urandom+0x4f>
    138f:	48 8d 05 72 0c 00 00 	lea    rax,[rip+0xc72]        # 2008 <_IO_stdin_used+0x8>
    1396:	48 89 c7             	mov    rdi,rax
    1399:	e8 a2 fe ff ff       	call   1240 <perror@plt>
    139e:	bf ff ff ff ff       	mov    edi,0xffffffff
    13a3:	e8 c8 fd ff ff       	call   1170 <_exit@plt>
    13a8:	8b 45 f4             	mov    eax,DWORD PTR [rbp-0xc]
    13ab:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
    13af:	64 48 2b 14 25 28 00 	sub    rdx,QWORD PTR fs:0x28
    13b6:	00 00 
    13b8:	74 05                	je     13bf <os_urandom+0x66>
    13ba:	e8 e1 fd ff ff       	call   11a0 <__stack_chk_fail@plt>
    13bf:	c9                   	leave  
    13c0:	c3                   	ret    

00000000000013c1 <guess>:
    13c1:	f3 0f 1e fa          	endbr64 
    13c5:	55                   	push   rbp
    13c6:	48 89 e5             	mov    rbp,rsp
    13c9:	48 83 ec 40          	sub    rsp,0x40
    13cd:	64 48 8b 04 25 28 00 	mov    rax,QWORD PTR fs:0x28
    13d4:	00 00 
    13d6:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
    13da:	31 c0                	xor    eax,eax
    13dc:	48 8d 05 2f 0c 00 00 	lea    rax,[rip+0xc2f]        # 2012 <_IO_stdin_used+0x12>
    13e3:	48 89 c7             	mov    rdi,rax
    13e6:	b8 00 00 00 00       	mov    eax,0x0
    13eb:	e8 50 fd ff ff       	call   1140 <printf@plt>
    13f0:	48 8d 45 e0          	lea    rax,[rbp-0x20]
    13f4:	ba 80 00 00 00       	mov    edx,0x80
    13f9:	48 89 c6             	mov    rsi,rax
    13fc:	bf 00 00 00 00       	mov    edi,0x0
    1401:	e8 ca fd ff ff       	call   11d0 <read@plt>
    1406:	89 45 d4             	mov    DWORD PTR [rbp-0x2c],eax
    1409:	83 7d d4 00          	cmp    DWORD PTR [rbp-0x2c],0x0
    140d:	79 19                	jns    1428 <guess+0x67>
    140f:	48 8d 05 12 0c 00 00 	lea    rax,[rip+0xc12]        # 2028 <_IO_stdin_used+0x28>
    1416:	48 89 c7             	mov    rdi,rax
    1419:	e8 22 fe ff ff       	call   1240 <perror@plt>
    141e:	bf ff ff ff ff       	mov    edi,0xffffffff
    1423:	e8 48 fd ff ff       	call   1170 <_exit@plt>
    1428:	8b 45 d4             	mov    eax,DWORD PTR [rbp-0x2c]
    142b:	89 c6                	mov    esi,eax
    142d:	48 8d 05 ff 0b 00 00 	lea    rax,[rip+0xbff]        # 2033 <_IO_stdin_used+0x33>
    1434:	48 89 c7             	mov    rdi,rax
    1437:	b8 00 00 00 00       	mov    eax,0x0
    143c:	e8 ff fc ff ff       	call   1140 <printf@plt>
    1441:	48 8d 55 cc          	lea    rdx,[rbp-0x34]
    1445:	48 8d 45 e0          	lea    rax,[rbp-0x20]
    1449:	48 8d 0d fe 0b 00 00 	lea    rcx,[rip+0xbfe]        # 204e <_IO_stdin_used+0x4e>
    1450:	48 89 ce             	mov    rsi,rcx
    1453:	48 89 c7             	mov    rdi,rax
    1456:	b8 00 00 00 00       	mov    eax,0x0
    145b:	e8 a0 fd ff ff       	call   1200 <__isoc99_sscanf@plt>
    1460:	83 f8 01             	cmp    eax,0x1
    1463:	74 19                	je     147e <guess+0xbd>
    1465:	48 8d 05 e5 0b 00 00 	lea    rax,[rip+0xbe5]        # 2051 <_IO_stdin_used+0x51>
    146c:	48 89 c7             	mov    rdi,rax
    146f:	e8 cc fd ff ff       	call   1240 <perror@plt>
    1474:	bf ff ff ff ff       	mov    edi,0xffffffff
    1479:	e8 f2 fc ff ff       	call   1170 <_exit@plt>
    147e:	48 8d 05 d9 0b 00 00 	lea    rax,[rip+0xbd9]        # 205e <_IO_stdin_used+0x5e>
    1485:	48 89 c7             	mov    rdi,rax
    1488:	e8 f3 fc ff ff       	call   1180 <puts@plt>
    148d:	48 8d 45 e0          	lea    rax,[rbp-0x20]
    1491:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
    1495:	c7 45 d0 00 00 00 00 	mov    DWORD PTR [rbp-0x30],0x0
    149c:	eb 2d                	jmp    14cb <guess+0x10a>
    149e:	8b 45 d0             	mov    eax,DWORD PTR [rbp-0x30]
    14a1:	48 63 d0             	movsxd rdx,eax
    14a4:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
    14a8:	48 01 d0             	add    rax,rdx
    14ab:	0f b6 00             	movzx  eax,BYTE PTR [rax]
    14ae:	0f b6 c0             	movzx  eax,al
    14b1:	89 c6                	mov    esi,eax
    14b3:	48 8d 05 b5 0b 00 00 	lea    rax,[rip+0xbb5]        # 206f <_IO_stdin_used+0x6f>
    14ba:	48 89 c7             	mov    rdi,rax
    14bd:	b8 00 00 00 00       	mov    eax,0x0
    14c2:	e8 79 fc ff ff       	call   1140 <printf@plt>
    14c7:	83 45 d0 01          	add    DWORD PTR [rbp-0x30],0x1
    14cb:	83 7d d0 0f          	cmp    DWORD PTR [rbp-0x30],0xf
    14cf:	7e cd                	jle    149e <guess+0xdd>
    14d1:	bf 0a 00 00 00       	mov    edi,0xa
    14d6:	e8 85 fc ff ff       	call   1160 <putchar@plt>
    14db:	48 8d 45 e0          	lea    rax,[rbp-0x20]
    14df:	ba 00 00 00 00       	mov    edx,0x0
    14e4:	be 00 00 00 00       	mov    esi,0x0
    14e9:	48 89 c7             	mov    rdi,rax
    14ec:	e8 ff fc ff ff       	call   11f0 <strtol@plt>
    14f1:	48 89 c6             	mov    rsi,rax
    14f4:	48 8d 05 7b 0b 00 00 	lea    rax,[rip+0xb7b]        # 2076 <_IO_stdin_used+0x76>
    14fb:	48 89 c7             	mov    rdi,rax
    14fe:	b8 00 00 00 00       	mov    eax,0x0
    1503:	e8 38 fc ff ff       	call   1140 <printf@plt>
    1508:	48 8d 45 e0          	lea    rax,[rbp-0x20]
    150c:	ba 00 00 00 00       	mov    edx,0x0
    1511:	be 00 00 00 00       	mov    esi,0x0
    1516:	48 89 c7             	mov    rdi,rax
    1519:	e8 d2 fc ff ff       	call   11f0 <strtol@plt>
    151e:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
    1522:	64 48 2b 14 25 28 00 	sub    rdx,QWORD PTR fs:0x28
    1529:	00 00 
    152b:	74 05                	je     1532 <guess+0x171>
    152d:	e8 6e fc ff ff       	call   11a0 <__stack_chk_fail@plt>
    1532:	c9                   	leave  
    1533:	c3                   	ret    

0000000000001534 <main>:
    1534:	f3 0f 1e fa          	endbr64 
    1538:	55                   	push   rbp
    1539:	48 89 e5             	mov    rbp,rsp
    153c:	48 83 ec 70          	sub    rsp,0x70
    1540:	64 48 8b 04 25 28 00 	mov    rax,QWORD PTR fs:0x28
    1547:	00 00 
    1549:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
    154d:	31 c0                	xor    eax,eax
    154f:	c7 45 9c 78 56 34 12 	mov    DWORD PTR [rbp-0x64],0x12345678
    1556:	48 8b 05 d3 2a 00 00 	mov    rax,QWORD PTR [rip+0x2ad3]        # 4030 <stdin@GLIBC_2.2.5>
    155d:	b9 00 00 00 00       	mov    ecx,0x0
    1562:	ba 02 00 00 00       	mov    edx,0x2
    1567:	be 00 00 00 00       	mov    esi,0x0
    156c:	48 89 c7             	mov    rdi,rax
    156f:	e8 9c fc ff ff       	call   1210 <setvbuf@plt>
    1574:	48 8b 05 a5 2a 00 00 	mov    rax,QWORD PTR [rip+0x2aa5]        # 4020 <stdout@GLIBC_2.2.5>
    157b:	b9 00 00 00 00       	mov    ecx,0x0
    1580:	ba 02 00 00 00       	mov    edx,0x2
    1585:	be 00 00 00 00       	mov    esi,0x0
    158a:	48 89 c7             	mov    rdi,rax
    158d:	e8 7e fc ff ff       	call   1210 <setvbuf@plt>
    1592:	48 8b 05 a7 2a 00 00 	mov    rax,QWORD PTR [rip+0x2aa7]        # 4040 <stderr@GLIBC_2.2.5>
    1599:	b9 00 00 00 00       	mov    ecx,0x0
    159e:	ba 02 00 00 00       	mov    edx,0x2
    15a3:	be 00 00 00 00       	mov    esi,0x0
    15a8:	48 89 c7             	mov    rdi,rax
    15ab:	e8 60 fc ff ff       	call   1210 <setvbuf@plt>
    15b0:	48 8d 05 d1 0a 00 00 	lea    rax,[rip+0xad1]        # 2088 <_IO_stdin_used+0x88>
    15b7:	48 89 c7             	mov    rdi,rax
    15ba:	b8 00 00 00 00       	mov    eax,0x0
    15bf:	e8 7c fb ff ff       	call   1140 <printf@plt>
    15c4:	48 8b 15 65 2a 00 00 	mov    rdx,QWORD PTR [rip+0x2a65]        # 4030 <stdin@GLIBC_2.2.5>
    15cb:	48 8d 45 b0          	lea    rax,[rbp-0x50]
    15cf:	be 40 00 00 00       	mov    esi,0x40
    15d4:	48 89 c7             	mov    rdi,rax
    15d7:	e8 04 fc ff ff       	call   11e0 <fgets@plt>
    15dc:	48 85 c0             	test   rax,rax
    15df:	75 19                	jne    15fa <main+0xc6>
    15e1:	48 8d 05 e4 0a 00 00 	lea    rax,[rip+0xae4]        # 20cc <_IO_stdin_used+0xcc>
    15e8:	48 89 c7             	mov    rdi,rax
    15eb:	e8 50 fc ff ff       	call   1240 <perror@plt>
    15f0:	bf ff ff ff ff       	mov    edi,0xffffffff
    15f5:	e8 76 fb ff ff       	call   1170 <_exit@plt>
    15fa:	48 8d 55 98          	lea    rdx,[rbp-0x68]
    15fe:	48 8d 45 b0          	lea    rax,[rbp-0x50]
    1602:	48 8d 0d 45 0a 00 00 	lea    rcx,[rip+0xa45]        # 204e <_IO_stdin_used+0x4e>
    1609:	48 89 ce             	mov    rsi,rcx
    160c:	48 89 c7             	mov    rdi,rax
    160f:	b8 00 00 00 00       	mov    eax,0x0
    1614:	e8 e7 fb ff ff       	call   1200 <__isoc99_sscanf@plt>
    1619:	83 f8 01             	cmp    eax,0x1
    161c:	74 19                	je     1637 <main+0x103>
    161e:	48 8d 05 ac 0a 00 00 	lea    rax,[rip+0xaac]        # 20d1 <_IO_stdin_used+0xd1>
    1625:	48 89 c7             	mov    rdi,rax
    1628:	e8 13 fc ff ff       	call   1240 <perror@plt>
    162d:	bf ff ff ff ff       	mov    edi,0xffffffff
    1632:	e8 39 fb ff ff       	call   1170 <_exit@plt>
    1637:	8b 45 98             	mov    eax,DWORD PTR [rbp-0x68]
    163a:	85 c0                	test   eax,eax
    163c:	0f 8e 17 02 00 00    	jle    1859 <main+0x325>
    1642:	48 8d 05 8f 0a 00 00 	lea    rax,[rip+0xa8f]        # 20d8 <_IO_stdin_used+0xd8>
    1649:	48 89 c7             	mov    rdi,rax
    164c:	b8 00 00 00 00       	mov    eax,0x0
    1651:	e8 ea fa ff ff       	call   1140 <printf@plt>
    1656:	48 8b 15 d3 29 00 00 	mov    rdx,QWORD PTR [rip+0x29d3]        # 4030 <stdin@GLIBC_2.2.5>
    165d:	48 8d 45 b0          	lea    rax,[rbp-0x50]
    1661:	be 40 00 00 00       	mov    esi,0x40
    1666:	48 89 c7             	mov    rdi,rax
    1669:	e8 72 fb ff ff       	call   11e0 <fgets@plt>
    166e:	48 85 c0             	test   rax,rax
    1671:	75 19                	jne    168c <main+0x158>
    1673:	48 8d 05 52 0a 00 00 	lea    rax,[rip+0xa52]        # 20cc <_IO_stdin_used+0xcc>
    167a:	48 89 c7             	mov    rdi,rax
    167d:	e8 be fb ff ff       	call   1240 <perror@plt>
    1682:	bf ff ff ff ff       	mov    edi,0xffffffff
    1687:	e8 e4 fa ff ff       	call   1170 <_exit@plt>
    168c:	48 8d 55 9c          	lea    rdx,[rbp-0x64]
    1690:	48 8d 45 b0          	lea    rax,[rbp-0x50]
    1694:	48 8d 0d b3 09 00 00 	lea    rcx,[rip+0x9b3]        # 204e <_IO_stdin_used+0x4e>
    169b:	48 89 ce             	mov    rsi,rcx
    169e:	48 89 c7             	mov    rdi,rax
    16a1:	b8 00 00 00 00       	mov    eax,0x0
    16a6:	e8 55 fb ff ff       	call   1200 <__isoc99_sscanf@plt>
    16ab:	83 f8 01             	cmp    eax,0x1
    16ae:	74 19                	je     16c9 <main+0x195>
    16b0:	48 8d 05 1a 0a 00 00 	lea    rax,[rip+0xa1a]        # 20d1 <_IO_stdin_used+0xd1>
    16b7:	48 89 c7             	mov    rdi,rax
    16ba:	e8 81 fb ff ff       	call   1240 <perror@plt>
    16bf:	bf ff ff ff ff       	mov    edi,0xffffffff
    16c4:	e8 a7 fa ff ff       	call   1170 <_exit@plt>
    16c9:	8b 45 98             	mov    eax,DWORD PTR [rbp-0x68]
    16cc:	8d 90 ff 0f 00 00    	lea    edx,[rax+0xfff]
    16d2:	85 c0                	test   eax,eax
    16d4:	0f 48 c2             	cmovs  eax,edx
    16d7:	c1 f8 0c             	sar    eax,0xc
    16da:	83 c0 01             	add    eax,0x1
    16dd:	c1 e0 0c             	shl    eax,0xc
    16e0:	89 45 94             	mov    DWORD PTR [rbp-0x6c],eax
    16e3:	8b 45 94             	mov    eax,DWORD PTR [rbp-0x6c]
    16e6:	ba 00 00 01 00       	mov    edx,0x10000
    16eb:	39 d0                	cmp    eax,edx
    16ed:	0f 4f c2             	cmovg  eax,edx
    16f0:	48 98                	cdqe   
    16f2:	41 b9 00 00 00 00    	mov    r9d,0x0
    16f8:	41 b8 ff ff ff ff    	mov    r8d,0xffffffff
    16fe:	b9 22 00 00 00       	mov    ecx,0x22
    1703:	ba 07 00 00 00       	mov    edx,0x7
    1708:	48 89 c6             	mov    rsi,rax
    170b:	bf 00 00 00 00       	mov    edi,0x0
    1710:	e8 9b fa ff ff       	call   11b0 <mmap@plt>
    1715:	48 89 45 a8          	mov    QWORD PTR [rbp-0x58],rax
    1719:	48 83 7d a8 00       	cmp    QWORD PTR [rbp-0x58],0x0
    171e:	75 19                	jne    1739 <main+0x205>
    1720:	48 8d 05 ef 09 00 00 	lea    rax,[rip+0x9ef]        # 2116 <_IO_stdin_used+0x116>
    1727:	48 89 c7             	mov    rdi,rax
    172a:	e8 11 fb ff ff       	call   1240 <perror@plt>
    172f:	bf ff ff ff ff       	mov    edi,0xffffffff
    1734:	e8 37 fa ff ff       	call   1170 <_exit@plt>
    1739:	8b 45 98             	mov    eax,DWORD PTR [rbp-0x68]
    173c:	89 c6                	mov    esi,eax
    173e:	48 8d 05 db 09 00 00 	lea    rax,[rip+0x9db]        # 2120 <_IO_stdin_used+0x120>
    1745:	48 89 c7             	mov    rdi,rax
    1748:	b8 00 00 00 00       	mov    eax,0x0
    174d:	e8 ee f9 ff ff       	call   1140 <printf@plt>
    1752:	c7 45 a0 00 00 00 00 	mov    DWORD PTR [rbp-0x60],0x0
    1759:	eb 4b                	jmp    17a6 <main+0x272>
    175b:	8b 45 98             	mov    eax,DWORD PTR [rbp-0x68]
    175e:	48 98                	cdqe   
    1760:	8b 55 a0             	mov    edx,DWORD PTR [rbp-0x60]
    1763:	48 63 ca             	movsxd rcx,edx
    1766:	48 8b 55 a8          	mov    rdx,QWORD PTR [rbp-0x58]
    176a:	48 01 d1             	add    rcx,rdx
    176d:	48 89 c2             	mov    rdx,rax
    1770:	48 89 ce             	mov    rsi,rcx
    1773:	bf 00 00 00 00       	mov    edi,0x0
    1778:	e8 53 fa ff ff       	call   11d0 <read@plt>
    177d:	89 45 94             	mov    DWORD PTR [rbp-0x6c],eax
    1780:	8b 45 94             	mov    eax,DWORD PTR [rbp-0x6c]
    1783:	85 c0                	test   eax,eax
    1785:	79 19                	jns    17a0 <main+0x26c>
    1787:	48 8d 05 3e 09 00 00 	lea    rax,[rip+0x93e]        # 20cc <_IO_stdin_used+0xcc>
    178e:	48 89 c7             	mov    rdi,rax
    1791:	e8 aa fa ff ff       	call   1240 <perror@plt>
    1796:	bf ff ff ff ff       	mov    edi,0xffffffff
    179b:	e8 d0 f9 ff ff       	call   1170 <_exit@plt>
    17a0:	8b 45 94             	mov    eax,DWORD PTR [rbp-0x6c]
    17a3:	01 45 a0             	add    DWORD PTR [rbp-0x60],eax
    17a6:	8b 45 98             	mov    eax,DWORD PTR [rbp-0x68]
    17a9:	39 45 a0             	cmp    DWORD PTR [rbp-0x60],eax
    17ac:	75 ad                	jne    175b <main+0x227>
    17ae:	8b 45 a0             	mov    eax,DWORD PTR [rbp-0x60]
    17b1:	89 c6                	mov    esi,eax
    17b3:	48 8d 05 86 09 00 00 	lea    rax,[rip+0x986]        # 2140 <_IO_stdin_used+0x140>
    17ba:	48 89 c7             	mov    rdi,rax
    17bd:	b8 00 00 00 00       	mov    eax,0x0
    17c2:	e8 79 f9 ff ff       	call   1140 <printf@plt>
    17c7:	e8 94 fa ff ff       	call   1260 <fork@plt>
    17cc:	89 45 a4             	mov    DWORD PTR [rbp-0x5c],eax
    17cf:	83 7d a4 00          	cmp    DWORD PTR [rbp-0x5c],0x0
    17d3:	79 19                	jns    17ee <main+0x2ba>
    17d5:	48 8d 05 83 09 00 00 	lea    rax,[rip+0x983]        # 215f <_IO_stdin_used+0x15f>
    17dc:	48 89 c7             	mov    rdi,rax
    17df:	e8 5c fa ff ff       	call   1240 <perror@plt>
    17e4:	bf ff ff ff ff       	mov    edi,0xffffffff
    17e9:	e8 82 f9 ff ff       	call   1170 <_exit@plt>
    17ee:	83 7d a4 00          	cmp    DWORD PTR [rbp-0x5c],0x0
    17f2:	75 32                	jne    1826 <main+0x2f2>
    17f4:	8b 45 9c             	mov    eax,DWORD PTR [rbp-0x64]
    17f7:	48 98                	cdqe   
    17f9:	48 01 45 a8          	add    QWORD PTR [rbp-0x58],rax
    17fd:	48 8b 45 a8          	mov    rax,QWORD PTR [rbp-0x58]
    1801:	48 8b 15 d8 27 00 00 	mov    rdx,QWORD PTR [rip+0x27d8]        # 3fe0 <printf@GLIBC_2.2.5>
    1808:	48 89 d7             	mov    rdi,rdx
    180b:	ff d0                	call   rax
    180d:	48 8d 05 50 09 00 00 	lea    rax,[rip+0x950]        # 2164 <_IO_stdin_used+0x164>
    1814:	48 89 c7             	mov    rdi,rax
    1817:	e8 64 f9 ff ff       	call   1180 <puts@plt>
    181c:	bf 00 00 00 00       	mov    edi,0x0
    1821:	e8 4a f9 ff ff       	call   1170 <_exit@plt>
    1826:	48 8d 4d 94          	lea    rcx,[rbp-0x6c]
    182a:	8b 45 a4             	mov    eax,DWORD PTR [rbp-0x5c]
    182d:	ba 00 00 00 00       	mov    edx,0x0
    1832:	48 89 ce             	mov    rsi,rcx
    1835:	89 c7                	mov    edi,eax
    1837:	e8 e4 f9 ff ff       	call   1220 <waitpid@plt>
    183c:	85 c0                	test   eax,eax
    183e:	79 19                	jns    1859 <main+0x325>
    1840:	48 8d 05 3a 09 00 00 	lea    rax,[rip+0x93a]        # 2181 <_IO_stdin_used+0x181>
    1847:	48 89 c7             	mov    rdi,rax
    184a:	e8 f1 f9 ff ff       	call   1240 <perror@plt>
    184f:	bf ff ff ff ff       	mov    edi,0xffffffff
    1854:	e8 17 f9 ff ff       	call   1170 <_exit@plt>
    1859:	48 8d 45 b0          	lea    rax,[rbp-0x50]
    185d:	48 c7 00 00 00 00 00 	mov    QWORD PTR [rax],0x0
    1864:	48 c7 40 08 00 00 00 	mov    QWORD PTR [rax+0x8],0x0
    186b:	00 
    186c:	48 c7 40 10 00 00 00 	mov    QWORD PTR [rax+0x10],0x0
    1873:	00 
    1874:	48 c7 40 18 00 00 00 	mov    QWORD PTR [rax+0x18],0x0
    187b:	00 
    187c:	48 c7 40 20 00 00 00 	mov    QWORD PTR [rax+0x20],0x0
    1883:	00 
    1884:	48 c7 40 28 00 00 00 	mov    QWORD PTR [rax+0x28],0x0
    188b:	00 
    188c:	48 c7 40 30 00 00 00 	mov    QWORD PTR [rax+0x30],0x0
    1893:	00 
    1894:	48 c7 40 38 00 00 00 	mov    QWORD PTR [rax+0x38],0x0
    189b:	00 
    189c:	b8 00 00 00 00       	mov    eax,0x0
    18a1:	e8 b3 fa ff ff       	call   1359 <os_urandom>
    18a6:	25 ff ff ff 7f       	and    eax,0x7fffffff
    18ab:	89 45 9c             	mov    DWORD PTR [rbp-0x64],eax
    18ae:	8b 45 a0             	mov    eax,DWORD PTR [rbp-0x60]
    18b1:	89 c6                	mov    esi,eax
    18b3:	48 8d 05 cf 08 00 00 	lea    rax,[rip+0x8cf]        # 2189 <_IO_stdin_used+0x189>
    18ba:	48 89 c7             	mov    rdi,rax
    18bd:	b8 00 00 00 00       	mov    eax,0x0
    18c2:	e8 79 f8 ff ff       	call   1140 <printf@plt>
    18c7:	b8 00 00 00 00       	mov    eax,0x0
    18cc:	e8 f0 fa ff ff       	call   13c1 <guess>
    18d1:	89 45 a0             	mov    DWORD PTR [rbp-0x60],eax
    18d4:	8b 45 a0             	mov    eax,DWORD PTR [rbp-0x60]
    18d7:	89 c6                	mov    esi,eax
    18d9:	48 8d 05 a9 08 00 00 	lea    rax,[rip+0x8a9]        # 2189 <_IO_stdin_used+0x189>
    18e0:	48 89 c7             	mov    rdi,rax
    18e3:	b8 00 00 00 00       	mov    eax,0x0
    18e8:	e8 53 f8 ff ff       	call   1140 <printf@plt>
    18ed:	8b 45 9c             	mov    eax,DWORD PTR [rbp-0x64]
    18f0:	39 45 a0             	cmp    DWORD PTR [rbp-0x60],eax
    18f3:	0f 85 a2 00 00 00    	jne    199b <main+0x467>
    18f9:	48 8d 05 94 08 00 00 	lea    rax,[rip+0x894]        # 2194 <_IO_stdin_used+0x194>
    1900:	48 89 c7             	mov    rdi,rax
    1903:	e8 78 f8 ff ff       	call   1180 <puts@plt>
    1908:	be 00 00 00 00       	mov    esi,0x0
    190d:	48 8d 05 8d 08 00 00 	lea    rax,[rip+0x88d]        # 21a1 <_IO_stdin_used+0x1a1>
    1914:	48 89 c7             	mov    rdi,rax
    1917:	b8 00 00 00 00       	mov    eax,0x0
    191c:	e8 0f f9 ff ff       	call   1230 <open@plt>
    1921:	89 45 94             	mov    DWORD PTR [rbp-0x6c],eax
    1924:	8b 45 94             	mov    eax,DWORD PTR [rbp-0x6c]
    1927:	85 c0                	test   eax,eax
    1929:	79 48                	jns    1973 <main+0x43f>
    192b:	48 8d 05 75 08 00 00 	lea    rax,[rip+0x875]        # 21a7 <_IO_stdin_used+0x1a7>
    1932:	48 89 c7             	mov    rdi,rax
    1935:	e8 06 f9 ff ff       	call   1240 <perror@plt>
    193a:	bf ff ff ff ff       	mov    edi,0xffffffff
    193f:	e8 2c f8 ff ff       	call   1170 <_exit@plt>
    1944:	8b 45 9c             	mov    eax,DWORD PTR [rbp-0x64]
    1947:	39 45 a0             	cmp    DWORD PTR [rbp-0x60],eax
    194a:	74 11                	je     195d <main+0x429>
    194c:	48 8d 05 5d 08 00 00 	lea    rax,[rip+0x85d]        # 21b0 <_IO_stdin_used+0x1b0>
    1953:	48 89 c7             	mov    rdi,rax
    1956:	e8 25 f8 ff ff       	call   1180 <puts@plt>
    195b:	eb 32                	jmp    198f <main+0x45b>
    195d:	48 8d 45 b0          	lea    rax,[rbp-0x50]
    1961:	ba 01 00 00 00       	mov    edx,0x1
    1966:	48 89 c6             	mov    rsi,rax
    1969:	bf 01 00 00 00       	mov    edi,0x1
    196e:	e8 1d f8 ff ff       	call   1190 <write@plt>
    1973:	8b 45 94             	mov    eax,DWORD PTR [rbp-0x6c]
    1976:	48 8d 4d b0          	lea    rcx,[rbp-0x50]
    197a:	ba 01 00 00 00       	mov    edx,0x1
    197f:	48 89 ce             	mov    rsi,rcx
    1982:	89 c7                	mov    edi,eax
    1984:	e8 47 f8 ff ff       	call   11d0 <read@plt>
    1989:	48 83 f8 01          	cmp    rax,0x1
    198d:	74 b5                	je     1944 <main+0x410>
    198f:	8b 45 94             	mov    eax,DWORD PTR [rbp-0x6c]
    1992:	89 c7                	mov    edi,eax
    1994:	e8 27 f8 ff ff       	call   11c0 <close@plt>
    1999:	eb 19                	jmp    19b4 <main+0x480>
    199b:	8b 45 9c             	mov    eax,DWORD PTR [rbp-0x64]
    199e:	89 c6                	mov    esi,eax
    19a0:	48 8d 05 2f 08 00 00 	lea    rax,[rip+0x82f]        # 21d6 <_IO_stdin_used+0x1d6>
    19a7:	48 89 c7             	mov    rdi,rax
    19aa:	b8 00 00 00 00       	mov    eax,0x0
    19af:	e8 8c f7 ff ff       	call   1140 <printf@plt>
    19b4:	b8 00 00 00 00       	mov    eax,0x0
    19b9:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
    19bd:	64 48 2b 14 25 28 00 	sub    rdx,QWORD PTR fs:0x28
    19c4:	00 00 
    19c6:	74 05                	je     19cd <main+0x499>
    19c8:	e8 d3 f7 ff ff       	call   11a0 <__stack_chk_fail@plt>
    19cd:	c9                   	leave  
    19ce:	c3                   	ret    

Disassembly of section .fini:

00000000000019d0 <_fini>:
    19d0:	f3 0f 1e fa          	endbr64 
    19d4:	48 83 ec 08          	sub    rsp,0x8
    19d8:	48 83 c4 08          	add    rsp,0x8
    19dc:	c3                   	ret    

Disassembly of section .rodata:

0000000000002000 <_IO_stdin_used>:
    2000:	01 00                	add    DWORD PTR [rax],eax
    2002:	02 00                	add    al,BYTE PTR [rax]
    2004:	00 00                	add    BYTE PTR [rax],al
    2006:	00 00                	add    BYTE PTR [rax],al
    2008:	67 65 74 72          	addr32 gs je 207e <_IO_stdin_used+0x7e>
    200c:	61                   	(bad)  
    200d:	6e                   	outs   dx,BYTE PTR ds:[rsi]
    200e:	64 6f                	outs   dx,DWORD PTR fs:[rsi]
    2010:	6d                   	ins    DWORD PTR es:[rdi],dx
    2011:	00 53 68             	add    BYTE PTR [rbx+0x68],dl
    2014:	6f                   	outs   dx,DWORD PTR ds:[rsi]
    2015:	77 20                	ja     2037 <_IO_stdin_used+0x37>
    2017:	6d                   	ins    DWORD PTR es:[rdi],dx
    2018:	65 20 79 6f          	and    BYTE PTR gs:[rcx+0x6f],bh
    201c:	75 72                	jne    2090 <_IO_stdin_used+0x90>
    201e:	20 61 6e             	and    BYTE PTR [rcx+0x6e],ah
    2021:	73 77                	jae    209a <_IO_stdin_used+0x9a>
    2023:	65 72 3f             	gs jb  2065 <_IO_stdin_used+0x65>
    2026:	20 00                	and    BYTE PTR [rax],al
    2028:	67 75 65             	addr32 jne 2090 <_IO_stdin_used+0x90>
    202b:	73 73                	jae    20a0 <_IO_stdin_used+0xa0>
    202d:	2f                   	(bad)  
    202e:	72 65                	jb     2095 <_IO_stdin_used+0x95>
    2030:	61                   	(bad)  
    2031:	64 00 2a             	add    BYTE PTR fs:[rdx],ch
    2034:	2a 20                	sub    ah,BYTE PTR [rax]
    2036:	67 75 65             	addr32 jne 209e <_IO_stdin_used+0x9e>
    2039:	73 73                	jae    20ae <_IO_stdin_used+0xae>
    203b:	3a 20                	cmp    ah,BYTE PTR [rax]
    203d:	25 64 20 62 79       	and    eax,0x79622064
    2042:	74 65                	je     20a9 <_IO_stdin_used+0xa9>
    2044:	28 73 29             	sub    BYTE PTR [rbx+0x29],dh
    2047:	20 72 65             	and    BYTE PTR [rdx+0x65],dh
    204a:	61                   	(bad)  
    204b:	64 0a 00             	or     al,BYTE PTR fs:[rax]
    204e:	25 64 00 67 75       	and    eax,0x75670064
    2053:	65 73 73             	gs jae 20c9 <_IO_stdin_used+0xc9>
    2056:	2f                   	(bad)  
    2057:	73 73                	jae    20cc <_IO_stdin_used+0xcc>
    2059:	63 61 6e             	movsxd esp,DWORD PTR [rcx+0x6e]
    205c:	66 00 62 75          	data16 add BYTE PTR [rdx+0x75],ah
    2060:	66 66 65 72 20       	data16 data16 gs jb 2085 <_IO_stdin_used+0x85>
    2065:	69 6e 20 67 75 65 73 	imul   ebp,DWORD PTR [rsi+0x20],0x73657567
    206c:	73 3a                	jae    20a8 <_IO_stdin_used+0xa8>
    206e:	00 25 30 32 6c 78    	add    BYTE PTR [rip+0x786c3230],ah        # 786c52a4 <_end+0x786c1254>
    2074:	20 00                	and    BYTE PTR [rax],al
    2076:	72 65                	jb     20dd <_IO_stdin_used+0xdd>
    2078:	74 75                	je     20ef <_IO_stdin_used+0xef>
    207a:	72 6e                	jb     20ea <_IO_stdin_used+0xea>
    207c:	3a 20                	cmp    ah,BYTE PTR [rax]
    207e:	25 78 0a 00 00       	and    eax,0xa78
    2083:	00 00                	add    BYTE PTR [rax],al
    2085:	00 00                	add    BYTE PTR [rax],al
    2087:	00 48 6f             	add    BYTE PTR [rax+0x6f],cl
    208a:	77 20                	ja     20ac <_IO_stdin_used+0xac>
    208c:	6d                   	ins    DWORD PTR es:[rdi],dx
    208d:	61                   	(bad)  
    208e:	6e                   	outs   dx,BYTE PTR ds:[rsi]
    208f:	79 20                	jns    20b1 <_IO_stdin_used+0xb1>
    2091:	62                   	(bad)  
    2092:	79 74                	jns    2108 <_IO_stdin_used+0x108>
    2094:	65 73 20             	gs jae 20b7 <_IO_stdin_used+0xb7>
    2097:	6f                   	outs   dx,DWORD PTR ds:[rsi]
    2098:	66 20 74 68 65       	data16 and BYTE PTR [rax+rbp*2+0x65],dh
    209d:	20 73 6f             	and    BYTE PTR [rbx+0x6f],dh
    20a0:	6c                   	ins    BYTE PTR es:[rdi],dx
    20a1:	76 65                	jbe    2108 <_IO_stdin_used+0x108>
    20a3:	72 20                	jb     20c5 <_IO_stdin_used+0xc5>
    20a5:	65 78 65             	gs js  210d <_IO_stdin_used+0x10d>
    20a8:	63 75 74             	movsxd esi,DWORD PTR [rbp+0x74]
    20ab:	61                   	(bad)  
    20ac:	62                   	(bad)  
    20ad:	6c                   	ins    BYTE PTR es:[rdi],dx
    20ae:	65 20 64 6f 20       	and    BYTE PTR gs:[rdi+rbp*2+0x20],ah
    20b3:	79 6f                	jns    2124 <_IO_stdin_used+0x124>
    20b5:	75 20                	jne    20d7 <_IO_stdin_used+0xd7>
    20b7:	77 61                	ja     211a <_IO_stdin_used+0x11a>
    20b9:	6e                   	outs   dx,BYTE PTR ds:[rsi]
    20ba:	74 20                	je     20dc <_IO_stdin_used+0xdc>
    20bc:	74 6f                	je     212d <_IO_stdin_used+0x12d>
    20be:	20 73 65             	and    BYTE PTR [rbx+0x65],dh
    20c1:	6e                   	outs   dx,BYTE PTR ds:[rsi]
    20c2:	64 20 74 6f 20       	and    BYTE PTR fs:[rdi+rbp*2+0x20],dh
    20c7:	6d                   	ins    DWORD PTR es:[rdi],dx
    20c8:	65 3f                	gs (bad) 
    20ca:	20 00                	and    BYTE PTR [rax],al
    20cc:	72 65                	jb     2133 <_IO_stdin_used+0x133>
    20ce:	61                   	(bad)  
    20cf:	64 00 73 73          	add    BYTE PTR fs:[rbx+0x73],dh
    20d3:	63 61 6e             	movsxd esp,DWORD PTR [rcx+0x6e]
    20d6:	66 00 57 68          	data16 add BYTE PTR [rdi+0x68],dl
    20da:	61                   	(bad)  
    20db:	74 20                	je     20fd <_IO_stdin_used+0xfd>
    20dd:	72 65                	jb     2144 <_IO_stdin_used+0x144>
    20df:	6c                   	ins    BYTE PTR es:[rdi],dx
    20e0:	61                   	(bad)  
    20e1:	74 69                	je     214c <_IO_stdin_used+0x14c>
    20e3:	76 65                	jbe    214a <_IO_stdin_used+0x14a>
    20e5:	20 61 64             	and    BYTE PTR [rcx+0x64],ah
    20e8:	64 72 65             	fs jb  2150 <_IO_stdin_used+0x150>
    20eb:	73 73                	jae    2160 <_IO_stdin_used+0x160>
    20ed:	20 69 6e             	and    BYTE PTR [rcx+0x6e],ch
    20f0:	20 74 68 65          	and    BYTE PTR [rax+rbp*2+0x65],dh
    20f4:	20 65 78             	and    BYTE PTR [rbp+0x78],ah
    20f7:	65 63 75 74          	movsxd esi,DWORD PTR gs:[rbp+0x74]
    20fb:	61                   	(bad)  
    20fc:	62                   	(bad)  
    20fd:	6c                   	ins    BYTE PTR es:[rdi],dx
    20fe:	65 20 64 6f 20       	and    BYTE PTR gs:[rdi+rbp*2+0x20],ah
    2103:	79 6f                	jns    2174 <_IO_stdin_used+0x174>
    2105:	75 20                	jne    2127 <_IO_stdin_used+0x127>
    2107:	77 61                	ja     216a <_IO_stdin_used+0x16a>
    2109:	6e                   	outs   dx,BYTE PTR ds:[rsi]
    210a:	74 20                	je     212c <_IO_stdin_used+0x12c>
    210c:	74 6f                	je     217d <_IO_stdin_used+0x17d>
    210e:	20 63 61             	and    BYTE PTR [rbx+0x61],ah
    2111:	6c                   	ins    BYTE PTR es:[rdi],dx
    2112:	6c                   	ins    BYTE PTR es:[rdi],dx
    2113:	3f                   	(bad)  
    2114:	20 00                	and    BYTE PTR [rax],al
    2116:	6d                   	ins    DWORD PTR es:[rdi],dx
    2117:	6d                   	ins    DWORD PTR es:[rdi],dx
    2118:	61                   	(bad)  
    2119:	70 00                	jo     211b <_IO_stdin_used+0x11b>
    211b:	00 00                	add    BYTE PTR [rax],al
    211d:	00 00                	add    BYTE PTR [rax],al
    211f:	00 53 65             	add    BYTE PTR [rbx+0x65],dl
    2122:	6e                   	outs   dx,BYTE PTR ds:[rsi]
    2123:	64 20 6d 65          	and    BYTE PTR fs:[rbp+0x65],ch
    2127:	20 79 6f             	and    BYTE PTR [rcx+0x6f],bh
    212a:	75 72                	jne    219e <_IO_stdin_used+0x19e>
    212c:	20 63 6f             	and    BYTE PTR [rbx+0x6f],ah
    212f:	64 65 20 28          	fs and BYTE PTR gs:[rax],ch
    2133:	25 64 20 62 79       	and    eax,0x79622064
    2138:	74 65                	je     219f <_IO_stdin_used+0x19f>
    213a:	73 29                	jae    2165 <_IO_stdin_used+0x165>
    213c:	3a 20                	cmp    ah,BYTE PTR [rax]
    213e:	00 00                	add    BYTE PTR [rax],al
    2140:	2a 2a                	sub    ch,BYTE PTR [rdx]
    2142:	20 63 6f             	and    BYTE PTR [rbx+0x6f],ah
    2145:	64 65 3a 20          	fs cmp ah,BYTE PTR gs:[rax]
    2149:	25 64 20 62 79       	and    eax,0x79622064
    214e:	74 65                	je     21b5 <_IO_stdin_used+0x1b5>
    2150:	28 73 29             	sub    BYTE PTR [rbx+0x29],dh
    2153:	20 72 65             	and    BYTE PTR [rdx+0x65],dh
    2156:	63 65 69             	movsxd esp,DWORD PTR [rbp+0x69]
    2159:	76 65                	jbe    21c0 <_IO_stdin_used+0x1c0>
    215b:	64 2e 0a 00          	fs or  al,BYTE PTR fs:[rax]
    215f:	66 6f                	outs   dx,WORD PTR ds:[rsi]
    2161:	72 6b                	jb     21ce <_IO_stdin_used+0x1ce>
    2163:	00 2a                	add    BYTE PTR [rdx],ch
    2165:	2a 20                	sub    ah,BYTE PTR [rax]
    2167:	46 75 6e             	rex.RX jne 21d8 <_IO_stdin_used+0x1d8>
    216a:	63 74 69 6f          	movsxd esi,DWORD PTR [rcx+rbp*2+0x6f]
    216e:	6e                   	outs   dx,BYTE PTR ds:[rsi]
    216f:	20 65 76             	and    BYTE PTR [rbp+0x76],ah
    2172:	61                   	(bad)  
    2173:	6c                   	ins    BYTE PTR es:[rdi],dx
    2174:	75 61                	jne    21d7 <_IO_stdin_used+0x1d7>
    2176:	74 69                	je     21e1 <_IO_stdin_used+0x1e1>
    2178:	6f                   	outs   dx,DWORD PTR ds:[rsi]
    2179:	6e                   	outs   dx,BYTE PTR ds:[rsi]
    217a:	20 64 6f 6e          	and    BYTE PTR [rdi+rbp*2+0x6e],ah
    217e:	65 2e 00 77 61       	gs add BYTE PTR gs:[rdi+0x61],dh
    2183:	69 74 70 69 64 00 6e 	imul   esi,DWORD PTR [rax+rsi*2+0x69],0x726e0064
    218a:	72 
    218b:	65 61                	gs (bad) 
    218d:	64 3a 20             	cmp    ah,BYTE PTR fs:[rax]
    2190:	25 78 0a 00 2a       	and    eax,0x2a000a78
    2195:	2a 20                	sub    ah,BYTE PTR [rax]
    2197:	47 6f                	rex.RXB outs dx,DWORD PTR ds:[rsi]
    2199:	6f                   	outs   dx,DWORD PTR ds:[rsi]
    219a:	64 20 4a 6f          	and    BYTE PTR fs:[rdx+0x6f],cl
    219e:	62 21                	(bad)  
    21a0:	00 2f                	add    BYTE PTR [rdi],ch
    21a2:	46                   	rex.RX
    21a3:	4c                   	rex.WR
    21a4:	41                   	rex.B
    21a5:	47 00 6f 70          	rex.RXB add BYTE PTR [r15+0x70],r13b
    21a9:	65 6e                	outs   dx,BYTE PTR gs:[rsi]
    21ab:	00 00                	add    BYTE PTR [rax],al
    21ad:	00 00                	add    BYTE PTR [rax],al
    21af:	00 2a                	add    BYTE PTR [rdx],ch
    21b1:	2a 20                	sub    ah,BYTE PTR [rax]
    21b3:	55                   	push   rbp
    21b4:	6e                   	outs   dx,BYTE PTR ds:[rsi]
    21b5:	65 78 70             	gs js  2228 <__GNU_EH_FRAME_HDR+0x34>
    21b8:	65 63 74 65 64       	movsxd esi,DWORD PTR gs:[rbp+riz*2+0x64]
    21bd:	20 73 6f             	and    BYTE PTR [rbx+0x6f],dh
    21c0:	6c                   	ins    BYTE PTR es:[rdi],dx
    21c1:	75 74                	jne    2237 <__GNU_EH_FRAME_HDR+0x43>
    21c3:	69 6f 6e 2c 20 70 6c 	imul   ebp,DWORD PTR [rdi+0x6e],0x6c70202c
    21ca:	65 61                	gs (bad) 
    21cc:	73 65                	jae    2233 <__GNU_EH_FRAME_HDR+0x3f>
    21ce:	20 66 69             	and    BYTE PTR [rsi+0x69],ah
    21d1:	78 69                	js     223c <__GNU_EH_FRAME_HDR+0x48>
    21d3:	74 21                	je     21f6 <__GNU_EH_FRAME_HDR+0x2>
    21d5:	00 2a                	add    BYTE PTR [rdx],ch
    21d7:	2a 20                	sub    ah,BYTE PTR [rax]
    21d9:	4e 6f                	rex.WRX outs dx,DWORD PTR ds:[rsi]
    21db:	20 6e 6f             	and    BYTE PTR [rsi+0x6f],ch
    21de:	20 6e 6f             	and    BYTE PTR [rsi+0x6f],ch
    21e1:	20 2e                	and    BYTE PTR [rsi],ch
    21e3:	2e 2e 20 6d 61       	cs cs and BYTE PTR [rbp+0x61],ch
    21e8:	67 69 63 20 3d 20 25 	imul   esp,DWORD PTR [ebx+0x20],0x7825203d
    21ef:	78 
    21f0:	0a 00                	or     al,BYTE PTR [rax]

Disassembly of section .eh_frame_hdr:

00000000000021f4 <__GNU_EH_FRAME_HDR>:
    21f4:	01 1b                	add    DWORD PTR [rbx],ebx
    21f6:	03 3b                	add    edi,DWORD PTR [rbx]
    21f8:	40 00 00             	rex add BYTE PTR [rax],al
    21fb:	00 07                	add    BYTE PTR [rdi],al
    21fd:	00 00                	add    BYTE PTR [rax],al
    21ff:	00 2c ee             	add    BYTE PTR [rsi+rbp*8],ch
    2202:	ff                   	(bad)  
    2203:	ff 74 00 00          	push   QWORD PTR [rax+rax*1+0x0]
    2207:	00 4c ef ff          	add    BYTE PTR [rdi+rbp*8-0x1],cl
    220b:	ff 9c 00 00 00 6c ef 	call   FWORD PTR [rax+rax*1-0x10940000]
    2212:	ff                   	(bad)  
    2213:	ff b4 00 00 00 7c f0 	push   QWORD PTR [rax+rax*1-0xf840000]
    221a:	ff                   	(bad)  
    221b:	ff 5c 00 00          	call   FWORD PTR [rax+rax*1+0x0]
    221f:	00 65 f1             	add    BYTE PTR [rbp-0xf],ah
    2222:	ff                   	(bad)  
    2223:	ff cc                	dec    esp
    2225:	00 00                	add    BYTE PTR [rax],al
    2227:	00 cd                	add    ch,cl
    2229:	f1                   	int1   
    222a:	ff                   	(bad)  
    222b:	ff                   	(bad)  
    222c:	ec                   	in     al,dx
    222d:	00 00                	add    BYTE PTR [rax],al
    222f:	00 40 f3             	add    BYTE PTR [rax-0xd],al
    2232:	ff                   	(bad)  
    2233:	ff 0c 01             	dec    DWORD PTR [rcx+rax*1]
	...

Disassembly of section .eh_frame:

0000000000002238 <__FRAME_END__-0xe8>:
    2238:	14 00                	adc    al,0x0
    223a:	00 00                	add    BYTE PTR [rax],al
    223c:	00 00                	add    BYTE PTR [rax],al
    223e:	00 00                	add    BYTE PTR [rax],al
    2240:	01 7a 52             	add    DWORD PTR [rdx+0x52],edi
    2243:	00 01                	add    BYTE PTR [rcx],al
    2245:	78 10                	js     2257 <__GNU_EH_FRAME_HDR+0x63>
    2247:	01 1b                	add    DWORD PTR [rbx],ebx
    2249:	0c 07                	or     al,0x7
    224b:	08 90 01 00 00 14    	or     BYTE PTR [rax+0x14000001],dl
    2251:	00 00                	add    BYTE PTR [rax],al
    2253:	00 1c 00             	add    BYTE PTR [rax+rax*1],bl
    2256:	00 00                	add    BYTE PTR [rax],al
    2258:	18 f0                	sbb    al,dh
    225a:	ff                   	(bad)  
    225b:	ff 26                	jmp    QWORD PTR [rsi]
    225d:	00 00                	add    BYTE PTR [rax],al
    225f:	00 00                	add    BYTE PTR [rax],al
    2261:	44 07                	rex.R (bad) 
    2263:	10 00                	adc    BYTE PTR [rax],al
    2265:	00 00                	add    BYTE PTR [rax],al
    2267:	00 24 00             	add    BYTE PTR [rax+rax*1],ah
    226a:	00 00                	add    BYTE PTR [rax],al
    226c:	34 00                	xor    al,0x0
    226e:	00 00                	add    BYTE PTR [rax],al
    2270:	b0 ed                	mov    al,0xed
    2272:	ff                   	(bad)  
    2273:	ff 20                	jmp    QWORD PTR [rax]
    2275:	01 00                	add    DWORD PTR [rax],eax
    2277:	00 00                	add    BYTE PTR [rax],al
    2279:	0e                   	(bad)  
    227a:	10 46 0e             	adc    BYTE PTR [rsi+0xe],al
    227d:	18 4a 0f             	sbb    BYTE PTR [rdx+0xf],cl
    2280:	0b 77 08             	or     esi,DWORD PTR [rdi+0x8]
    2283:	80 00 3f             	add    BYTE PTR [rax],0x3f
    2286:	1a 3a                	sbb    bh,BYTE PTR [rdx]
    2288:	2a 33                	sub    dh,BYTE PTR [rbx]
    228a:	24 22                	and    al,0x22
    228c:	00 00                	add    BYTE PTR [rax],al
    228e:	00 00                	add    BYTE PTR [rax],al
    2290:	14 00                	adc    al,0x0
    2292:	00 00                	add    BYTE PTR [rax],al
    2294:	5c                   	pop    rsp
    2295:	00 00                	add    BYTE PTR [rax],al
    2297:	00 a8 ee ff ff 20    	add    BYTE PTR [rax+0x20ffffee],ch
	...
    22a5:	00 00                	add    BYTE PTR [rax],al
    22a7:	00 14 00             	add    BYTE PTR [rax+rax*1],dl
    22aa:	00 00                	add    BYTE PTR [rax],al
    22ac:	74 00                	je     22ae <__GNU_EH_FRAME_HDR+0xba>
    22ae:	00 00                	add    BYTE PTR [rax],al
    22b0:	b0 ee                	mov    al,0xee
    22b2:	ff                   	(bad)  
    22b3:	ff 10                	call   QWORD PTR [rax]
    22b5:	01 00                	add    DWORD PTR [rax],eax
	...
    22bf:	00 1c 00             	add    BYTE PTR [rax+rax*1],bl
    22c2:	00 00                	add    BYTE PTR [rax],al
    22c4:	8c 00                	mov    WORD PTR [rax],es
    22c6:	00 00                	add    BYTE PTR [rax],al
    22c8:	91                   	xchg   ecx,eax
    22c9:	f0 ff                	lock (bad) 
    22cb:	ff 68 00             	jmp    FWORD PTR [rax+0x0]
    22ce:	00 00                	add    BYTE PTR [rax],al
    22d0:	00 45 0e             	add    BYTE PTR [rbp+0xe],al
    22d3:	10 86 02 43 0d 06    	adc    BYTE PTR [rsi+0x60d4302],al
    22d9:	02 5f 0c             	add    bl,BYTE PTR [rdi+0xc]
    22dc:	07                   	(bad)  
    22dd:	08 00                	or     BYTE PTR [rax],al
    22df:	00 1c 00             	add    BYTE PTR [rax+rax*1],bl
    22e2:	00 00                	add    BYTE PTR [rax],al
    22e4:	ac                   	lods   al,BYTE PTR ds:[rsi]
    22e5:	00 00                	add    BYTE PTR [rax],al
    22e7:	00 d9                	add    cl,bl
    22e9:	f0 ff                	lock (bad) 
    22eb:	ff 73 01             	push   QWORD PTR [rbx+0x1]
    22ee:	00 00                	add    BYTE PTR [rax],al
    22f0:	00 45 0e             	add    BYTE PTR [rbp+0xe],al
    22f3:	10 86 02 43 0d 06    	adc    BYTE PTR [rsi+0x60d4302],al
    22f9:	03 6a 01             	add    ebp,DWORD PTR [rdx+0x1]
    22fc:	0c 07                	or     al,0x7
    22fe:	08 00                	or     BYTE PTR [rax],al
    2300:	1c 00                	sbb    al,0x0
    2302:	00 00                	add    BYTE PTR [rax],al
    2304:	cc                   	int3   
    2305:	00 00                	add    BYTE PTR [rax],al
    2307:	00 2c f2             	add    BYTE PTR [rdx+rsi*8],ch
    230a:	ff                   	(bad)  
    230b:	ff 9b 04 00 00 00    	call   FWORD PTR [rbx+0x4]
    2311:	45 0e                	rex.RB (bad) 
    2313:	10 86 02 43 0d 06    	adc    BYTE PTR [rsi+0x60d4302],al
    2319:	03 92 04 0c 07 08    	add    edx,DWORD PTR [rdx+0x8070c04]
	...

0000000000002320 <__FRAME_END__>:
    2320:	00 00                	add    BYTE PTR [rax],al
	...

Disassembly of section .init_array:

0000000000003d30 <__frame_dummy_init_array_entry>:
    3d30:	50                   	push   rax
    3d31:	13 00                	adc    eax,DWORD PTR [rax]
    3d33:	00 00                	add    BYTE PTR [rax],al
    3d35:	00 00                	add    BYTE PTR [rax],al
	...

Disassembly of section .fini_array:

0000000000003d38 <__do_global_dtors_aux_fini_array_entry>:
    3d38:	10 13                	adc    BYTE PTR [rbx],dl
    3d3a:	00 00                	add    BYTE PTR [rax],al
    3d3c:	00 00                	add    BYTE PTR [rax],al
	...

Disassembly of section .dynamic:

0000000000003d40 <_DYNAMIC>:
    3d40:	01 00                	add    DWORD PTR [rax],eax
    3d42:	00 00                	add    BYTE PTR [rax],al
    3d44:	00 00                	add    BYTE PTR [rax],al
    3d46:	00 00                	add    BYTE PTR [rax],al
    3d48:	bf 00 00 00 00       	mov    edi,0x0
    3d4d:	00 00                	add    BYTE PTR [rax],al
    3d4f:	00 0c 00             	add    BYTE PTR [rax+rax*1],cl
    3d52:	00 00                	add    BYTE PTR [rax],al
    3d54:	00 00                	add    BYTE PTR [rax],al
    3d56:	00 00                	add    BYTE PTR [rax],al
    3d58:	00 10                	add    BYTE PTR [rax],dl
    3d5a:	00 00                	add    BYTE PTR [rax],al
    3d5c:	00 00                	add    BYTE PTR [rax],al
    3d5e:	00 00                	add    BYTE PTR [rax],al
    3d60:	0d 00 00 00 00       	or     eax,0x0
    3d65:	00 00                	add    BYTE PTR [rax],al
    3d67:	00 d0                	add    al,dl
    3d69:	19 00                	sbb    DWORD PTR [rax],eax
    3d6b:	00 00                	add    BYTE PTR [rax],al
    3d6d:	00 00                	add    BYTE PTR [rax],al
    3d6f:	00 19                	add    BYTE PTR [rcx],bl
    3d71:	00 00                	add    BYTE PTR [rax],al
    3d73:	00 00                	add    BYTE PTR [rax],al
    3d75:	00 00                	add    BYTE PTR [rax],al
    3d77:	00 30                	add    BYTE PTR [rax],dh
    3d79:	3d 00 00 00 00       	cmp    eax,0x0
    3d7e:	00 00                	add    BYTE PTR [rax],al
    3d80:	1b 00                	sbb    eax,DWORD PTR [rax]
    3d82:	00 00                	add    BYTE PTR [rax],al
    3d84:	00 00                	add    BYTE PTR [rax],al
    3d86:	00 00                	add    BYTE PTR [rax],al
    3d88:	08 00                	or     BYTE PTR [rax],al
    3d8a:	00 00                	add    BYTE PTR [rax],al
    3d8c:	00 00                	add    BYTE PTR [rax],al
    3d8e:	00 00                	add    BYTE PTR [rax],al
    3d90:	1a 00                	sbb    al,BYTE PTR [rax]
    3d92:	00 00                	add    BYTE PTR [rax],al
    3d94:	00 00                	add    BYTE PTR [rax],al
    3d96:	00 00                	add    BYTE PTR [rax],al
    3d98:	38 3d 00 00 00 00    	cmp    BYTE PTR [rip+0x0],bh        # 3d9e <_DYNAMIC+0x5e>
    3d9e:	00 00                	add    BYTE PTR [rax],al
    3da0:	1c 00                	sbb    al,0x0
    3da2:	00 00                	add    BYTE PTR [rax],al
    3da4:	00 00                	add    BYTE PTR [rax],al
    3da6:	00 00                	add    BYTE PTR [rax],al
    3da8:	08 00                	or     BYTE PTR [rax],al
    3daa:	00 00                	add    BYTE PTR [rax],al
    3dac:	00 00                	add    BYTE PTR [rax],al
    3dae:	00 00                	add    BYTE PTR [rax],al
    3db0:	f5                   	cmc    
    3db1:	fe                   	(bad)  
    3db2:	ff 6f 00             	jmp    FWORD PTR [rdi+0x0]
    3db5:	00 00                	add    BYTE PTR [rax],al
    3db7:	00 b0 03 00 00 00    	add    BYTE PTR [rax+0x3],dh
    3dbd:	00 00                	add    BYTE PTR [rax],al
    3dbf:	00 05 00 00 00 00    	add    BYTE PTR [rip+0x0],al        # 3dc5 <_DYNAMIC+0x85>
    3dc5:	00 00                	add    BYTE PTR [rax],al
    3dc7:	00 70 06             	add    BYTE PTR [rax+0x6],dh
    3dca:	00 00                	add    BYTE PTR [rax],al
    3dcc:	00 00                	add    BYTE PTR [rax],al
    3dce:	00 00                	add    BYTE PTR [rax],al
    3dd0:	06                   	(bad)  
    3dd1:	00 00                	add    BYTE PTR [rax],al
    3dd3:	00 00                	add    BYTE PTR [rax],al
    3dd5:	00 00                	add    BYTE PTR [rax],al
    3dd7:	00 e8                	add    al,ch
    3dd9:	03 00                	add    eax,DWORD PTR [rax]
    3ddb:	00 00                	add    BYTE PTR [rax],al
    3ddd:	00 00                	add    BYTE PTR [rax],al
    3ddf:	00 0a                	add    BYTE PTR [rdx],cl
    3de1:	00 00                	add    BYTE PTR [rax],al
    3de3:	00 00                	add    BYTE PTR [rax],al
    3de5:	00 00                	add    BYTE PTR [rax],al
    3de7:	00 44 01 00          	add    BYTE PTR [rcx+rax*1+0x0],al
    3deb:	00 00                	add    BYTE PTR [rax],al
    3ded:	00 00                	add    BYTE PTR [rax],al
    3def:	00 0b                	add    BYTE PTR [rbx],cl
    3df1:	00 00                	add    BYTE PTR [rax],al
    3df3:	00 00                	add    BYTE PTR [rax],al
    3df5:	00 00                	add    BYTE PTR [rax],al
    3df7:	00 18                	add    BYTE PTR [rax],bl
    3df9:	00 00                	add    BYTE PTR [rax],al
    3dfb:	00 00                	add    BYTE PTR [rax],al
    3dfd:	00 00                	add    BYTE PTR [rax],al
    3dff:	00 15 00 00 00 00    	add    BYTE PTR [rip+0x0],dl        # 3e05 <_DYNAMIC+0xc5>
	...
    3e0d:	00 00                	add    BYTE PTR [rax],al
    3e0f:	00 03                	add    BYTE PTR [rbx],al
    3e11:	00 00                	add    BYTE PTR [rax],al
    3e13:	00 00                	add    BYTE PTR [rax],al
    3e15:	00 00                	add    BYTE PTR [rax],al
    3e17:	00 30                	add    BYTE PTR [rax],dh
    3e19:	3f                   	(bad)  
    3e1a:	00 00                	add    BYTE PTR [rax],al
    3e1c:	00 00                	add    BYTE PTR [rax],al
    3e1e:	00 00                	add    BYTE PTR [rax],al
    3e20:	02 00                	add    al,BYTE PTR [rax]
    3e22:	00 00                	add    BYTE PTR [rax],al
    3e24:	00 00                	add    BYTE PTR [rax],al
    3e26:	00 00                	add    BYTE PTR [rax],al
    3e28:	98                   	cwde   
    3e29:	01 00                	add    DWORD PTR [rax],eax
    3e2b:	00 00                	add    BYTE PTR [rax],al
    3e2d:	00 00                	add    BYTE PTR [rax],al
    3e2f:	00 14 00             	add    BYTE PTR [rax+rax*1],dl
    3e32:	00 00                	add    BYTE PTR [rax],al
    3e34:	00 00                	add    BYTE PTR [rax],al
    3e36:	00 00                	add    BYTE PTR [rax],al
    3e38:	07                   	(bad)  
    3e39:	00 00                	add    BYTE PTR [rax],al
    3e3b:	00 00                	add    BYTE PTR [rax],al
    3e3d:	00 00                	add    BYTE PTR [rax],al
    3e3f:	00 17                	add    BYTE PTR [rdi],dl
    3e41:	00 00                	add    BYTE PTR [rax],al
    3e43:	00 00                	add    BYTE PTR [rax],al
    3e45:	00 00                	add    BYTE PTR [rax],al
    3e47:	00 70 09             	add    BYTE PTR [rax+0x9],dh
    3e4a:	00 00                	add    BYTE PTR [rax],al
    3e4c:	00 00                	add    BYTE PTR [rax],al
    3e4e:	00 00                	add    BYTE PTR [rax],al
    3e50:	07                   	(bad)  
    3e51:	00 00                	add    BYTE PTR [rax],al
    3e53:	00 00                	add    BYTE PTR [rax],al
    3e55:	00 00                	add    BYTE PTR [rax],al
    3e57:	00 50 08             	add    BYTE PTR [rax+0x8],dl
    3e5a:	00 00                	add    BYTE PTR [rax],al
    3e5c:	00 00                	add    BYTE PTR [rax],al
    3e5e:	00 00                	add    BYTE PTR [rax],al
    3e60:	08 00                	or     BYTE PTR [rax],al
    3e62:	00 00                	add    BYTE PTR [rax],al
    3e64:	00 00                	add    BYTE PTR [rax],al
    3e66:	00 00                	add    BYTE PTR [rax],al
    3e68:	20 01                	and    BYTE PTR [rcx],al
    3e6a:	00 00                	add    BYTE PTR [rax],al
    3e6c:	00 00                	add    BYTE PTR [rax],al
    3e6e:	00 00                	add    BYTE PTR [rax],al
    3e70:	09 00                	or     DWORD PTR [rax],eax
    3e72:	00 00                	add    BYTE PTR [rax],al
    3e74:	00 00                	add    BYTE PTR [rax],al
    3e76:	00 00                	add    BYTE PTR [rax],al
    3e78:	18 00                	sbb    BYTE PTR [rax],al
    3e7a:	00 00                	add    BYTE PTR [rax],al
    3e7c:	00 00                	add    BYTE PTR [rax],al
    3e7e:	00 00                	add    BYTE PTR [rax],al
    3e80:	1e                   	(bad)  
    3e81:	00 00                	add    BYTE PTR [rax],al
    3e83:	00 00                	add    BYTE PTR [rax],al
    3e85:	00 00                	add    BYTE PTR [rax],al
    3e87:	00 08                	add    BYTE PTR [rax],cl
    3e89:	00 00                	add    BYTE PTR [rax],al
    3e8b:	00 00                	add    BYTE PTR [rax],al
    3e8d:	00 00                	add    BYTE PTR [rax],al
    3e8f:	00 fb                	add    bl,bh
    3e91:	ff                   	(bad)  
    3e92:	ff 6f 00             	jmp    FWORD PTR [rdi+0x0]
    3e95:	00 00                	add    BYTE PTR [rax],al
    3e97:	00 01                	add    BYTE PTR [rcx],al
    3e99:	00 00                	add    BYTE PTR [rax],al
    3e9b:	08 00                	or     BYTE PTR [rax],al
    3e9d:	00 00                	add    BYTE PTR [rax],al
    3e9f:	00 fe                	add    dh,bh
    3ea1:	ff                   	(bad)  
    3ea2:	ff 6f 00             	jmp    FWORD PTR [rdi+0x0]
    3ea5:	00 00                	add    BYTE PTR [rax],al
    3ea7:	00 f0                	add    al,dh
    3ea9:	07                   	(bad)  
    3eaa:	00 00                	add    BYTE PTR [rax],al
    3eac:	00 00                	add    BYTE PTR [rax],al
    3eae:	00 00                	add    BYTE PTR [rax],al
    3eb0:	ff                   	(bad)  
    3eb1:	ff                   	(bad)  
    3eb2:	ff 6f 00             	jmp    FWORD PTR [rdi+0x0]
    3eb5:	00 00                	add    BYTE PTR [rax],al
    3eb7:	00 01                	add    BYTE PTR [rcx],al
    3eb9:	00 00                	add    BYTE PTR [rax],al
    3ebb:	00 00                	add    BYTE PTR [rax],al
    3ebd:	00 00                	add    BYTE PTR [rax],al
    3ebf:	00 f0                	add    al,dh
    3ec1:	ff                   	(bad)  
    3ec2:	ff 6f 00             	jmp    FWORD PTR [rdi+0x0]
    3ec5:	00 00                	add    BYTE PTR [rax],al
    3ec7:	00 b4 07 00 00 00 00 	add    BYTE PTR [rdi+rax*1+0x0],dh
    3ece:	00 00                	add    BYTE PTR [rax],al
    3ed0:	f9                   	stc    
    3ed1:	ff                   	(bad)  
    3ed2:	ff 6f 00             	jmp    FWORD PTR [rdi+0x0]
    3ed5:	00 00                	add    BYTE PTR [rax],al
    3ed7:	00 03                	add    BYTE PTR [rbx],al
	...

Disassembly of section .got:

0000000000003f30 <_GLOBAL_OFFSET_TABLE_>:
    3f30:	40 3d 00 00 00 00    	rex cmp eax,0x0
	...
    3f46:	00 00                	add    BYTE PTR [rax],al
    3f48:	30 10                	xor    BYTE PTR [rax],dl
    3f4a:	00 00                	add    BYTE PTR [rax],al
    3f4c:	00 00                	add    BYTE PTR [rax],al
    3f4e:	00 00                	add    BYTE PTR [rax],al
    3f50:	40 10 00             	rex adc BYTE PTR [rax],al
    3f53:	00 00                	add    BYTE PTR [rax],al
    3f55:	00 00                	add    BYTE PTR [rax],al
    3f57:	00 50 10             	add    BYTE PTR [rax+0x10],dl
    3f5a:	00 00                	add    BYTE PTR [rax],al
    3f5c:	00 00                	add    BYTE PTR [rax],al
    3f5e:	00 00                	add    BYTE PTR [rax],al
    3f60:	60                   	(bad)  
    3f61:	10 00                	adc    BYTE PTR [rax],al
    3f63:	00 00                	add    BYTE PTR [rax],al
    3f65:	00 00                	add    BYTE PTR [rax],al
    3f67:	00 70 10             	add    BYTE PTR [rax+0x10],dh
    3f6a:	00 00                	add    BYTE PTR [rax],al
    3f6c:	00 00                	add    BYTE PTR [rax],al
    3f6e:	00 00                	add    BYTE PTR [rax],al
    3f70:	80 10 00             	adc    BYTE PTR [rax],0x0
    3f73:	00 00                	add    BYTE PTR [rax],al
    3f75:	00 00                	add    BYTE PTR [rax],al
    3f77:	00 90 10 00 00 00    	add    BYTE PTR [rax+0x10],dl
    3f7d:	00 00                	add    BYTE PTR [rax],al
    3f7f:	00 a0 10 00 00 00    	add    BYTE PTR [rax+0x10],ah
    3f85:	00 00                	add    BYTE PTR [rax],al
    3f87:	00 b0 10 00 00 00    	add    BYTE PTR [rax+0x10],dh
    3f8d:	00 00                	add    BYTE PTR [rax],al
    3f8f:	00 c0                	add    al,al
    3f91:	10 00                	adc    BYTE PTR [rax],al
    3f93:	00 00                	add    BYTE PTR [rax],al
    3f95:	00 00                	add    BYTE PTR [rax],al
    3f97:	00 d0                	add    al,dl
    3f99:	10 00                	adc    BYTE PTR [rax],al
    3f9b:	00 00                	add    BYTE PTR [rax],al
    3f9d:	00 00                	add    BYTE PTR [rax],al
    3f9f:	00 e0                	add    al,ah
    3fa1:	10 00                	adc    BYTE PTR [rax],al
    3fa3:	00 00                	add    BYTE PTR [rax],al
    3fa5:	00 00                	add    BYTE PTR [rax],al
    3fa7:	00 f0                	add    al,dh
    3fa9:	10 00                	adc    BYTE PTR [rax],al
    3fab:	00 00                	add    BYTE PTR [rax],al
    3fad:	00 00                	add    BYTE PTR [rax],al
    3faf:	00 00                	add    BYTE PTR [rax],al
    3fb1:	11 00                	adc    DWORD PTR [rax],eax
    3fb3:	00 00                	add    BYTE PTR [rax],al
    3fb5:	00 00                	add    BYTE PTR [rax],al
    3fb7:	00 10                	add    BYTE PTR [rax],dl
    3fb9:	11 00                	adc    DWORD PTR [rax],eax
    3fbb:	00 00                	add    BYTE PTR [rax],al
    3fbd:	00 00                	add    BYTE PTR [rax],al
    3fbf:	00 20                	add    BYTE PTR [rax],ah
    3fc1:	11 00                	adc    DWORD PTR [rax],eax
    3fc3:	00 00                	add    BYTE PTR [rax],al
    3fc5:	00 00                	add    BYTE PTR [rax],al
    3fc7:	00 30                	add    BYTE PTR [rax],dh
    3fc9:	11 00                	adc    DWORD PTR [rax],eax
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

0000000000004020 <stdout@GLIBC_2.2.5>:
	...

0000000000004030 <stdin@GLIBC_2.2.5>:
	...

0000000000004040 <stderr@GLIBC_2.2.5>:
	...

0000000000004048 <completed.0>:
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
  12:	30 2d 31 75 62 75    	xor    BYTE PTR [rip+0x75627531],ch        # 75627549 <_end+0x756234f9>
  18:	6e                   	outs   dx,BYTE PTR ds:[rsi]
  19:	74 75                	je     90 <__abi_tag-0x2fc>
  1b:	31 7e 32             	xor    DWORD PTR [rsi+0x32],edi
  1e:	32 2e                	xor    ch,BYTE PTR [rsi]
  20:	30 34 29             	xor    BYTE PTR [rcx+rbp*1],dh
  23:	20 31                	and    BYTE PTR [rcx],dh
  25:	31 2e                	xor    DWORD PTR [rsi],ebp
  27:	33 2e                	xor    ebp,DWORD PTR [rsi]
  29:	30 00                	xor    BYTE PTR [rax],al
