	.intel_syntax noprefix
	.text
	
virtnet_poll:
	cmp    r12d,r13d
    	jg     virtnet_poll + 0x12a	
#	.byte 0x45
#	.byte 0x39
#	.byte 0xec
#	.byte 0x0f
#	.byte 0x8f
#	.byte 0x21
#	.byte 0x01
#	.byte 0x00
#	.byte 0x00
		







	
