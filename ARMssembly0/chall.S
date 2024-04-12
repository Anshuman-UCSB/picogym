	.arch armv8-a
	.file	"chall.c"
	.text
	.align	2
	.global	func1
	.type	func1, %function
func1: 				
	# inp1 = 266134863 
	# inp2 = 1592237099 
	sub	sp, sp, #16 # (#num is constant, allocates 2 vars on stack)
	str	w0, [sp, 12] # store inp1 at sp12
	str	w1, [sp, 8] # store inp2 at sp8
	ldr	w1, [sp, 12] # load inp1 to w1
	ldr	w0, [sp, 8] # load inp2 to w0
	cmp	w1, w0		# inp2 - inp1
	bls	.L2			# if if inp2 < inp1 then jump to .L2
	ldr	w0, [sp, 12]# load inp1 to w0
	b	.L3			# jump to .L3
.L2:
	ldr	w0, [sp, 8] # not reached
.L3:
	add	sp, sp, 16 	# deallocate vars
	ret				# go back
	.size	func1, .-func1
	.section	.rodata
	.align	3
.LC0:
	.string	"Result: %ld\n"
	.text
	.align	2
	.global	main
	.type	main, %function
main:
	stp	x29, x30, [sp, -48]!
	add	x29, sp, 0
	str	x19, [sp, 16]
	str	w0, [x29, 44]
	str	x1, [x29, 32]
	ldr	x0, [x29, 32]
	add	x0, x0, 8
	ldr	x0, [x0]
	bl	atoi
	mov	w19, w0
	ldr	x0, [x29, 32]
	add	x0, x0, 16
	ldr	x0, [x0]
	bl	atoi
	mov	w1, w0		# w1 = inp2
	mov	w0, w19		# w0 = inp1
	bl	func1
	mov	w1, w0
	adrp	x0, .LC0
	add	x0, x0, :lo12:.LC0
	bl	printf
	mov	w0, 0
	ldr	x19, [sp, 16]
	ldp	x29, x30, [sp], 48
	ret
	.size	main, .-main
	.ident	"GCC: (Ubuntu/Linaro 7.5.0-3ubuntu1~18.04) 7.5.0"
	.section	.note.GNU-stack,"",@progbits
