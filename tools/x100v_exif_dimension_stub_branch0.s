/* Historical branch-0-only EXIF height experiment, superseded by the
 * common-join hook. This assembles to the 116-byte stub in the first
 * experimental manifest; do not use for a new camera card.
 */
.syntax unified
.arm
.text
.global x100v_exif_dimension_stub_branch0
x100v_exif_dimension_stub_branch0:
    push {r0, r1, r2, lr}
    ldrb r0, [r4, #0x5be]
    cmp r0, #2
    bne original
    ldr r0, [r6, #0x2a0]
    adr r2, dimensions
next:
    ldr r1, [r2], #12
    cmp r1, #0
    beq original
    cmp r0, r1
    bne next
    ldr r1, [r2, #-8]
    cmp r3, r1
    bne next
    ldr r1, [r2, #-4]
    str r1, [r6, #0x2a4]
    pop {r0, r1, r2, pc}
original:
    str r3, [r6, #0x2a4]
    pop {r0, r1, r2, pc}
dimensions:
    .word 6240, 3512, 2304
    .word 4416, 2488, 1632
    .word 3120, 1760, 1152
    .word 0
