/* Experimental X100V 3.01 EXIF dimension correction, common-join version.
 * Linked as raw A32 code at primary 0x0128fe00. The BL at secondary
 * 0x01f581cc replaces `ldrb r3, [r4, #0x624]` after both dimension paths.
 * Retain the encoder's original dimensions and all nonmatching metadata.
 */
.syntax unified
.arm
.text
.global x100v_exif_dimension_stub
x100v_exif_dimension_stub:
    push {r0, r1, r2, lr}
    ldrb r0, [r4, #0x5be]
    cmp r0, #2                 @ stock 16:9 aspect code
    bne original
    ldr r0, [r6, #0x2a0]       @ staged width from either path
    ldr r1, [r6, #0x2a4]       @ staged height from either path
    adr r2, dimensions
next:
    ldr r3, [r2], #12          @ stock width; 0 terminates
    cmp r3, #0
    beq original
    cmp r0, r3
    bne next
    ldr r3, [r2, #-8]         @ stock 16:9 height
    cmp r1, r3
    bne next
    ldr r3, [r2, #-4]         @ matching 65:24 height
    str r3, [r6, #0x2a4]
original:
    ldrb r3, [r4, #0x624]     @ displaced instruction
    pop {r0, r1, r2, pc}
dimensions:
    .word 6240, 3512, 2304
    .word 4416, 2488, 1632
    .word 3120, 1760, 1152
    .word 0
