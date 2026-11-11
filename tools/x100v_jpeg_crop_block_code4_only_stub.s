/* Offline selectable-code-4 successor. Preserve every original code-2
 * (16:9) encode by guarding the whole L/M/S and preview crop path.
 * The active context pointer is r5 at the hook entry. This file is not
 * a camera-tested patch and does not establish code-4 input geometry.
 */
.syntax unified
.arm
.text
.global jpeg_crop_stub
jpeg_crop_stub:
    push {r0, r4, r5, lr}
    ldrb r0, [r5, #0x5be]
    cmp r0, #4
    bne store
    adr r5, sizes
next:
    ldr r0, [r5], #16
    cmp r0, #0
    beq preview_check
    ldr r4, [r6, #0x10]
    cmp r0, r4
    bne next
    ldr r0, [r5, #-12]
    ldr r4, [fp, #-0x44]
    cmp r0, r4
    bne next
    ldr r0, [r5, #-8]
    str r0, [r3, #0x10]
    ldr r0, [r5, #-4]
    ldr r4, [r6, #0xc]
    mla r1, r0, r4, r1
    b store
preview_check:
    ldr r0, [r6, #0x10]
    movw r4, #8832
    cmp r0, r4
    bne store
    ldr r0, [fp, #-0x44]
    movw r4, #2944
    cmp r0, r4
    bne store
    movw r0, #1632
    str r0, [r3, #0x10]
    movw r0, #656
    ldr r4, [r6, #0xc]
    mla r1, r0, r4, r1
store:
    str r1, [r3, #0x14]
    pop {r0, r4, r5, pc}
sizes:
    .word 12480, 3512, 2304, 604
    .word 8832, 2488, 1632, 428
    .word 6240, 1760, 1152, 304
    .word 0
