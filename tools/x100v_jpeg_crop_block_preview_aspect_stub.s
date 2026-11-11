/* Offline diagnostic successor to card 5g. No SD/camera/flash approval.
 * Crop the 4416x2944 encode only when the active context aspect is code 2
 * (the 16:9 alias). Unlike card 5g, do not assume selector 1. This tests
 * whether a mode-0 call with another selector owns the RAF preview.
 * Other 3:2 aspects pass unchanged; existing L/M/S rows are preserved.
 */
.syntax unified
.arm
.text
.global jpeg_crop_stub
jpeg_crop_stub:
    push {r0, r4, r5, lr}
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
    ldr r4, [sp, #8]          @ saved context, before r5 became table ptr
    ldrb r0, [r4, #0x5be]     @ active image aspect
    cmp r0, #2
    bne store
    ldr r0, [r6, #0x10]      @ 4416 px at 2 bytes per pixel
    movw r4, #8832
    cmp r0, r4
    bne store
    ldr r0, [fp, #-0x44]
    movw r4, #2944
    cmp r0, r4
    bne store
    movw r0, #1632
    str r0, [r3, #0x10]
    movw r0, #656            @ (2944 - 1632) / 2
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
