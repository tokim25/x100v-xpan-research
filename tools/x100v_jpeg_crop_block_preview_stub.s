/* Offline candidate only: card-5f JPEG crop plus a guarded RAF-preview-size
 * encode case. Not camera-tested and not an SD-card or flash artifact.
 *
 * Existing hook 0x01edc4f0, setup 0x01edc308: r1 = image base,
 * r3 = encoder block, r6 = descriptor, r8 = wrapper's mode/selector bytes,
 * r5 = context (loaded at wrapper 0x01f40cfc before the call). The normal
 * L/M/S 16:9 rows remain exactly as card 5f. The extra 4416x2944 row runs
 * only for context aspect code 2 (the 16:9 alias) and selector byte 1.
 * Neither guard proves that this is the RAF preview's live route.
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
    ldrb r0, [r8, #1]         @ selector 1 only
    cmp r0, #1
    bne store
    ldr r4, [sp, #8]          @ saved context pointer, before r5 became table ptr
    ldrb r0, [r4, #0x5be]     @ image aspect code
    cmp r0, #2               @ stock 16:9 alias
    bne store
    ldr r0, [r6, #0x10]      @ 4416 pixels, 2 bytes/pixel
    movw r4, #8832
    cmp r0, r4
    bne store
    ldr r0, [fp, #-0x44]
    movw r4, #2944
    cmp r0, r4
    bne store
    movw r0, #1632
    str r0, [r3, #0x10]
    movw r0, #656            @ centered skip: (2944 - 1632) / 2
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
