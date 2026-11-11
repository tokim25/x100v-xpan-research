/* Offline-only card-5h successor. The stock EXIF join at 0x01f581cc
 * stages TIFF dimensions at r6+0x2a0/+0x2a4. Keep the existing L/M/S
 * 16:9 alias cases and additionally correct a 4416x2944 preview that
 * card 5h's encoder physically saves as 4416x1632. This applies only
 * when the metadata context still reports aspect code 2. Its live
 * context and call order have not been observed; do not use on an SD card.
 */
.syntax unified
.arm
.text
.global x100v_exif_dimension_stub_preview
x100v_exif_dimension_stub_preview:
    push {r0, r1, r2, lr}
    ldrb r0, [r4, #0x5be]
    cmp r0, #2
    bne original
    ldr r0, [r6, #0x2a0]
    ldr r1, [r6, #0x2a4]
    adr r2, dimensions
next:
    ldr r3, [r2], #12
    cmp r3, #0
    beq original
    cmp r0, r3
    bne next
    ldr r3, [r2, #-8]
    cmp r1, r3
    bne next
    ldr r3, [r2, #-4]
    str r3, [r6, #0x2a4]
original:
    ldrb r3, [r4, #0x624]
    pop {r0, r1, r2, pc}
dimensions:
    .word 6240, 3512, 2304
    .word 4416, 2488, 1632
    .word 3120, 1760, 1152
    .word 4416, 2944, 1632
    .word 0
