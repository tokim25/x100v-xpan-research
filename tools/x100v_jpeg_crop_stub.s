/* X100V 3.01: crop 16:9 still JPEGs to 65:24 at encode time. NOT camera-validated.
 * Placed at 0x0128fc80 in primary zero padding; reached by a BL that replaces
 * `str r1, [r3, #0x14]` at secondary 0x01edc4f0 (main-image branch of the
 * compression setup 0x01edc308). There r1 = image base (descriptor +4),
 * r3 = encoder parameter block, r6 = image descriptor (+0xc stride bytes,
 * +0x10 width bytes, +0x14 height), [fp, #-0x44] = height used for the
 * encoder block and the header call. For a stock 16:9 L/M/S image the stub
 * sets the 65:24 height in both places and moves the base down by the rows
 * it skips; every other image passes through unchanged.
 */
.syntax unified
.arm
.text
.global jpeg_crop_stub
jpeg_crop_stub:
    push {r0, r4, r5, lr}
    adr r5, sizes
next:
    ldr r0, [r5], #16          @ width in bytes; 0 ends the table
    cmp r0, #0
    beq store
    ldr r4, [r6, #0x10]
    cmp r0, r4
    bne next
    ldr r0, [r5, #-12]         @ stock 16:9 height
    ldr r4, [fp, #-0x44]
    cmp r0, r4
    bne next
    ldr r0, [r5, #-8]          @ 65:24 height
    str r0, [fp, #-0x44]
    str r0, [r3, #0x10]
    ldr r0, [r5, #-4]          @ rows skipped at the top
    ldr r4, [r6, #0xc]
    mla r1, r0, r4, r1         @ base += rows * stride
store:
    str r1, [r3, #0x14]        @ the replaced instruction
    pop {r0, r4, r5, pc}
sizes:
    .word 12480, 3512, 2304, 604   @ L: 6240 px at 2 bytes per pixel
    .word 8832, 2488, 1632, 428    @ M: 4416 px
    .word 6240, 1760, 1152, 304    @ S: 3120 px
    .word 0
