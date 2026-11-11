/* Offline-only card 6a. Two stubs for the primary zero padding.
 *
 * raf_container runs in place of `sub sp, fp, #0x18` at 0x01ed85c8, just
 * after the RAF-info builder 0x01f689b0 returns inside 0x01ed8544. There
 * r4 is the per-shot object and r0 the builder's result. When the record
 * at r4+0x228 is the full-sensor layout with the 24:65 aspect and the
 * mosaic is the uncompressed full size, it reshapes the RAF into the
 * Sports Finder container: 3348 rows starting at sensor row 420, with a
 * 6240x2304 visible area at (519, 6). Otherwise it changes nothing.
 *
 * crop_mode runs in place of `mov r3, #0` at 0x01f54130, the default
 * maker-note crop mode. It returns 2 for aspect code 2 and 0 otherwise.
 *
 * Static design; the live buffer layout and call order are unobserved.
 */
.syntax unified
.arm
.text
.global x100v_raf_container_stub
x100v_raf_container_stub:
    push {r0, r1, r2, r3, lr}
    add r2, r4, #0x228          /* RAF record buffer */
    add r3, r4, #0xae00
    add r3, r3, #0x98           /* sensor-data directory */
    adr lr, expected
    ldr r0, [r2, #0x14]         /* aspect halfwords 24, 65 */
    ldr r1, [lr], #4
    cmp r0, r1
    ldreq r0, [r2]              /* mosaic 4182 rows, 6384 wide */
    ldreq r1, [lr], #4
    cmpeq r0, r1
    ldreq r0, [r2, #4]          /* origin top 13, left 6 */
    ldreq r1, [lr], #4
    cmpeq r0, r1
    ldreq r0, [r2, #8]          /* visible 4160 rows, 6240 wide */
    ldreq r1, [lr], #4
    cmpeq r0, r1
    ldreq r0, [r4, #0x90]       /* uncompressed full mosaic length */
    ldreq r1, [lr], #4
    cmpeq r0, r1
    ldreq r0, [r3, #0x7c]       /* directory byte count agrees */
    cmpeq r0, r1
    ldreq r0, [r3, #0x34]       /* directory height 4182 */
    ldreq r1, [lr], #4
    cmpeq r0, r1
    bne done
    ldr r0, [r4, #0x8c]
    ldr r1, [lr], #4            /* 420 rows of 12768 bytes */
    add r0, r0, r1
    str r0, [r4, #0x8c]
    ldr r0, [lr], #4            /* 3348 rows of 12768 bytes */
    str r0, [r4, #0x90]
    str r0, [r3, #0x7c]
    add r1, r0, #0x800
    str r1, [r4, #0x1d4]
    movw r1, #3348
    str r1, [r3, #0x34]
    strh r1, [r2]
    movw r0, #519
    strh r0, [r2, #4]
    movw r0, #2304
    movw r1, #6240
    strh r0, [r2, #8]
    strh r1, [r2, #0xa]
    strh r1, [r2, #0xc]
    strh r0, [r2, #0xe]
    strh r0, [r2, #0x10]
    strh r1, [r2, #0x12]
    strh r0, [r2, #0x20]
    strh r1, [r2, #0x22]
done:
    pop {r0, r1, r2, r3, lr}
    sub sp, fp, #0x18
    bx lr
expected:
    .word 0x00410018            /* aspect: 24, 65 */
    .word 0x18f01056            /* mosaic: 4182, 6384 */
    .word 0x0006000d            /* origin: 13, 6 */
    .word 0x18601040            /* visible: 4160, 6240 */
    .word 0x032ec140            /* 6384 * 4182 * 2 */
    .word 4182
    .word 0x0051d380            /* 420 * 12768 */
    .word 0x028c4580            /* 3348 * 12768 */

.global x100v_crop_mode_stub
x100v_crop_mode_stub:
    ldrb r3, [sl, #0x5be]
    cmp r3, #2
    movne r3, #0
    bx lr
