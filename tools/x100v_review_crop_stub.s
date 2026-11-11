/* X100V 3.01: crop the post-shot review window to 65:24 for aspect code 2.
 * NOT camera-validated. Placed at 0x0128fe80 in primary zero padding and
 * reached by BLs that replace `bl 0x0115f0a4` in the three review routines
 * (0x01f17978, 0x01f18da0, 0x01f19a80). It runs the original window fit
 * (width, height, aspect, &rect) and, for aspect 2 only, shrinks the height
 * to width*24/65 rounded down to a multiple of 4, adding the removed rows to
 * the top and bottom margins (rect: w, h, top, bottom, left, right words).
 */
.syntax unified
.arch_extension idiv
.arm
.text
.global review_crop_stub
review_crop_stub:
    push {r2, r3, r4, lr}
    ldr ip, fit
    blx ip
    pop {r2, r3}
    cmp r2, #2
    bne done
    ldr r0, [r3]            @ window width
    mov r1, #24
    mul r0, r0, r1
    mov r1, #65
    udiv r0, r0, r1
    bic r0, r0, #3          @ 65:24 height
    ldr r1, [r3, #4]        @ 16:9 height
    subs r1, r1, r0
    bls done                @ only ever shrink
    str r0, [r3, #4]
    lsr r2, r1, #1
    ldr r0, [r3, #8]
    add r0, r0, r2
    str r0, [r3, #8]        @ top margin
    sub r1, r1, r2
    ldr r0, [r3, #0xc]
    add r0, r0, r1
    str r0, [r3, #0xc]      @ bottom margin
done:
    pop {r4, pc}
fit:
    .word 0x0115f0a4
