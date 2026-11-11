/* X100V 3.01: mark 16:9-setting RAFs as a 65:24 image area. NOT camera-validated.
 * Placed at 0x0128fd40 in primary zero padding; reached by a B that replaces
 * `mov r3, #9` at secondary 0x01f69464, the aspect-code-2 case of RAF info
 * builder 0x01f689b0. There r4 = RAF info record and sl = its mirror record
 * (or 0). The RAF directory template at 0x013ec880 serializes record +0x04
 * as tag 0x0110 (top, left), +0x08 as tag 0x0111 (height, width) and +0x14 as
 * tag 0x0115 (aspect). The stub writes the 24:65 aspect, and when the stored
 * height is the stock 4160 it narrows the area to 2304 rows starting 930 rows
 * lower (a multiple of 6, so the X-Trans pattern phase is kept), mirrors both
 * fields into sl, then rejoins the builder at 0x01f6939c.
 */
.syntax unified
.arm
.text
.global raf_crop_stub
raf_crop_stub:
    push {r0, r1}
    mov r3, #24
    strh r3, [r4, #0x14]
    mov r3, #65
    strh r3, [r4, #0x16]
    ldrh r0, [r4, #8]          @ stored height
    movw r1, #4160
    cmp r0, r1
    bne done                   @ unexpected area: aspect tag only
    movw r0, #2304
    strh r0, [r4, #8]
    ldrh r0, [r4, #4]          @ stored top
    movw r1, #930
    add r0, r0, r1
    strh r0, [r4, #4]
    cmp sl, #0
    beq done
    strh r0, [sl, #4]
    movw r0, #2304
    strh r0, [sl, #8]
done:
    pop {r0, r1}
    ldr pc, rejoin
rejoin:
    .word 0x01f6939c
