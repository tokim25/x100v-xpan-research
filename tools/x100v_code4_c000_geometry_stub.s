/* Offline-only X100V 3.01 C000 geometry experiment. The two entry points
 * replace one default-path instruction each, while preserving code 1/2
 * branches and the original default calculation for other aspect codes.
 * This does not establish that the zero-filled destination is executable
 * on camera or that the C000 fields define a RAW editor crop.
 */
.syntax unified
.arch armv7-a
.arch_extension idiv
.arm
.text
.global code4_c000_first
.global code4_c000_second
code4_c000_first:
    cmp r3, #4
    bne first_default
    cmp r5, #0
    ble first_default
    mov r3, #24
    mul r6, r5, r3
    mov r3, #65
    udiv r6, r6, r3
    ldr pc, [pc, #-4]
    .word 0x01ed6c84
first_default:
    lsl r3, r5, #1
    ldr pc, [pc, #-4]
    .word 0x01ed6c74

    .org 0x40
code4_c000_second:
    cmp ip, #4
    bne second_default
    cmp r0, #0
    ble second_default
    mov r3, #24
    mul r2, r0, r3
    mov r3, #65
    udiv r2, r2, r3
    ldr pc, [pc, #-4]
    .word 0x01ed6cc0
second_default:
    lsl r3, r0, #1
    ldr pc, [pc, #-4]
    .word 0x01ed6cb0
