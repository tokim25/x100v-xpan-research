/* Analysis-only X100V 3.01 preview experiment. NOT boot-validated.
 * Linked by placement at 0x0128fb20; local labels need no relocation.
 * All original table rows/cache sizes stay intact. New code-4 keys reuse
 * code-2 cache indices, whose suitability remains UNVERIFIED.
 */
.syntax unified
.arm
.text
.global preview_alias_stubs
preview_alias_stubs:
    cmp r0, #1
    ldreq pc, bypass_return
    cmp r3, #4
    bne old_lookup
    cmp r1, #2
    bhi old_lookup
    cmp r2, #1
    bhi old_lookup
    mov r3, #2
old_lookup:
    ldr pc, lookup_continuation
bypass_return: .word 0x0115d758
lookup_continuation: .word 0x0115d704

/* Second hook: original instruction at 0x0115d9a0. The type-29 branch
 * has already occurred before this hook and is deliberately untouched.
 */
.org 0x40
dimension_override:
    ldrb r3, [r5, #6]
    cmp r3, #4
    bne old_dimensions
    ldrb r3, [r5, #2]
    cmp r3, #1
    beq old_dimensions
    ldrb r3, [r5, #5]
    cmp r3, #2
    bhi old_dimensions
    ldrb r12, [r5, #4]
    cmp r12, #1
    bhi old_dimensions
    adr r12, sizes
    add r3, r12, r3, lsl #2
    ldrh r2, [r3]
    strh r2, [r4, #2]
    ldrh r3, [r3, #2]
    strh r3, [r4, #4]
    ldr pc, dimensions_done
old_dimensions:
    movw r3, #0x6230
    ldr pc, dimensions_continuation
sizes:
    .hword 6240, 2304
    .hword 4416, 1632
    .hword 3120, 1152
dimensions_done: .word 0x0115d9bc
dimensions_continuation: .word 0x0115d9a4
