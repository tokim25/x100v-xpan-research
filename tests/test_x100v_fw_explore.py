from tools.x100v_fw_explore import branch_target, mov_imm, movw_imm


def test_movw_immediate_splits_imm4_and_imm12():
    assert movw_imm(0xE3063278) == 0x6278  # movw r3, #0x6278
    assert movw_imm(0xE30E3064) == 0xE064  # movw r3, #0xe064


def test_mov_immediate_applies_rotation():
    assert mov_imm(0xE3A03018) == 24  # mov r3, #24
    assert mov_imm(0xE3A00B01) == 0x400  # mov r0, #0x400
    assert mov_imm(0xE1A00000) is None  # mov r0, r0


def test_branch_target_matches_hand_encoded_hooks():
    # card 5e hook: b 0x0128fd40 at 0x01f69464
    offset = ((0x0128FD40 - (0x01F69464 + 8)) >> 2) & 0xFFFFFF
    assert branch_target(0xEA000000 | offset, 0x01F69464) == 0x0128FD40
    # stock `b 0x1f6939c` at 0x01f69474
    assert branch_target(0xEAFFFFC8, 0x01F69474) == 0x01F6939C
    assert branch_target(0xE3A03009, 0x01F69464) is None
