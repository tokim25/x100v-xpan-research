"""Static, read-only aspect-data validation for pinned X100V/GFX100 updates.

It does not prove menu, finder, RAF, JPEG, or boot behavior. In particular it
must never be used as a firmware-signature check or a release gate by itself.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
from pathlib import Path

from tools.fuji_firmware_probe import HEADER_SIZE, lzss_decode


SOURCES = {
    "x100v_3_01": {
        "sha256": "18351a9a552c06ec9c70483abca1b74ab2a29fa139f19aef244e178045323591",
        "version": (3, 1),
        "primary_header": 0x280060,
        "primary_load": 0x00F21000,
        # Same pinned FujiMod recovery catalog; offset is relative to XOR payload.
        "kernel_partition_offset": 0x60060,
        "kernel_partition_size": 0x1B0E0,
        "kernel_partition_load": 0x00040000,
        "kernel_partition_sha256": "d499061311e8519fb8fa5d3d6a41c8bc0f37aee05ef924e404699e60e35766cd",
        "configuration_defaults_offset": 0xC0060,
        "configuration_defaults_size": 0xA0000,
        "configuration_defaults_sha256": "4f237f5e01e546bc7763679ec5016cc715a653fb66c3ec35b96e39d125841bd6",
        "encoder_accessor_kernel_words": {
            0x5AA18: 0xE52DB004,
            0x5AA1C: 0xE28DB000,
            0x5AA20: 0xE5801000,  # direct 32-bit store r1 -> [r0], no translation
            0x5AA24: 0xE28BD000,
            0x5AA28: 0xE49DB004,
            0x5AA2C: 0xE12FFF1E,
            0x5AA60: 0xE52DB004,
            0x5AA64: 0xE28DB000,
            0x5AA68: 0xE5900000,  # direct 32-bit load [r0] -> r0, no translation
            0x5AA6C: 0xE28BD000,
            0x5AA70: 0xE49DB004,
            0x5AA74: 0xE12FFF1E,
        },
        "volume_partition_offset": 0x180060,
        "volume_partition_size": 0x2AD20,
        "volume_partition_load": 0x00D20400,
        "volume_partition_sha256": "898409ea6179c319bfe42a69bac97e45faff85872ddd5a69505d2bbdcd4832d7",
        # FujiMod pinned X100V recovery catalog maps this raw overlay extent.
        "overlay_partition_offset": 0xA00060,
        "overlay_partition_size": 0xA00000,
        "overlay_partition_load": 0x03720000,
        "overlay_partition_sha256": "cb8770127a28edff2474ce8f05d7ccb39a33a39e02801a2449182fb5843855b3",
        "exif_buffer_pack_overlay_words": {
            0x3DAC578: 0xE92D4800,
            0x3DAC580: 0xE2802008,  # pair array at destination +8
            0x3DAC588: 0xE5933650,  # source +0x12650 selects alternate layout
            0x3DAC594: 0xE5913000,  # source pointer +0
            0x3DAC598: 0xE5803008,  # destination pair pointer
            0x3DAC59C: 0xE5913008,  # source length +8
            0x3DAC5A0: 0xE580300C,  # destination pair length
            0x3DAC5C4: 0xE591E130,  # second component pointer
            0x3DAC5CC: 0xE591E138,  # second component length
            0x3DAC5F0: 0xE591E37C,  # third component pointer
            0x3DAC5F8: 0xE591E380,  # third component length
            0x3DAC618: 0xE5D1C390,  # optional-component gate
            0x3DAC628: 0xE591E020,  # final component pointer
            0x3DAC630: 0xE5911028,  # final component length
            0x3DAC644: 0xE7821183,  # terminator pointer zero
            0x3DAC648: 0xE58C1004,  # terminator length zero
            0x3DAC658: 0xE5913660,  # alternate pointer at source +0x12660
            0x3DAC68C: 0xE580300C,  # alternate six-length sum
            0x3DAC69C: 0xE591E250,  # optional component pointer
            0x3DAC6A4: 0xE591E258,  # optional component length
        },
        "encoder_component_overlay_words": {
            0x3DAC42C: 0xE5962008,  # main input width candidate
            0x3DAC47C: 0xE5963010,  # main input height candidate
            0x3DAC480: 0xE58D3008,
            0x3DAC484: 0xE58D2004,
            0x3DAF08C: 0xE59B3008,  # caller stack +4 -> codec +0xc
            0x3DAF090: 0xE58030AC,
            0x3DAF094: 0xE59B300C,  # caller stack +8 -> codec +0x10
            0x3DAF098: 0xE58030B0,
            0x3DAC444: 0xE5963018,  # input descriptor output-address low word
            0x3DAC448: 0xE58D3028,  # stack argument at +0x28
            0x3DAF0AC: 0xE59B202C,  # after saved frame word
            0x3DAF0B0: 0xE58020C0,  # main descriptor +0xc0 = source +0x100
            0x3DAF0B4: 0xE58030C4,  # initialize high word to zero
            0x3DAC49C: 0xE2840040,  # main descriptor at source +0x40
            0x3DAC4A0: 0xEB000AE9,  # descriptor setup
            0x3DAF204: 0xE28450A0,  # codec subobject at descriptor +0xa0
            0x3DAF21C: 0xE1A00005,
            0x3DAF220: 0xEB81F109,  # codec subobject -> 0x01e2b64c
            0x3DAC1F4: 0xE5903110,  # final component input length
            0x3DAC1F8: 0xE5902100,  # final component input pointer
            0x3DAC1FC: 0xE2822002,  # omit first two bytes
            0x3DAC200: 0xE5802020,  # final component pointer +0x20
            0x3DAC204: 0xE2433002,
            0x3DAC208: 0xE5803028,  # final component length +0x28
            0x3DAC20C: 0xE5905000,  # separate first-component destination
            0x3DAC250: 0xEB000CAD,  # header builder 0x03daf50c
            0x3DAC258: 0xE5840008,  # first-component length from builder result
            0x3DAC2C0: 0xE5840130,  # additional component pointer
            0x3DAC2E0: 0xE5843138,  # additional component length
            0x3DADF84: 0xE5847018,  # job completion callback
            0x3DADF88: 0xE5845020,  # job retains source object
            0x3DADF8C: 0xE5C46024,  # job variant
            0x3DADF94: 0xE5843028,  # job argument
            0x3DADFB8: 0xE3011349,  # request 0x1349
            0x3DADFC4: 0xEB000B75,  # through veneer to 0x01116c74
            0x3DAE024: 0xEBFFFFBA,  # compression wrapper -> job builder
            0x3DAE2AC: 0xEBFFF7CB,  # variant-zero completion -> component finalizer
            0x3DAF54C: 0xEB000605,  # header builder -> SOI writer veneer
            0x3DAF56C: 0xEB0005F3,  # TIFF header writer veneer
            0x3DB0D40: 0xE51FF004,
            0x3DB0D44: 0x01056FD0,  # TIFF header writer
            0x3DB0D68: 0xE51FF004,
            0x3DB0D6C: 0x01056F9C,  # SOI writer
            0x3DB0DA0: 0xE51FF004,
            0x3DB0DA4: 0x01116C74,
        },
        "encoder_component_primary_words": {
            # Complete dimension setter; no local alignment or rounding step.
            0x10B239C: 0xE5903000,
            0x10B23A0: 0xE3530801,
            0x10B23A4: 0x2A00000C,
            0x10B23A8: 0xE3A01000,
            0x10B23AC: 0xE5902004,
            0x10B23B0: 0xE3520801,
            0x10B23B4: 0x2A00000A,
            0x10B23B8: 0xE92D4800,
            0x10B23BC: 0xE28DB004,
            0x10B23C0: 0xE7DF1813,
            0x10B23C4: 0xE7CF1012,
            0x10B23C8: 0xE3A00044,
            0x10B23CC: 0xE34F0FFA,
            0x10B23D0: 0xEBBEA190,
            0x10B23D4: 0xE3A00000,
            0x10B23D8: 0xE8BD8800,
            0x10B23DC: 0xE3E0001D,
            0x10B23E0: 0xE12FFF1E,
            0x10B23E4: 0xE3E0001D,
            0x10B23E8: 0xE12FFF1E,
            0x10B27C4: 0xE1C020D0,  # 64-bit supplied address
            0x10B27CC: 0xE3A05003,  # upper bound high word 3
            0x10B27E0: 0xE2031003,  # high two bits
            0x10B27E4: 0xE30A0744,  # driver destination 0xfff4a744
            0x10B27E8: 0xE34F0FF4,
            0x10B27EC: 0xEBBEA089,  # lower accessor 0x0005aa18
            0x10B27F0: 0xE5941000,  # low 32 bits
            0x10B27F4: 0xE3A00F43,  # driver destination 0xfffa010c
            0x10B27F8: 0xE34F0FFA,
            0x10B27FC: 0xEBBEA085,
            0x10B2650: 0xE3A00094,  # driver request address 0xfffa0094
            0x10B2654: 0xE34F0FFA,
            0x10B2658: 0xEBBEA100,  # direct word-read accessor 0x0005aa60
            0x10B265C: 0xE5840000,  # returned value written to caller output
            0x1056FA8: 0xE30030B4,  # marker data address 0x012900b4
            0x1056FAC: 0xE3403129,
            0x1056FB0: 0xE1D330B0,  # read SOI halfword
            0x1056FBC: 0xE3A02002,  # two-byte copy
            0x1056FC0: 0xEB03A610,
            0x1056FC4: 0xE3A00002,  # returns byte count
            0x12900B4: 0x0000D8FF,  # original bytes FF D8
            0x12900B8: 0x00004949,  # TIFF little-endian marker
            0x12900BC: 0x00004D4D,  # TIFF big-endian marker
        },
        "encoder_component_secondary_words": {
            0x1EDC3E0: 0x1596A010,  # non-thumbnail input +0x10
            0x1EDC3E4: 0x11A0A0AA,  # shifted right one; do not assume pixel units
            0x1EDC3E8: 0x15963014,
            0x1EDC3EC: 0x150B3044,
            0x1EDC4D4: 0xE583A008,
            0x1EDC4E4: 0xE51B1044,
            0x1EDC4E8: 0xE5831010,
            0x1E2B39C: 0xE5963000,  # active codec
            0x1E2B3A0: 0xE593200C,  # width candidate -> second setter word
            0x1E2B3A4: 0xE50B2050,
            0x1E2B3A8: 0xE5933010,  # height candidate -> first setter word
            0x1E2B3AC: 0xE50B3054,
            0x1E2B3B0: 0xE24B0054,
            0x1E2B3B4: 0xEBCA1BF8,  # setter 0x010b239c
            0x1EDC690: 0xE3590000,  # null result slot skips all result copying
            0x1EDC694: 0x0A000054,
            0x1EDC698: 0xE3013778,  # fixed global, not necessarily source override
            0x1EDC69C: 0xE34032ED,
            0x1EDC6A0: 0xE5932000,
            0x1EDC6A4: 0xE5892000,
            0x1EDC6A8: 0xE5933008,
            0x1EDC6AC: 0xE5893004,
            0x1EDC6B0: 0xE5D83000,  # control byte selects component pair
            0x1EDC6B4: 0xE3530000,
            0x1EDC6B8: 0x0A000045,  # zero -> main final-component copy
            0x1EDC7D4: 0xE3013778,
            0x1EDC7D8: 0xE34032ED,
            0x1EDC7DC: 0xE5932020,  # global final-component pointer
            0x1EDC7E0: 0xE5892008,  # result +8
            0x1EDC7E4: 0xE5933028,  # global final-component length
            0x1EDC7E8: 0xE589300C,  # result +12
            0x1E2B450: 0xE1C322D0,  # codec +0x20/+0x24, main source +0x100/+0x104
            0x1E2B454: 0xE202000F,  # low four bits alignment guard
            0x1E2B464: 0xEAFFFFFE,  # failed guard spins
            0x1E2B484: 0xE1C322D0,  # reload address for driver wrapper
            0x1E2B488: 0xE14B25F4,
            0x1E2B490: 0xEBCA1CC9,  # driver wrapper 0x010b27bc
            0x1EDC4F4: 0xE5832018,  # default-format input descriptor initializes this field to zero
            0x1E2B654: 0xEBFFFF0F,  # wrapper -> codec setup
            0x1E2B2A4: 0xE30F63E8,  # shared active-codec pointer 0x0245f3e8
            0x1E2B2A8: 0xE3406245,
            0x1E2B2AC: 0xE5860000,  # stores codec subobject argument
            0x1E2B254: 0xE30A1F90,  # callback 0x01e2af90
            0x1E2B258: 0xE34011E2,
            0x1E2B25C: 0xEBC9C776,  # callback registration call
            0x1E2AFBC: 0xE51B3020,  # driver status copied to local result
            0x1E2AFC0: 0xE3530001,  # success/status branch
            0x1E2AFE0: 0xE5832030,  # non-success clears count
            0x1E2B028: 0xE24B0044,  # count output local address
            0x1E2B02C: 0xEBCA1D84,  # count wrapper 0x010b2644
            0x1E2B030: 0xE5943000,  # reload active-codec pointer
            0x1E2B034: 0xE51B2044,  # read returned count
            0x1E2B038: 0xE5832030,  # codec +0x30 = source +0x110 on main layout
            0x1EDC334: 0xE5987004,  # optional compression source override
            0x1EDC338: 0xE3013778,  # fallback source 0x02ed1778
            0x1EDC33C: 0xE34032ED,
            0x1EDC344: 0x01A07003,
            0x1EDC5D0: 0xE1A00007,  # source to descriptor setup
            0x1EDC5D4: 0xEB7B3F57,
            0x1EDC640: 0xE3052CE8,  # completion callback 0x01ed5ce8
            0x1EDC644: 0xE34021ED,
            0x1EDC648: 0xE1A01007,  # same source to job submit
            0x1EDC650: 0xEB7B466B,
            0x1EDC65C: 0xE3A00010,  # wait primitive argument 16
            0x1EDC660: 0xEBC9829A,
            0x1ED5D14: 0xE3A01010,  # completion primitive argument 16
            0x1ED5D18: 0xEBC99D28,
        },
        "volume_interface_words": {
            0xD20404: 0x00D49028,  # pre-refresh control method +4
            0xD20424: 0x00D2703C,  # volume query interface method +0x24
            0xD2708C: 0x00D271E4,  # query 8: rounding-unit field
            0xD204F8: 0x00D20600,  # default interface pathname request A
            0xD204FC: 0x00D2069C,  # default interface pathname request B
            0xD20520: 0x00D209EC,  # default interface method at +0x120
        },
        "volume_method_words": {
            0xD27070: 0x00D2714C,  # request 1, cache-refresh gate input
            0xD2714C: 0xE28CCA16,
            0xD27150: 0xE59C3B6C,  # context +0x16b6c word, not request-8 unit
            0xD27154: 0xE5813000,
            0xD27158: 0xEAFFFFF1,
            0xD34338: 0xE24B1050,  # producer temp output = frame -0x50
            0xD3433C: 0xEB001372,  # original record reader 0xd3910c
            0xD34918: 0xE5940000,  # published context pointer at 0xd89a20
            0xD3491C: 0xE2803A16,
            0xD34940: 0xE51B202C,  # temp +0x24 is frame -0x2c
            0xD34944: 0xE5832B80,  # publishes raw product as rounding unit
            0xD34948: 0xE15B12B8,  # separate normalized halfword
            0xD3494C: 0xE3002BD2,
            0xD34950: 0xE18310B2,
            0xD34994: 0xE3A02001,
            0xD34998: 0xE5C32BEC,  # marks context ready after publication
            0xD3911C: 0xE3093A64,
            0xD39120: 0xE34030D8,
            0xD39124: 0xE5936000,  # volume-record array pointer 0xd89a64
            0xD39128: 0xE3A030A0,
            0xD3912C: 0xE0236093,  # record stride 160
            0xD392B8: 0xE3A0C0A0,
            0xD392BC: 0xE02C659C,
            0xD392E8: 0xE1DC24B8,  # raw halfword +0x48
            0xD392EC: 0xE1DC31BC,  # raw halfword +0x1c
            0xD392F0: 0xE0030293,  # multiply, no zero normalization
            0xD392F4: 0xE5843024,  # output +0x24 -> context +0x16b80
            0xD392F8: 0xE1DC31BC,
            0xD392FC: 0xE3530000,
            0xD39300: 0x03A03C02,  # zero -> 512 ONLY for output halfword +0x28
            0xD39304: 0xE1C432B8,
            0xD2703C: 0xE3093A20,
            0xD27040: 0xE34030D8,
            0xD27044: 0xE593C000,  # volume context pointer
            0xD27048: 0xE35C0000,
            0xD2704C: 0x0A0001AA,  # null context -> status 1
            0xD27060: 0xE3500028,
            0xD27064: 0x979FF100,
            0xD271E4: 0xE28CCA16,
            0xD271E8: 0xE59C3B80,  # context +0x16b80: query-8 value
            0xD271EC: 0xE5813000,
            0xD271F0: 0xEAFFFFCB,
            0xD27124: 0xE3A00000,
            0xD27128: 0xE3093A20,
            0xD2712C: 0xE34030D8,
            0xD27130: 0xE5933000,
            0xD27134: 0xE2833A16,
            0xD27138: 0xE5D33BEC,  # context +0x16bec: nonzero permits status 0
            0xD2713C: 0xE3530000,
            0xD27140: 0x03A00001,
            0xD276FC: 0xE3A00001,
            0xD27700: 0xE12FFF1E,
            0xD2061C: 0xE50B102C,  # request A retains payload pointer (r1)
            0xD20620: 0xE14B22F4,  # retains length (r2) and next argument (r3)
            0xD20634: 0xE3A02030,  # bound pathname copy to 48 bytes
            0xD20640: 0xEB107ECB,  # pathname copy via 0x01140174
            0xD2064C: 0xE30138A2,  # request ID 0x18a2
            0xD20690: 0xEB107479,  # generic service submit
            0xD206CC: 0xE3A02030,  # second request: same pathname bound
            0xD206D8: 0xEB107EA5,  # pathname copy
            0xD206E0: 0xE30138A3,  # request ID 0x18a3
            0xD20724: 0xEB107454,  # generic service submit
            0xD209EC: 0xE92D4800,  # method entry
            0xD209F4: 0xEB000FC5,  # forwards to 0xd24910
            0xD24910: 0xE92D4BF0,  # request-buffer metadata helper
            0xD2497C: 0xEB107032,  # writes formatted field into buffer
            0xD249A4: 0xE1C56DB0,  # stores halfword at buffer +0xd0
        },
        "dimension_lookup_width": 0x14A72DC,
        "dimension_lookup_height": 0x14A75C0,
        "dimension_lookup_columns": 5,
        "dimension_lookup_code4_expected": [[0, 0], [0, 0], [0, 0]],
        "dimension_lookup_reference_code1": [[6240, 4160], [4416, 2944], [3120, 2080]],
        "crop_ratio_helper": 0x115EEE0,
        "crop_ratio_code4_target": 0x115EF14,
        "crop_ratio_code4": [4, 3],  # width:height; default branch, not 65:24
        "crop_ratio_common_body_offset": 0x6C,
        "crop_ratio_common_body_size": 0xA8,
        "crop_ratio_common_body_sha256": "7f0af5a008b807acb5b61aa891ea39dc12913e9f322efe0b259757bba58b3394",
        "crop_ratio_code4_stub_candidate": 0x128FB14,  # zero padding, NOT proven executable/free
        "crop_ratio_code4_stub_pad_end": 0x1290000,
        "crop_ratio_stub_adjacent_arm_function": 0x128FAB0,
        "crop_ratio_stub_adjacent_arm_words": {
            0x128FAB0: 0xE92D40D0,  # ARM function prologue in the stub's 4 KiB page
            0x128FB08: 0xE12FFF1E,  # function return before literal and zero padding
        },
        "crop_ratio_stub_adjacent_arm_bl_sites_expected": {
            "primary": [0x116953C, 0x11695D8, 0x1169610],
            "secondary": [0x1BA11B0, 0x1BA11C0, 0x20AE248],
        },
        "crop_ratio_dispatch_targets_expected": [
            0x115EF20, 0x115EF2C, 0x115EF44, 0x115EF14,
            0x115EF14, 0x115EF14, 0x115EF38,
        ],
        "crop_ratio_direct_bl_sites_expected": {
            "primary": [0x115F0DC, 0x115F0F8],
            "secondary": [0x1F3B728, 0x1F3D294, 0x1F404E4, 0x1F4B920, 0x1F4B9B0],
        },
        "crop_ratio_words": {
            0x115EEE8: 0xE2422001,  # aspect minus one
            0x115EEEC: 0xE3520006,  # seven-way dispatch
            0x115EEF0: 0x979FF102,
            0x115EEF4: 0xEA000006,  # out-of-range branch to shared 4:3 default
            0x115EF14: 0xE3A02003,  # default denominator 3
            0x115EF18: 0xE3A0E004,  # default numerator 4
            0x115EF2C: 0xE3A02009,  # code 2, denominator 9
            0x115EF30: 0xE3A0E010,  # code 2, numerator 16
            0x115EF38: 0xE3A02009,  # code 7, denominator 9
            0x115EF3C: 0xE3A0E011,  # code 7, numerator 17
            0x115EF4C: 0xE00C0E91,  # height * numerator
            0x115EF50: 0xE06CC290,  # minus width * denominator
            0x115EF64: 0xE732FE12,  # width-limited height: unsigned division
            0x115EF68: 0xE3C22003,  # align height down to multiple of four
            0x115EFC0: 0xE732F21E,  # height-limited width: unsigned division
            0x115EFC4: 0xE3C22003,  # align width down to multiple of four
        },
        "secondary_ratio_descriptor_table": 0x1F6929C,
        "secondary_ratio_descriptor_targets_expected": [
            0x1F6938C, 0x1F69450, 0x1F69464, 0x1F69478,
            0x1F69488, 0x1F6949C, 0x1F694B0,
        ],
        "secondary_ratio_descriptor_words": {
            0x1F689B0: 0xE92D4FF0,  # parameter-builder entry
            0x1F6928C: 0xE5D635BE,  # working-state aspect +0x5be
            0x1F69290: 0xE3530006,  # codes 0..6
            0x1F69294: 0x979FF103,  # indexed absolute branch
            0x1F69488: 0xE3A03018,  # code 4: ratio component 24
            0x1F6948C: 0xE1C431B4,  # halfword output +0x14
            0x1F69490: 0xE3A03041,  # code 4: ratio component 65
            0x1F69494: 0xE1C431B6,  # halfword output +0x16
            0x1ED85B8: 0xE2842F8A,  # wrapper passes embedded output as r2
            0x1ED85C4: 0xEB0240F9,  # sole aligned direct BL to builder
        },
        "secondary_ratio_descriptor_direct_bl_sites_expected": [0x1ED85C4],
        "secondary_ratio_descriptor_constructor_gate_words": {
            0x1EE4808: 0xE5D93001,  # constructor reads parameter record +1
            0x1EE480C: 0xE3530004,  # subtype 4 takes a separate path
            0x1EE4810: 0x0A000026,
            0x1EE4814: 0xE5D93001,
            0x1EE4818: 0xE3530002,  # only subtype 2 enters ratio-builder loop
            0x1EE481C: 0x0A000027,  # branches to 0x01ee48c0
            0x1EE48C0: 0xE5D435B0,  # subtype-2 block begins here
            0x1EE48D8: 0xE3A06000,  # loop index starts at zero
            0x1EE48E8: 0xE3560000,  # first output follows zero-index path
            0x1EE496C: 0xEBFFCEF4,
            0x1EE49AC: 0xEBFFCEE4,
            0x1EE49F8: 0xEBFFCED1,
        },
        "secondary_ratio_descriptor_wrapper_bl_sites_expected": [
            0x1EE496C, 0x1EE49AC, 0x1EE49F8,
        ],
        "secondary_ratio_descriptor_record_source_words": {
            0x1F47580: 0xEBFFD3C6,  # command route gets 28-byte record
            0x1F47568: 0x03550000,  # exceptional key 67 requires selector zero
            0x1F47570: 0x03A01043,  # exceptional key 67
            0x1F47578: 0x13A0102B,  # ordinary route uses key 43
            0x1F3C4A8: 0xE5900000,  # working state pointer
            0x1F3C4AC: 0xE280003C,  # object ID at state +0x3c
            0x1F3C4B0: 0xEBFE579D,  # select record via 0x01ed232c
            0x1ED2294: 0xE350001A,  # keys >26 use banked headers
            0x1ED229C: 0xE240001B,  # key - 27
            0x1ED22A8: 0xE5D32000,  # runtime bank selector at 0x034d0d50
            0x1ED22AC: 0xE3A03E5F,  # bank stride 0x5f0
            0x1ED22B4: 0xE3A02014,  # key stride 20 bytes
            0x1ED22BC: 0xE303346C,  # header base 0x022c346c
            0x1ED22C0: 0xE340322C,
            0x1ED2370: 0xEBFFFEBE,  # lookup mutable 36-byte registry at 0x01ed1e70
            0x1ED2384: 0xC3A0301C,  # output records have 28-byte stride
            0x1ED2390: 0xC5950008,  # runtime list's data pointer
            0x1ED2394: 0xC0800003,  # selected record pointer
        },
        "secondary_ratio_descriptor_key43_subkey66_registration_words": {
            0x1F47510: 0x13A07042,  # successful command-0x30 path selects subkey 66
            0x1F47574: 0x11A02007,  # ordinary lookup forwards that subkey
            0x1F47578: 0x13A0102B,  # ordinary lookup uses key 43
            0x1F377DC: 0xE35400CC,  # registration dispatch compares case 0xcc
            0x1F377E0: 0x0A00004D,  # case 0xcc enters branch at 0x01f3791c
            0x1F37938: 0xEB008C65,  # branch precondition call
            0x1F3793C: 0xE3500001,  # only result 1 continues to registration
            0x1F37980: 0xE3A02042,  # matching registration: subkey 66
            0x1F37984: 0xE3A0102B,  # key 43
            0x1F37988: 0xE286003C,  # object ID at working object +0x3c
            0x1F3798C: 0xEBFE709A,  # registration helper 0x01ed3bfc
            0x1F379D0: 0xE3A02044,  # neighboring registration uses subkey 68
            0x1F379D4: 0xE3A0102B,
            0x1F379D8: 0xE286003C,
            0x1F379DC: 0xEBFE7086,
            0x1ED3DC8: 0xE3A0201C,  # copy 28-byte source record
            0x1ED3DE8: 0xE354002B,  # key-43 special case
            0x1ED3DEC: 0x050B803C,  # changes copied field +8, not subtype +1
            0x1ED3E20: 0xE24B004C,  # assembled registration record
            0x1ED3E24: 0xEBFFFA74,  # append registration record
        },
        "secondary_ratio_descriptor_registration_bl_sites_expected": [
            0x1F126E8, 0x1F22814, 0x1F22ED4, 0x1F236F0,
            0x1F3798C, 0x1F379DC, 0x1F3B43C, 0x1F3BF98,
            0x1F4B7C4,
        ],
        "secondary_ratio_descriptor_registration_event_group_data_words": {
            0x22DA548: 204, 0x22DA55C: 0x1F377C0,  # case 0xcc event callback
            0x22DA560: 205, 0x22DA574: 0x1F377C0,  # neighboring case 0xcd
            0x22DC920: 15, 0x22DC924: 0x22DB3B4,
            0x22DC928: 13, 0x22DC92C: 0x22DB868,
            0x22DB868: 204, 0x22DB874: 204, 0x22DB880: 204,
            0x22DB88C: 58,  # group 13: registration candidates precede crop
            0x22DB3B4: 205, 0x22DB3C0: 205, 0x22DB3CC: 205,
            0x22DB3D8: 58,  # group 15 has the parallel case-0xcd order
            0x22DB8F8: 17, 0x22DB900: 3, 0x22DB910: 231,
            0x22DB918: 103,  # distinct per-row prerequisite IDs
            0x22DB444: 17, 0x22DB44C: 3, 0x22DB45C: 231,
            0x22DB464: 103,
            0x22DD0A0: 0x11A3, 0x22DD0A8: 17,
            0x22DD0AC: 0x1F31514,  # bounded message-table source for bit 17
        },
        "secondary_ratio_descriptor_registration_group_prefixes": {
            13: [204, 204, 204, 58],
            15: [205, 205, 205, 58],
        },
        "secondary_ratio_descriptor_cmd32_subtype5_words": {
            0x1F3D950: 0xE1A06001,  # wrapper retains caller selector in r6
            0x1F3D980: 0xE54B603F,  # input record byte +1 = selector
            0x1F3DA6C: 0xE24B2030,  # output record pointer
            0x1F3DA70: 0xE24B1040,  # input record pointer
            0x1F3DA74: 0xEBFE9AFF,  # constructor 0x01ee4678
            0x1EE4688: 0xE1A09001,  # constructor retains input record in r9
            0x1EE46B8: 0xE5D93001,  # reads input byte +1
            0x1EE46BC: 0xE3530005,  # subtype 5 takes a distinct branch
            0x1EE46C0: 0x0A000038,
        },
        "secondary_ratio_descriptor_cmd32_wrapper_bl_sites_expected": [0x1F50028],
        "secondary_ratio_descriptor_shared_selector_subkey_words": {
            0x1F47300: 0x13A07043,  # command 0x33 / selector 0: subkey 67
            0x1F47510: 0x13A07042,  # command 0x30 / selector 1: subkey 66
            0x1F47568: 0x03550000,  # state 29 + selector 0 exception
            0x1F4756C: 0x03A02000,  # exceptional subkey 0
            0x1F47570: 0x03A01043,  # exceptional key 67
            0x1F47574: 0x11A02007,  # ordinary route forwards subkey
            0x1F47578: 0x13A0102B,  # ordinary key 43
            0x1F476EC: 0x13A07044,  # command 0x2f / selector 2: subkey 68
            0x1F47728: 0x13A07003,  # command 0x31 / selector 4: subkey 3
        },
        "secondary_ratio_descriptor_record_bank_headers_0_to_7": [
            {"bank": 0, "address": 0x22C35AC, "count": 208, "pointer": 0x22CDF30, "subtypes": {0: 208}},
            {"bank": 1, "address": 0x22C3B9C, "count": 116, "pointer": 0x22C82FC, "subtypes": {0: 116}},
            {"bank": 2, "address": 0x22C418C, "count": 1, "pointer": 0x22CADA4, "subtypes": {0: 1}},
            {"bank": 3, "address": 0x22C477C, "count": 0, "pointer": 0, "subtypes": {}},
            {"bank": 4, "address": 0x22C4D6C, "count": 0, "pointer": 0, "subtypes": {}},
            {"bank": 5, "address": 0x22C535C, "count": 0, "pointer": 0, "subtypes": {}},
            {"bank": 6, "address": 0x22C594C, "count": 1, "pointer": 0x22CA20C, "subtypes": {0: 1}},
            {"bank": 7, "address": 0x22C5F3C, "count": 1, "pointer": 0x22D1FB8, "subtypes": {0: 1}},
        ],
        "secondary_ratio_descriptor_recbf_dispatch_words": {
            0x1F4FF20: 0xE3A01002,  # command 0x2f -> selector 2
            0x1F4FF28: 0xEBFFDCDF,  # shared compression/EXIF parameter route
            0x1F4FF34: 0xE3A01001,  # command 0x30 -> selector 1
            0x1F4FF3C: 0xEBFFDCDA,
            0x1F4FF48: 0xE3A01000,  # command 0x33 -> selector 0
            0x1F4FF50: 0xEBFFDCD5,
            0x1F4FFF8: 0xE3A01004,  # command 0x31 -> selector 4
            0x1F50000: 0xEBFFDCA9,
            0x1F50020: 0xE3A01005,  # command 0x32 -> separate wrapper
            0x1F50028: 0xEBFFB644,
            0x1F4740C: 0xE5D715BE,  # shared route reads aspect +0x5be
            0x1F47410: 0xE5D70A2A,  # size category +0xa2a
            0x1F47414: 0xEBC86176,  # primary width lookup
            0x1F47424: 0xE5D715BE,
            0x1F47428: 0xE5D70A2A,
            0x1F4742C: 0xEBC861A2,  # primary height lookup
            0x1F474A4: 0xEBFE7473,  # shared route -> parameter constructor
            0x1F476AC: 0xEBFE73F1,  # second gated call to constructor
            0x1F3DA74: 0xEBFE9AFF,  # 0x33 wrapper -> constructor
        },
        "secondary_ratio_descriptor_recbf_dispatch_data_words": {
            0x1F50970: 0x01F4FF20,  # command bytes 0x2f..0x33
            0x1F50974: 0x01F4FF34,
            0x1F50978: 0x01F4FFF8,
            0x1F5097C: 0x01F50020,
            0x1F50980: 0x01F4FF48,
            0x22DFBB0: 0x02209714,  # recbfCompress diagnostic
            0x22DFBBC: 0x005E002F,
            0x22DFBD8: 0x0220977C,  # recbfCreateExifHead diagnostic
            0x22DFBE4: 0x00600030,
            0x22DFC0C: 0x00620031,
            0x22DFC34: 0x00640032,
            0x22DFC50: 0x022097C8,  # CreateExifHeadTiffInnerJpeg
            0x22DFC5C: 0x00660033,
        },
        "secondary_ratio_descriptor_recbf_direct_bl_sites_expected": [
            0x1F3DA74, 0x1F474A4, 0x1F476AC,
        ],
        "secondary_ratio_descriptor_recbf_command_modes_expected": {
            0x2F: [30], 0x30: [4, 28, 35], 0x31: [37, 38],
            0x32: [37, 38], 0x33: [4, 29, 36],
        },
        "dimension_lookup_height_words": {
            0x115FAF4: 0xE30735C0,  # height-table low half
            0x115FAF8: 0xE340314A,  # height-table high half
            0x115FAFC: 0xE3A02005,  # five columns
            0x115FB00: 0xE0201092,  # row*5 + aspect
            0x115FB04: 0xE7930100,  # return indexed height
        },
        "primary_table": 0x4C195C,
        "primary_sha256": "3be0132c4bb17aa7504aaaf7e6d85d037368d21f49463ea0ce1ae37a764f6c87",
        "secondary_header": 0x560060,
        "secondary_sha256": "b116e52462f245b7bfa341ebf75a644baa32590d3957518dbea436456169cb35",
        "develop_aspect_jump_offset": 0x3CE5BC,
        "develop_aspect_jump_count": 9,
        "develop_aspect_dispatch_words": {
            0x1F6E3F0: 0xE5951209,  # record +0x209 supplies aspect index
            0x1F6E3F4: 0xE5953205,  # record +0x205 supplies parameter type
            0x1F6E408: 0xE3530007,  # type 7 enters aspect dispatch
            0x1F6E40C: 0x0A000066,
            0x1F6E5AC: 0xE2413001,  # input minus one
            0x1F6E5B0: 0xE3530008,  # nine-entry bound
            0x1F6E5B4: 0x979FF103,  # indexed PC load
            0x1F6E5B8: 0xEA000011,  # out-of-range branch
            0x1F6E5E0: 0xE3A03001,  # first case starts immediately after table
        },
        "develop_aspect_builder_words": {
            0x1F6D378: 0xE3A03007,  # record type 7
            0x1F6D37C: 0xE5843205,
            0x1F6D380: 0xE5D535BC,  # source state +0x5bc
            0x1F6D388: 0x03A03004,  # seed input 4 when state == 3
            0x1F6D38C: 0x13A03007,  # otherwise seed input 7
            0x1F6D390: 0xE5843209,
        },
        "develop_aspect_builder_seed_inputs": [4, 7],
        "develop_record_builder_call_words": {
            0x1F2426C: 0xEB01241F,  # build first indexed record
            0x1F24270: 0xE3A02F9D,  # 628-byte copy length
            0x1F2427C: 0xEBC87161,  # copy to adjacent record
            0x1F25030: 0xEB0120AE,
            0x1F25034: 0xE3A02F9D,
            0x1F25040: 0xEBC86DF0,
            0x1F252CC: 0xEB012007,
            0x1F252D0: 0xE3A02F9D,
            0x1F252DC: 0xEBC86D49,
        },
        "develop_aspect_targets": {
            0x1F6E5E0: 1, 0x1F6E5EC: 2, 0x1F6E5F8: 3,
        },
        "secondary_load": 0x1BA0000,
        "vg_geometry_table": 0x22BF858,
        "vg_geometry_words": {
            0x1EB21F0: 0xE5DB9004,  # caller-supplied aspect byte
            0x1EB2270: 0x979FF109,  # zero-other-selector jump through aspect code
            0x1EB2280: 0x01EB229C,  # aspect 2 jump-table target
            0x1EB229C: 0xE3A03002,  # aspect 2 -> row 2
            0x1EB2264: 0xE3570000,  # alternate rectangle selection
            0x1EB2288: 0x01EB22AC,  # aspect 4 jump-table target
            0x1EB22AC: 0xE3A03004,  # aspect 4 -> row 4
            0x1EB2424: 0xE30F1858,  # 32-byte record table address
            0x1EB2428: 0xE340122B,
            0x1EB2430: 0xE0223892,  # family * 17 + row
            0x1EB2434: 0xE1A02282,  # record stride 32
            0x1EB243C: 0xE1D300B8,  # inner rectangle x
            0x1EB2454: 0xE1D300BE,  # inner rectangle height
            0x1EB24C8: 0xE5C3805D,  # selector records chosen family in graphics state
            0x1EB24CC: 0xE5C3705E,  # records other selector
            0x1EB2590: 0xE3A00000,  # family 0 caller
            0x1EB2594: 0xEBFFFF10,
            0x1EB27F0: 0xE5D46070,  # two-route update reads active preview code
            0x1EB2800: 0x13A06001,  # graphics-mode override to code 1
            0x1EB2950: 0xE5D4005D,  # first route selects family from state
            0x1EB2974: 0xE58D6000,  # same preview code passed on stack
            0x1EB2978: 0xEBFFFE17,
            0x1EB286C: 0x0A000078,  # branch to family-clear block
            0x1EB2880: 0x1A000077,  # alternate branch bypasses clear
            0x1EB2A60: 0xE5C3205D,  # selected path clears family to 0
            0x1EB2A74: 0xE5D5005D,  # second route selects family from state
            0x1EB2A98: 0xE58D6000,
            0x1EB2A9C: 0xEBFFFDCE,
            0x1EB26DC: 0xE3A00002,  # family 2 caller
            0x1EB26E0: 0xEBFFFEBD,
            0x1EB2778: 0xE30F069C,  # nearby OVFSW diagnostic
            0x1EB2C3C: 0xE3A00001,  # family 1 caller
            0x1EB2C40: 0xEBFFFD65,
        },
        "vg_selector_branch_words": {
            0x1EB2264: 0xE3570000,  # alternate-selector split
            0x1EB2270: 0x979FF109,  # normal branch table
            0x1EB230C: 0xE5DB3008,  # special-mode stack byte
            0x1EB2310: 0xE3530001,
            0x1EB2314: 0x0A000009,  # special subbranch
            0x1EB231C: 0x979FF109,  # alternate branch table
            0x1EB2340: 0xE3590002,  # special code 2
            0x1EB2344: 0x03A0300F,  # code 2 -> row 15
            0x1EB2348: 0x0A000035,
            0x1EB2358: 0xE3590001,
            0x1EB235C: 0x0A00005D,
            0x1EB2360: 0xE3A02000,
            0x1EB239C: 0xEBFFA7E6,  # special-case diagnostic call
            0x1EB23A0: 0xE3A0300E,  # other special codes -> row 14
            0x1EB23A4: 0xEA00001E,
        },
        "vg_selector_table_addresses": [0x1EB2278, 0x1EB2324],
        "vg_selector_table_expected": [
            [0, 1, 2, 3, 4, 5, 6],
            [7, 8, 9, 10, 11, 12, 13],
        ],
        "vg_geometry_diagnostic": (0x22BF69C, b"REC_VG_LIB CPV&OVFSW\0"),
        "preview_key_table": 0x14A6230,
        "preview_key_count": 57,
        "dimension_estimate_coeff_table": 0x1519744,
        "dimension_estimate_coeff_count": 132,
        "dimension_estimate_property_key_inventory_expected": (111, 0x126C2, 0x1280F),
        "dimension_estimate_target_rows_expected": [],
        "dimension_estimate_16_9_row_indices_expected": list(range(24, 36)),
        "dimension_estimate_16_9_source_dimensions": [[6240, 3512], [4416, 2488], [3120, 1760]],
        "dimension_estimate_coeff_words": {
            0x1127728: 0xE2403A3D,  # first remapped-key range starts at 0x3d000
            0x112772C: 0xE3530B11,
            0x1127730: 0x3A000006,
            0x1127734: 0xE2402846,  # second remapped-key range starts at 0x460000
            0x1127738: 0xE3083F3F,
            0x112773C: 0xE3403002,
            0x1127740: 0xE1520003,
            0x1127744: 0x9A000009,
            0x1127748: 0xE1A00004,  # keys outside both ranges are unchanged
            0x112774C: 0xE8BD8830,
            0x1127850: 0xE30E3DB4,
            0x1127854: 0xE3403159,
            0x1127858: 0xE5934000,  # runtime settings-buffer pointer
            0x112785C: 0xEBFFFFAE,
            0x1127860: 0xE7D40000,  # direct byte load, no local value clamp
            0x1127864: 0xE8BD8830,
            0x1127E10: 0xE30E3DB4,  # settings initializer selects pointer global
            0x1127E14: 0xE3403159,
            0x1127E18: 0xE3A00902,
            0x1127E1C: 0xE340041E,  # candidate runtime settings base 0x041e8000
            0x1127E20: 0xE5830000,  # publish that base
            0x1127E24: 0xE3A01819,  # initial load length 0x190000
            0x1127E28: 0xEB000450,  # loader helper 0x01128f70
            0x1127ED4: 0xE3A02B33,
            0x1127ED8: 0xE3402009,  # alternate transfer length 0x9cc00
            0x1127EDC: 0xE3001000,
            0x1127EE0: 0xE3401750,  # alternate source argument 0x07500000
            0x1127EE4: 0xE5930000,
            0x1127EE8: 0xEB006246,  # transfer call; conditional initialization branch
            0x1168CD0: 0xE3098744,  # 132 x 16-byte coefficient records
            0x1168CDC: 0xE599000C,  # lookup property key at record +12
            0x1168CE4: 0xE5C90007,  # replace record +7 with runtime coefficient
            0x1168CEC: 0xE3570D21,  # loop bound 2112 bytes
            0x1168CC8: 0x1A00000D,  # initialized flag skips property loads
            0x1168D08: 0xE3530003,  # category input 3 selects table category 2
            0x1168D68: 0xE1D0C0D5,  # match signed mode byte
            0x1168D24: 0xE3A03020,  # fallback coefficient 32
            0x1168D28: 0xE54B3028,
            0x1168D2C: 0xE3A0300A,  # fallback divisor 10
            0x1168D30: 0xE54B3027,
            0x1168D48: 0xE1520004,  # match width
            0x1168D54: 0xE15C0005,  # match height
            0x1168D88: 0xE5D03007,  # runtime coefficient byte, populated from row +12 key
            0x1168D90: 0xE5D03008,  # divisor is read as one byte
            0x1168D98: 0xE55B3028,  # also used on unmatched fallback
            0x1168DA0: 0xE0020392,  # multiply coefficient by ten
            0x1168DB8: 0xE0810492,  # multiply by width after height
            0x1168DD4: 0xEBBBC7D3,  # division in byte-count calculation
            0x1168DD8: 0xE3560001,
            0x1168DDC: 0x92800A03,  # selector 0/1 adds 12288 bytes
            0x1168E08: 0xEAFFFFE2,  # unmatched scan uses default pair
            0x115DB44: 0xE5C42020,  # extra descriptor mode 1
            0x115DB48: 0xE3A01D0A,
            0x115DB4C: 0xE1C411BC,  # extra width 640 at +0x1c
            0x115DB50: 0xE3A01E1E,
            0x115DB54: 0xE1C411BE,  # extra height 480 at +0x1e
            0x11685CC: 0xE3DCE002,
            0x11685D0: 0x0284E01C,  # format 0 or 2 -> descriptor +0x1c
            0x1168618: 0xE58DE028,  # extra pointer into count argument stack
            0x1167374: 0xE59B302C,
            0x1167378: 0xE58D300C,  # format-0 first cost's extra pointer
            0x11673AC: 0xE59B102C,
            0x11673B0: 0xE58D100C,  # second cost's same extra pointer
            0x113A8FC: 0xE79CC103,  # selector-65 registry lookup
            0x113A900: 0xE37C0001,
            0x113A904: 0x0A00000B,
            0x113A938: 0xE3A00001,  # missing volume -> status 1
            0x11678F0: 0xEBFF4BFC,
            0x11678F4: 0xE3500001,
            0x11678F8: 0x03A03901,  # status 1 -> 16-KiB unit
            0x11678FC: 0x050B3008,
            0x1168EF8: 0xEBFFFA77,  # kind-0 wrapper queries rounding unit
            0x1168F38: 0xEE677A87,  # optional float32 multiplier 1.25
            0x1168F48: 0xE2833B96,  # then optional 153600 bytes
            0x1168F5C: 0xE2833801,  # 65536-byte allowance
            0x1168F6C: 0xE3100080,  # property 0xa8 bit 7
            0x1168F74: 0x1283361E,  # conditional 30-MiB allowance
            0x1168F88: 0xE3C33FFF,
            0x1168F8C: 0xE3C33003,  # round to 1 KiB
            0x1168FA4: 0x1733F413,  # signed divide by volume unit
            0x1168FA8: 0x10030394,
            0x1168FAC: 0x03A03000,  # zero unit -> zero estimate
            0x1168FD4: 0xEBFFFF2F,  # optional extra component estimate
            0x1168FF4: 0xE0830000,
            0x1169020: 0xEBFFFF1C,  # extra component without multiplier
            0x1169674: 0xE004049A,  # separate width x height product
            0x1169680: 0xE2844902,  # add 32768-byte allowance
            0x11696BC: 0xEBFFFDD8,  # add another estimated component
            0x11696C0: 0xE0844000,
            0x115D3A4: 0xE583A2A4,  # save first estimate in slot record
            0x115D3A8: 0xE58392AC,  # save second estimate in slot record
            0x115BA30: 0xE59502A4,  # later read first estimate
            0x115BA34: 0xE59522AC,  # later read second estimate
            0x115BA3C: 0xE0232390,  # count-weighted accounting, not pixel write
        },
        "preview_lookup_bypass_primary_words": {
            0x115D6FC: 0xE3500001,  # r0 == 1 bypasses the key table
            0x115D700: 0x0A000014,  # take zero-index return
            0x115D758: 0xE3A00000,
            0x1155B80: 0xE5D33040,  # preview global +0x40
            0x1155B84: 0xE3530001,
            0x1155BBC: 0xE5C43071,  # constructor publishes it at preview +0x71
            0x115FD68: 0xE5D53071,  # builder reads source preview +0x71
            0x115FD6C: 0xE5C43040,  # and places it at staging +0x40
        },
        "preview_lookup_bypass_secondary_words": {
            0x1EBB4FC: 0xE5D12071,  # active preview +0x71 selects builder mode
            0x1EBB504: 0xEBCA91A5,  # builder copies it into staging
            0x1EB5824: 0xE5DC0071,  # same preview byte is lookup argument r0
            0x1EB5830: 0xEBCA9FCA,
        },
        "preview_mode_key227_fixed_object_words": {
            0x1127850: 0xE30E3DB4,  # getter locates runtime settings-buffer pointer
            0x1127854: 0xE3403159,
            0x1127858: 0xE5934000,
            0x112785C: 0xEBFFFFAE,  # key-to-offset conversion
            0x1127860: 0xE7D40000,  # selected byte from runtime buffer
            0x1152874: 0xE3000227,  # keyed-byte ID 0x227
            0x1152878: 0xEBFF53F2,  # read byte through key-to-offset getter
            0x115287C: 0xE5C40071,  # copy to caller object +0x71
            0x116D2B4: 0xEBFF9466,  # wrapper invokes that object builder
            0x1036CD8: 0xE3030588,  # startup supplies fixed object 0x01943588
            0x1036CDC: 0xE3400194,
            0x1036CE0: 0xEB04D971,
        },
        "preview_mode_fixed_object_cache_copy_words": {
            0xF2A79C: 0xE3A02F65,  # length 404
            0xF2A7A0: 0xE3031588,  # source 0x01943588
            0xF2A7A4: 0xE3401194,
            0xF2A7A8: 0xE3080C34,  # distinct destination 0x01738c34
            0xF2A7AC: 0xE3400173,
            0xF2A7B0: 0xEBC4BA5C,  # copy routine
        },
        "preview_bypass_global_accessor_words": {
            0x1156A00: 0xE3063290,  # global base 0x01916290
            0x1156A04: 0xE3403191,
            0x1156A08: 0xE5D30040,  # direct getter for +0x40
            0x1156A40: 0xE3063290,
            0x1156A44: 0xE3403191,
            0x1156A48: 0xE5C30040,  # direct setter for +0x40
        },
        "preview_mode_key227_fixed_object_secondary_words": {
            0x1DD91B8: 0xE3030588,  # second bounded direct caller uses same object
            0x1DD91BC: 0xE3400194,
            0x1DD91C0: 0xEBCDE4A3,
        },
        "preview_lookup_words": {
            0x115D710: 0xE3064230,  # 8-byte key table address
            0x115D714: 0xE340414A,
            0x115D720: 0xE3500039,  # 57 rows; miss returns 57
            0x115D72C: 0xE7D4E180,  # compare first key byte
            0x115D73C: 0xE5DCE001,  # compare second key byte
            0x115D748: 0xE5DCC002,  # compare preview-state +0x70
            0x115D778: 0xE3500038,  # wrapper accepts indices 0..56
            0x115D780: 0xEAFFFFFE,  # missing key enters fail loop
            0x115D888: 0xE3060230,  # second direct key-table address materialization
            0x115D88C: 0xE340014A,
            0x115D9A0: 0xE3063230,  # dimension read uses the same 8-byte table
            0x115D9A4: 0xE340314A,
            0x115D9AC: 0xE1D320B4,  # selected row width
            0x115D9B0: 0xE1C420B2,  # descriptor +2
            0x115D9B4: 0xE1D330B6,  # selected row height
            0x115D9B8: 0xE1C430B4,  # descriptor +4
            0x115D27C: 0xEB002D81,  # hand populated descriptor to processor
            0x11688E0: 0xE1D180B2,  # processor reads descriptor width
            0x11688E4: 0xE1D120B4,  # processor reads descriptor height
        },
        "preview_parallel_index_words": {
            0x115C6A4: 0xE28310E4,  # base + 228 bytes (57 words)
            0x115C6AC: 0xE5A32004,  # clear one parallel index word
            0x115C6B0: 0xE1530001,  # stop at base + 228
            0x115C6F8: 0xE0832100,  # select parallel word by lookup index * 4
            0x115C81C: 0xE5AA0004,  # fill next parallel word
            0x115C824: 0xE3590039,  # exactly 57 entries
        },
        "preview_capacity_count_words": {
            0x115C7D8: 0xEB000461,  # row -> descriptor dimension prefix
            0x115C810: 0xEB002F3F,  # count producer 0x01168514
            0x115C814: 0xE1550000,  # clamp result against caller's r5
            0x115C818: 0x31A00005,
            0x115C81C: 0xE5AA0004,  # store clamped count into indexed cache
            0x115C6FC: 0xE5926004,  # selected local cache value
            0x115C718: 0xE1560000,
            0x115C71C: 0x33A06000,  # count below required value becomes zero
            0x115C744: 0xE1A02006,
            0x115C750: 0xEBFFFD9F,  # selected count -> state updater
            0x1168654: 0xE1D430B4,  # height into count producer
            0x116865C: 0xE1D430B2,  # width into count producer
            0x1168674: 0xEBFFFB1C,  # common count routine 0x011672ec
            0x11673A4: 0xEB00069E,  # first estimated cost
            0x11673A8: 0xE1A05000,
            0x11673D4: 0xEB000692,  # second estimated cost
            0x11673D8: 0xE3500000,
            0x11673DC: 0x13550000,  # both costs must be nonzero
            0x1167594: 0xE1A02080,  # 2*cost_b, 32-bit
            0x11675A4: 0x83A00001,  # capacity below second threshold -> 1
            0x11675AC: 0xE1A03080,
            0x11675B0: 0xE0830000,  # 3*cost_b, 32-bit
            0x11675C4: 0x83A00002,  # capacity below third threshold -> 2
            0x11675CC: 0xE1A02005,  # denominator cost_a
            0x11675D4: 0xE0560008,  # available - 3*cost_b, low word
            0x11675D8: 0xE0C71009,  # high word with borrow
            0x11675DC: 0xEBBBCDD1,  # stock 64-bit division helper
            0x11675E0: 0xE2800003,  # add three to quotient low word
            0x11675E4: 0xE59B3024,  # limit argument
            0x11675E8: 0xE1500003,
            0x11675EC: 0x21A00003,  # late clamp; early 1/2 returns bypass it
        },
        "preview_parallel_following_array_words": {
            0x115C948: 0xE59F82F8,  # load literal for final preview-cache word
            0x115C968: 0xE5B81004,  # preincrement into following array
            0x115C98C: 0xE3550036,  # traverse 54 words
            0x115CAA8: 0xE59F61A0,  # load following array's first word
        },
        "preview_parallel_following_array_literals": {
            0x115CC48: 0x0184E45C,  # preview cache's 57th word
            0x115CC50: 0x0184E460,  # following array's first word
        },
        "preview_parallel_first_word": 0x0184E37C,
        "preview_parallel_following_array_first_word": 0x0184E460,
        "preview_row_enumeration_words": {
            0x115C778: 0xE3A09000,  # constructor starts at row 0
            0x115C79C: 0xEB000433,  # copy row key into a synthetic descriptor
            0x115C7D8: 0xEB000461,  # derive dimensions from that descriptor
            0x115C820: 0xE2899001,  # advance to next row
            0x115C824: 0xE3590039,  # enumerate all 57 rows, including code-0 keys
            0x115D890: 0xE7D01183,  # synthetic descriptor takes table key byte 0
            0x115D894: 0xE5C21005,
            0x115D8A4: 0xE5D03002,  # and table aspect byte 2
            0x115D8A8: 0xE5C23006,
        },
        "preview_secondary_lookup_miss_words": {
            0x1ECEA60: 0xE5DC106B,  # first key: shared preview-state aspect
            0x1ECEA64: 0xE5DC0071,  # bypass flag
            0x1ECEA70: 0xEBCA3B21,  # direct call to lookup
            0x1ECEA74: 0xE3500039,  # test miss index 57
            0x1ECEA78: 0x23A00000,  # on miss, use row 0
        },
        "preview_state_producer_primary_words": {
            0x11549E8: 0xE3063290,  # getter targets global 0x01916290
            0x11549F0: 0xE5D30016,  # getter reads global +0x16
            0x1154A08: 0xE3063290,  # setter targets global 0x01916290
            0x1154A10: 0xE5C30016,  # setter writes global +0x16
            0x1155158: 0xE5D3041F,  # event fallback gate source +0x41f
            0x1155AD4: 0xE92D4830,  # preview-state constructor entry
            0x1155B70: 0xE5D32014,  # global +0x14: paired aspect-related field
            0x1155B74: 0xE5C4206B,  # active preview-state +0x6b
            0x1155BA4: 0xE5D52016,  # read global +0x16
            0x1155BA8: 0xE5C42070,  # copy into destination +0x70
        },
        "preview_state_producer_secondary_words": {
            0x1EC32E8: 0xE591173C,  # load active preview-state pointer
            0x1EC32EC: 0xE5821008,  # cache pointer at 0x03115fb0+8
            0x1EC3B74: 0xE5934008,  # retrieve cached active pointer
            0x1EC3C20: 0xE1A00004,  # pass it to constructor
            0x1EC3C24: 0xEBCA47AA,  # cross-partition constructor call
        },
        "preview_source_bridge_secondary_words": {
            0x1EBD528: 0xE30B4C00,  # pointer holder 0x02a3bc00
            0x1EBD52C: 0xE34042A3,
            0x1EBD548: 0xE59F3018,  # active preview-state holder literal
            0x1EBD54C: 0xE593173C,  # source: active preview-state pointer
            0x1EBD554: 0xE59F0010,  # fallback object pointer literal
            0x1EBD558: 0xE5840020,  # install fallback at holder +0x20
            0x1EBD55C: 0xE3A02E5D,  # 1488 bytes
            0x1EBD560: 0xEBCA0CA8,  # copy active object to fallback
            0x1EBD578: 0xE30B3C00,  # same pointer holder
            0x1EBD57C: 0xE34032A3,
            0x1EBD588: 0xE59F20F4,  # active preview-state holder literal
            0x1EBD58C: 0xE592273C,  # load active preview-state pointer
            0x1EBD590: 0xE5832020,  # install active pointer at holder +0x20
            0x1EBE6A4: 0xE30B3C00,  # runtime source-pointer holder: 0x02a3bc00
            0x1EBE6A8: 0xE34032A3,
            0x1EBE6AC: 0xE5935020,  # source object pointer at holder +0x20
            0x1EBE6C0: 0xE59F8100,  # destination state literal 0x02879848
            0x1EBE6C4: 0xE5D52071,  # mode byte from source +0x71
            0x1EBE6C8: 0xE1A01005,  # pass source object
            0x1EBE6CC: 0xE1A00008,  # pass destination state
            0x1EBE6D0: 0xEBCA8532,  # call primary state builder
            0x1EBE6F4: 0xE1A00008,  # pass same destination state
            0x1EBE6F8: 0xEBCA656D,  # call publisher
        },
        "preview_source_bridge_secondary_data_words": {
            0x1EBD568: 0x028787A0,  # active preview-state pointer holder
            0x1EBD56C: 0x02879E6C,  # fixed fallback object
            0x1EBD684: 0x028787A0,  # active preview-state pointer holder
            0x1EBE7C8: 0x02879848,
        },
        "preview_source_bridge_primary_words": {
            0x1140838: 0xE4D1C001,  # copy routine reads source byte
            0x114083C: 0xE5E3C001,  # and writes destination byte
            0x115FBF8: 0xE3520001,  # builder mode split
            0x115FC04: 0xE5D1206B,  # ordinary branch: source +0x6b
            0x115FC0C: 0xE5C02014,  # destination +0x14
            0x115FC34: 0xE5D13070,  # ordinary branch: source +0x70
            0x115FC38: 0xE5C03016,  # destination +0x16
            0x1160108: 0xE5D1206B,  # mode-1 branch: same source +0x6b
            0x1160110: 0xE5C02014,  # same destination +0x14
            0x116011C: 0xE5D12070,  # mode-1 branch: same source +0x70
            0x1160120: 0xE5C02016,  # same destination +0x16
            0x1157CD0: 0xEBFFF240,  # publisher calls bulk-state handoff
            0x11545E8: 0xE3065290,  # bulk-state destination 0x01916290
            0x11545EC: 0xE3405191,
            0x11545F0: 0xE300647C,  # 0x47c-byte handoff
            0x11545F8: 0xE1A01004,  # source is builder destination
            0x11545FC: 0xE1A00005,  # destination is preview global
            0x1154600: 0xEBBC12C8,  # copy-like routine
        },
        "preview_builder_other_direct_callsite_words": {
            0x1EBB4D0: 0xE5931010,  # active preview pointer from mode table
            0x1EBB4D4: 0xE582173C,  # install it at shared active +0x73c
            0x1EBB4F8: 0xE59F546C,  # destination 0x02879848
            0x1EBB4FC: 0xE5D12071,  # mode from active preview object
            0x1EBB500: 0xE1A00005,
            0x1EBB504: 0xEBCA91A5,  # builder call with active source
            0x1EC3B78: 0xE59F6724,  # fixed fallback source literal
            0x1EC3B9C: 0xEBCA6FFF,  # builder call with fallback source
            0x1EC3BB4: 0xE1A00009,  # built state sent to publisher
            0x1EC3BB8: 0xEBCA503D,
            0x1EC47E4: 0xEBCA52CF,  # alternate staging destination getter
            0x1EC47E8: 0xE5D42071,
            0x1EC47EC: 0xE1A01004,
            0x1EC47F0: 0xEBCA6CEA,  # builder with caller-supplied source
            0x1EC6138: 0xE51F0230,  # only direct caller supplies fallback
            0x1EC613C: 0xEBFFF9A5,
        },
        "preview_builder_other_direct_callsite_data_words": {
            0x1EBB96C: 0x02879848,
            0x1EBB970: 0x028787A0,
            0x1EC42A4: 0x02879E6C,
            0x1EC5F10: 0x02879E6C,
        },
        "preview_builder_alternate_staging_primary_words": {
            0x1159330: 0xE59F0008,  # staging destination getter
        },
        "preview_builder_alternate_staging_primary_data_words": {
            0x1159340: 0x01916914,  # separate from global 0x01916290
        },
        "preview_state_source_global": 0x019162A6,
        "preview_lookup_caller_words": {
            0x1EB5814: 0xE593C73C,  # shared preview-state pointer
            0x1EB5818: 0xE5DC3070,  # preview row code
            0x1EB582C: 0xE58DC000,  # fifth tuple field
            0x1EB5830: 0xEBCA9FCA,  # cross-partition lookup
            0x1EB5834: 0xE1A05000,  # retain returned row index
            0x1EB5840: 0xE3500001,  # runtime-array selection gate
            0x1EB584C: 0x15933740,  # non-gated route loads runtime array pointer
            0x1EB5850: 0x12855002,  # skip two array entries
            0x1EB5854: 0x17933105,  # index into runtime 32-bit-word array
        },
        "preview_lookup_pointer_handoff_words": {
            0x1EB5858: 0xE50B3028,  # selected word saved in caller local
            0x1EB5A34: 0xE51B3028,  # same local passed as r3
            0x1EB5A48: 0xEB01387C,  # command-builder call
            0x1F03C58: 0xE1A09003,  # callee retains opaque word in r9
            0x1F03D10: 0xE50B904C,  # copied, not dereferenced, into command fields
            0x1F03D50: 0xE14B33B0,  # command halfword 0x1159
            0x1F03D78: 0xEB0063E2,  # sends local command to next routine
            0x1F1CD4C: 0xE309023B,  # that routine also scans 0x923b entries
        },
        "preview_descriptor_bridge_secondary_words": {
            0x1EB5938: 0xE593073C,  # same active preview pointer as the row-index lookup
            0x1EB5954: 0xEBFFAB38,  # construct 36-byte descriptor from preview state
            0x1EB5960: 0xE24B0070,  # descriptor passed to primary processor wrapper
            0x1EB5964: 0xEBCA9E30,
            0x1EA0660: 0xE5C13002,  # preview +0x71 -> descriptor +2 (bypass)
            0x1EA0670: 0xE5C13004,  # preview +0x6d -> descriptor +4
            0x1EA0678: 0xE353002D,  # state 45 changes first-key source
            0x1EA067C: 0x11A03000,  # ordinary source +0x6b
            0x1EA0680: 0x02803001,  # state-45 source +0x6c
            0x1EA0688: 0xE5C13005,  # preview +0x6b (or +0x6c in state 45) -> +5
            0x1EA0690: 0xE5C13006,  # preview +0x70 -> descriptor +6 (code)
            0x1EA0728: 0xE5C53017,  # preview +0x572 -> descriptor +0x17
        },
        "preview_descriptor_bridge_primary_words": {
            0x115D250: 0xEBFF8D6C,  # descriptor copy, 36 bytes
            0x115D25C: 0xEBFFF947,  # normalize bypass byte for first lookup
            0x115D26C: 0xEB0001BC,  # first descriptor-to-dimension lookup
            0x115D27C: 0xEB002D81,  # first dimension processor call
            0x115D290: 0xEBFF8D5C,  # restore original descriptor before second lookup
            0x115D294: 0xE3A05000,  # zero used to disable bypass
            0x115D298: 0xE54B5076,  # force copied descriptor +2 to zero
            0x115D2A4: 0xEB0001AE,  # second descriptor-to-dimension lookup
            0x115D2B4: 0xEB002D73,  # second dimension processor call
            0x115D984: 0xE5D00002,  # descriptor +2 is lookup bypass argument
            0x115D990: 0xEBFFFF72,  # same 57-row key lookup as secondary caller
            0x115D9AC: 0xE1D320B4,  # selected width from row
            0x115D9B4: 0xE1D330B6,  # selected height from row
        },
        "preview_1159_dispatch_controller_words": {
            0x1F03D7C: 0xEB008959,  # command builder unconditionally follows with controller
            0x1F1CD18: 0xEB002C92,  # generic dispatcher copies command payload to shared state
            0x1F1CD1C: 0xE30C3E30,  # message-table base 0x022dce30
            0x1F1CD20: 0xE340322D,
            0x1F1CD34: 0xE1D21BB8,  # current command ID from shared state
            0x1F1CDDC: 0xE5936008,  # selected table row bit ID
            0x1F1CE04: 0xE593300C,  # selected table row callback
            0x1F1CE08: 0xE3530000,  # zero callback bypasses indirect call
            0x1F262F4: 0xEBFF7E43,  # controller action 0
            0x1F05C88: 0xE3012159,  # controller recognizes command 0x1159
            0x1F05E00: 0xE3A02005,  # maps command to state 5
            0x1F05E04: 0xE1C320B0,  # stores state halfword
            0x1F05E10: 0xEB008DA2,  # forwards to state-machine matrix
        },
        "preview_1159_conditional_gate_alias_words": {
            0x1F03D10: 0xE50B904C,  # selected word at local payload +8
            0x1F03D64: 0xE3A03024,  # payload length 36
            0x1F03D6C: 0xE24B3054,  # local payload base
            0x1F03D70: 0xE50B3028,  # payload pointer in command header
            0x1F27FB4: 0xE28300C4,  # shared payload destination +0xc4
            0x1F27FB8: 0xEBC86212,  # copies payload; word reaches shared +0xcc
            0x1F23C50: 0xE3A00001,  # gate requests fresh snapshot of current message
            0x1F23C54: 0xEB0010DE,  # snapshot from 0x034cad70
            0x1F23C7C: 0xE51B310C,  # snapshot +0x14 as pointer (= shared +0xcc)
            0x1F23C80: 0xE5D33006,  # pointed-to byte +6
        },
        "preview_1159_threshold_route_words": {
            0x1F06050: 0xE3012159,  # mode-1 action-0 classifies 0x1159
            0x1F06128: 0xE3A02002,  # mode-1 row 2
            0x1F06138: 0xEB008CD8,  # mode-1 matrix dispatch
            0x1F07618: 0xEBFFFA74,  # mode-0 callback 5 enters mode 1
            0x1F07658: 0xEBFFFA64,  # mode-0 callback 7 also enters mode 1
            0x1F07A04: 0xEBFFFCF3,  # mode-1 callback 4 enters mode 5
            0x1F07A20: 0xEBFFFCEC,  # mode-1 callback 5 enters mode 5
            0x1F06E2C: 0xE3012159,  # mode-5 action-0 classifies 0x1159
            0x1F06F04: 0xE3A02002,  # mode-5 row 2
            0x1F06F14: 0xEB008961,  # mode-5 matrix dispatch
            0x1F09614: 0xE3A00002,  # mode-5 callback 7 selects type 2
            0x1F09618: 0xEB00460B,  # snapshot/parameter routine
            0x1F0961C: 0xE3A00002,  # same type for context initializer
            0x1F09620: 0xEB00579A,
            0x1F1AE5C: 0xE3A00001,  # snapshot source: current message record
            0x1F1AE60: 0xEB00345B,  # type-2 routine snapshots current message
            0x1F1AE68: 0xE3A00001,  # stack copy uses snapshotted source
            0x1F1AE6C: 0xEB00346B,
            0x1F1AF04: 0xE2473001,  # type minus one selects jump-table case
            0x1F1AF0C: 0x979FF103,  # type 2 enters 0x01f1b050
            0x1F1B050: 0xE30C3CB8,  # base 0x0341ccb8
            0x1F1B054: 0xE3403341,
            0x1F1B058: 0xE2832A07,  # global +0x7000
            0x1F1B05C: 0xE51B110C,  # snapshot +0x14, the selected word field
            0x1F1B060: 0xE582101C,  # store it at 0x03423cd4
            0x1F1F508: 0x93A00001,  # initializer type 2 selects snapshot source
            0x1F1F50C: 0xEB0022C3,  # copy snapshot to per-context record
            0x1F20A54: 0xE30C3CB8,  # same global base
            0x1F20A58: 0xE3403341,
            0x1F20A60: 0xE2833A07,  # global +0x7000
            0x1F20A68: 0xE593301C,  # another routine reads global +0x1c
            0x1F20A6C: 0xE1520003,  # compares a counter with selected word
            0x1F20A70: 0x9AFFFF5D,  # counter <= word skips threshold action
        },
        "preview_1159_threshold_route_data_words": {
            0x22D7D00: 0x01F0760C,  # mode-0 callback 5
            0x22D7D08: 0x01F07640,  # mode-0 callback 7
            0x22D7B80: 0x01F079A8,  # mode-1 callback 2, direct event-44 gate caller
            0x22D7B88: 0x01F079F4,  # mode-1 callback 4
            0x22D7B8C: 0x01F07A14,  # mode-1 callback 5
            0x22D78BC: 0x01F07C48,  # mode-2 callback 2, other direct gate caller
            0x22D79D8: 0x01F095CC,  # mode-5 callback 6
            0x22D79DC: 0x01F0960C,  # mode-5 callback 7
            0x1F1AF18: 0x01F1B050,  # type-2 jump-table case
        },
        "preview_1159_event44_gate_direct_bl_sites_expected": [0x1F079BC, 0x1F07C50],
        "preview_runtime_config_206_207_secondary_words": {
            0x1E8CB58: 0xE3004206,  # alternate copy site selects ID 0x206
            0x1E8CB5C: 0xE3002207,  # or ID 0x207
            0x1E8CB64: 0x11A04002,
            0x1E8CC58: 0xEB004D5E,  # first direct mapped-copy call
            0x1E8CE2C: 0xE3004206,  # caller selects configuration ID 0x206
            0x1E8CE30: 0xE3002207,  # or ID 0x207
            0x1E8CE38: 0x11A04002,
            0x1E8CE50: 0xE3A0108C,  # second mapper argument 140
            0x1E8CE54: 0xE1A00004,
            0x1E8CE58: 0xEB004CDE,  # copy selected config to temporary block
            0x1E8CF98: 0xE3004206,  # third copy site selects ID 0x206
            0x1E8CF9C: 0xE3002207,  # or ID 0x207
            0x1E8CFA4: 0x11A04002,
            0x1E8CFD8: 0xEB004C7E,  # third direct mapped-copy call
            0x1E9F9DC: 0xE5933734,  # header mapper reads runtime selector
            0x1E9FDDC: 0xE5933734,  # payload mapper reads same selector
            0x1E9FC24: 0x0A000010,  # ID-0x206/arg-140 header branch
            0x1E9FC78: 0x03A0204C,  # 76-byte selected-record stride
            0x1E9FC80: 0x00200392,
            0x1EA0024: 0x0A000010,  # ID-0x206/arg-140 payload branch
            0x1EA0078: 0x03A0204C,
            0x1EA0080: 0x00200392,
            0x1EA01EC: 0xEBFFFDF9,  # obtain header pointer
            0x1EA0200: 0xEBFFFEF4,  # obtain payload pointer
            0x1EA0210: 0xE3A0200C,  # copy 12-byte header
            0x1EA0218: 0xE30507A0,  # destination 0x028757a0
            0x1EA021C: 0xE3400287,
            0x1EA0220: 0xEBCA8178,
            0x1EA022C: 0xE5942004,  # length from selected header +4
            0x1EA0230: 0xE1A01005,  # selected payload source
            0x1EA0234: 0xE59F0020,  # destination 0x028757ac
            0x1EA0238: 0xEBCA8172,
        },
        "preview_runtime_config_206_207_data_words": {
            0x1E9FD40: 0x028780E4,  # ID-0x207 fixed header
            0x1E9FD7C: 0x02875A00,  # ID-0x206 selected header base
            0x1EA0140: 0x028780F0,  # ID-0x207 fixed payload
            0x1EA017C: 0x02875A0C,  # ID-0x206 selected payload base
            0x1EA025C: 0x028757AC,  # runtime payload destination
        },
        "preview_runtime_config_206_207_direct_bl_sites_expected": [
            0x1E8CC58, 0x1E8CE58, 0x1E8CFD8,
        ],
        "runtime_config_206_stack_words": {
            0x1E9F1E8: 0xE1D330B0,  # generic writer reads ID from temporary header
            0x1E9F27C: 0xE3002206,  # ID 0x206 dispatch
            0x1E9F4A0: 0xE353008C,  # subtype 140 selects the record bank
            0x1E9F500: 0xE2841A03,  # temporary header + 0x3000 reaches shared selector
            0x1E9F504: 0xE5912734,  # current record count
            0x1E9F508: 0xE3A0304C,  # 76-byte record stride
            0x1E9F50C: 0xE0030293,  # count * stride
            0x1E9F510: 0xE2835E26,  # header-bank offset from temporary header
            0x1E9F518: 0xE2833F9B,  # payload-bank offset
            0x1E9F520: 0xE2822001,  # increment selector after reserving slot
            0x1E9F524: 0xE5812734,
            0x1E9F358: 0xE3A0200C,  # copy 12-byte temporary header to slot
            0x1E9F37C: 0xE5912004,  # payload length from temporary header
            0x1E9F380: 0xE281100C,  # temporary payload source
            0x1E9F388: 0xEBCA851E,  # copy payload to slot
            0x1E8CE58: 0xEB004CDE,  # consumer copies selected slot to temporary block
            0x1E8CE64: 0xEB004CFD,  # then clears/consumes selected slot
            0x1EA02A0: 0xE3A0200C,  # clear selected header
            0x1EA02B8: 0xE3A02040,  # clear selected payload allocation
            0x1EA0308: 0xE2488001,  # ID-0x206 branch decrements selector
            0x1EA0310: 0xE5838734,
        },
        "preview_temp_block_header_init_words": {
            0x1E5D60C: 0xE30537A0,  # temporary block 0x028757a0 initialized at startup
            0x1E5D610: 0xE3403287,
            0x1E5D614: 0xE3A02040,  # initial length 64 bytes
            0x1E5D618: 0xE5832004,  # stores initial payload length
            0x1E5D61C: 0xE283200C,  # payload pointer is temporary block +12
            0x1E5D620: 0xE5832008,
            0x1E5D624: 0xE3A03030,  # independent channel configuration 48
            0x1E5D62C: 0xE3A03048,  # independent channel configuration 72
            0x1E5D638: 0xE3A00007,  # channel-7 setup precedes receiver-thread registration
            0x1E5D63C: 0xEBCB7FB8,
        },
        "preview_temp_block_channel7_receiver_secondary_words": {
            0x1E5D66C: 0xE30A3AD8,  # register receiver callback 0x01e6aad8
            0x1E5D670: 0xE34031E6,
            0x1E5D674: 0xE50B3020,
            0x1E5D684: 0xEBCB7C76,  # register channel-7 worker configuration
            0x1E6AAE8: 0xE30547A0,  # receiver's temporary block 0x028757a0
            0x1E6AAEC: 0xE3404287,
            0x1E6AB04: 0xE1A01004,  # pass temporary header as receive destination
            0x1E6AB08: 0xE3A00007,  # channel 7
            0x1E6AB0C: 0xEBCB4BED,  # receive/copy helper 0x0113dac8
            0x1E6AB1C: 0xE8940007,  # copy 12-byte header to filter's stack argument
            0x1E6AB28: 0xEB0262A3,  # packet filter can skip further processing
            0x1E6AAFC: 0xEBFFCD03,  # otherwise dispatch the received packet
            0x1E5DF1C: 0xEBFFFFC8,  # worker dispatch calls header-ID classifier
            0x1E5DE54: 0xE1D330B0,  # classify temporary header ID
            0x1E5DE58: 0xE3530C02,  # ID 0x200 gets category-4 selector path
            0x1E5DEAC: 0xE5933010,  # dereference received second payload word
            0x1E5DEB0: 0xE5D330C2,  # byte at payload target +0xc2
            0x1E5DEC8: 0xE1C320B8,  # write category-4 first selector, not second
            0x1E5DECC: 0xE3A00004,  # category 4, not the category-22 publisher
            0x1E5DED0: 0xEBFFFEA0,  # generic callback dispatch
        },
        "preview_temp_block_channel7_receiver_primary_words": {
            0x113C9D4: 0xE5943010,  # worker registration reads callback at config +0x10
            0x113CA14: 0xEBBC3DF1,  # passes assembled config to worker creation
            0x113DAFC: 0xE1D130B0,  # incoming header ID
            0x113DB00: 0xE1C530B0,  # copy ID to destination header
            0x113DB14: 0xE5913004,  # incoming payload length
            0x113DB18: 0xE5853004,  # copy length to destination header
            0x113DB6C: 0xE2811008,  # incoming payload starts after 8-byte header
            0x113DB70: 0xE5950008,  # destination payload pointer at header +8
            0x113DB74: 0xEB000B23,  # memcpy payload into destination buffer
        },
        "preview_id200_channel7_sender_secondary_words": {
            0x1E44200: 0xE5903004,  # input +4 points to mutable payload object
            0x1E44204: 0xE5D3240A,  # copy object byte +0x40a to +0x409
            0x1E44208: 0xE5C32409,
            0x1E4420C: 0xE5903000,  # payload word 0 <- input +0
            0x1E44210: 0xE50B3028,
            0x1E44214: 0xE5903004,  # payload word 1 <- input +4
            0x1E44218: 0xE50B3024,
            0x1E4421C: 0xE5903008,  # payload word 2 <- input +8: array base
            0x1E44220: 0xE50B3020,
            0x1E4423C: 0xE3A03C02,  # packet ID 0x200
            0x1E44240: 0xE14B31B0,
            0x1E4424C: 0xE3A00007,  # channel 7
            0x1E44250: 0xE54B000D,
            0x1E44254: 0xE3A03018,  # 24-byte payload
            0x1E44258: 0xE50B300C,
            0x1E4425C: 0xE24B3028,  # payload pointer
            0x1E44260: 0xE50B3008,
            0x1E44264: 0xE24B1010,  # packet header pointer
            0x1E44268: 0xEBCBE583,  # generic channel send
            0x1D2106C: 0xE3003B80,  # caller 1: first word 0x01920b80
            0x1D21070: 0xE3403192,
            0x1D21078: 0xE3013C24,  # second word / gate object 0x01851c24
            0x1D2107C: 0xE3403185,
            0x1D21084: 0xE3043A8C,  # third word 0x01734a8c
            0x1D21088: 0xE3403173,
            0x1D2108C: 0xE50B3018,
            0x1D21114: 0xE24B0020,
            0x1D21118: 0xEB048C35,
            0x1E55EAC: 0xE2833074,  # caller 2: gate object base +0x74
            0x1E55EB0: 0xE50B3024,
            0x1E55EB4: 0xE2833E5D,  # array base +0x5d0
            0x1E55EB8: 0xE50B3020,
            0x1E55ECC: 0xEBFFB8C8,
            0x1E59A7C: 0xE2833074,  # caller 3: same gate object
            0x1E59A80: 0xE50B303C,
            0x1E59A84: 0xE2833E5D,  # same array base
            0x1E59A88: 0xE50B3038,
            0x1E59AA0: 0xEBFFA9D3,
        },
        "preview_id200_channel7_sender_secondary_data_words": {
            0x1E56098: 0x02EE9B00,  # caller-2 initialization RAM base
            0x1E5609C: 0x02EE9C08,  # caller 2 RAM-structure base
            0x1E59C30: 0x02EE9C08,  # caller 3 same base
            0x1E567F8: 0x02EE9C7C,  # separate copy source is object prefix
        },
        "preview_id200_channel7_sender_object_prefix_copy_words": {
            0x1E55C9C: 0xE59F43F4,  # RAM base 0x02ee9b00
            0x1E55D38: 0xE3A02E5D,  # copy 0x5d0 bytes
            0x1E55D3C: 0xE3021BF8,  # source 0x022c2bf8
            0x1E55D40: 0xE340122C,
            0x1E55D44: 0xE2840F5F,  # dest base +0x17c = 0x02ee9c7c
            0x1E55D48: 0xEBCBAAAE,  # copy ends at array base 0x02eea24c
        },
        "preview_cache_refresh_gate_primary_words": {
            0x115C5DC: 0xE5D33000,  # global 0x0184e378 byte
            0x115C5E0: 0xE3530001,
            0x115C5E4: 0x13A05000,
            0x115C5E8: 0x0A00001F,
            0x115C5F4: 0xEBFFFCB2,  # state helper, not a key-change test
            0x115C600: 0xE5D33000,
            0x115C604: 0xE3530001,
            0x115C608: 0x0A000021,
            0x115C66C: 0xE24B2054,
            0x115C670: 0xE3A01001,  # request 1
            0x115C674: 0xE3A00041,
            0x115C678: 0xEBFF789A,
            0x115C67C: 0xE3500000,
            0x115C680: 0x051B5054,
            0x115C684: 0x02255001,
            0x115C688: 0x02055001,  # success AND returned bit0 clear
            0x115C68C: 0x13A05000,
            0x115C690: 0xEAFFFFD5,
            0x115C694: 0xE3550000,
            0x115C698: 0x1A00002E,  # enter recomputation
            0x115C69C: 0xE30E3378,
            0x115C6A0: 0xE3403184,
            0x115C6A4: 0xE28310E4,
            0x115C6A8: 0xE3A02000,
            0x115C6AC: 0xE5A32004,  # otherwise clear all 57 words
            0x115C6B0: 0xE1530001,
            0x115C6B4: 0x1AFFFFFC,
            0x115C6BC: 0xE5DB3004,  # fifth argument skip gate
            0x115C6C0: 0xE3530000,
            0x115C6C4: 0x1AFFFFD0,
            0x115D044: 0xE30E3378,
            0x115D048: 0xE3403184,
            0x115D04C: 0xE3A02001,
            0x115D050: 0xE5C32000,  # explicit enable before calling constructor
            0x115D064: 0xEBFFFD53,
        },
        "preview_runtime_array_cache_export_primary_words": {
            0x1039920: 0xE3042A8C,  # initializer object 0x01734a8c
            0x1039924: 0xE3402173,
            0x103997C: 0xE2823004,
            0x1039980: 0xE28220E8,  # last slot +0xe8, inclusive
            0x1039984: 0xE302170F,  # 9999
            0x1039988: 0xE5A31004,  # first slot +8; 57 stores
            0x103998C: 0xE1520003,
            0x1039990: 0x1AFFFFFC,
            0x104C780: 0xEBFFB464,  # direct initializer call
            0x115C148: 0xE59B6004,  # init fifth arg: array destination
            0x115C1C4: 0xE3A020E4,
            0x115C1C8: 0xE59F1054,
            0x115C1CC: 0xE1A00006,
            0x115C1D0: 0xEBFF918C,
            0x115C5CC: 0xE1A07002,  # update r2 retained as output r7
            0x115C60C: 0xE3570000,
            0x115C610: 0x0A000003,  # null output skips copy
            0x115C614: 0xE3A020E4,  # exactly 228 bytes
            0x115C618: 0xE59F12EC,
            0x115C61C: 0xE1A00007,
            0x115C620: 0xEBFF9078,  # original memcpy 0x1140808
        },
        "preview_runtime_array_cache_export_primary_data_words": {
            0x115C224: 0x0184E37C,
            0x115C90C: 0x0184E37C,
        },
        "preview_runtime_array_cache_export_secondary_words": {
            0x1EA3D1C: 0xE5942740,  # explicit-enable caller also exports to shared array
            0x1EA3D2C: 0xE2822008,
            0x1EA3D38: 0xEBCAE4BA,  # wrapper 0x115d028 sets refresh flag 1
            0x1EA05DC: 0xE59F4054,
            0x1EA05E4: 0xE5943740,
            0x1EA0600: 0xE2833008,  # init array +8 fifth argument
            0x1EA0604: 0xE58D3000,
            0x1EA0614: 0xEBCAEEC7,
            0x1EB5968: 0xE30547A0,
            0x1EB596C: 0xE3404287,
            0x1EB5970: 0xE2848A03,  # shared 0x028787a0
            0x1EB5974: 0xE5982740,
            0x1EB5988: 0xE2822008,  # update array +8 third argument
            0x1EB5990: 0xEBCA9B08,  # refresh AFTER selected read 0x1eb5854
        },
        "preview_runtime_array_cache_export_secondary_data_words": {
            0x1EA3D70: 0x028787A0,
            0x1EA0638: 0x028787A0,
            0x1EB5B18: 0x028787A0,
        },
        "preview_id200_channel7_sender_primary_words": {
            0x113D8A0: 0xE5912004,  # queued send checks payload length
            0x113D964: 0xE1D530B0,  # copies packet ID into queued header
            0x113D968: 0xE1C030B0,
            0x113D97C: 0xE5953004,  # copies payload length
            0x113D980: 0xE5803004,
            0x113D9E8: 0xE5951008,  # reads payload source pointer
            0x113D9EC: 0xE2800008,  # destination after 8-byte header
            0x113D9F0: 0xEB000B84,  # copies payload bytes
        },
        "preview_id200_channel7_sender_direct_bl_sites_expected": [
            0x1D21118, 0x1E55ECC, 0x1E59AA0,
        ],
        "preview_pointer_array_id200_publication_words": {
            0x1E7FD70: 0xEB007D18,  # first caller imports temporary block
            0x1E7FD88: 0xEB00EDC0,  # then invokes ID-0x200 publisher
            0x1E8E230: 0xEB0043E8,  # second caller imports temporary block
            0x1E8E248: 0xEB00B490,  # then invokes same publisher
            0x1E9F1E8: 0xE1D330B0,  # importer reads temporary-block ID
            0x1E9F2B8: 0xE3530C02,  # ID-0x200 fixed-record branch
            0x1E9F2BC: 0x059F436C,  # fixed payload pointer
            0x1EBB490: 0xE92D4870,  # publisher entry
            0x1EBB4A4: 0xE1D310B0,  # reads temporary-block ID
            0x1EBB4A8: 0xE3510C02,  # requires ID 0x200
            0x1EBB4AC: 0x0A000002,  # only ID-0x200 reaches publication
            0x1EBB4C4: 0xE593000C,  # first temporary payload word
            0x1EBB4D0: 0xE5931010,  # second temporary payload word
            0x1EBB4D8: 0xE5933014,  # third temporary payload word
            0x1EBB4DC: 0xE5823740,  # publishes third word as pointer array
        },
        "preview_pointer_array_id200_publication_data_words": {
            0x22B2D80: 0x01E7FD58,  # first handler in callback table
            0x22B2F78: 0x01E8E228,  # second handler in callback table
            0x22B8004: 0x022B2D70,  # first callback-table base
            0x22B80D8: 0x022B2F64,  # second callback-table base
            0x1E9F630: 0x028757F8,  # ID-0x200 fixed payload slot
            0x1E9FD44: 0x028757EC,  # ID-0x200 fixed header mapper
            0x1EA0144: 0x028757F8,  # ID-0x200 fixed payload mapper
        },
        "preview_count_filter_ranges": {
            0x115C718: (0x3C, "7520527dd3d14bdf0fc586bffe14231e4d52b252b047683eadefb34e5c55182d"),
        },
        "preview_count_threshold_ranges": {
            0x115C040: (0xF8, "12b0e061ab40f817feb3e81698d93fc8b70fb1a021fd3293536e5bb4fa99711a"),
            0x115BFE4: (0x5C, "248b33a7e043f2993df7500a4bec327af7836e09ac7962fe3809213612cbcbec"),
            0x115B6F8: (0x44, "e7c7dd03b564070549089417bd15fb004aaf3820954b733b62b19a96d002fdf3"),
            0x115B780: (0x74, "80f70533fdacaa88724b7cd6ea083e2d98d51bdc2e3452b037b6fc8ad6f0c2d0"),
        },
        "preview_refresh_caller_primary_ranges": {
            0x1166E68: (0x44, "f3b1fa115ea74bfaacb562ce1bca1ddec4b26a1ed414d36c4ad7981ef3b4d92a"),
            0x115D028: (0x40, "2e1bd1295872691c40d6989512f7b97428f4e0c47abaaf360bfebd3ab0e5406b"),
            0x115D760: (0x2C, "3a82959d2f88641314cb2c044ffe6601338fb6e217487ba736fb9bacc78ec3b8"),
        },
        "preview_refresh_caller_secondary_ranges": {
            0x1EA3CFC: (0x40, "8de56332c5ee859142aa0e9f04f5b9ba28a8ee3d08b371b2ffd9e6968f7c0103"),
            0x1EA3D70: (4, "2fc69d853534e8c005bcfa1feac428da9dbc774ab2234c4c8836f34e5042af3a"),
            0x1F68898: (0x1C, "235c625d64f763e959fbb917ed0b24a07a81546ab2185acef7c48d596ecbe143"),
        },
        "preview_cache_descriptor_primary_ranges": {
            0x1159270: (0x20, "0651a0f9e337e2321c56b22ef2b83d9fa458e5efd811530e85256df0f1318198"),
        },
        "preview_cache_descriptor_secondary_ranges": {
            0x1EA063C: (0x1A4, "b2ccedb222d2cf5a283ce28307f7a5a853fd933ac6d0ad2f834148338320259a"),
        },
        "preview_cache_control_primary_ranges": {
            0x113A6A0: (0x5C, "9f9ea035910f6bb32b90a94e882acf7da2e9162fc9b2830ad9145966e0413f54"),
        },
        "preview_cache_control_volume_ranges": {
            0xD49028: (0xA4, "7555c76981dd4318a4e47b8a35c8868e99647e4af7aeb0b4cf23f5cac37e049a"),
        },
        "preview_cache_enable_dispatch_ranges": {
            # Complete original instruction/table slices, not executed-path claims.
            0x1EA84C8: (0x34, "ea0d3f404467950c4b0b4b6f3fea45c11877f690d02a156bde6b88fbe8f6e0df"),
            0x1E9C128: (0x98, "5c51672e51f9a16620554f91765f56a8fd160ec7e14d26084476120d33d709a3"),
            0x1E9C1C0: (0x14, "a253346e4092f3b81d7397f1b44da82ab7c61edd58bc15476b8b43c4e6adcd6a"),
            0x1EA82A0: (0x18, "54c7e41e0d5d67bbc16f7e659d99a71fb97cf89083659a4fa209feb6edc156b5"),
            0x1EA831C: (8, "4f59d339dde703ddf0c0a0449bdfb27893b341eb99003473a3c8c2be65e1b210"),
            0x1EA8A90: (0x74, "d8e23e3aab091e72808b0df32e89816934b696751cb07b863b15f70d7c1cb0c4"),
            0x1EA85D4: (0x4BC, "dc37d1bfe950b83bf4c6012a325f2aec9fb5cd5048dea602080924cb5659ad4e"),
            0x1E9BE64: (0x2C4, "1d400106ed9e8058455669badf4ed22c248e7225d96043f856ff60510f0bffa8"),
            0x1EA8594: (0x40, "c83d5e371f456bc312cf95e103ae3c94af71b56403e7b5b9c61edbe35e42ca81"),
            0x22B8614: (0xA4, "cf9d096529d16bfb50a6e82ff1fac62f6e191257bb357233ea21ced63ee290d9"),
            0x1E6243C: (0x158, "91b9190522c1f57fa6245cb6c6ee03d97e3c643d96cd564f49d223b426418970"),
            0x1E7FF6C: (0x14, "e482c4ef096c8c0f3f212c31bb10380c35bf2e08cb483a53a1316096f22c673d"),
            0x1E8E3DC: (0x14, "cec1cb653c3964d0f6c58e12502b1ba08873eac50fb3140e8269de1a6b9b611a"),
            0x1EBB268: (0x30, "63af6166da981ec4a770b8738db6f99936a26192c0f42ebcecf3343c0c2d2e85"),
            0x1E6ABE4: (0x1C, "8e080e8ad820d68eca524889c805f14c829f614dcad30b56cafd304ce42ebc44"),
            0x22B2CD8: (0x96, "82c6008a7521704e1c0d2c9451adb71e8f27a724e4b10145a802cc748fff2252"),
            0x22B2DE8: (0x96, "df9c13c06a8ed8c9c3c107c79f8fad1436695ad13248c191eb1abf245459e44b"),
            0x1E5D958: (0xCC, "f2f5667d0089836dd40f7d579981d20dd28efbba19fd1ff295061502785ce134"),
            0x1E5DAF8: (0xB8, "075abbae69df164a5207d3520bddec8da733aab50c730b7f2df6f368615ff0da"),
            0x1E6AC1C: (0x4C, "50f0dbb80294f0b959be230245e76f4875728e8b088d800865b44ac1e5c864fb"),
            0x1EA82DC: (0x40, "fcfc04bb1e6b52a4b4fbd447c27b7dcf7368c48f171beacb3908623d3663f354"),
            0x1EA8428: (0x6C, "48eddd4a313fcd6c71c823b5f78e3de97074c6020dbafc0adc25278743e98151"),
            0x1EBB1F4: (0x48, "efafb79e1d96134a1c84651a4e8c9f3e715d48dae6d757eb0768eed172ef0611"),
            0x22B7574: (0x3C, "33fa02bd5440d1c157f29010ac39fcd23c282c2ce759107c59911b8f6d2d0644"),
        },
        "preview_cache_enable_dispatch_data_words": {
            0x22B2D84: 0x01E7FDA8,  # category 22 non-refresh control callback
            0x22B2DCC: 0x01E7FF6C,  # category 22 slot 23, refresh-request wrapper
            0x22B2FC4: 0x01E8E3DC,  # category 75 slot 24, same wrapper
            0x22B7FB0: 0x022B7588,  # category 1 callbacks
            0x22B8270: 0x022B7574,  # category 1 selector records
            0x22B8444: 0x022B75A8,  # post-callback table (slot 1 null)
        },
        "preview_pointer_publisher_callback_dispatch_words": {
            0x1E5D960: 0xE308326C,  # category -> selector-record table
            0x1E5D964: 0xE340322B,
            0x1E5D968: 0xE7932100,
            0x1E5D97C: 0xE3083440,  # category -> post-callback table
            0x1E5D980: 0xE340322B,
            0x1E5D984: 0xE7935100,
            0x1E5D988: 0xE306348C,  # mutable per-category selector table
            0x1E5D98C: 0xE34032D5,
            0x1E5D994: 0xE3080180,  # category dimension/count table
            0x1E5D998: 0xE340022B,
            0x1E5D99C: 0xE19330B1,  # first runtime halfword for category
            0x1E5D9A0: 0xE190C0B1,  # static stride, 3 for categories 22/75
            0x1E5D9A4: 0xE30E0308,  # separate mutable selector table
            0x1E5D9A8: 0xE34002C9,
            0x1E5D9AC: 0xE19010B1,  # second runtime halfword for category
            0x1E5D9B0: 0xE1031C83,  # signed low-halfword multiply-add
            0x1E5D9B4: 0xE6FF3073,  # narrow selected record index to 16 bits
            0x1E5D9BC: 0xE3071FAC,  # category -> primary callback table
            0x1E5D9C0: 0xE340122B,
            0x1E5D9C4: 0xE7D22083,  # selector byte from selected 2-byte record
            0x1E5D9C8: 0xE7913104,
            0x1E5D9CC: 0xE7933102,  # callback indexed by selector byte
            0x1E5D9D8: 0xE12FFF33,  # indirect call to selected callback
        },
        "preview_pointer_publisher_callback_dispatch_data_words": {
            0x22B7FBC: 0x022B7F6C,  # category 4 callback table (receive-side ID 0x200)
            0x22B8004: 0x022B2D70,  # category 22 primary callback table
            0x22B80D8: 0x022B2F64,  # category 75 primary callback table
            0x22B827C: 0x022B112C,  # category 4 selector records
            0x22B82C4: 0x022B2CD8,  # category 22 selector records
            0x22B8398: 0x022B2DE8,  # category 75 selector records
            0x22B2D80: 0x01E7FD58,  # first import/publish handler, slot 4
            0x22B2F78: 0x01E8E228,  # second import/publish handler, slot 5
        },
        "preview_pointer_publisher_callback_dispatch_record_prefixes": {
            0x22B8182: bytes.fromhex("02 00"),  # category 1 stride
            0x22B8188: bytes.fromhex("07 00"),  # category 4 stride
            0x22B81AC: bytes.fromhex("03 00"),  # category 22 stride
            0x22B8216: bytes.fromhex("03 00"),  # category 75 stride
            0x22B2CD8: bytes.fromhex("02 01 03 01 03 01 04 01"),
            0x22B2DE8: bytes.fromhex("02 01 03 01 04 01 05 ff"),
        },
        "preview_pointer_publisher_category22_trigger_words": {
            0x1E62444: 0xE3023498,  # reads state selector byte at 0x02ca2498
            0x1E62448: 0xE34032CA,
            0x1E62458: 0xE2432001,  # values 1 or 2 reach category-22 stage 1
            0x1E62460: 0xE3520001,
            0x1E62464: 0x9A000051,
            0x1E625B8: 0xE3A02001,  # stage 1
            0x1E625BC: 0xE1C322BC,  # writes first runtime selector halfword
            0x1E625C0: 0xE3A00016,  # category 22
            0x1E625C4: 0xEBFFECE3,  # invoke generic dispatcher
            0x1E7FD6C: 0xE1C322BC,  # selected callback advances second halfword to 1
            0x1E8007C: 0xE1C322BC,  # separate branch can clear it to 0
        },
        "preview_pointer_publisher_conditional_channel7_bridge_words": {
            0x1E6AAE4: 0xEBFFFF7E,  # worker zeros mutable dispatcher selectors
            0x1E6A908: 0xE1C320B8,  # initial category-4 second selector = 0
            0x1E6A90C: 0xE1C320BA,  # initial category-5 second selector = 0
            0x1E6A950: 0xE1C322BC,  # initial category-22 second selector = 0
            0x1E6AA34: 0xE1C329BE,  # initial category-79 second selector = 0
            0x1E5DEB4: 0xE3530001,  # received payload-target byte +0xc2 gate
            0x1E5DEC4: 0x13A02001,  # non-1 selects category-4 first selector 1
            0x1E6BB6C: 0xEBFFC8EF,  # category-4 slot 3 calls header classifier
            0x1E5DF88: 0xE5D22002,  # category-5 path reads runtime exclusion flag
            0x1E5DF90: 0x1AFFFFEE,  # nonzero flag takes a different route
            0x1E5DF94: 0xE3530C02,  # exact ID 0x200
            0x1E5DF98: 0x0A00002D,  # ID 0x200 reaches category-5 first selector 0
            0x1E5E060: 0xE3A00005,  # category 5
            0x1E5E064: 0xEBFFFE3B,  # generic dispatcher
            0x1E6BE84: 0xE5931010,  # category-5 slot 2 loads received second payload word
            0x1E6BE88: 0xE3A00001,  # pass state 1
            0x1E6BE8C: 0xEB013ABD,  # call state setter 0x01eba988
            0x1EBA998: 0xE5C30000,  # state setter writes 1 to 0x02ca2498
            0x1EBA99C: 0xE5831004,  # and forwards second payload word
            0x1EBA9A0: 0xEBFEAF74,  # calls category-79 wrapper
            0x1E6678C: 0xE1C329BE,  # category-79 first selector = 0
            0x1E66790: 0xE3A0004F,  # category 79
            0x1E66794: 0xEBFFDC6F,  # generic dispatcher
            0x1E8F77C: 0xEBFF4B2E,  # category-79 slot 2 calls category-22 wrapper
        },
        "preview_pointer_publisher_conditional_channel7_bridge_data_words": {
            0x22B7F78: 0x01E6BB64,  # category-4 slot 3
            0x22B7FC0: 0x022B2C58,  # category-5 callback table
            0x22B8280: 0x022B1180,  # category-5 selector records
            0x22B2C60: 0x01E6BE6C,  # category-5 slot 2
            0x22B80E8: 0x022B2FDC,  # category-79 callback table
            0x22B83A8: 0x022B2CD4,  # category-79 selector records
            0x22B2FE4: 0x01E8F774,  # category-79 slot 2
        },
        "preview_pointer_publisher_conditional_channel7_bridge_bytes": {
            0x22B113A: bytes.fromhex("03 ff"),  # category 4: first=1, second=0
            0x22B818A: bytes.fromhex("08 00"),  # category-5 stride
            0x22B1180: bytes.fromhex("02 ff"),  # category 5: first=0, second=0
            0x22B821E: bytes.fromhex("01 00"),  # category-79 stride
            0x22B2CD4: bytes.fromhex("02 01"),  # category 79: first=0, second=0
        },
        "preview_pointer_publisher_channel7_filter_words": {
            0x1E6AB28: 0xEB0262A3,  # filter return controls worker loop
            0x1E6AB2C: 0xE3500001,
            0x1E6AB30: 0x0AFFFFF2,  # result 1 skips normal dispatch
            0x1F293B8: 0xE1D020B0,  # first filter reads packet ID
            0x1F293BC: 0xE3013239,  # special ID 0x1239
            0x1F293C4: 0x0A000001,
            0x1F293C8: 0xE3A00001,  # other IDs, including 0x200, return 1
            0x1F03678: 0xEB00974E,  # wrapper calls first filter
            0x1F0367C: 0xE3500001,  # result 1 allows second filter
            0x1F03688: 0xE1A00004,  # packet header argument
            0x1F0368C: 0xEB00659D,  # second filter 0x01f1cd08
            0x1F03690: 0xE1A04000,  # return value governs worker skip
            0x1F1CD2C: 0x0A0000DB,  # empty descriptor table returns 0
            0x1F1CE3C: 0xE3A00000,  # unmatched descriptor returns 0
            0x1F1D0A0: 0xE3A00000,  # zero-descriptor return
        },
        "vg_selector_source_words": {
            0x1EB21F0: 0xE5DB9004,  # selector reads first stack argument as row code
            0x1EB2540: 0xE5D20070,  # preview state +0x70 supplies row code
            0x1EB2550: 0xE2033202,  # graphics-mode bit gate
            0x1EB2558: 0x13A00001,  # may override row code with one
            0x1EB258C: 0xE58D0000,  # preview row code -> first stack argument
            0x1EB2594: 0xEBFFFF10,  # selector call
            0x1EB230C: 0xE5DB3008,  # separate second stack argument: mode flag
            0x1EB2684: 0xE5D46070,  # family 2 reads same preview-state row code
            0x1EB2694: 0x13A06001,  # same graphics-mode override to one
            0x1EB26A0: 0xE5D33068,  # separate alternate-rectangle flag
            0x1EB26A8: 0x0A000025,  # flag one enters diagnostic detour
            0x1EB26D8: 0xE58D6000,  # family-2 row code -> first stack argument
            0x1EB26DC: 0xE3A00002,  # family-2 selector ID
            0x1EB26E0: 0xEBFFFEBD,  # selector call
            0x1EB2784: 0xEAFFFFC8,  # diagnostic detour rejoins selector setup
        },
        "vg_packet_alternate_flag_words": {
            0x1EB1AA8: 0xE3A02020,  # copy a 32-byte packet
            0x1EB1AAC: 0xE30300D4,  # graphics-state base 0x02e030d4
            0x1EB1AB0: 0xE34002E0,
            0x1EB1AB4: 0xEBCA3B53,  # packet -> graphics state
            0x1EB1F44: 0xE5D3101C,  # state +0x1c
            0x1EB1F48: 0xE5C31068,  # alternate-rectangle flag +0x68
            0x1EB2584: 0xE5D4C068,  # separate alternate-rectangle flag
            0x1EB2588: 0xE58DC004,  # second stack argument, not row code
            0x1EB763C: 0xE1A05000,  # one packet builder takes r0
            0x1EB76AC: 0xE54B5010,  # packet +0x1c = r0 low byte
            0x1E77F04: 0xE3500003,  # caller tests working-state +0xbe == 3
            0x1E77F08: 0x13A00000,  # false -> zero
            0x1E77F0C: 0x03A00001,  # true -> one
            0x1E77F10: 0xEB00FDC6,  # passes binary value to packet builder
            0x1ECB940: 0xE5D33002,  # another builder reads 0x02d557ec+2
            0x1ECB944: 0xE54B3008,  # copies counter to packet +0x1c
            0x1ECB9F0: 0xE5C32002,  # counter reset to zero
            0x1ECBA3C: 0xE3530008,  # increment limited at eight
            0x1ECBA4C: 0xE2833001,
            0x1ECBA50: 0xE5C23002,
            0x1ECBA64: 0xE5C32002,  # saturation value nine
            0x1DE7264: 0xE5C40281,  # runtime-record +0x281 writer
            0x1EC96C0: 0xE5D33281,  # third packet source: record +0x281
            0x1EC96C4: 0xE54B3008,  # copy to packet +0x1c
        },
        "vg_channel_descriptor_table": 0x1510EB4,
        "vg_channel_context_table": 0x141C54C,
        "vg_channel_routes_expected": [
            {"descriptor_id": 0, "context_index": 1},
            {"descriptor_id": 1, "context_index": 1},
            {"descriptor_id": 2, "context_index": 0},
        ],
        "vg_channel_secondary_words": {
            0x1ED0E60: 0xE5D030BE,  # selects descriptor 0 or 1
            0x1ED0E68: 0x03A00000,
            0x1ED0E6C: 0x13A00001,
            0x1ED0E70: 0xEBC848B1,
            0x1ED0E7C: 0xE5830000,  # stores primary descriptor pointer
            0x1ED0E84: 0xE353002D,  # conditional third descriptor
            0x1ED0EA0: 0xE5D430BF,
            0x1ED0EAC: 0xE5D43581,
            0x1ED0EB8: 0xE3A00002,
            0x1ED0EBC: 0xEBC8489E,
            0x1EB1F44: 0xE5D3101C,  # VG aspect source from graphics state
            0x1EB1F48: 0xE5C31068,
            0x1EB20F8: 0xE3A02000,  # alternate mode clears VG aspect
            0x1EB20FC: 0xE5C32068,
        },
        "vg_channel_primary_words": {
            0x10E23EC: 0xE590000C,  # descriptor +12 yields runtime pointer
            0x10E2680: 0xE30C354C,  # context map base
            0x10E2684: 0xE3403141,
            0x10E2688: 0xE0833080,  # descriptor ID * 2
            0x10E268C: 0xE5D30001,  # mapped context index
            0x10E2690: 0xEB004870,
            0x10E2694: 0xE584000C,  # populate descriptor runtime pointer
            0x10E3144: 0xE3500002,  # three descriptor IDs 0..2
            0x10E3148: 0x93003EB4,
            0x10E314C: 0x93403151,
            0x10E3150: 0x90830200,
            0x10E3344: 0xE3A06001,  # initializer sends IDs 0, 1, 2
            0x10E3350: 0xE3A00000,
            0x10E3354: 0xEBFFFCB1,
            0x10E3370: 0xE1A00006,
            0x10E3374: 0xEBFFFCA9,
            0x10E3394: 0xE3A00002,
            0x10E3398: 0xEBFFFCA0,
            0x10F4860: 0xE30C3220,  # runtime context array base
            0x10F4864: 0xE3403185,
            0x10F4868: 0xE3A02EB2,  # 2848-byte context stride
            0x10F486C: 0xE0203092,
        },
        "vg_geometry_output_words": {
            0x1EB25C0: 0xE24B1024,  # family-0 inner-rectangle output
            0x1EB25C8: 0xEB007B9B,  # secondary setter wrapper
            0x1ED0E60: 0xE5D030BE,  # choose descriptor 0/1 from preview mode
            0x1ED0E70: 0xEBC848B1,  # resolve primary descriptor
            0x1ED0E7C: 0xE5830000,  # first handle pointer
            0x1ED0EA0: 0xE5D430BF,  # optional descriptor 2 gate
            0x1ED0EAC: 0xE5D43581,
            0x1ED0EB8: 0xE3A00002,
            0x1ED0EC8: 0xE5830000,  # optional second handle pointer
            0x1ED0EEC: 0xE353002D,  # special graphics-setup object branch
            0x1ED0EF0: 0x0A0000BF,
            0x1ED11FC: 0xE5D530BF,  # branch requires object +bf != 1
            0x1ED1214: 0xE593373C,  # active preview object pointer
            0x1ED1264: 0x028787A0,  # shared base for pointer at +0x73c
            0x1ED1218: 0xE5D33070,  # read active preview aspect code
            0x1ED121C: 0xE3530007,  # codes 7 or 2 -> class 4
            0x1ED1220: 0x13530002,
            0x1ED1234: 0x13A03004,
            0x1ED1238: 0x03A03003,  # other codes -> class 3
            0x1ED0F44: 0xE5C43001,  # store class in setup record +1
            0x1EBE034: 0xE5941020,  # setup source: active/fallback object slot
            0x1EBE03C: 0xEB004C89,
            0x1EC4BA8: 0xE59F1018,  # setup source: fixed fallback object
            0x1EC4BB0: 0xEB0031AC,
            0x1EC4BC8: 0x02879E6C,
            0x1ED1564: 0xEBFFFF3F,  # setup source: caller-supplied object
            0x1ED144C: 0xE30B39E8,  # always use first handle
            0x1ED1460: 0xEBC84BDF,  # wrapper enters primary setter
            0x1ED1464: 0xE30B39F0,  # second handle when nonnull
            0x1ED1470: 0xE3500000,
            0x1ED1480: 0xEBC84BD7,
        },
        "vg_geometry_primary_sink_words": {
            0x10E43E4: 0xE1A03002,  # primary setter receives structure
            0x10E4414: 0xE1D3E0B8,  # checks first inner dimension
            0x10E44B8: 0xE1CCE2B0,  # caches that dimension
            0x10E44DC: 0xEB004361,  # forwards converted 22-byte structure
            0x10F5268: 0xE1A03001,  # destination configuration routine
            0x10F52A4: 0xE3A02016,  # copies 22 bytes
            0x10F52B4: 0xEB012D53,
        },
        "vg_geometry_primary_readback_words": {
            0x10F52A4: 0xE3A02016,  # setter: 22-byte slot stride
            0x10F52A8: 0xE0200392,  # handle + 22 * slot
            0x10F52AC: 0xE2800F76,  # add +0x1d8
            0x10F52B0: 0xE2800002,  # slot payload begins at +0x1da
            0x10F52FC: 0xE3510001,  # getter rejects slot >1
            0x10F5300: 0x8A00000A,
            0x10F5310: 0xE3A02016,  # getter: same 22-byte stride
            0x10F5314: 0xE0210192,  # handle + 22 * slot
            0x10F5318: 0xE2811F76,  # add +0x1d8
            0x10F531C: 0xE2811002,  # same slot payload
            0x10F5320: 0xE1A00003,  # caller output buffer -> copy destination
            0x10F5324: 0xEB012D37,  # copy 22 bytes from slot
        },
        "vg_geometry_primary_getter_bl_sites_expected": [
            0x10E488C, 0x10E60BC, 0x10E6820, 0x10E6D88,
            0x10E6E34, 0x10E6EEC, 0x10E6F38,
        ],
        "vg_geometry_primary_setter_bl_sites_expected": [0x10E44DC, 0x10E45E4],
        "recbf_script_table_address": 0x22DF148,
        "recbf_script_count": 43,
        "recbf_script_terminator": 0x9E,
        "recbf_copy_crop_raw_command": 0x15,
        "recbf_resize_yc_command": 0x16,
        "recbf_copy_crop_raw_modes": [3, 21, 35, 37],
        "recbf_resize_yc_modes": [23, 36, 38],
        "recbf_short_crop_event_id": 58,
        "recbf_short_crop_mode": 21,
        "recbf_short_crop_script": bytes.fromhex("15 17 9d 9e"),
        "recbf_short_crop_builder": 0x1F21978,
        "recbf_short_crop_builder_bl_count": 30,
        "recbf_short_crop_dispatch_span": (0x1F32B7C, 0x1F334E8),
        "recbf_short_crop_data_words": {
            0x22D9798: 58,  # event descriptor ID
            0x22D97AC: 0x1F32B7C,  # event callback
            0x1F32C08: 0x1F33024,  # event-58 dispatch slot
            0x22DC920: 15, 0x22DC924: 0x22DB3B4,
            0x22DC928: 13, 0x22DC92C: 0x22DB868,
            0x22DC958: 34, 0x22DC95C: 0x22DBCA8,
            0x22DC960: 36, 0x22DC964: 0x22DBDCC,
            0x22DB88C: 58, 0x22DB890: 0,  # group-13 event has no secondary predicate
            0x22DB3D8: 58, 0x22DB3DC: 0,  # group-15 event has no secondary predicate
            0x22DBCD8: 58, 0x22DBCDC: 0,  # group-34 event has no secondary predicate
            0x22DBDCC: 58, 0x22DBDD0: 0,  # group-36 event has no secondary predicate
            0x22DB3E0: 0x22DB464,  # group 15 event-58 prerequisite list
            0x22DB894: 0x22DB918,  # group 13 event-58 prerequisite list
            0x22DBCE0: 0x22DBD9C,  # group 34 event-58 prerequisite list
            0x22DBDD4: 0x22DBE50,  # group 36 event-58 prerequisite list
            0x22DB464: 103, 0x22DB468: 0xFFFFFFFF,
            0x22DB918: 103, 0x22DB91C: 0xFFFFFFFF,
            0x22DBD9C: 231, 0x22DBDA0: 0xFFFFFFFF,
            0x22DBE50: 103, 0x22DBE54: 0xFFFFFFFF,
            0x22DA848: 0, 0x22DA850: 1, 0x22DA854: 0x22DAB48,
            0x22DA878: 0xFFFFFFFF,  # six-entry profile-group table terminator
            0x22DAC5C: 58, 0x22DAC60: 0, 0x22DAC64: 0x22DB520,
            0x22DB520: 231, 0x22DB524: 0xFFFFFFFF,
            0x22DC8B8: 44, 0x22DC9D8: 0xFFFFFFFF,  # 36-entry dynamic-group table
            0x22D97A0: 220,  # event-58 descriptor type accepted by slot guard
            0x1F1B768: 0x034CE4F8,  # 231 exclusion scans shared prerequisite count/list
            0x1F1C15C: 0x034CE4FC,  # shared runtime row-prerequisite template
            0x1F1D0B8: 0x034CACB8,  # message-state source for bit-103 route
            0x22DD790: 0x001D923B, 0x22DD794: 42, 0x22DD798: 103,
            0x22DDE10: 0x00ED923B, 0x22DDE14: 42, 0x22DDE18: 103,
            0x22DDF60: 0,  # end of 275-entry message-to-bit table
            0x22DDFDC: 0x1F2B488,  # indexed callback entry 13
            0x22DDFEC: 0,  # indexed callback entry 15 has no direct function
            0x22DE084: 0x1F2D198,  # indexed callback entry 34
            0x22DE094: 0x1F2C370,  # indexed callback entry 36
            0x1F6E0C0: 0x1F6E334,  # signed zero maps to record +0x269 = 0
            0x1F702B4: 0x1F705CC,  # record zero maps to output byte +15 = 0
            0x22DF7F0: 0x022095CC,  # command 0x17 shares YC-resize name
        },
        "recbf_short_crop_group_pointers": {
            15: 0x22DB3B4, 13: 0x22DB868,
            34: 0x22DBCA8, 36: 0x22DBDCC,
        },
        "recbf_short_crop_route_words": {
            0x1F33024: 0xE3A01015,  # request script mode 21
            0x1F33028: 0xEBFFBA52,  # call request builder
            0x1F219F8: 0xEBFFCAA3,  # builder forwards mode
            0x1F146E4: 0xE5C45000,  # request byte 0 = script mode
            0x1F3AD1C: 0xE5D03000,  # sender reads that byte
        },
        "recbf_short_crop_group_callback_sweep_words": {
            0x1F1C60C: 0xEB00437C,  # list controller calls group-callback sweep
            0x1F1C3C4: 0xEBFFFCE8,  # conditional event-list rebuild
            0x1F2D430: 0xE30D4F70,  # callback table base low half
            0x1F2D434: 0xE340422D,  # callback table base high half
            0x1F2D588: 0xE5943004,  # indexed callback pointer at entry +4
            0x1F2D598: 0xE12FFF33,  # call non-null group callback
            0x1F1B948: 0xE5951004,  # event-builder loads secondary predicate
            0x1F1B950: 0xEBFFFF40,  # checks predicate for listed event
            0x1F1B660: 0xE2514000,  # null predicate...
            0x1F1B664: 0x0A000014,  # ...takes success branch
            0x1F1B6BC: 0xE3A00001,  # returns true
        },
        "recbf_short_crop_scheduler_words": {
            0x1F1C360: 0xE2811024,  # per-slot +0x9e24 processed/suppression bitmap
            0x1F1C4E0: 0xE5145004,  # queued event ID
            0x1F1C4EC: 0xEB00F978,  # test its processed/suppression bit
            0x1F1C4F4: 0x0AFFFFF3,  # already processed: skip row
            0x1F1C500: 0x0A000004,  # absent row predicate: continue
            0x1F1C50C: 0xEB00F980,  # present row predicate: test bitmap
            0x1F1C520: 0xEBFFFF10,  # further slot/event guard
            0x1F1C528: 0x0AFFFFB6,  # success: invoke event dispatcher
            0x1F1C410: 0xEBFFFCAC,  # invoke descriptor callback wrapper
            0x1F1B6E8: 0xE51B3010,  # event descriptor's callback pointer
            0x1F1B6FC: 0xE12FFF33,  # call dispatcher through pointer
            0x1F1B700: 0xE3500001,  # only callback success advances
            0x1F1B718: 0xEBFFFF78,  # mark handled event
            0x1F1B518: 0xEBC92E52,  # handled-event bitmap update has own gate
            0x1F1B520: 0x1A00000E,  # gate permits set/clear path
            0x1F3302C: 0xE3A04001,  # mode-21 case reports success
            0x1F32CB8: 0xE1A00004,  # dispatcher returns case result
            0x1F1B63C: 0xEB00FD01,  # set +0x9e24 bitmap bit
            0x1F1B650: 0xEB00FCB2,  # clear +0x9e44 bitmap bit
            0x1F5AA68: 0xE183111C,  # shared bit-set helper
            0x1F5A940: 0xE1C3111C,  # shared bit-clear helper
        },
        "recbf_short_crop_event58_slot_guard_words": {
            0x1F1C1E4: 0xEBFFBEA8,  # copy event descriptor by queued ID
            0x1F1C1E8: 0xE51B3034,  # descriptor field +8 (type)
            0x1F1C1EC: 0xE35300DC,  # compare type with 220
            0x1F1C1F0: 0x13740001,  # test alternate slot only when type is not 220
            0x1F1C1F4: 0x03A00001,  # type 220 selects success result
            0x1F1C1F8: 0x0AFFFFE9,  # type 220 returns before later bitmap scan
        },
        "recbf_short_crop_row_template_words": {
            0x1F1BC4C: 0xE7834002,  # builder writes event ID at row -4
            0x1F1BC6C: 0xE3A02040,  # builder copies 64 prerequisite bytes
            0x1F1BC70: 0xE59F14E4,  # source pointer: shared runtime template
            0x1F1BC7C: 0xEBC892E1,  # copy into row following event ID
            0x1F1C0FC: 0xE7834002,  # second builder branch writes event ID
            0x1F1C11C: 0xE3A02040,  # same 64-byte template length
            0x1F1C120: 0xE59F1034,  # same source pointer
            0x1F1C12C: 0xEBC891B5,  # second branch copies row template
            0x1F1C4E0: 0xE5145004,  # scheduler reads event ID at row -4
            0x1F1C4F8: 0xE5943000,  # scheduler reads row's first prerequisite
            0x1F1C4FC: 0xE3730001,  # -1 means no prerequisite
            0x1F5AB30: 0xE5912000,  # bitmap helper reads first prerequisite
            0x1F5AB34: 0xE3720001,  # -1 sentinel in prerequisite list
        },
        "recbf_short_crop_prerequisite_builder_words": {
            0x1F0BB1C: 0xE3A02000,  # reset shared list count
            0x1F0BB20: 0xE1C320B0,
            0x1F0BB24: 0xE3A02010,  # sixteen 32-bit sentinel slots
            0x1F0BB28: 0xE3E01000,  # sentinel value -1
            0x1F0BB2C: 0xE2830004,  # list starts after count
            0x1F0BB30: 0xEBC8D3A8,  # fill sixteen words
            0x1F0BB9C: 0xE5810004,  # append group-subrecord prerequisite ID
            0x1F1B910: 0xEBFFC07E,  # builder resets list for an event row
            0x1F1B95C: 0xE5973008,  # group-subrecord +8 list pointer
            0x1F1B960: 0xE5930000,  # first prerequisite ID
            0x1F1B970: 0xEBFFC071,  # append it to shared template
            0x1F1B978: 0xE7930006,  # read next prerequisite ID
            0x1F1B984: 0x1AFFFFF9,  # repeat until -1 terminator
        },
        "recbf_short_crop_231_exclusion_words": {
            0x1F1B72C: 0xE59F3034,  # read shared prerequisite count/list pointer
            0x1F1B730: 0xE1D320B0,  # list count
            0x1F1B748: 0xE5B32004,  # scan next bit ID
            0x1F1B74C: 0xE35200E7,  # 231 is an exclusion marker
            0x1F1B750: 0x03A00001,  # mark found
            0x1F1BA5C: 0xEBFFFF30,  # first builder branch checks marker
            0x1F1BA64: 0x1AFFFF98,  # found: skip event, not enqueue row
            0x1F1BED8: 0xEBFFFE11,  # second builder branch checks marker
            0x1F1BEE0: 0x0A00000C,  # absent: continue toward row write
        },
        "recbf_short_crop_bit103_message_writer_words": {
            0x1F1CD10: 0xE3500000,  # entry gate: zero input bypasses table
            0x1F1CD14: 0x0A00000E,
            0x1F1CD24: 0xE1D330B0,  # bounded 16-byte message-row scan
            0x1F1CD34: 0xE1D21BB8,  # message-state command
            0x1F1CD38: 0xE1D2CCBE,  # message-state subtype
            0x1F1CD3C: 0xE5D2E0D0,  # message-state selector
            0x1F1CD64: 0xE1F231B0,  # next 16-byte row
            0x1F1CD78: 0xE1510000,  # special command 0x923b
            0x1F1CD80: 0xE1D230B2,  # compare row subtype
            0x1F1CD90: 0xE353002A,  # selector 42 bypasses selector match
            0x1F1CDB0: 0xEBFFE377,  # derive active slot
            0x1F1CDDC: 0xE5936008,  # row +8 supplies bit ID
            0x1F1CDE0: 0xE35600E8,  # 232 and -1 take another route
            0x1F1CDE8: 0x1A00005D,  # ordinary bit IDs enter setter path
            0x1F1CF74: 0x1A000011,  # diagnostics enabled: test/log first
            0x1F1CF78: 0xE355007F,  # in-range slot check
            0x1F1D080: 0xE3092E24,  # per-slot processed bitmap +0x9e24
            0x1F1D090: 0xE1A01006,  # bit ID from message table
            0x1F1D098: 0xEB00F66A,  # set the bit
        },
        "recbf_short_crop_message_payload_bridge_words": {
            0x1F1CD18: 0xEB002C92,  # nonnull message is copied into global state first
            0x1F27F78: 0xE1D020B0,  # input +0: 16-bit command
            0x1F27F80: 0xE1C32BB8,  # global +0xb8: command
            0x1F27F94: 0xE5902004,  # input +4: payload length
            0x1F27FB0: 0xE5901008,  # input +8: payload pointer
            0x1F27FB4: 0xE28300C4,  # global +0xc4: payload destination
            0x1F27FB8: 0xEBC86212,  # copy length bytes to global payload
        },
        "recbf_short_crop_message_payload_bridge_data_words": {
            0x1F27FD0: 0x034CACB8,  # global message-state base
        },
        "recbf_short_crop_923b_packet_constructor_words": {
            0x1F0A4B0: 0xE5903000,  # context-derived slot pointer from caller object
            0x1F0A4B4: 0xE50B3010,  # first constructor: payload +4
            0x1F0A4BC: 0xE14B10BA,  # subtype r1 at payload +10
            0x1F0A4C4: 0xE54B3008,  # selector at payload +12
            0x1F0A4C8: 0xE309323B,  # 0x923b command
            0x1F0A4D0: 0xE14B32B0,  # 16-bit packet command
            0x1F0A4E4: 0xE3A03010,  # payload length 16
            0x1F0A4F0: 0xE50B3018,  # payload pointer
            0x1F0A4FC: 0xEBC8CCDE,  # transmit packet
            0x1F16160: 0xE1D130B2,  # second constructor looks up row subtype
            0x1F16164: 0xE1530004,  # compare row subtype to input r4
            0x1F16178: 0xE5906008,  # fetch row bit ID
            0x1F161E4: 0xE5953000,  # context-derived slot pointer from caller object
            0x1F161E8: 0xE50B3020,  # second constructor: payload +4
            0x1F161F0: 0xE14B41BA,  # second constructor: subtype r4 at payload +10
            0x1F161F8: 0xE54B3018,  # selector at payload +12
            0x1F16204: 0xE14B34B0,  # 0x923b packet command
            0x1F16218: 0xE3A03010,  # payload length 16
            0x1F16224: 0xE50B3038,  # payload pointer
            0x1F16230: 0xEBC89D91,  # transmit packet
        },
        "recbf_short_crop_923b_callback_gate_words": {
            0x1F16160: 0xE1D130B2,  # compare table subtype to callback input
            0x1F16164: 0xE1530004,
            0x1F16178: 0xE5906008,  # matched row bit ID (103 for 0x1d/0xed)
            0x1F1617C: 0xE3760001,  # only bit ID -1 takes exceptional path
            0x1F16180: 0x0A000034,
            0x1F16184: 0xE352000A,  # r2=0..10 use the bounded jump table
            0x1F16188: 0x979FF102,
            0x1F1618C: 0xEA00002C,  # other r2 values use fallback
            0x1F161C4: 0xE3A02000,  # selected cases normalize r2 to zero
            0x1F161C8: 0xE246606A,  # bit ID minus 106
            0x1F161CC: 0xE3560005,  # only 106..111 read the object-state guard
            0x1F161D0: 0x8A000002,  # 103 bypasses that guard
            0x1F161D4: 0xE5D5301C,
            0x1F161DC: 0x0A000016,
            0x1F161E0: 0xE50B5024,  # common 0x923b payload construction
            0x1F16244: 0xEB004734,  # fallback normalization helper
            0x1F16248: 0xE3A02002,
            0x1F1624C: 0xEAFFFFDD,  # fallback joins common packet construction
        },
        "recbf_short_crop_923b_callback_dispatch_data_words": {
            0x1F16190: 0x1F161C4,
            0x1F16194: 0x1F161C8,
            0x1F16198: 0x1F161C8,
            0x1F1619C: 0x1F16244,
            0x1F161A0: 0x1F161C8,
            0x1F161A4: 0x1F161C4,
            0x1F161A8: 0x1F161C4,
            0x1F161AC: 0x1F161C8,
            0x1F161B0: 0x1F16244,
            0x1F161B4: 0x1F161C8,
            0x1F161B8: 0x1F161C8,
            0x22DD790: 0x001D923B,  # bit-103 subtype 0x1d
            0x22DD798: 103,
            0x22DDE10: 0x00ED923B,  # bit-103 subtype 0xed
            0x22DDE18: 103,
        },
        "recbf_short_crop_mode21_callback_request_words": {
            0x1F219F0: 0xE1A01006,  # event builder forwards script mode
            0x1F219F8: 0xEBFFCAA3,  # construct mode-specific request descriptor
            0x1F21A0C: 0xE24B0040,  # forward descriptor to queue sender
            0x1F21A10: 0xEB0064BD,
            0x1F1449C: 0xE1A05001,  # selector receives mode 21 in r5
            0x1F145A8: 0xE3A07005,  # mode-21 case selects descriptor index 5
            0x1F145CC: 0xE3550014,  # 21 avoids the mode-20 special case
            0x1F14734: 0xE3550021,  # 21 avoids the mode-33 special case
            0x1F147C8: 0xE3A03000,  # ordinary descriptor branch
            0x1F146D8: 0xE1A00007,  # index 5 to descriptor lookup
            0x1F146DC: 0xEB005307,
            0x1F146E0: 0xE5840008,  # selected channel descriptor at +8
            0x1F146E4: 0xE5C45000,  # script mode at +0
            0x1F146E8: 0xE306310C,  # callback = 0x01f1610c
            0x1F146EC: 0xE34031F1,
            0x1F146F0: 0xE584300C,  # callback stored at +12
            0x1F3AD3C: 0xE594300C,  # queue sender reads callback
            0x1F3AD40: 0xE50B3054,  # copies it into request payload +8
            0x1F3AD84: 0xE301323B,  # request command 0x123b
            0x1F3AE20: 0xE5D30000,  # channel ID from selected descriptor
            0x1F3AE24: 0xEBC80A94,  # submits request
        },
        "recbf_short_crop_mode21_callback_request_data_words": {
            0x1F14514: 0x1F145A8,  # jump-table mode 21 to index-5 case
            0x22D8874: 14,  # index-5 channel descriptor starts with channel 14
            0x22D8878: 0x02205B40,
            0x22D887C: 6,
        },
        "recbf_short_crop_channel14_worker_words": {
            0x1F3B344: 0xE3003B30,  # worker entry 0x01f50b30
            0x1F3B348: 0xE34031F5,
            0x1F3B358: 0xEBC80541,  # task creation, conditional
            0x1F50B64: 0xEBC7B3D7,  # channel dequeue
            0x1F50B78: 0xE51B4074,  # request context pointer
            0x1F50B84: 0xEBFFAAA8,  # copy payload fields into context
            0x1F3B644: 0xE5912004,  # payload callback pointer
            0x1F3B648: 0xE5802008,  # context callback pointer
            0x1F50B98: 0xE3530005,  # script execution branch
            0x1F50B4C: 0xE1A00004,  # worker context into script executor
            0x1F50B50: 0xEBFFFB88,
            0x1F4F9E4: 0xE5936004,  # script pointer from mode table
            0x1F4F9F4: 0xE353009E,  # terminator 0x9e
            0x1F508A8: 0xE353009D,  # command jump table includes 0x9d
            0x1F506DC: 0xE3A03000,  # 0x9d branch
            0x1F50728: 0xE300113B,  # completion callback subtype 0x13b
            0x1F50730: 0xEBFFAF9A,  # callback wrapper
            0x1F3C5A8: 0xE5903008,  # pointer at context +8
            0x1F3C5B4: 0xE12FFF33,  # conditional indirect call
        },
        "recbf_short_crop_channel14_script_dispatch_data_words": {
            0x1F50908: 0x01F4FC84,  # 0x15 -> crop handler
            0x1F50910: 0x01F4FCAC,  # 0x17 -> YC resize handler
            0x1F50B28: 0x01F506DC,  # 0x9d -> completion branch
        },
        "recbf_upstream_1218_callback_source_words": {
            0x1F2450C: 0xE30A34A0,  # caller loads callback 0x01f0a4a0
            0x1F24510: 0xE34031F0,
            0x1F24520: 0xEB0099D3,  # first wrapper
            0x1F245F0: 0xE30A34A0,  # second caller path
            0x1F245F4: 0xE34031F0,
            0x1F24604: 0xEB009D54,  # second wrapper
            0x1F4AD3C: 0xE21540FF,  # first wrapper's bounded loop
            0x1F4ADA8: 0xEBFFBE92,  # first wrapper invokes 0x1218 sender
            0x1F4BC90: 0xEBFFBAD8,  # second wrapper invokes same sender
            0x1F3A860: 0xE50B605C,  # callback pointer into payload +8
            0x1F3A864: 0xE3A03005,  # worker state 5
            0x1F3A898: 0xE3013218,  # request command 0x1218
            0x1F3A8C4: 0xEBC80BEC,  # conditional transport submit
            0x1F4FC2C: 0xE3A01000,  # script command 0x0e dispatch
            0x1F4FC34: 0xEBFFEA53,  # to 0x01f4a588
            0x1F4A5A8: 0xE3A0000E,  # lookup command 0x0e, selector 9
            0x1F4A794: 0xEBFFC961,  # success route to 0x01f3cd20
            0x1F50550: 0xE3A01076,  # script command 0x76 dispatch
            0x1F50558: 0xEBFFF635,  # to 0x01f49de34
            0x1F4DE6C: 0xE1A00005,  # lookup command 0x76, selector 9
            0x1F4DF94: 0xEBFFBB61,  # success route to 0x01f3cd20
            0x1F3CD88: 0xE1D510B4,  # row +4 success subtype
            0x1F3CD90: 0xEBFFFE02,  # invoke carried callback through wrapper
            0x1F0A4BC: 0xE14B10BA,  # callback copies supplied subtype
            0x1F0A4C8: 0xE309323B,  # builds command 0x923b
            0x1F0A4FC: 0xEBC8CCDE,  # submits packet
        },
        "recbf_upstream_1218_callback_source_data_words": {
            0x22DE89C: 9,  # channel-9 descriptor for 0x1218
            0x1F508EC: 0x01F4FC2C,  # command 0x0e handler
            0x1F50A8C: 0x01F50550,  # command 0x76 handler
            0x22DF694: 0x001C000E,  # action row 0x0e: entry subtype 0x1c
            0x22DF698: 0x001C001D,  # success subtype 0x1d at row +4
            0x22E06D4: 0x00EC0076,  # action row 0x76: entry subtype 0xec
            0x22E06D8: 0x00EC00ED,  # success subtype 0xed at row +4
        },
        "recbf_upstream_1218_mode_gate_words": {
            0x1F3A818: 0xE5D039D9,  # root +0x9d9 chooses the 35/36 or 37/38 pair
            0x1F3A81C: 0xE2433004,
            0x1F3A824: 0xE3530001,  # values 4 or 5 take the 37/38 pair
            0x1F3A828: 0x9A000028,
            0x1F3A82C: 0xEBFE7E80,  # state/subtype exception helper
            0x1F3A83C: 0xE5D339DA,  # fallback tests root +0x9da
            0x1F3A84C: 0xE5D335B0,  # root +0x5b0 must not be 44 for mode 35
            0x1F3A850: 0xE353002C,
            0x1F3A854: 0x13A03023,  # mode 35
            0x1F3A8D0: 0xEBFE7E57,  # same helper on 37/38 side
            0x1F3A8E0: 0xE5D339DA,
            0x1F3A8F0: 0xE5D335B0,
            0x1F3A8F4: 0xE353002C,
            0x1F3A8F8: 0x13A03025,  # mode 37
            0x1F3A904: 0xE3A03026,  # mode 38
            0x1F3A910: 0xE3A03024,  # mode 36
        },
        "recbf_upstream_1218_slot_provenance_words": {
            0x1F16A84: 0xEB00457F,  # slot allocator supplies an index
            0x1F16A8C: 0xEB004208,  # 0x01f272b4 maps that index to root pointer
            0x1F24FB4: 0xE1A0000E,  # first caller forwards its root
            0x1F24FB8: 0xEBFFFCC2,
            0x1F25238: 0xE51B0014,  # second caller forwards its root
            0x1F2523C: 0xEBFFFC21,
            0x1F242D4: 0xE1A05000,  # producer keeps that root
            0x1F24420: 0xE1A01005,  # root into 80-byte request object
            0x1F3B3B8: 0xE5801000,  # request object first word = root
            0x1F4AD78: 0xE5868000,  # first wrapper restores parent root
            0x1F4ADA8: 0xEBFFBE92,  # then queues sender
            0x1F4BC8C: 0xE1A00004,  # second wrapper queues request object
            0x1F4BC90: 0xEBFFBAD8,
            0x1F3A810: 0xE50B0064,  # sender places object pointer in payload
            0x1F50B78: 0xE51B4074,  # worker takes queued object pointer
            0x1F50B84: 0xEBFFAAA8,  # copies request fields but not first word
            0x1F3C5A8: 0xE5903008,  # success wrapper loads carried callback
            0x1F3C5B4: 0xE12FFF33,  # and conditionally invokes it
            0x1F0A4B0: 0xE5903000,  # callback loads its root for 0x923b
            0x1F0A4B4: 0xE50B3010,  # copied to packet payload +4
            0x1F28310: 0xE1500003,  # inverse slot mapper compares root 0
            0x1F28324: 0xE3051610,  # then checks stride 0x5610
        },
        "recbf_upstream_1218_mode7_dispatch_words": {
            0x1F05B30: 0xE30131B9,  # upstream sender builds event 0x11b9
            0x1ECDEEC: 0xEB00DEFD,  # sole bounded direct caller of sender
            0x1E9B3EC: 0xEB00CAB6,  # direct caller of that wrapper
            0x1F073F4: 0xE30121B8,  # mode-7 classifier checks 0x11b8
            0x1F07400: 0xE30121B9,  # then 0x11b9
            0x1F07404: 0xE1530002,
            0x1F07408: 0x0A00002A,  # equal branches to row-1 write
            0x1F074C0: 0xE3A02001,  # row 1
            0x1F074C4: 0xE1C320BE,  # stored in mode-7 row halfword
            0x1F074CC: 0xE3A00007,  # dispatch controller mode 7
            0x1F074D0: 0xEB0087F2,
            0x1F294F4: 0xE1032683,  # row*column-count + current column
            0x1F29514: 0xE7DE3083,  # matrix callback index
            0x1F29528: 0xE12FFF33,  # dispatch selected callback
            0x1F09E74: 0xEB006C98,  # callback 4 enters 0x01f250dc
        },
        "recbf_upstream_1218_mode7_dispatch_data_words": {
            0x22D7D68: 0x022D7950,  # mode-7 callback table
            0x22D7D98: 0x022D7918,  # mode-7 transition matrix
            0x22D7960: 0x01F09E68,  # callback index 4
        },
        "recbf_upstream_1218_mode7_dispatch_row": (
            0x22D7918, 4, 1, [[4, 1], [3, 1], [3, 1], [3, 1]],
        ),
        "recbf_upstream_1218_event_11b9_nested_words": {
            0x1F0368C: 0xEB00659D,  # channel-7 receive calls message matcher
            0x1F03694: 0xE3500001,  # nested dispatch requires matcher result 1
            0x1F03698: 0x1A000000,
            0x1F0369C: 0xEB008B11,  # then enters nested controller
            0x1F262F0: 0xE3A00000,  # nested mode 0
            0x1F262F4: 0xEBFF7E43,
            0x1F05D00: 0xE30121B9,  # mode-0 event classifier
            0x1F05D08: 0x0A000094,  # 0x11b9 -> row 15
            0x1F05F68: 0xE3A0200F,
            0x1F05F6C: 0xE1C320B0,
            0x1F05F78: 0xEB008D48,
            0x1F07744: 0xE3A00000,  # callback 13 enters mode 1
            0x1F07748: 0xEBFFFA28,
            0x1F0608C: 0xE30121B9,  # mode-1 event classifier
            0x1F06094: 0x0A00004E,  # 0x11b9 -> row 7
            0x1F061DC: 0xE3A02007,
            0x1F061E0: 0xE1C320B2,
            0x1F061EC: 0xEB008CAB,
            0x1F07A50: 0xE3A00000,  # callback 7 enters mode 7
            0x1F07A54: 0xEBFFFE54,
        },
        "recbf_upstream_1218_event_11b9_nested_data_words": {
            0x22DCF90: 0x000011B9,  # message-table row 22
            0x22DCF94: 0x00000000,
            0x22DCF98: 0xFFFFFFFF,  # no prerequisite bit written by this row
            0x22DCF9C: 0x00000000,
            0x22D7D4C: 0x022D7CEC,  # mode-0 callback table
            0x22D7D50: 0x022D7B78,  # mode-1 callback table
            0x22D7D7C: 0x022D76BC,  # mode-0 action matrix
            0x22D7D80: 0x022D7790,  # mode-1 action matrix
            0x22D7D20: 0x01F07730,  # mode-0 callback 13
            0x22D7B94: 0x01F07A44,  # mode-1 callback 7
        },
        "recbf_upstream_1218_event_11b9_nested_rows": (
            (0x22D76BC, 5, 15, [[3, 1], [13, 1], [3, 1], [3, 1], [3, 1]]),
            (0x22D7790, 5, 7, [[7, 1], [3, 1], [3, 1], [3, 1], [3, 1]]),
        ),
        "recbf_short_crop_completion_stage_words": {
            0x1F47B68: 0xE3A0009E,  # selector-based stage lookup
            0x1F47B6C: 0xEBFFCAF2,
            0x1F47BB8: 0xE1D410B2,  # first stage subtype
            0x1F47BC0: 0xEBFFD276,  # conditional callback wrapper
            0x1F47BE4: 0xE1D410B4,  # second stage subtype
            0x1F47BEC: 0xEBFFD26B,
            0x1F3A770: 0x0350009E,  # lookup matches selector and 0x9e
            0x1F3A7A4: 0xE354009E,  # bounded sentinel
        },
        "recbf_short_crop_request_transport_copy_primary_words": {
            0x113D89C: 0xE2433008,  # queue capacity minus eight-byte header
            0x113D8A0: 0xE5912004,  # requested payload length
            0x113D8A4: 0xE1520003,  # reject over-capacity payload
            0x113D8B8: 0xE5933000,  # pre-copy hook loaded from RAM
            0x113D8C0: 0xE12FFF33,  # hook behavior is unresolved
            0x113D964: 0xE1D530B0,  # copy packet command
            0x113D968: 0xE1C030B0,
            0x113D97C: 0xE5953004,  # copy payload length
            0x113D980: 0xE5803004,
            0x113D9E8: 0xE5951008,  # source payload pointer
            0x113D9EC: 0xE2800008,  # destination after queue header
            0x113D9F0: 0xEB000B84,  # copy payload bytes
        },
        "recbf_short_crop_923b_slot_provenance_words": {
            0x1F150EC: 0xEB004BCB,  # snapshot message state into local record
            0x1F15144: 0xE309223B,  # select 0x923b path
            0x1F15150: 0xE51B0120,  # snapshot +16 = payload +4
            0x1F15154: 0xEB004C69,  # pointer-to-slot mapper
            0x1F15164: 0xE1D330B0,  # subtype from snapshot +22 = payload +10
            0x1F15168: 0xE35300B1,  # 0x1d/0xed avoid subtype 177 special case
            0x1F15170: 0xE35300B7,  # 0x1d/0xed avoid subtype 183 special case
            0x1F15520: 0xE1A00004,  # ordinary path returns mapped slot
            0x1F15B50: 0xEBFFE81C,  # optional command-based remapper
            0x1F0FBD8: 0xE1A00001,  # remapper defaults to original slot
            0x1F0FC18: 0xE3530001,  # 0x923b is outside its special command range
            0x1F0FC1C: 0x812FFF1E,  # return unchanged for 0x923b
            0x1F28064: 0xE3A02F43,  # snapshot copies 268 bytes
            0x1F28310: 0xE1500003,  # root object maps to slot 0
            0x1F28324: 0xE3051610,  # per-object pointer stride 0x5610
            0x1F28338: 0xE3520080,  # bound 128 slots
            0x1F28344: 0xE1A00002,  # return mapped slot index
        },
        "recbf_short_crop_923b_slot_provenance_data_words": {
            0x1F28084: 0x034CAD70,  # message snapshot source = global +0xb8
        },
        "recbf_short_crop_message_receive_route_words": {
            0x1E6AB08: 0xE3A00007,  # dequeue channel 7
            0x1E6AB0C: 0xEBCB4BED,  # receive packet header
            0x1E6AB1C: 0xE8940007,  # copy three packet header words
            0x1E6AB28: 0xEB0262A3,  # invoke packet handler
            0x1F035F0: 0xE1D430B0,  # read incoming command
            0x1F03600: 0xE3530002,  # only 0x122f..0x1231 take special path
            0x1F03604: 0x9A00000C,  # 0x923b goes through generic path
            0x1F03678: 0xEB00974E,  # generic validation helper
            0x1F0368C: 0xEB00659D,  # invoke message-to-bit table handler
            0x1F293BC: 0xE3013239,  # helper singles out 0x1239
            0x1F293C8: 0xE3A00001,  # other commands, including 0x923b, pass
        },
        "recbf_short_crop_channel7_default_send_words": {
            0x1E5D690: 0xE3A00007,  # initialization caller supplies channel 7
            0x1E5D694: 0xEB0297C1,  # call channel initializer
            0x1F035A8: 0xE1A04000,  # preserve channel argument across setup
            0x1F035B0: 0xE1A00004,  # restore channel 7
            0x1F035B4: 0xEB0021CE,  # call state initializer
            0x1F0BD0C: 0xEB006658,  # state initializer calls channel setter
            0x1F2567C: 0xE30C3CB8,  # channel-state byte base low half
            0x1F25680: 0xE3403341,  # channel-state byte base high half
            0x1F25684: 0xE5C30000,  # store caller's channel ID
            0x1F256A4: 0xE5D30000,  # sender getter reads same byte
            0x1F0A4F4: 0xEB006C66,  # first packet constructor reads channel
            0x1F161FC: 0xE309323B,  # second packet constructor: 0x923b
            0x1F16228: 0xEB003D19,  # second packet constructor reads channel
        },
        "recbf_short_crop_channel7_default_send_primary_words": {
            0x113D888: 0xE1A06000,  # send helper retains channel in r0
            0x113D894: 0xE2402001,  # channel-indexed transport table
        },
        "recbf_short_crop_handled_bit_update_words": {
            0x1F1B51C: 0xE3500000,  # diagnostics gate result
            0x1F1B520: 0x1A00000E,  # nonzero enters duplicate/logging path
            0x1F1B524: 0xE354007F,  # both paths reach in-range check
            0x1F1B528: 0x9A00003B,  # in-range slot enters bit update
            0x1F1B584: 0x1AFFFFE6,
            0x1F1B618: 0xEAFFFFC1,  # duplicate/logging path rejoins slot check
            0x1F1B63C: 0xEB00FD01,  # set +0x9e24 bit
            0x1F1B650: 0xEB00FCB2,  # clear +0x9e44 bit
        },
        "recbf_short_crop_prerequisite_fill_primary_words": {
            0x11409E8: 0xE4801004,  # write one 32-bit sentinel
            0x11409EC: 0xE2522001,  # count down sixteen words
            0x11409F0: 0x1AFFFFFC,
        },
        "recbf_short_crop_group_gate_words": {
            0x1F2B4A0: 0xEBFF9261,  # group-13 callback classifies slot
            0x1F2B4A4: 0xE3500000,  # this branch accepts class 0
            0x1F2B4C0: 0xE7D33002,  # per-slot +0xb096 alternate gate
            0x1F2B4C4: 0xE3530001,
            0x1F2B4F0: 0xE5D535E8,  # context +0x5e8 mask gate
            0x1F2B4F4: 0xE31300FD,
            0x1F2B4FC: 0xE5D535B0,  # context state gate
            0x1F2B500: 0xE3530020,
            0x1F2B504: 0x1A0000BB,  # non-32 route tests adjustment
            0x1F2B7FC: 0xEBFEBA8C,  # exceptional state-45 check
            0x1F2B808: 0xE5D539DA,  # zero adjustment route
            0x1F2B80C: 0xE3530000,
            0x1F2B8B8: 0xE3A0100D,  # group-13 bit set on that route
            0x1F2B8C0: 0xEB00BC60,
            0x1F2B6D0: 0xE3A0100D,  # group-13 callback can set bit 13
            0x1F2B6D8: 0xEB00BCDA,
            0x1F2B894: 0xE3A0100F,  # same callback can set bit 15
            0x1F2B89C: 0xEB00BC69,
            0x1F2C380: 0xE5D035B0,  # group-36 callback reads state +0x5b0
            0x1F2C384: 0xE3530020,  # state 32 gate
            0x1F2C388: 0x18BD88F0,  # other states return
            0x1F2C3F8: 0xE3A01024,  # sets candidate group 36
            0x1F2C400: 0xEB00B990,
            0x1F2D1AC: 0xEBFEB420,  # group-34 callback's external gate
            0x1F2D1B0: 0xE3500000,
            0x1F2D1B8: 0xE5D539DA,  # context +0x9da
            0x1F2D1BC: 0xE3530000,
            0x1F2D1FC: 0xE3A01022,  # sets candidate group 34
            0x1F2D204: 0xEB00B60F,
            0x1EDA23C: 0xE5D035B0,  # helper reads state +0x5b0
            0x1EDA240: 0xE353002D,  # only state 45 enters exceptional branch
            0x1EDA244: 0x13A00000,  # every other state returns zero
            0x1EDA258: 0xE5D005BD,  # state-45 branch reads +0x5bd
            0x1EDA25C: 0xE2400007,
            0x1EDA260: 0xE6EF0070,
            0x1EDA264: 0xE3500001,  # values 7 or 8 return one
            0x1F6B328: 0xE1A05001,  # context initializer retains input record
            0x1F6B484: 0xE1D530DF,  # record +15 feeds context +0x9da
            0x1F6B488: 0xE5C439DA,
            0x1F6B33C: 0xE5D035B0,  # initializer reads state +0x5b0
            0x1F6B340: 0xE3530020,  # special state 32
            0x1F6B5DC: 0xE3A03021,  # normalizes 32 to 33 on this route
            0x1F6B5E0: 0xE5C035B0,
            0x1F24444: 0xE24B2044,  # caller passes 30-byte converter output
            0x1F24454: 0xEB0127DA,  # converter call at 0x1f6e3c4
            0x1F24518: 0xE24B1044,  # same output reaches context initializer
            0x1F24520: 0xEB0099D3,
            0x1F4AC84: 0xE1A09001,
            0x1F4AD28: 0xE1A01009,
            0x1F4AD30: 0xEBFFFF93,
            0x1F4ABD4: 0xEB0081CF,
            0x1F6E094: 0xE30039DA,  # builder reads signed working-state +0x9da
            0x1F6E098: 0xE19510D3,
            0x1F6E334: 0xE3A03000,  # zero case writes record +0x269 = 0
            0x1F6E338: 0xE5843269,
            0x1F701D8: 0xE5951269,  # converter reads record +0x269
            0x1F705CC: 0xE3A03000,  # zero case writes output +15 = 0
            0x1F705D0: 0xE5C4300F,
        },
        "recbf_save_to_media_modes": {
            0x3C: [4, 31, 39],
            0x3D: [4, 32, 40],
            0x3E: [41],
        },
        "recbf_crop_compress_mode": 35,
        "recbf_compress_save_mode": 4,
        "recbf_compress_record_words": {
            0x22DFA70: 0x02209734,  # command 0x27 diagnostic: Compress
            0x22DFA7C: 0x004E0027,
        },
        "recbf_compress_strings": {
            0x2209734: b"\x81\xa1Compress\0",
        },
        "recbf_compress_dispatch_targets": {
            0x1F50950: 0x01F4FE3C,  # command 0x27
        },
        "recbf_compress_descriptor_route_words": {
            0x1F4FE3C: 0xE3A02001,  # variant 1
            0x1F4FE40: 0xE3A01000,  # mode 0
            0x1F4FE48: 0xEBFFC319,  # shared compression handler
            0x1F40B64: 0x0A000192,  # variant 1 branches to +0x5ae gate
            0x1F411B8: 0xE5D335AE,  # context +0x5ae
            0x1F411C0: 0x1AFFFE68,  # non-1 rejoins descriptor path
            0x1F40D88: 0xE2813901,  # descriptor source context
            0x1F40D8C: 0xE28120F0,  # context +0xf0
            0x1F40D98: 0xEBFE44DB,  # validate descriptor
            0x1F40DA4: 0x028880F0,  # successful validation selects +0xf0
            0x1F40D18: 0xE1A02008,  # selected descriptor as compression arg 2
            0x1F40D20: 0xEBFE6D78,  # compression setup
            0x1EDC308: 0xE92D4FF0,  # compression setup entry
            0x1EDC31C: 0xE1A06002,  # retain descriptor argument
            0x1EDC3E0: 0x1596A010,  # descriptor width +0x10 (non-format-1)
            0x1EDC3E8: 0x15963014,  # descriptor height +0x14
            0x1EDC4EC: 0xE5961004,  # descriptor base pointer
        },
        "recbf_compress_result_slot_words": {
            0x1F40AC8: 0xE1A04002,  # retain command variant in r4
            0x1F40CFC: 0xE5950000,  # context pointer from command wrapper
            0x1F40D00: 0xE0804284,  # context + variant * 32
            0x1F40D04: 0xE2844B12,  # plus 0x4800
            0x1F40D08: 0xE28440F4,  # plus 0xf4
            0x1F40D0C: 0xE58D4004,  # sixth callee argument: result slot
            0x1EDC324: 0xE59B9008,  # callee retains sixth argument in r9
            0x1EDC6A4: 0xE5892000,  # result word +0
            0x1EDC6AC: 0xE5893004,  # result word +4
            0x1EDC81C: 0xE5892010,  # format-1 result word +0x10
            0x1EDC824: 0xE5893014,  # format-1 result word +0x14
            0x1EDC6D0: 0xE5892018,  # other-format result word +0x18
            0x1EDC6D8: 0xE589301C,  # other-format result word +0x1c
            0x1ED66DC: 0xE2845B12,  # initializer starts at context +0x4800
            0x1ED66E0: 0xE28550F4,  # plus 0xf4
            0x1ED66E4: 0xE2846C49,  # end starts at context +0x4900
            0x1ED66E8: 0xE28660B4,  # plus 0xb4 = 0x49b4
            0x1ED6704: 0xE2855020,  # clear loop strides 32 bytes
        },
        "recbf_save_to_media_record_words": {
            0x22DFDB8: 0x0220983C,
            0x22DFDC4: 0x0078003C,
            0x22DFDE0: 0x0220983C,
            0x22DFDEC: 0x007A003D,
            0x22DFE08: 0x0220983C,
            0x22DFE14: 0x007C003E,
        },
        "recbf_save_to_media_strings": {
            0x220983C: b"\x81\xa1recbfSaveToMedia\0",
        },
        "recbf_save_to_media_dispatch_targets": {
            0x1F509A4: 0x1F4FFAC,  # command 0x3c
            0x1F509A8: 0x1F4FFC0,  # command 0x3d
            0x1F509AC: 0x1F50078,  # command 0x3e
        },
        "recbf_save_to_media_route_words": {
            0x1F4FFAC: 0xE3A01001,  # save command 0x3c selects variant 1
            0x1F4FFB4: 0xEBFFC4E4,  # common save handler
            0x1F4FFC0: 0xE3A01000,  # command 0x3d selects variant 0
            0x1F4FFC8: 0xEBFFC4DF,
            0x1F50078: 0xE3A01004,  # command 0x3e selects variant 4
            0x1F50080: 0xEBFFC4B1,
            0x1F41378: 0xE3510001,  # handler maps variant 1 to record 60
            0x1F4137C: 0x03A0003C,
            0x1F41380: 0x13A0003D,  # otherwise record 61
            0x1F41558: 0xEBFE5F0A,  # guarded save worker call
            0x1ED91C8: 0xE5D33E51,  # worker dispatches on context save state
            0x1ED922C: 0xE3530004,  # save variant selector bound
            0x1ED942C: 0xEBC98AEE,  # downstream cross-partition submit
        },
        "recbf_save_jpeg_buffer_request_words": {
            0x1ED9668: 0xE3A03E17,  # per-row stride 368
            0x1ED9670: 0xE0030293,  # row * stride
            0x1ED9678: 0xE2833DFB,  # pathname offset +0x3ec0
            0x1ED967C: 0xE2833030,  # pathname offset +0x3ef0
            0x1ED9B1C: 0xE3033E6C,  # buffer length field
            0x1ED9B20: 0xE7962003,  # r2 = buffer length
            0x1ED9B48: 0xE7961008,  # r1 = buffer pointer
            0x1ED9B4C: 0xE51B00C0,  # r0 = selected pathname
            0x1ED9B50: 0xEBC987F0,  # submit pathname/pointer/length
            0x1ED9F48: 0xE3530010,  # 16-entry buffer array bound
            0x1ED9F58: 0xE0836182,  # row offset + entry*8
            0x1ED9F5C: 0xE0846006,  # add context base
            0x1ED9F60: 0xE3038E68,  # pointer field +0x3e68
            0x1ED9F64: 0xE7963008,  # test candidate pointer
            0x1F273F8: 0xE3A02E17,  # independent consumer uses same row stride
            0x1F27400: 0xE3033E6C,  # read buffer length
            0x1F2740C: 0xE3031E68,  # read buffer pointer
            0x1F27424: 0xE30F2FD9,  # JPEG EOI marker FF D9
            0x1F27428: 0xE1530002,  # compare final two bytes
            0x1F27450: 0xE3A03E17,  # second EOI test: same row stride
            0x1F27458: 0xE3032E68,  # read buffer pointer
            0x1F27460: 0xE3032E6C,  # read buffer length
            0x1F2747C: 0xE30F1FD9,  # second FF D9 comparison
        },
        "recbf_exif_tag_buffer_handoff_record_words": {
            0x22DFCA0: 0x022097E8,  # command 0x35: recbfCreateExifTag
            0x22DFCAC: 0x006A0035,
            0x22DFCC8: 0x022097E8,  # command 0x36: same diagnostic
            0x22DFCD4: 0x006C0036,
            0x22DFCF0: 0x022097E8,  # command 0x37: same diagnostic
            0x22DFCFC: 0x006E0037,
            0x1F50988: 0x01F4FF70,  # command 0x35 dispatch wrapper
            0x1F5098C: 0x01F4FF84,  # command 0x36 dispatch wrapper
            0x1F50990: 0x01F50064,  # command 0x37 dispatch wrapper
        },
        "recbf_exif_tag_strings": {
            0x22097E8: b"\x81\xa1recbfCreateExifTag\0",
        },
        "recbf_exif_tag_buffer_handoff_words": {
            0x1F4FF70: 0xE3A01001,  # command 0x35 variant 1
            0x1F4FF78: 0xEBFFC496,  # shared EXIF-tag handler
            0x1F4FF84: 0xE3A01000,  # command 0x36 variant 0
            0x1F4FF8C: 0xEBFFC491,
            0x1F412B8: 0xE54B5023,  # selected variant in control byte +1
            0x1F412BC: 0xE3A03000,  # zero control +4
            0x1F412C0: 0xE50B3020,
            0x1F412D8: 0xEBFE8E13,  # EXIF tag -> 0x01ee4b2c
            0x1EE4B4C: 0xE5956004,  # optional source pointer from control +4
            0x1EE4B50: 0xE3013778,  # global fallback 0x02ed1778
            0x1EE4B54: 0xE34032ED,
            0x1EE4B5C: 0x01A06003,  # zero source selects global fallback
            0x1EE4B60: 0xE5D53001,  # variant byte selects row path
            0x1EE4B98: 0xE3A05000,  # variant 0/default selects row 0
            0x1EE4B9C: 0xE3A00E17,  # 368-byte row stride
            0x1EE4BA0: 0xE0204590,  # row offset + context
            0x1EE4BA8: 0xE2800DF9,  # +0x3e40
            0x1EE4BAC: 0xE2800020,  # helper destination +0x3e60
            0x1EE4BB0: 0xEB7B1E70,  # raw-overlay helper 0x03dac578
            0x1EE4C10: 0xE3A05001,  # variant 1 selects row 1
            0x1EE4E50: 0xE2880DF9,  # start pair table at row +0x3e68
            0x1EE4E54: 0xE2800028,
            0x1EE4E70: 0xE59E1004,  # read pair length
            0x1EE4E78: 0xE3C2203F,  # round up to multiple of 64
            0x1EE4EA0: 0xE58E2004,  # store padded length
            0x1EDC698: 0xE3013778,  # compression result copied from same global
            0x1EDC69C: 0xE34032ED,
            0x1EDC6A4: 0xE5892000,  # result slot word +0
            0x1EDC6AC: 0xE5893004,  # result slot word +4
        },
        "recbf_save_primary_indirect_submit_words": {
            0x113A0A0: 0xE5D03001,  # selector reads pathname byte 1
            0x113A0A4: 0xE353003A,  # requires ':' after drive letter
            0x113A0AC: 0xE5D00000,  # reads drive letter
            0x113A0C8: 0xE2403041,  # maps uppercase letter from 'A'
            0x1140174: 0xE52DB004,  # bounded NUL-terminated string-copy helper
            0x1140184: 0xE5D1C000,  # read source byte
            0x1140188: 0xE35C0000,  # stop on NUL
            0x1140194: 0xE4C3C001,  # copy byte
            0x113D87C: 0xE92D4870,  # generic service submit entry
            0x113D8D8: 0xEBBC46D8,  # lower-level service call outside decoded partitions
            0x113BB8C: 0xE593A0F8,  # pathname request A via interface +0xf8
            0x113BBA0: 0xE12FFF3A,  # indirect call
            0x113BC7C: 0xE59380FC,  # pathname request B via interface +0xfc
            0x113BC90: 0xE12FFF38,  # indirect call
            0x113A604: 0xE30039B0,  # interface array at 0x018509b0
            0x113A608: 0xE3403185,
            0x113A60C: 0xE3002400,  # default pointer 0x00d20400
            0x113A610: 0xE34020D2,
            0x113A614: 0xE5832000,  # assign default interface index 0
            0x113A630: 0xE3013BB4,  # selector index table at 0x01851bb4
            0x113A63C: 0xE5832000,  # selector 65 maps to index 0
            0x113BFEC: 0xE92D49F0,  # cross-partition submit entry
            0x113C020: 0xE2402041,  # selector relative to 65
            0x113C024: 0xE7935102,  # map through runtime index table
            0x113C050: 0xE7933105,  # runtime interface pointer
            0x113C06C: 0xE5935120,  # method at interface +0x120
            0x113C080: 0xE12FFF35,  # indirect dispatch; default selector 65 resolves to volume method
        },
        "recbf_mode4_message_route_secondary_words": {
            0x1F2A1B4: 0xE3500001,  # callback 5 gate
            0x1F2A1B8: 0x0A000001,
            0x1F2A1EC: 0xEBFFAB47,  # callback 5 calls mode-4 wrapper
            0x1F14F78: 0xEB009834,  # wrapper calls mode-4 sender
            0x1F3B064: 0xE3A03004,  # sender writes script mode 4
            0x1F3B068: 0xE54B3058,
            0x1F3B070: 0xE3A03005,  # request state 5
            0x1F3B074: 0xE54B3050,
            0x1F3B0AC: 0xE3013252,  # message ID 0x1252
            0x1F3B0D8: 0xEBC809E7,  # queue transfer
        },
        "recbf_mode4_action_data_words": {
            0x22D8C6C: 0x01F2A1A4,  # controller-1 callback index 5
            0x22D8C9C: 0x01F2A5C0,  # callback index 17 on col-4→col-6 candidate
        },
        "recbf_mode4_action_rows": [
            (0x22D8974, 10, 2, [[3, 1], [3, 1], [3, 1], [3, 1], [3, 1], [3, 1], [5, 1], [3, 1], [3, 1], [3, 1]]),
            (0x22D8974, 10, 24, [[3, 1], [4, 1], [4, 1], [4, 1], [4, 1], [4, 1], [5, 1], [3, 1], [3, 1], [3, 1]]),
            (0x22D8974, 10, 11, [[3, 1], [17, 1], [3, 1], [3, 1], [17, 250], [3, 1], [3, 1], [3, 1], [3, 1], [3, 1]]),
        ],
        "recbf_copy_crop_raw_record_words": {
            0x22DF7A0: 0x22095A0,  # prefixed diagnostic name pointer
            0x22DF7AC: 0x002A0015,  # command 0x15 and associated event field
            0x22DF7BC: 0x00000009,  # record type used by lookup
        },
        "recbf_copy_crop_raw_strings": {
            0x22095A0: b"\x81\xa1recbfCopyCropRaw\0",
            0x22095B4: b"COPYCP_S\0",
            0x22095C0: b"COPYCP_E\0",
        },
        "recbf_dispatch_words": {
            0x1F4F994: 0xE30F3148,  # script-table low half
            0x1F4F998: 0xE340322D,  # script-table high half
            0x1F508A4: 0xE7D63004,  # read command byte from script
            0x1F508AC: 0x979FF103,  # indexed dispatch
            0x1F4FC84: 0xE3A01001,  # command 0x15 selects branch argument 1
            0x1F4FC8C: 0xEBFFBC60,  # command 0x15 calls branch routine
            0x1F4FC98: 0xE3A01000,  # command 0x16 selects branch argument 0
            0x1F4FCA0: 0xEBFFBC5B,  # command 0x16 calls same routine
            0x1F3EE28: 0xE3510001,  # branch on argument 1
            0x1F3EE34: 0xE3A00016,  # other route uses record 22
            0x1F3F110: 0xE3A00015,  # branch 1 uses record 21
        },
        "recbf_dispatch_targets": {
            0x1F50908: 0x1F4FC84,  # byte 0x15
            0x1F5090C: 0x1F4FC98,  # byte 0x16
        },
        "recbf_script_mode_selector_words": {
            0x1F50B78: 0xE51B4074,  # worker takes dequeued request object
            0x1F50B7C: 0xE24B1070,  # message descriptor on worker stack
            0x1F50B80: 0xE1A00004,
            0x1F50B84: 0xEBFFAAA8,  # copy descriptor into request
            0x1F3B63C: 0xE5D12000,  # descriptor byte 0
            0x1F3B640: 0xE5C02004,  # request script-mode byte +4
            0x1F50B94: 0xE5D4300C,  # request state byte +0xc
            0x1F50B98: 0xE3530005,  # state 5 dispatches script
            0x1F50B9C: 0x0AFFFFEA,
            0x1F50B4C: 0xE1A00004,  # passes request to script dispatcher
            0x1F50B50: 0xEBFFFB88,
            0x1F4F9A8: 0xE5D50004,  # script-mode byte is request +4
            0x1F4F9C4: 0xE7D12183,  # 8-byte table entry mode
            0x1F4F9D0: 0xE1520000,  # compare with request mode
            0x1F4F9E4: 0xE5936004,  # selected script pointer
        },
        "recbf_mode3_message_route_secondary_words": {
            0x1F2A234: 0xEBFF8B9F,  # callback wrapper enters mode-3 caller
            0x1F0D0E4: 0xEBFFFBCE,  # obtain this context's queue descriptor
            0x1F0D0EC: 0xE1D433B8,  # conditional pre-send state
            0x1F0D0F0: 0xE3530001,
            0x1F0D108: 0xEB00B790,  # sole direct call to mode-3 sender
            0x1F28414: 0xE350007F,  # bounded context index
            0x1F28434: 0xE5903604,  # descriptor index from context
            0x1F28438: 0xE3730001,  # -1 has no descriptor
            0x1F28440: 0xE3082838,  # 12-byte queue descriptor table
            0x1F28444: 0xE340222D,
            0x1F28448: 0xE3A0100C,
            0x1F2844C: 0xE0232391,  # selected descriptor by index
            0x1F28450: 0xE8930007,  # load 12-byte descriptor
            0x1F28454: 0xE88C0007,  # copy to caller buffer
            0x1F27E4C: 0xE3084838,  # worker initializer uses same table
            0x1F27E50: 0xE340422D,
            0x1F27E54: 0xE28450C0,  # 16 descriptors, 12 bytes each
            0x1F27E60: 0xE5D40000,  # queue ID from descriptor byte 0
            0x1F27E64: 0xEB004D21,  # create worker with descriptor
            0x1F27E70: 0xE284400C,  # next descriptor
            0x1F3B2FC: 0xE1A04000,  # worker builder retains queue ID
            0x1F3B344: 0xE3003B30,  # worker entry 0x01f50b30
            0x1F3B348: 0xE34031F5,
            0x1F3B350: 0xE50B4024,  # queue ID as worker argument
            0x1F3AF60: 0xE50B005C,  # message payload: request pointer
            0x1F3AF64: 0xE3A03003,  # script mode 3
            0x1F3AF68: 0xE54B3058,  # payload byte +4
            0x1F3AF70: 0xE3A03005,  # request state 5
            0x1F3AF74: 0xE54B3050,  # payload byte +0xc
            0x1F3AFA4: 0xE3013251,  # event ID 0x1251
            0x1F3AFA8: 0xE14B31B8,
            0x1F3AFBC: 0xE3A03044,  # 68-byte payload
            0x1F3AFC4: 0xE24B305C,  # payload source
            0x1F3AFCC: 0xE24B1018,  # message header
            0x1F3AFD0: 0xEBC80A29,  # queue send wrapper
            0x1F4BAEC: 0xE1D030B0,  # special handler reads event ID
            0x1F4BAF0: 0xE2433C12,  # subtract 0x1200
            0x1F4BAF4: 0xE243303D,  # special range starts at 0x123d
            0x1F4BAF8: 0xE3530003,  # only 0x123d..0x1240
            0x1F4BB54: 0xE3A00000,  # 0x1251 returns unhandled
            0x1F50B40: 0xE24B6074,  # payload receive buffer
            0x1F50B54: 0xE50B6078,  # queue receiver's output pointer
            0x1F50B64: 0xEBC7B3D7,  # receive message and payload
            0x1F50B68: 0xE24B0080,  # message header
            0x1F50B6C: 0xEBFFEBDC,  # special-event classifier
            0x1F50B70: 0xE3500000,  # 0x1251 is not specially handled
            0x1F50B74: 0x1AFFFFF6,  # handled events loop without script
        },
        "recbf_mode3_message_route_primary_words": {
            0x113D9E8: 0xE5951008,  # sender reads payload pointer
            0x113D9EC: 0xE2800008,  # destination after header
            0x113D9F0: 0xEB000B84,  # sender copies payload
            0x113DB14: 0xE5913004,  # receiver reads payload length
            0x113DB6C: 0xE2811008,  # receiver source after header
            0x113DB70: 0xE5950008,  # receiver output pointer
            0x113DB74: 0xEB000B23,  # receiver copies payload
        },
        "recbf_mode3_message_route_data_words": {
            0x22D8838: 9,           # first queue descriptor ID
            0x22D8840: 6,           # first descriptor capacity field
            0x22D88EC: 24,         # last of 16 queue descriptor IDs
            0x22D88F4: 6,
            0x22D8C78: 0x01F2A22C, # mode-3 caller wrapper in action table
        },
        "recbf_mode3_action_gate_words": {
            0x1F0FE6C: 0xE3012232,  # message ID 0x1232 is classified as 6
            0x1F0FE70: 0xE1530002,
            0x1F0FE74: 0x0A00000F,
            0x1F0FEB8: 0xE3A00006,
            0x1F29610: 0xE3500006,  # classifier 6 is stored as row 5
            0x1F2961C: 0x03A02005,
            0x1F29624: 0xE1C320B0,
            0x1F2AD1C: 0xE3083D20,  # mode-1 action-pointer table
            0x1F2AD24: 0xE7939100,
            0x1F2AD3C: 0xE1A04080,  # select mode-1 event-row halfword
            0x1F2AD48: 0xE19330B4,  # classified event row
            0x1F2AD4C: 0xE19C60B4,  # ten state columns per row
            0x1F2AD68: 0xE02C0C97,
            0x1F2AD70: 0xE194C0BC,
            0x1F2AD74: 0xE103C683,  # row * 10 + state-column offset
            0x1F2AD98: 0xE7DE3083,  # two-byte matrix action index
            0x1F2AD9C: 0xE7993103,  # selected action callback
            0x1F2ADB0: 0xE12FFF33,
            0x1F057F0: 0xE3013232,  # concrete sender of message 0x1232
            0x1F057F4: 0xE14B32B0,
            0x1F0581C: 0xEB005D39,
            0x1ECDB34: 0xEB00DF0C,  # direct caller of sender
            0x1E9A5BC: 0xEB00CD50,  # one further direct caller
        },
        "recbf_mode3_action_gate_data_words": {
            0x22D8D24: 0x022D8C58,  # mode-1 callback table base
            0x22D8D2C: 0x000A0001,  # mode-1 matrix stride 10
            0x22D8D38: 0x022D8974,  # mode-1 transition matrix base
            0x22D8C78: 0x01F2A22C,  # callback index 8
        },
        "recbf_mode3_action_matrix": 0x22D8974,
        "recbf_mode3_action_matrix_rows": 37,
        "recbf_mode3_action_matrix_columns": 10,
        "recbf_event_1232_final_route_words": {
            0x1F29610: 0xE3500006,  # classifier 6 selects controller-0 row 5
            0x1F2961C: 0x03A02005,
            0x1F29624: 0xE1C320B0,
            0x1F29630: 0xE3A00000,  # controller index 0, not index 1
            0x1F29634: 0xEB0005B3,
            0x1F2AD18: 0xE793E100,  # callback table indexed by controller
            0x1F2AD24: 0xE7939100,  # action-pointer table, same controller
            0x1F2AD30: 0xE7935100,  # follow-up table, same controller
            0x1F2AD48: 0xE19330B4,  # controller's stored row
            0x1F2AD4C: 0xE19C60B4,  # controller's matrix width
            0x1F2AD70: 0xE194C0BC,  # per-slot controller column
            0x1F2AD74: 0xE103C683,  # row * width + column
            0x1F2A120: 0xEBFFFF52,  # controller-0 callback 2 -> 0x01f29e70
            0x1F2A13C: 0xEBFFFD7C,  # distinct callback 3 -> controller-1 helper
            0x1F298F4: 0xE3A00001,  # helper action-2 branch selects controller 1
            0x1F298F8: 0xEB000502,
            0x1F29EA8: 0xE3540002,  # action 2 selects controller-2 branch
            0x1F29EAC: 0x0A00001D,
            0x1F29F34: 0xE1C320B4,  # set controller-2 row 0
            0x1F29F40: 0xE1A00002,  # dispatch controller index 2
            0x1F29F44: 0xEB00036F,
            0x1F2ABB4: 0xE3A00000,  # controller-2 row-0 column-0 callback returns 0
            0x1F2ABC0: 0xE12FFF1E,
        },
        "recbf_event_1232_final_route_data_words": {
            0x22D8D20: 0x022D8D04,  # controller-0 callback table
            0x22D8D28: 0x022D8938,  # controller-2 callback table
            0x22D8D2C: 0x000A0001,  # widths: controller 0 = 1, controller 1 = 10
            0x22D8D30: 0x00000002,  # controller 2 = 2
            0x22D8D34: 0x022D88F8,  # controller-0 transition matrix
            0x22D8D3C: 0x022D8908,  # controller-2 transition matrix
            0x22D8D0C: 0x01F2A118,  # controller-0 callback index 2
            0x22D8D10: 0x01F2A134,  # controller-0 callback index 3
            0x22D8940: 0x01F2ABAC,  # controller-2 callback index 2
            0x22D8944: 0x01F2ABC4,  # controller-2 callback index 3
        },
        "recbf_event_1232_final_route_rows": [
            (0x22D88F8, 1, 5, [[2, 1]]),
            (0x22D8908, 2, 0, [[2, 255], [3, 1]]),
        ],
        "recbf_controller1_row5_producer_words": {
            0x1F0FE78: 0xE5D035B0,  # non-special message falls back to context +0x5b0
            0x1F0FE7C: 0xE353001D,  # working state 29 -> classifier 3
            0x1F0FE80: 0x0A00000E,
            0x1F0FEC0: 0xE3A00003,
            0x1F295F0: 0xE3500003,  # classifier 3 -> controller-0 row 3
            0x1F295F4: 0x0A000033,
            0x1F296D0: 0xE3A02003,
            0x1F296D4: 0xE1C320B0,
            0x1F296E4: 0xEB000587,  # dispatch controller 0
            0x1F2A13C: 0xEBFFFD7C,  # controller-0 callback 3 enters helper
            0x1F29790: 0xE3540000,  # action 0 selects message-ID map
            0x1F29798: 0xE59F36C8,  # global event record pointer
            0x1F2979C: 0xE1D33BB8,  # global +0xb8 event ID
            0x1F297A0: 0xE30121A2,  # ID 0x11a2
            0x1F297A8: 0x0A000082,  # branch to row 5
            0x1F299C0: 0xE3A02005,
            0x1F299C4: 0xE1C320B2,  # controller-1 row 5
            0x1F299C8: 0xE3A02000,  # forwarded action remains 0
            0x1F299D0: 0xE3A00001,  # controller index 1
            0x1F299D4: 0xEB0004CB,
            0x1F298E8: 0xE1C320B2,  # distinct action-2 entry stores row 0
            0x1F0818C: 0xE3A01000,  # one direct action-0 caller
            0x1F08194: 0xEB00855F,
            0x1F1E438: 0xE30131A2,  # separate producer of ID 0x11a2
            0x1F1E48C: 0xE30131A2,
        },
        "recbf_controller1_row5_producer_data_words": {
            0x1F29E68: 0x034CACB8,  # global record; +0xb8 = 0x034cad70
        },
        "recbf_controller1_row5_producer_rows": [
            (0x22D88F8, 1, 3, [[3, 1]]),
        ],
        "recbf_controller1_crop_column_predecessor_words": {
            0x1F29768: 0xE3540002,  # helper action 2 selects controller-1 row 0
            0x1F2976C: 0x0A00005A,
            0x1F298E8: 0xE1C320B2,
            0x1F298F4: 0xE3A00001,
            0x1F298F8: 0xEB000502,
            0x1F2983C: 0xE3092251,  # ID 0x9251 selects row 18 on action 0
            0x1F29844: 0x0A0000DD,
            0x1F29BC8: 0xE3A02012,
            0x1F29BCC: 0xE1C320B2,
            0x1F2ADB8: 0xE1D830D1,  # signed matrix byte
            0x1F2ADBC: 0xE3530000,
            0x1F2ADC0: 0xDA000009,  # <= 0 writes negated byte to column state
            0x1F2ADC4: 0xE7953103,  # > 0 selects follow-up callback index
            0x1F2AE0C: 0xE2633000,
            0x1F2AE10: 0xE18230B0,
        },
        "recbf_controller1_crop_column_predecessor_rows": [
            (0x22D8974, 10, 0, [[2, 255], [3, 1], [3, 1], [3, 1], [3, 1],
                                  [3, 1], [3, 1], [3, 1], [3, 1], [3, 1]]),
            (0x22D8974, 10, 18, [[3, 1], [23, 252], [24, 1], [23, 250], [3, 1],
                                   [3, 1], [3, 1], [3, 1], [3, 1], [25, 1]]),
        ],
        "recbf_event_1232_nested_route_words": {
            0x1F0581C: 0xEB005D39,  # sender copies event into controller-wide record
            0x1F05820: 0xEB0082B0,  # then enters first controller layer
            0x1F27F78: 0xE1D020B0,  # event halfword from sender payload
            0x1F27F80: 0xE1C32BB8,  # global +0xb8 = 0x034cad70
            0x1F262F4: 0xEBFF7E43,  # mode-0 event classifier
            0x1F05CE8: 0xE3012232,
            0x1F05CF0: 0x0A000088,  # ID 0x1232 selects row 13
            0x1F05F20: 0xE3A0200D,
            0x1F05F24: 0xE1C320B0,
            0x1F05F30: 0xEB008D5A,  # dispatch controller mode 0
            0x1F07618: 0xEBFFFA74,  # mode-0 state 3 -> mode 1
            0x1F07658: 0xEBFFFA64,  # mode-0 state 1 -> mode 1
            0x1F06074: 0xE3012232,
            0x1F0607C: 0x0A000042,  # ID 0x1232 selects row 5
            0x1F06194: 0xE3A02005,
            0x1F06198: 0xE1C320B2,
            0x1F061A4: 0xEB008CBD,  # dispatch controller mode 1
            0x1F07A04: 0xEBFFFCF3,  # mode-1 state 0 -> mode 5
            0x1F07A20: 0xEBFFFCEC,  # mode-1 state 1 -> mode 5
            0x1F06E50: 0xE3012232,
            0x1F06E58: 0x0A000042,  # ID 0x1232 selects row 5
            0x1F06F70: 0xE3A00005,
            0x1F06F74: 0xE1C300BA,
            0x1F06F7C: 0xEB008947,  # dispatch controller mode 5
            0x1F096A8: 0xE3A00006,
            0x1F096B4: 0xEB005775,  # mode-5 state 0 initializes context from event
            0x1F096C0: 0xEB004CD3,
            0x1F096D0: 0xEB008010,  # then dispatch final controller
            0x1F096E4: 0xE3A00006,
            0x1F096F0: 0xEB005766,  # mode-5 state 1 also initializes context
            0x1F096FC: 0xEB004CC4,
            0x1F0970C: 0xEB008001,
            0x1F1F4E0: 0xE2453001,  # init type 6 selects source zero
            0x1F1F4E4: 0xE3530002,
            0x1F1F4F0: 0xE3091CEC,  # destination per-context +0x9cec
            0x1F1F500: 0xE0811003,
            0x1F1F504: 0x83A00000,
            0x1F1F508: 0x93A00001,
            0x1F1F50C: 0xEB0022C3,  # global-record copy helper
            0x1F2804C: 0xE59F1030,  # source for selector zero
            0x1F28064: 0xE3A02F43,  # 268-byte record
            0x1F2806C: 0xEBC861E5,  # copy to per-context destination
            0x1F0FE4C: 0xE3093CEC,  # final classifier reads same offset
            0x1F0FE50: 0xE19430B3,
        },
        "recbf_event_1232_nested_route_data_words": {
            0x1F27FD0: 0x034CACB8,  # +0xb8 is global event record
            0x1F28084: 0x034CAD70,  # global event record source
            0x22D7D4C: 0x022D7CEC,  # mode-0 callback base
            0x22D7D50: 0x022D7B78,  # mode-1 callback base
            0x22D7D60: 0x022D79C0,  # mode-5 callback base
            0x22D7D6C: 0x00050005,  # modes 0 and 1 have 5 columns
            0x22D7D74: 0x00020004,  # mode 5 has 2 columns
            0x22D7D7C: 0x022D76BC,  # mode-0 matrix
            0x22D7D80: 0x022D7790,  # mode-1 matrix
            0x22D7D90: 0x022D7984,  # mode-5 matrix
            0x22D7CF8: 0x01F075D8,  # mode-0 default callback 3
            0x22D7D00: 0x01F0760C,  # mode-0 callback 5
            0x22D7D08: 0x01F07640,  # mode-0 callback 7
            0x22D7B88: 0x01F079F4,  # mode-1 callback 4
            0x22D7B8C: 0x01F07A14,  # mode-1 callback 5
            0x22D79E8: 0x01F0969C,  # mode-5 callback 10
            0x22D79EC: 0x01F096DC,  # mode-5 callback 11
        },
        "recbf_event_1232_nested_rows": [
            (0x22D76BC, 5, 13, [[3, 1], [7, 253], [3, 1], [5, 1], [3, 1]]),
            (0x22D7790, 5, 5, [[4, 255], [5, 1], [3, 1], [3, 1], [3, 1]]),
            (0x22D7984, 2, 5, [[10, 255], [11, 1]]),
        ],
        "recbf_event_1232_tagged_context_words": {
            0x1F09E74: 0xEB006C98,  # mode-7 callback 4 calls one tag-1 writer path
            0x1F16A84: 0xEB00457F,  # allocator selects a new slot
            0x1F16A88: 0xE5840000,  # initializer receives that slot through its stack
            0x1F1F49C: 0xE1A05000,  # initializer retains argument 6 in r5
            0x1F1F4B4: 0xEBFFDD69,  # context initializer invokes allocator
            0x1F1F4E8: 0xE51B3018,  # copy destination uses the allocated slot
            0x1F1F6BC: 0x979FF103,  # mode-specific jump table selects mode-6 body
            0x1F1FEAC: 0xE51B1018,  # mode-6 body starts with the same slot
            0x1F1FF2C: 0xEAFFFE73,  # returns to common initializer tail
            0x1F096B8: 0xE3A00001,  # mode-5 callback requests tag 1, not the copied slot
            0x1F096BC: 0xEB00716C,
            0x1F096C0: 0xEB004CD3,  # first lookup feeds intervening 0x01f1ca14
            0x1F096C4: 0xE3A00001,
            0x1F096C8: 0xEB007169,
            0x1F096D0: 0xEB008010,  # final dispatch receives tag-1 lookup result
            0x1F096F4: 0xE3A00001,
            0x1F096F8: 0xEB00715D,
            0x1F096FC: 0xEB004CC4,  # same intervening dispatcher in callback 11
            0x1F09700: 0xE3A00001,
            0x1F09704: 0xEB00715A,
            0x1F0970C: 0xEB008001,
            0x1F25C8C: 0xE59300B4,  # tag lookup reads first registry index
            0x1F25CA0: 0xE5D330B8,  # and compares its tag byte
            0x1F25CA4: 0xE1530001,
            0x1F25CB4: 0x0A00000D,  # matching first tag returns first index
            0x1F25CB8: 0xE59300BC,  # later registry entries, stride 8
            0x1F25CC4: 0xE5D320C0,
            0x1F284B8: 0xE350007F,  # writer requires an in-range slot
            0x1F284C8: 0xE59334AC,  # last of 128 registry slots
            0x1F284D0: 0x1A000027,  # full registry rejects insertion
            0x1F284E4: 0x0A000028,  # already-present first slot rejects insertion
            0x1F28514: 0xE59324A4,  # shift older entries down before prepend
            0x1F28518: 0xE58324AC,
            0x1F28538: 0xE58300B4,  # registry writer stores slot index
            0x1F2853C: 0xE5C310B8,  # and tag byte
            0x1F2856C: 0xE3A00000,  # zero return on successful insertion
            0x1F1DFA8: 0xE3A01002,  # direct writer call: tag 2
            0x1F1DFB0: 0xEB00293E,
            0x1F21044: 0xE3550003,  # same initializer tail: mode 6 selects tag 1
            0x1F21048: 0x03A06003,
            0x1F2104C: 0x13A06001,
            0x1F21050: 0xE51B4018,  # reload exactly the event-copy slot
            0x1F21058: 0xEBFFBB64,  # unrelated per-context status read
            0x1F2105C: 0xE1A05000,  # save that status, before writer call
            0x1F21060: 0xE1A01006,  # tag from r6
            0x1F21064: 0xE1A00004,  # slot from r4
            0x1F21068: 0xEB001D10,
            0x1F2106C: 0xE51B301C,  # overwrites r3; writer's r0 not tested
            0x1F2107C: 0xE3550000,  # branches on pre-writer status in r5
            0x1F0FE0C: 0xE7D00003,  # that status reads per-context +0xb138
            0x1F0FE14: 0xE3500001,  # range check only; no registry write
            0x1F284E4: 0x0A000028,  # duplicate head slot rejects insertion
            0x1F28500: 0x0A000021,  # duplicate later slot also rejects insertion
            0x1F210B4: 0xE8BD88F0,  # initializer epilogue after writer
            0x1F210D8: 0xE92D4FF0,  # following function's prologue
            0x1F24EF4: 0xE3A05001,  # direct writer call: tag 1
            0x1F24F24: 0xEB000D61,
            0x1F251FC: 0xE3A04001,  # direct writer call: tag 1
            0x1F2522C: 0xEB000C9F,
            0x1F25264: 0xEBFFFECD,  # same mode-7 path can call second tag-1 initializer
            0x1F29728: 0xE1C300B0,  # final helper stores lookup result as halfword
            0x1F2972C: 0xEBFFFF91,  # and passes the same r0 to 0x01f29578
            0x1F29588: 0xE1A05001,  # latter retains action 2 in r5
            0x1F2962C: 0xE1A01004,  # forward lookup slot as dispatcher r1
            0x1F29634: 0xEB0005B3,  # state-dependent branch calls 0x01f2ad08
        },
        "recbf_event_1232_tagged_context_data_words": {
            0x1F1F6D8: 0x01F1FEAC,  # initializer argument 6 jump-table target
            0x22D7D68: 0x022D7950,  # nested-controller mode-7 callback table
            0x22D7960: 0x01F09E68,  # callback index 4 enters 0x01f250dc
        },
        "recbf_tagged_context_writer": 0x1F284B0,
        "recbf_tagged_context_direct_calls_secondary": [
            0x1F1DFB0, 0x1F21068, 0x1F24F24, 0x1F2522C,
        ],
        "recbf_tagged_context_remover": 0x1F28598,
        "recbf_tagged_context_direct_remover_calls_secondary": [
            0x1F0DDB0, 0x1F1F2C0, 0x1F1F3A4, 0x1F246A0, 0x1F24738,
        ],
        "recbf_tagged_context_reset": 0x1F25B1C,
        "recbf_tagged_context_direct_reset_calls_secondary": [0x1F26E7C],
        "recbf_geometry_event_words": {
            0x1F0BC9C: 0xE309C228,  # 24-byte event table base 0x22d9228
            0x1F0BCA0: 0xE340C22D,
            0x1F0BCA8: 0xE3A03018,  # 24-byte stride
            0x1F1B6E4: 0xEBFFC168,  # copy event descriptor
            0x1F1B6E8: 0xE51B3010,  # descriptor callback at +20
            0x1F1B6F8: 0xE1A00005,  # forward scheduler argument as callback r0
            0x1F1B6FC: 0xE12FFF33,  # call callback with event ID in r1
            0x1F1C330: 0xE50B0058,  # scheduler saves its r0 argument
            0x1F1C40C: 0xE51B0058,  # scheduler forwards it to callback dispatcher
            0x1F32B84: 0xE1A05000,  # case dispatcher retains callback r0
            0x1F1686C: 0xE5D035BE,  # working-state aspect byte
            0x1F16870: 0xE54B3014,  # event payload +4
            0x1F1685C: 0xE3700001,  # -1 selects fallback route
            0x1F168CC: 0xEBC8FA1D,  # fallback checks global gate +0x41f
            0x1F168D4: 0x03A03001,  # gate value one forces payload code one
            0x1F168E0: 0xEBC8F83E,  # otherwise read global +0x16
            0x1F168E4: 0xE54B0014,  # copy it to payload +4
            0x1F168AC: 0xE24B0018,  # payload base
            0x1F168B0: 0xEB00925A,  # send via 0x1f3b220
            0x1F3B248: 0xE301323E,  # event 0x123e
            0x1F3B264: 0xE3A02014,  # 20-byte payload
            0x1F4BAEC: 0xE1D030B0,  # dispatcher event ID
            0x1F4BB24: 0xE5900008,  # event payload pointer
            0x1F4BB28: 0xEBFFFF57,  # receiver 0x1f4b88c
            0x1F4B90C: 0xE5910010,  # baseline buffer width field
            0x1F4B914: 0xE3A02001,  # first helper call with code 1
            0x1F4B918: 0xE5911014,  # baseline buffer height field
            0x1F4B91C: 0xE1A00230,  # halve width before helper
            0x1F4B920: 0xEBC84D6E,  # primary ratio helper
            0x1F4B924: 0xE5D42004,  # read payload aspect
            0x1F4B928: 0xE3520001,  # code 1 or alternate geometry
            0x1F4B9B0: 0xEBC84D4A,  # second helper call with payload aspect
            0x1F4B968: 0xEBFFB5B4,  # submit geometry to buffer routine
            0x1F32DC0: 0xEBFF8EA2,  # event-dispatch case calls sender
        },
        "recbf_geometry_event_registration_words": {
            0x22D9648: 0x0000002C,  # event ID 44
            0x22D965C: 0x01F32B7C,  # handler callback
            0x1F32BD0: 0x01F32DC0,  # handler case 44 -> sender
        },
        "recbf_geometry_event_registration_id": 44,
        "recbf_geometry_event_runtime_list_words": {
            0x1F1B7EC: 0xE3093E64,  # builder locates per-context count at +0x9e64
            0x1F1B7F4: 0xE18420B3,  # reset the count before building the list
            0x1F1BC48: 0xE3092E68,  # row event-ID field at +0x9e68
            0x1F1BC4C: 0xE7834002,  # append selected descriptor ID
            0x1F1BC88: 0xE1C430B0,  # increment list count
            0x1F1C3AC: 0xE3019488,  # scheduler context stride 0x1488
            0x1F1C3B0: 0xE0292499,  # context base 0x0341ccb8 + stride * r0
            0x1F1C3B4: 0xE2899C9E,  # count region +0x9e00
            0x1F1C3B8: 0xE2899064,  # count at +0x9e64
            0x1F1C4CC: 0xE2844048,  # 72-byte row stride
            0x1F1C4D0: 0xE1D930B0,  # list count
            0x1F1C4E0: 0xE5145004,  # listed event ID
            0x1F2C808: 0xE59F0050,  # group-47 gate pointer literal
            0x1F2C80C: 0xEB00B8B0,  # test global bit 0
            0x1F2C834: 0xE3A0102F,  # enable group 47, not event 47
            0x1F2C83C: 0xEB00B881,  # set group bit at per-context +0x9df8
        },
        "recbf_geometry_event_runtime_list_data_words": {
            0x1F2C860: 0x0341CCD8,  # group-47 gate bitset pointer
            0x22DC8B8: 44,          # outer group 44, not event 44
            0x22DC8BC: 0x022DC070, # group-44 subrecord array
            0x22DC990: 47,          # outer group selector
            0x22DC994: 0x022DC254, # group-47 subrecord array
            0x22DC26C: 44,         # subrecord 2 event ID
            0x22DC270: 0,          # no secondary condition pointer
            0x22DC274: 0x022DC2D0,
            0x22DC278: 44,         # subrecord 3 also has event ID 44
            0x22DC27C: 0x022DE728, # additional condition pointer
            0x22DC280: 0x022DC2D8,
            0x22DE0EC: 0x01F2C7F8, # callback that enables group 47
        },
        "recbf_geometry_event_group_44_address": 0x22DC070,
        "recbf_geometry_event_group_47_address": 0x22DC254,
        "recbf_geometry_event_group_47_gate_source_words": {
            0x1F27F94: 0xE5902004,  # configuration setter reads payload length
            0x1F27FB0: 0xE5901008,  # configuration setter reads payload pointer
            0x1F27FB4: 0xE28300C4,  # copy destination 0x034cacb8+0xc4
            0x1F27FB8: 0xEBC86212,  # copy caller-supplied payload
            0x1F27FF8: 0xE3A02F43,  # 268-byte RAM configuration copy
            0x1F28000: 0xE59F0014,  # destination 0x03421368
            0x1F28004: 0xEBC861FF,  # copy from 0x034cad70
            0x1F23C58: 0xE24B1E12,  # 268-byte configuration copy destination on stack
            0x1F23C60: 0xEB0010EE,  # copy configuration via 0x1f28020
            0x1F28038: 0x059F1040,  # r0=1 selects 0x03421368 source
            0x1F28064: 0xE3A02F43,  # 268 bytes
            0x1F2806C: 0xEBC861E5,  # copy source into caller's stack buffer
            0x1F23C70: 0xE3A01004,  # clear four-byte global gate bitmap
            0x1F23C78: 0xEB00DB17,  # zero bitmap at 0x0341ccd8
            0x1F23C7C: 0xE51B310C,  # pointer at copied structure +0x14
            0x1F23C80: 0xE5D33006,  # read pointed-to byte +6
            0x1F23C84: 0xE3530001,  # compare with 1
            0x1F23C88: 0x0A00002E,  # equal branches to bit-0 setter
            0x1F23D48: 0xE3A01000,  # bit index 0
            0x1F23D50: 0xEB00DB3C,  # set bit 0 in global bitmap
            0x1F2C810: 0xE3500000,  # group-47 callback checks bit-0 result
            0x1F2C814: 0x08BD8830,  # absent bit returns without enabling group
        },
        "recbf_geometry_event_group_47_gate_source_data_words": {
            0x1F23DC4: 0x0341CCD8,  # cleared/set global gate bitmap
            0x1F28018: 0x034CAD70,  # RAM source for 268-byte configuration copy
            0x1F2801C: 0x03421368,  # RAM destination for that copy
            0x1F28080: 0x03421368,  # configuration copy source for r0=1
        },
        "recbf_geometry_event_bitmap_words": {
            0x1F2C4BC: 0xEBFF8E4B,  # callback checks state byte +0xb138 in {1,2}
            0x1F2C4EC: 0xEBFF8E4E,  # classify camera mode
            0x1F2C4F0: 0xE3500002,  # class 2 takes another route
            0x1F2C4FC: 0xEBFFC749,  # test state byte +0xb0b4 == 2
            0x1F1E244: 0xE7D00003,  # read state byte +0xb0b4
            0x1F1E248: 0xE3500002,
            0x1F36A6C: 0xE3A02002,  # conditional transition writes 2
            0x1F36A74: 0xE7C12000,  # store state byte +0xb0b4
            0x1F2C528: 0xE3A0102C,  # group index 44
            0x1F2C530: 0xEB00B944,  # OR group 44 in +0x9df8 enable bitmap
            0x1F5AA68: 0xE183111C,  # bit-set primitive: OR shifted bit
            0x1F5AA6C: 0xE7801102,
            0x1F5AAF8: 0xE1D33002,  # bit-test primitive
            0x1F1C4E0: 0xE5145004,  # scheduler loads listed event ID
            0x1F1C4EC: 0xEB00F978,  # test separate +0x9e24 bit for listed event ID
            0x1F1C4F4: 0x0AFFFFF3,  # a set +0x9e24 bit skips dispatch
            0x1F1C410: 0xEBFFFCAC,  # otherwise callback dispatcher
        },
        "recbf_geometry_event_bitmap_data_words": {
            0x22DE0B4: 0x01F2C4B0,  # callback that can enable group 44
        },
        "develop_aspect_copy_words": {
            0x1F24574: 0xE24B2044,  # converter output = frame - 0x44
            0x1F24584: 0xEB01278E,  # call converter
            0x1F245FC: 0xE24B1044,  # same buffer passed to initializer
            0x1F24604: 0xEB009D54,
            0x1F4BBE8: 0xE1A0100C,  # initializer forwards buffer
            0x1F4BBF0: 0xEB007DC8,
            0x1F6B454: 0xE5D53002,  # load output byte +2
            0x1F6B458: 0xE5C435BE,  # store in working state +0x5be
        },
        "geometry_code4_branch": False,
        "geometry_aspect_words": {
            0x1ED6C5C: 0xE5D435BE,  # read working-state aspect
            0x1ED6C60: 0xE3530001,
            0x1ED6C68: 0xE3530002,
            0x1ED6C70: 0xE1A03085,  # otherwise use default 2:3 calculation
            0x1ED6C74: 0xE3056556,
            0x1ED6C78: 0xE3456555,
            0x1ED6C98: 0xE5D4C5BE,  # second aspect-dependent dimension
            0x1ED6C9C: 0xE35C0001,
            0x1ED6CA4: 0xE35C0002,
            0x1ED6CAC: 0xE1A03080,
            0x1ED6CB0: 0xE3052556,
            0x1ED6CB4: 0xE3452555,
        },
        "geometry_call_words": {
            0x1F316A8: 0xEBFE9532,
            0x1F316F8: 0xEBFE95C7,  # same caller writes geometry record
            0x1F31848: 0xEBFFFF64,  # parent enters geometry caller
            0x1F32A94: 0xEBFFFB3F,  # current-frame route enters parent
            0x1F6BA50: 0xEBFDAC48,  # same initializer that copies aspect +2 to +0x5be
            0x1F74458: 0xEBFD89C6,
            0x1F74464: 0xEBFD8778,  # following table-selector call
            0x1F7A0F4: 0xEBFD729F,
            0x1F7A100: 0xEBFD7051,  # following table-selector call
        },
        "movie_geometry_caller_words": {
            0x1F7430C: 0xE92D4BF0,  # recmvr caller entry
            0x1F744E4: 0xEBFD8A4C,  # geometry record writer
            0x1F745AC: 0xE3040120,  # diagnostic string low half
            0x1F745B0: 0xE340022E,  # diagnostic string high half
            0x1F79CA8: 0xE24DD010,  # recmvs caller entry
            0x1F79CF8: 0xE3040258,  # diagnostic string low half
            0x1F79CFC: 0xE340022E,  # diagnostic string high half
            0x1F79D18: 0xE3040270,  # second diagnostic string low half
            0x1F79D1C: 0xE340022E,  # second diagnostic string high half
            0x1F7A180: 0xEBFD7325,  # geometry record writer
        },
        "movie_geometry_diagnostic_strings": {
            0x22E4120: b"recmvrSetSaclaCaptureInfo()\0",
            0x22E4258: b"recmvsGetEmptyIndex()\0",
            0x22E4270: b"recmvsCreateFrameInfo()\0",
        },
        "movie_geometry_caller_addresses": [0x1F74458, 0x1F7A0F4],
        "movie_descriptor_caller_words": {
            0x1F7DBD0: 0xEBFD82D9,  # movie route calls descriptor wrapper
            0x1F7DC04: 0xEBFFF674,  # same route emits resize event
            0x1F7B5F8: 0xE30536E4,  # event diagnostic low half
            0x1F7B5FC: 0xE340322E,  # event diagnostic high half
        },
        "movie_descriptor_diagnostic_strings": {
            0x22E56E4: b"RECMB_SV_RESZ\0",
        },
        "movie_descriptor_caller_addresses": [0x1F7DBD0],
        "descriptor_code4_branch": False,
        "size_selection_bridge_words": {
            0x1D6AB60: 0xE5D43010,  # selection scan reads enabled byte
            0x1D6AB64: 0xE3530001,
            0x1D6AB8C: 0xE7D24005,  # matching row ID
            0x1D6AB94: 0xE30003BF,  # property key 0x3bf
            0x1D6AB98: 0xEB0170A4,
            0x1D6ABB0: 0xE30003BF,
            0x1D6ABB4: 0xEB009D9D,  # submit ID with event 0xf001
            0x1DC11F4: 0xE30003BF,  # reverse path reads property
            0x1DC1208: 0xE30003BF,
            0x1DC124C: 0xE5D31004,  # reverse scan compares aspect
            0x1DC1258: 0xE5D31005,  # then size level; no enabled-byte read
            0x1DC1274: 0xE7913002,  # returns matching image-size ID
        },
        "primary_aspect_state_bridge_words": {
            0x10394DC: 0xEB004FB9,  # read/normalize key 0x3bf
            0x10394FC: 0xE30013BF,  # key passed with normalized byte
            0x1039504: 0xEBFBAC67,
            0x103951C: 0xEBFF80F1,  # pass normalized byte to state setter
            0x104D3DC: 0xE30003BF,  # getter loads property key
            0x104D3E0: 0xEBFB4F34,
            0x104D3F0: 0xE30003BF,  # normalize key value
            0x104D3F4: 0xEBFB554C,
            0x101990C: 0xE5D3006B,  # setter checks current aspect byte
            0x1019944: 0xE5C3406B,  # writes shared state +0x6b
            0x1049D98: 0xEB000DAB,  # settings update gets adjacent property
            0x1049DA4: 0xEB000D87,  # and key 0x3bf value
            0x1049E00: 0xEBFFD12F,  # passes normalized fields to state updater
            0x103E32C: 0xEBFF6D6D,  # updater writes aspect state +0x6b
            0x103E348: 0xEBFF6EBC,  # updater writes size-related state +0x70
            0x1019E9C: 0xE5C34070,  # size-related byte in same global struct
        },
        "primary_aspect_dispatch_words": {
            0x10149CC: 0xE52DB004,  # entry
            0x1014A08: 0xE5D3306B,  # shared aspect byte
            0x1014A0C: 0xE3530024,  # indexed dispatch bound 36
            0x1014A10: 0x979FF103,  # PC = table[aspect]
            0x1014A18: 0x01014C88,  # code 0
            0x1014A1C: 0x01014DD4,  # code 1
            0x1014A20: 0x01014F20,  # code 2
            0x1014A24: 0x01014C18,  # code 3
            0x1014A28: 0x010150F0,  # code 4: default
            0x10150F0: 0xE3A00000,  # default returns zero
            0x00FB165C: 0xEB018CC1,  # table-lookup wrapper
            0x1014974: 0xE7900101,  # word table indexed by returned enum + 2
        },
        "recbf_aspect_lookup_primary_words": {
            0x115F9FC: 0xE3510000,  # aspect input is categorized 0..4
            0x115FA20: 0xE3510003,
            0x115FA28: 0x13A01004,  # codes beyond 3 use category 4
            0x115FA2C: 0xE30732DC,  # lookup base 0x014a72dc
            0x115FA30: 0xE340314A,
            0x115FA34: 0xE3A02005,  # five columns
            0x115FA38: 0xE0201092,  # index = other category*5 + aspect
            0x115FA3C: 0xE7930100,  # return indexed word
        },
        "recbf_aspect_lookup_secondary_words": {
            0x1F3EF70: 0xE3520003,  # processing-mode gate
            0x1F3F348: 0xE5D329D9,  # submode byte
            0x1F3F354: 0xE3520001,  # only submodes 4 or 5 after subtract 4
            0x1F3F35C: 0xE5D315BE,  # working-state aspect +0x5be
            0x1F3F360: 0xE5D30A2A,  # other lookup category +0xa2a
            0x1F3F364: 0xEBC881A2,  # cross-partition lookup call
            0x1F3F390: 0xE50B3058,  # derived local field
            0x1F3F00C: 0xE24B1048,  # 28-byte structure containing local field
            0x1F3F014: 0xEBFE7DFD,  # hand structure to parameter builder
        },
        "recbf_crop_descriptor_branch_words": {
            0x1F3EE28: 0xE3510001,  # argument 1 selects command 0x15's branch
            0x1F3EE2C: 0x0A0000B2,  # argument 1 branches to crop-command setup
            0x1F3F104: 0xE359001D,  # crop branch checks state 29
            0x1F3F108: 0x0A0000FE,  # state 29 has a separate flag setup
            0x1F3F124: 0xE3A08000,  # other states pass flag 0
            0x1F3F518: 0xE3A08002,  # state 29 passes flag 2
            0x1F3EFF8: 0xE58D8004,  # caller flag goes to callee stack argument
            0x1F3F014: 0xEBFE7DFD,  # shared descriptor routine
            0x1F3F05C: 0xE3560001,  # command argument chooses destination
            0x1F3F060: 0x028CC0F0,  # command 0x15: context +0xf0
            0x1F3F064: 0x128CC0D4,  # command 0x16: context +0xd4
            0x1F3F068: 0xE24BE064,  # copy local descriptor
            0x1F3F070: 0xE8AC000F,  # first 16 bytes into context
            0x1F3F078: 0xE88C0007,  # remaining 12 bytes
            0x1EDE82C: 0xE5DB7008,  # callee reads that flag as a byte
            0x1EDE9E8: 0xEBFFEE11,  # additional guard helper
            0x1EDE9EC: 0xE1800007,  # either nonzero value blocks rewrite
            0x1EDE9F0: 0xE31000FF,
            0x1EDE9F4: 0x0A00001D,  # zero enters centered descriptor rewrite
            0x1EDEAA0: 0xE5D515BE,  # aspect code
            0x1EDEAA4: 0xE5D50A2A,  # dimension category
            0x1EDEAA8: 0xEBCA03D1,  # width lookup
            0x1EDEAAC: 0xE1A07080,  # doubled target width in descriptor units
            0x1EDEAB8: 0xEBCA03FF,  # height lookup
            0x1EDEABC: 0xE59A100C,  # descriptor stride
            0x1EDEAC0: 0xE59A3014,  # old height
            0x1EDEAC4: 0xE0433000,  # old minus target height
            0x1EDEAC8: 0xE1A030A3,  # half vertical difference
            0x1EDEACC: 0xE59A2010,  # old width
            0x1EDEAD0: 0xE0422007,  # old minus target width
            0x1EDEAD4: 0xE1A020A2,  # half horizontal difference
            0x1EDEAD8: 0xE0232391,  # centered vertical*stride + horizontal
            0x1EDEADC: 0xE59A2004,  # original base pointer
            0x1EDEAE0: 0xE0823003,  # add computed offset
            0x1EDEAE4: 0xE58A3004,  # adjusted base pointer
            0x1EDEAE8: 0xE58A7010,  # target width
            0x1EDEAEC: 0xE58A0014,  # target height
            0x1EDEAF0: 0xE0000190,  # target height*stride
            0x1EDEAF4: 0xE58A0008,  # target height*stride
        },
        "recbf_crop_descriptor_guard_words": {
            0x1EDA23C: 0xE5D035B0,  # helper gate reads state +0x5b0
            0x1EDA240: 0xE353002D,  # only state 45 has a subtype exception
            0x1EDA244: 0x13A00000,  # other states allow rewrite at this gate
            0x1EDA258: 0xE5D005BD,  # state-45 subtype +0x5bd
            0x1EDA25C: 0xE2400007,  # subtypes 7/8 block centered rewrite
            0x1EDA264: 0xE3500001,
            0x1EDEA70: 0xE5D535B0,  # later state gate
            0x1EDEA74: 0xE3530020,  # state 32 has another exception
            0x1EDEA78: 0x0A00001F,
            0x1EDEAFC: 0xE5D525CD,  # state-32 subtype +0x5cd
            0x1EDEB08: 0xE352000D,  # subtype 13 bypasses rewrite
            0x1EDEB0C: 0x13530002,  # subtypes 3/4/5 also bypass
            0x1EDEB10: 0x9AFFffB8,  # permitted exceptions return to non-rewrite route
        },
        "recbf_crop_descriptor_slot_gate_words": {
            0x1F3F11C: 0xE3590019,  # command-0x15 setup: state 25
            0x1F3F128: 0xE5953B34,  # otherwise inspect context +0xb34
            0x1F3F12C: 0xE7E03553,  # extract bit 10
            0x1F3F130: 0xE359001A,  # state 26 also enables +0xf0 source
            0x1F3F13C: 0x0A0000FE,  # else select +0xd4 input descriptor
            0x1F3F03C: 0xE3520019,  # post-helper state 25 shortcut
            0x1F3F040: 0x0A000005,
            0x1F3F044: 0xE59C3B34,  # post-helper +0xb34 flag source
            0x1F3F048: 0xE7E03553,  # bit 10
            0x1F3F04C: 0xE352001A,  # state 26 shortcut
            0x1F3F058: 0x0A0000F2,  # neither state nor bit: +0xd4
            0x1F3F05C: 0xE3560001,  # command 0x15 is argument 1
            0x1F3F060: 0x028CC0F0,  # argument 1: context +0xf0
            0x1F3F064: 0x128CC0D4,  # other command: context +0xd4
            0x1F3F428: 0xE28CC0D4,  # fallback copies to +0xd4
        },
        "recbf_b34_bit10_source_primary_words": {
            0x1164270: 0xE2003001,  # input bit 0
            0x1164274: 0xE1A03683,  # becomes output bit 13
            0x1164278: 0xE3100002,  # input bit 1
            0x116427C: 0x13833B01,  # becomes output bit 10
            0x1164280: 0xE3100004,  # input bit 2
            0x1164284: 0x13833901,  # becomes output bit 14
        },
        "recbf_b34_bit10_source_secondary_words": {
            0x1F15C80: 0xE58D501C,  # caller supplies selected per-slot input object
            0x1F15CC0: 0xEB011618,  # one direct builder call
            0x1F5B544: 0xE59B901C,  # callee receives that stack argument
            0x1F5B560: 0xE3003222,  # input offset +0x222
            0x1F5B564: 0xE19900B3,  # read input halfword
            0x1F5B568: 0xEBC8233E,  # map bits via primary helper
            0x1F5B56C: 0xE58A0B34,  # store mapped word at context +0xb34
        },
        "recbf_b34_bit10_indexed_input_words": {
            0x1F15BC8: 0xEB0049CC,  # obtain slot index
            0x1F15BD0: 0xE30C5CB8,  # shared base 0x0341ccb8
            0x1F15BD4: 0xE3405341,
            0x1F15C4C: 0xE3013488,  # per-slot stride 0x1488
            0x1F15C50: 0xE0265693,  # base + stride*slot
            0x1F15C54: 0xE30B30A4,  # signed index at slot +0xb0a4
            0x1F15C58: 0xE19630F3,
            0x1F15C5C: 0xE3A02E12,  # selected-record stride 288
            0x1F15C60: 0xE0255392,  # base + 288*signed index
            0x1F15C64: 0xE2855C99,  # add 0x9900
            0x1F15C68: 0xE2855060,  # add 0x60
            0x1F15C80: 0xE58D501C,  # pass selected pointer as stack argument
        },
        "recbf_b34_selector_writer_words": {
            0x1F126EC: 0xE354001B,  # caller mode 27 takes a separate branch
            0x1F12718: 0xE3540006,  # only mode 6 reaches this selector update
            0x1F12728: 0xE358007F,  # slot index must be at most 127
            0x1F12730: 0xE3A02000,  # lookup subkey 0
            0x1F12734: 0xE3A01006,  # lookup key 6
            0x1F12738: 0xE280003C,  # slot object's +0x3c halfword
            0x1F1273C: 0xEBFEFDCB,  # keyed lookup at 0x01ed1e70
            0x1F12740: 0xE30C3CB8,  # per-slot base 0x0341ccb8
            0x1F12744: 0xE3403341,
            0x1F12748: 0xE3012488,  # stride 0x1488
            0x1F1274C: 0xE0283892,
            0x1F12750: 0xE2400001,  # convert lookup's 1-based result to index
            0x1F12754: 0xE30B30A4,  # selector offset
            0x1F12758: 0xE18800B3,  # store signed halfword; zero lookup -> -1
            0x1ED1E78: 0xE1D0E0F0,  # lookup input: signed slot-object halfword
            0x1ED1EE0: 0xE5D03002,  # match lookup key
            0x1ED1EF0: 0xE5D03003,  # match lookup subkey
            0x1ED1F00: 0xE1D000B4,  # return signed record halfword at +4
            0x1ED1F0C: 0xE3A00000,  # bounded miss returns zero
        },
        "recbf_b34_mode6_registration_table_words": {
            0x1F126E8: 0xEBFF0543,  # registration attempt before selector lookup
            0x1F12718: 0xE3540006,  # request mode 6
            0x1ED3C0C: 0xE1A04001,  # preserve registration key/mode
            0x1ED3D98: 0xE3730001,  # reject allocator result -1
            0x1ED3DA8: 0xE14B24BC,  # record +0: signed object ID
            0x1ED3DAC: 0xE54B404A,  # record +2: key/mode byte
            0x1ED3DB4: 0xE54B2049,  # record +3: subkey byte
            0x1ED3DB8: 0xE14B34B8,  # record +4: 1-based allocated index
            0x1ED3E20: 0xE24B004C,  # record base at stack -76
            0x1ED3E24: 0xEBFFFA74,  # conditional append at 0x01ed27fc
            0x1ED2804: 0xE5D03002,  # choose bank by record key
            0x1ED280C: 0xE3530018,  # keys <=24 use first RAM bank
            0x1ED2814: 0xE3003D50,  # base 0x034d0d50
            0x1ED2818: 0xE340334D,
            0x1ED2820: 0xE5924638,  # bank-1 count at base +0x8638
            0x1ED2824: 0xE3A0C024,  # 36-byte records
            0x1ED2828: 0xE02C349C,  # stride times count
            0x1ED2830: 0xE28CC028,  # bank-1 table at 0x034d3578
            0x1ED283C: 0xE8AC000F,  # copy record data to RAM
            0x1ED284C: 0xE58C3000,  # final four bytes of record
            0x1ED2854: 0xE3540094,  # count limit 148
            0x1ED28BC: 0xE5834638,  # publish new bank-1 count
            0x1ED1E7C: 0xE59F0098,  # lookup bank-1 base literal
            0x1ED1E90: 0x33A04094,  # lookup bound 148
        },
        "recbf_selector_writer_direct_bl_sites_expected": [
            0x1F12830, 0x1F12A00, 0x1F1354C, 0x1F1640C, 0x1F164D8,
            0x1F16A80, 0x1F1DFC4, 0x1F1E92C, 0x1F1E964, 0x1F1ECD0,
            0x1F22608, 0x1F22738, 0x1F227A0,
        ],
        "recbf_mode6_selected_record_geometry_words": {
            0x1F1DFC4: 0xEBFFD1B3,  # another mode-6 direct caller
            0x1F1E958: 0xE3A02000,  # mode-6 subkey 0
            0x1F1E95C: 0xE3A01006,  # request mode 6
            0x1F1E964: 0xEBFFCF4B,  # registration/selector writer
            0x1F1E970: 0xE3013488,  # same per-slot stride
            0x1F1E974: 0xE0235893,  # same base + slot*stride
            0x1F1E978: 0xE30B20A4,  # signed selector offset
            0x1F1E97C: 0xE19330F2,  # read selector immediately
            0x1F1E980: 0xE3A04E12,  # selected-record stride 288
            0x1F1E984: 0xE0040394,
            0x1F1E988: 0xE2843C99,  # selected record base +0x9900
            0x1F1E98C: 0xE2833060,  # selected record +0x60
            0x1F1E9AC: 0xEBFEF51D,  # selected record into geometry initializer
            0x1EDBEF8: 0xE5D435BE,  # initializer reads working-state aspect
            0x1EDBEFC: 0xE3530001,  # special case 1
            0x1EDBF04: 0xE3530002,  # special case 2; code 4 takes default
            0x1EDBF3C: 0xE5D4C5BE,  # second aspect decision
            0x1EDBF40: 0xE35C0001,
            0x1EDBF48: 0xE35C0002,  # code 4 again takes default
        },
        "recbf_mode6_geometry_callback_packet_words": {
            0x1F22BC4: 0xE3032828,  # construct callback address 0x01f23828
            0x1F22BC8: 0xE34021F2,
            0x1F22BCC: 0xE58D2028,  # outgoing argument +0x28
            0x1F22C28: 0xEB02E09F,  # packet wrapper 0x01fdaeac
            0x1FDAF1C: 0xE59B302C,  # wrapper reads that argument
            0x1FDAF20: 0xE50B301C,  # record base -0x54: callback is payload +0x38
            0x1FDAF6C: 0xE3A02048,  # 72-byte record
            0x1FDAF70: 0xE24B1054,  # record base
            0x1FDAF74: 0xE3A00007,  # message selector 7
            0x1FDAF78: 0xEB00056F,  # send wrapper 0x01fdc53c
            0x1FDC550: 0xE2800B05,  # selector plus 0x1400
            0x1FDC554: 0xE2800033,  # plus 0x33
            0x1FDC558: 0xE14B01B8,  # 0x143a message identifier
            0x1FDC568: 0xE3A03040,  # channel 64
            0x1FDC570: 0xE50B5014,  # preserve record length
            0x1FDC574: 0xE50B4010,  # preserve record pointer
            0x1FDC588: 0xE3A00040,  # submit on channel 64
            0x1FDC58C: 0xEBC584BA,  # lower-level submit
            0x1F23828: 0xE92D4FF0,  # candidate callback entry
            0x1F23858: 0xE3530001,  # one of its entry gates
            0x1F2389C: 0xE3500001,  # another entry gate
            0x1F238A4: 0xE3540000,  # setup-variant gate
            0x1F238C8: 0xEBFFEBCC,  # calls mode-6 geometry setup
        },
        "recbf_mode6_geometry_payload_copy_primary_words": {
            0x113D89C: 0xE2433008,  # channel capacity less transport header
            0x113D8A0: 0xE5912004,  # requested payload length
            0x113D8A4: 0xE1520003,  # bounds check before copy path
            0x113D960: 0xE51B0018,  # allocated message buffer
            0x113D97C: 0xE5953004,  # copy payload length into message header
            0x113D984: 0xE5952004,  # nonzero payload length
            0x113D9E8: 0xE5951008,  # caller payload pointer
            0x113D9EC: 0xE2800008,  # destination after eight-byte header
            0x113D9F0: 0xEB000B84,  # byte copy at 0x1140808
            0x11408A0: 0xE0CC40D8,  # copy routine reads paired words
            0x11408A4: 0xE1EE40F8,  # copy routine stores paired words
        },
        "recbf_mode6_geometry_receive_direct_bl_sites_expected": [
            0x1E45E14,  # literal channel 1
            0x20F0CD8,  # channel loaded from RAM; initializer writes 69
            0x21C137C,  # literal channel 78
        ],
        "recbf_mode6_geometry_channel64_receiver_secondary_words": {
            0x1FDAA48: 0xE3A04040,  # initialize channel 64
            0x1FDAA4C: 0xE5834000,  # store channel 64 in task state
            0x1FDAA64: 0xE1A00004,  # pass channel to queue creation
            0x1FDAA68: 0xEBC58AAD,  # create channel queue
            0x1FDAA90: 0xE3073D80,  # receiver task address low half
            0x1FDAA94: 0xE34031FE,  # receiver task = 0x01fe7d80
            0x1FDAAA8: 0xEBC5876D,  # register receiver task
            0x1FE7DC8: 0xE3A00040,  # dequeue channel 64
            0x1FE7DCC: 0xEBC5573D,  # generic receive with payload copy
            0x1FE7DD8: 0xE1D500B4,  # received message ID
            0x1FE7DDC: 0xE2400B05,  # subtract 0x1400
            0x1FE7DE0: 0xE2400033,  # subtract 0x33: 0x143a -> index 7
            0x1FE7DE8: 0xE354003B,  # table bound, max index 59
            0x1FE7DF0: 0xE30F3BFC,  # destination table at 0x022efbfc
            0x1FE7DF4: 0xE340322E,
            0x1FE7DF8: 0xE5952008,  # received payload length
            0x1FE7DFC: 0xE595100C,  # received payload pointer
            0x1FE7E00: 0xE7930104,  # destination table[index]
            0x1FE7E04: 0xEBC70973,  # copy received bytes to destination
            0x1FE7E08: 0xE3A01001,  # arrival flag value
            0x1FE7E0C: 0xE1A00004,  # arrival flag index
            0x1FE7E10: 0xEBFFD1E0,  # mark arrival
            0x1FDC714: 0xE52DB004,  # accessor for index-7 buffer
            0x1FDC71C: 0xE59F0008,  # load literal destination
            0x20F0928: 0xE3A04045,  # unrelated variable receiver: channel 69
            0x20F092C: 0xE5834000,  # store into 0x02e98380
            0x20F0CD4: 0xE5940000,  # read channel 69 from that slot
        },
        "recbf_mode6_geometry_channel64_index7_destination_word": {
            0x22EFC18: 0x0288D330,
            0x1FDC72C: 0x0288D330,  # accessor literal for same buffer
        },
        "recbf_mode6_geometry_index7_accessor_direct_bl_sites_expected": [
            0x200532C, 0x20098B8, 0x202B168, 0x202C0A4,
            0x202C35C, 0x202C3FC, 0x202D410, 0x202EFD0,
            0x203E128, 0x203E22C, 0x203E3C0, 0x203E72C,
            0x203E774, 0x203EA1C, 0x203EA80, 0x203EB18,
            0x2066A0C,
        ],
        "recbf_mode6_geometry_index7_downstream_copy_secondary_words": {
            0x202EFD0: 0xEBFEB5CF,  # accessor -> received 72-byte record
            0x202EFD4: 0xE59F4F88,  # destination literal at 0x0202ff64
            0x202EFD8: 0xE3A02048,  # length 72
            0x202EFDC: 0xE1A01000,  # source = accessor result
            0x202EFE0: 0xE1A00004,  # destination = 0x02e9b174
            0x202EFE4: 0xEBC5ECFB,  # byte-copy routine
            0x202EFE8: 0xE1A00004,  # pass copied record
            0x202EFEC: 0xEBFFF774,  # process copied record at 0x0202cdc4
        },
        "recbf_mode6_geometry_index7_downstream_copy_destination_word": {
            0x202C498: 0x02E9B174,  # copied-record accessor literal
            0x202FF64: 0x02E9B174,
        },
        "recbf_mode6_geometry_index7_indirect_callback_secondary_words": {
            0x202C480: 0xE52DB004,  # accessor for copied record
            0x202C488: 0xE59F0008,  # return 0x02e9b174
            0x20366C4: 0xE92D4FF0,  # callback-dispatch routine entry
            0x20366EC: 0xEBFFD763,  # copied-record accessor
            0x20366F0: 0xE1A04000,  # preserve returned record pointer
            0x20366F4: 0xE30057A0,  # callback input base 0x02ea07a0
            0x20366F8: 0xE34052EA,
            0x203670C: 0xE2855024,  # callback input becomes 0x02ea07c4
            0x2036720: 0xE5943038,  # load record callback at +0x38
            0x2036724: 0xE1A00005,  # callback argument
            0x2036728: 0xE12FFF33,  # BLX r3: indirect callback call
            0x2036730: 0xE3500001,  # test callback result
            0x2036734: 0x0A000010,  # result 1 branches to success path
            0x1F238C4: 0xE1A00005,  # gated callback forwards its input
            0x1F238C8: 0xEBFFEBCC,  # into mode-6 geometry setup
        },
        "recbf_mode6_geometry_index7_indirect_callback_registration_words": {
            0x203954C: 0xE595303C,  # distinct dynamic field for payload +0x40
            0x2039550: 0xE58D3034,  # caller stack +0x34
            0x203956C: 0xE30636C4,  # callback routine low half
            0x2039570: 0xE3403203,  # 0x020366c4 high half
            0x2039574: 0xE58D3028,  # place in outgoing stack record
            0x20395FC: 0xEB02E57F,  # submit registration record
            0x20F2C6C: 0xE59B302C,  # stack +0x28 -> payload +0x38
            0x20F2C70: 0xE50B3020,
            0x20F2C7C: 0xE59B3038,  # stack +0x34 -> payload +0x40
            0x20F2C80: 0xE50B3018,
            0x20F2CA4: 0xE3A02054,  # 84-byte registration payload
            0x20F2CAC: 0xE3010587,  # message ID 0x1587
            0x20F2CB0: 0xEBFFF790,  # generic transport sender
        },
        "recbf_mode6_geometry_registration_channel69_secondary_words": {
            0x20F0044: 0xE3083380,  # receiver descriptor base 0x02e98380
            0x20F0048: 0xE34032E9,
            0x20F004C: 0xE2832018,  # payload destination = base +0x18
            0x20F0050: 0xE5832010,  # base +0x10 = descriptor +8 stores payload pointer
            0x20F0928: 0xE3A04045,  # task initializes channel 69
            0x20F092C: 0xE5834000,  # shared channel slot 0x02e98380
            0x20F00AC: 0xEBC13685,  # receiver dequeues from shared channel slot
            0x20F00C0: 0xEB000261,  # dispatch received ID via state table
            0x20F0AB8: 0xE92D4800,  # preserve descriptor + inline payload
            0x20F0AC4: 0xE3A020E8,  # copy 232 bytes to second descriptor
            0x20F0AC8: 0xE1A01000,  # source descriptor
            0x20F0ACC: 0xE0800002,  # destination descriptor +232
            0x20F0AD0: 0xEBC2E640,  # copy and return destination pointer
            0x20F0B18: 0xE3083380,  # outgoing sender reads same slot
            0x20F0B1C: 0xE34032E9,
            0x20F0B20: 0xE5930000,
            0x20F0B34: 0xEBC13350,  # generic queue send
            0x20F0658: 0xEB00A7B7,  # state-4 ID handler enters nested dispatch
            0x211A55C: 0xE3010B98,  # nested state table 0x023c1b98
            0x211A564: 0xEBFF5938,  # nested ID dispatch
            0x211F110: 0xE92D4870,  # nested ID-0x1587 handler
            0x211F11C: 0xEBFF4665,  # get copied receive descriptor
            0x211F180: 0xE5903048,  # descriptor +0x48 = payload +0x38
            0x211F184: 0xE584302C,  # writes module-state callback slot +0x2c
            0x211F1B0: 0xE3A02F4B,  # 300-byte out-of-line payload copy
            0x211F1B4: 0xE5901060,  # copied descriptor +0x60 pointer
            0x2116800: 0xE593402C,  # later reads that distinct callback slot
            0x2116804: 0xE3540000,  # null callback returns 0
            0x2116830: 0xE12FFF34,  # BLX r4 if nonzero
            0x211FB68: 0xE5D32174,  # runner gate: module-state byte +0x174
            0x211FB6C: 0xE2423010,  # switch index = state - 16
            0x211FB70: 0xE353000D,  # states 16..29 use switch table
            0x211FBB4: 0xEBFFDB0C,  # state 27 calls callback runner
            0x211FD24: 0xE3520013,  # other-state branch checks state 19
            0x211FD34: 0xE5D33328,  # otherwise reads flag +0x328
            0x211FD3C: 0x1A000003,  # nonzero flag enters runner branch
            0x211FD50: 0xEBFFDAA5,  # alternative call to runner
        },
        "recbf_mode6_geometry_registration_channel69_dispatch_data_words": {
            0x20F00C8: 0x02E98388,  # receive descriptor = channel slot +8
            0x20F0AD8: 0x02E98388,  # second-descriptor copy source
            0x23C1A38: 0x0235322C,  # first-level state 4 table
            0x235329C: 0x00001587,  # state-4 ID 0x1587
            0x23532A0: 0x020F0644,  # state-4 handler
            0x23C1A4C: 0x0235346C,  # first-level state 9 table
            0x2353474: 0x00001587,  # state-9 ID 0x1587
            0x2353478: 0x020F07F4,  # state-9 handler
            0x23C1B98: 0x02355540,  # nested state 0 table
            0x2355540: 0x00001587,  # nested ID 0x1587
            0x2355544: 0x0211F110,  # nested handler
            0x211FBA8: 0x0211FBB4,  # state 27 switch target
        },
        "recbf_mode6_channel69_1529_nested_table_address": 0x23C1B98,
        "recbf_mode6_channel69_1529_nested_table_entries": 34,
        "recbf_mode6_channel69_1529_runner_first_entry_states": [13, 16, 19, 21, 24, 27, 29],
        "recbf_mode6_channel69_1529_handler": 0x211F8D8,
        "recbf_mode6_channel69_1529_sender_secondary_words": {
            0x20F0C64: 0xE3010529,  # simple sender loads message ID 0x1529
            0x20F0C68: 0xEBFFFFA2,  # sends through channel-69 helper
            0x2119988: 0xE3010529,  # conditional self-message from state handler
            0x211998C: 0xEBFF5C59,
            0x211B064: 0xE3010529,  # second conditional self-message
            0x211B068: 0xEBFF56A2,
        },
        "recbf_mode6_channel69_1529_handler_gate_secondary_words": {
            0x211F8E4: 0xEBFFDBAF,  # first early-exit test
            0x211F8EC: 0x0A00004F,  # result 1 bypasses callback runner
            0x211F8F0: 0xEBFFDB96,  # second early-exit test
            0x211F8F8: 0x0A000053,  # result 1 bypasses runner
            0x2119780: 0xE59331BC,  # first literal-27 store gate: module +0x1bc
            0x2119794: 0xE5D334D6,  # alternative gate: module +0x4d6
            0x21197A8: 0xE3A0201B,  # literal state 27
            0x21197AC: 0xE5C32174,  # state byte +0x174
            0x211D5D4: 0xE3A0201B,  # second literal state-27 store
            0x211D5D8: 0xE5C32174,
        },
        "recbf_mode6_state27_transition_secondary_words": {
            0x2119488: 0xE5D33214,  # producer requires module byte +0x214
            0x2119490: 0x012FFF1E,  # zero exits
            0x211949C: 0xE5D33213,  # also requires byte +0x213
            0x21194A4: 0x012FFF1E,
            0x2119780: 0xE59331BC,  # when prior state 26: word +0x1bc
            0x2119794: 0xE5D334D6,  # or byte +0x4d6
            0x21197A8: 0xE3A0201B,  # then state 27
            0x21197AC: 0xE5C32174,
        },
        "recbf_mode6_state27_transition_direct_bl_sites_expected": [
            0x2119D98, 0x211A390, 0x211A3E0, 0x211A47C,
        ],
        "recbf_mode6_geometry_registration_transport_header_primary_words": {
            0x113D964: 0xE1D530B0,  # message ID at wire +0
            0x113D968: 0xE1C030B0,
            0x113D97C: 0xE5953004,  # payload length at wire +4
            0x113D980: 0xE5803004,
            0x113D9E8: 0xE5951008,  # payload source pointer
            0x113D9EC: 0xE2800008,  # payload destination at wire +8
            0x113D9F0: 0xEB000B84,  # copy payload
            0x113DB1C: 0xE5912004,  # receive payload length from queued header
            0x113DB6C: 0xE2811008,  # queued payload begins after 8-byte header
            0x113DB70: 0xE5950008,  # destination from receive descriptor +8
            0x113DB74: 0xEB000B23,  # copy payload to destination pointer
            0x11AA3E0: 0xE1A04000,  # copy wrapper preserves destination
            0x11AA3E4: 0xEBFE5907,  # byte copy
            0x11AA3E8: 0xE1A00004,  # returns original destination pointer
        },
        "recbf_mode6_registration_callback_runner_direct_bl_sites_expected": [
            0x211FBB4, 0x211FD50,
        ],
        "recbf_mode6_geometry_receive_copy_primary_words": {
            0x113DAFC: 0xE1D130B0,  # copy received ID into supplied header
            0x113DB14: 0xE5913004,  # copy payload length
            0x113DB6C: 0xE2811008,  # source payload after header
            0x113DB70: 0xE5950008,  # supplied payload destination
            0x113DB74: 0xEB000B23,  # copy received payload bytes
        },
        "recbf_mode6_geometry_setup_direct_bl_sites_expected": [0x1F238C8],
        "secondary_aspect_enum_consumer_words": {
            0x1D40F74: 0xEBC9C1C2,  # call primary code-to-enum wrapper
            0x1D40F78: 0xE1A06000,  # retain enum in r6
            0x1D410C0: 0xE1A01006,  # pass enum as word-table index
            0x1D410C8: 0xEBC9C161,  # table-lookup wrapper
            0x1D410D4: 0xE3000776,  # output property 0x776
            0x1D410D8: 0xEBC77FEE,
            0x1D410E4: 0xE1A01006,  # second slot uses same enum
            0x1D410EC: 0xEBC9C158,
            0x1D410F8: 0xE3000776,
        },
        "descriptor_words": {
            0x1EDCCA4: 0xE5953520,  # geometry field -> descriptor +0x30
            0x1EDCCA8: 0xE5843030,
            0x1EDCCE0: 0xE5D535BE,  # aspect -> descriptor +0x4d
            0x1EDCCE4: 0xE5C4304D,
            0x1EDE7C0: 0xEBFFF8F6,  # pack descriptor
            0x1EDE7DC: 0xE1A00009,  # pass output descriptor to processor
            0x1EDE7E0: 0xEBFFFC18,
            0x1EDE2EC: 0xE5DA204E,  # subtype gate before aspect arithmetic
            0x1EDE2F0: 0xE3520006,
            0x1EDE2F4: 0x0A000002,
            0x1EDE304: 0xE5DA304D,  # processor reads aspect
            0x1EDE308: 0xE3530001,
            0x1EDE310: 0xE3530002,
            0x1EDE324: 0x151B3044,  # default ratio calculation
        },
    },
    "gfx100_5_18": {
        "sha256": "c24a410267ffe2d254caa58f9d54eb28945dad0eec69c630ca904a5479aa066a",
        "version": (5, 18),
        "primary_header": 0x260060,
        "primary_load": 0x01081000,
        "dimension_lookup_width": 0x17CD6B4,
        "dimension_lookup_height": 0x17CD9B4,
        "dimension_lookup_columns": 8,
        "dimension_lookup_code4_expected": [[11648, 4304], [8256, 3048], [4000, 1480]],
        "crop_ratio_helper": 0x1341AA8,
        "crop_ratio_code4_target": 0x1341B0C,
        "crop_ratio_code4": [65, 24],  # explicit code-4 branch
        "crop_ratio_common_body_offset": 0x90,
        "crop_ratio_common_body_size": 0xA8,
        "crop_ratio_common_body_sha256": "7f0af5a008b807acb5b61aa891ea39dc12913e9f322efe0b259757bba58b3394",
        "crop_ratio_dispatch_targets_expected": [
            0x1341AE8, 0x1341AF4, 0x1341B30, 0x1341B0C,
            0x1341B18, 0x1341B24, 0x1341B00,
        ],
        "crop_ratio_words": {
            0x1341AB0: 0xE2422001,
            0x1341AB4: 0xE3520006,
            0x1341AB8: 0x979FF102,
            0x1341ABC: 0xEA000006,  # out-of-range branch to 4:3 default
            0x1341B0C: 0xE3A02018,  # denominator 24
            0x1341B10: 0xE3A0E041,  # numerator 65
            0x1341B38: 0xE00C0E91,
            0x1341B3C: 0xE06CC290,
            0x1341B50: 0xE732FE12,
            0x1341B54: 0xE3C22003,
            0x1341BAC: 0xE732F21E,
            0x1341BB0: 0xE3C22003,
        },
        "secondary_ratio_descriptor_table": 0x23B1994,
        "secondary_ratio_descriptor_targets_expected": [
            0x23B19B8, 0x23B19F0, 0x23B1A04, 0x23B1A18,
            0x23B1A28, 0x23B1A3C, 0x23B1A50,
        ],
        "secondary_ratio_descriptor_words": {
            0x23B1984: 0xE5D538DA,  # working-state aspect +0x8da
            0x23B1988: 0xE3530006,  # codes 0..6
            0x23B198C: 0x979FF103,  # indexed absolute branch
            0x23B1A28: 0xE3A03018,  # code 4: ratio component 24
            0x23B1A2C: 0xE1C431B4,
            0x23B1A30: 0xE3A03041,  # code 4: ratio component 65
            0x23B1A34: 0xE1C431B6,
        },
        "secondary_ratio_descriptor_gfx_subtype2_record_words": {
            0x2335E74: 0xE5D63001,  # GFX constructor reads input record +1
            0x2335E78: 0xE3530005,  # subtype 5 branches separately
            0x2336058: 0xE5D63001,  # second input-record subtype read
            0x233605C: 0xE3530002,  # only subtype 2 reaches ratio wrapper
            0x2336060: 0x0A00002C,
            0x2336130: 0xEBFFC7A7,  # subtype-2 block calls 0x02327fd4
            0x2328090: 0xEB02248C,  # wrapper calls 0x023b12c8 ratio builder
            0x2390710: 0x13A0102B,  # shared route uses ordinary key 43
            0x2390718: 0xEBFFCC75,  # record lookup wrapper 0x023838f4
            0x23838FC: 0xE5900000,  # working-state pointer
            0x2383900: 0xE280002C,  # object ID at +0x2c
            0x2383904: 0xEBFE76D6,  # selector 0x02321464
            0x23213D4: 0xE240001B,  # key - 27
            0x23213D8: 0xE30E35B0,  # bank selector 0x039de5b0
            0x23213DC: 0xE340339D,
            0x23213E0: 0xE5D32000,
            0x23213E4: 0xE3A03E5F,  # bank stride 0x5f0
            0x23213EC: 0xE3A02014,  # key stride 20
            0x23213F4: 0xE30C3D44,  # header base 0x0279cd44
            0x23213F8: 0xE3403279,
            0x23214BC: 0xC3A03030,  # selected record stride 48
            0x23214C4: 0xC2433030,
        },
        "secondary_ratio_descriptor_gfx_builder_bl_sites_expected": [0x2328090],
        "secondary_ratio_descriptor_gfx_wrapper_bl_sites_expected": [0x2336130],
        "secondary_ratio_descriptor_gfx_constructor_bl_sites_expected": [
            0x2385168, 0x2390630, 0x23908BC,
        ],
        "secondary_ratio_descriptor_record_stride": 48,
        "secondary_ratio_descriptor_record_bank_headers_0_to_7": [
            {"bank": 0, "address": 0x279CE84, "count": 311, "pointer": 0x27AAB60, "subtypes": {0: 311}},
            {"bank": 1, "address": 0x279D474, "count": 0, "pointer": 0, "subtypes": {}},
            {"bank": 2, "address": 0x279DA64, "count": 1, "pointer": 0x27A6D50, "subtypes": {0: 1}},
            {"bank": 3, "address": 0x279E054, "count": 0, "pointer": 0, "subtypes": {}},
            {"bank": 4, "address": 0x279E644, "count": 0, "pointer": 0, "subtypes": {}},
            {"bank": 5, "address": 0x279EC34, "count": 0, "pointer": 0, "subtypes": {}},
            {"bank": 6, "address": 0x279F224, "count": 1, "pointer": 0x27A61E0, "subtypes": {0: 1}},
            {"bank": 7, "address": 0x279F814, "count": 1, "pointer": 0x27B0560, "subtypes": {0: 1}},
        ],
        "dimension_lookup_width_words": {
            0x1341D98: 0xE3510004,  # explicit aspect code 4
            0x1341D9C: 0x03A02004,
            0x1341DBC: 0xE30D36B4,  # width-table low half
            0x1341DC0: 0xE340317C,  # width-table high half
            0x1341DC4: 0xE0820180,  # row*8 + aspect
            0x1341DC8: 0xE7930100,
        },
        "dimension_lookup_height_words": {
            0x1341F08: 0xE3510004,  # explicit aspect code 4
            0x1341F0C: 0x03A02004,
            0x1341F2C: 0xE30D39B4,  # height-table low half
            0x1341F30: 0xE340317C,
            0x1341F34: 0xE0820180,
            0x1341F38: 0xE7930100,
        },
        "primary_table": 0x574AC8,
        "primary_sha256": "bdf51193cb11c5851827dcb22c33ce3fcae59b9fd1823fad44fe92ecf1402263",
        "secondary_header": 0x620060,
        "secondary_sha256": "a7f24cabf6b8b5c002a7702ed6f74da7105ab02934868f4631dddaf5ba0c1d7b",
        "develop_aspect_jump_offset": 0x3FAA00,
        "develop_aspect_jump_count": 21,
        "develop_aspect_dispatch_words": {
            0x23B69F0: 0xE2413001,
            0x23B69F4: 0xE3530014,  # 21-entry bound
            0x23B69F8: 0x979FF103,
            0x23B69FC: 0xEA000029,
            0x23B6A54: 0xE3A03001,  # first case starts immediately after table
        },
        "develop_aspect_builder_words": {
            0x23B54D0: 0xE3A03007,
            0x23B54D4: 0xE5843205,
            0x23B54D8: 0xE5D538D8,  # source state +0x8d8
            0x23B54E0: 0x03A03012,  # 18 when state == 3
            0x23B54E4: 0x05843209,
            0x23B54EC: 0xE3530004,
            0x23B54F0: 0x03A03007,  # 7 when state == 4
            0x23B54F4: 0x13A0300E,  # otherwise 14
            0x23B54F8: 0xE5843209,
        },
        "develop_aspect_builder_seed_inputs": [7, 14, 18],
        "develop_aspect_targets": {
            0x23B6A54: 1, 0x23B6A60: 2, 0x23B6A6C: 3,
            0x23B6A78: 0, 0x23B6A84: 4, 0x23B6A90: 5, 0x23B6A9C: 6,
        },
        "secondary_load": 0x1FBC000,
        "vg_geometry_table": 0x2798D1C,
        "vg_geometry_words": {
            0x22FE940: 0xE35C0006,  # aspect <= 6
            0x22FE95C: 0x022FEA2C,  # aspect 4 jump-table target
            0x22FEA2C: 0xE3A03004,  # aspect 4 -> row 4
            0x22FE970: 0xE3085D1C,  # matching 32-byte record table
            0x22FE974: 0xE3405279,
            0x22FE980: 0xE08C3003,  # family * 17 + row
            0x22FE984: 0xE1A0C283,  # record stride 32
            0x22FE98C: 0xE1D360B8,  # inner rectangle x
            0x22FE9A4: 0xE1D360BE,  # inner rectangle height
        },
        "preview_key_table": 0x17CC338,
        "preview_key_count": 99,
        "dimension_estimate_coeff_table": 0x1896818,
        "dimension_estimate_coeff_count": 228,
        "dimension_estimate_target_rows_expected": list(range(72, 90)),
        "dimension_estimate_coeff_words": {
            0x134CE3C: 0xE3068818,  # 228 x 16-byte coefficient records
            0x134CE48: 0xE599000C,  # property key at record +12
            0x134CE50: 0xE5C90007,  # runtime coefficient replaces record +7
            0x134CE58: 0xE3570D39,  # loop bound 3648 bytes
            0x134CEB4: 0xE1520005,  # match width
            0x134CEC0: 0xE15C0006,  # match height
            0x134CEF4: 0xE5D03007,  # runtime coefficient byte
            0x134CF24: 0xE0810692,  # width-height coefficient product
        },
        "preview_lookup_bypass_primary_words": {
            0x133696C: 0xE5D33042,  # GFX preview global +0x42
            0x1336970: 0xE3530001,
            0x13369B8: 0xE5C43071,  # constructor publishes preview +0x71
            0x1340364: 0xE3500001,  # same table bypass predicate
            0x1340368: 0x0A000014,
        },
        "preview_lookup_bypass_secondary_words": {
            0x2316BF4: 0xE5DC0071,  # GFX caller passes preview +0x71 as r0
            0x2316C00: 0xEBC0A5F0,
        },
        "preview_bypass_global_accessor_words": {
            0x1337908: 0xE30B3F40,  # global base 0x01babf40
            0x133790C: 0xE34031BA,
            0x1337910: 0xE5D30042,  # direct getter for +0x42
            0x1337948: 0xE30B3F40,
            0x133794C: 0xE34031BA,
            0x1337950: 0xE5C30042,  # direct setter for +0x42
        },
        "preview_lookup_words": {
            0x1340378: 0xE30C4338,  # 8-byte key table address
            0x134037C: 0xE340417C,
            0x1340388: 0xE3500063,  # 99 rows; miss returns 99
            0x1340394: 0xE7D4E180,  # compare first key byte
            0x13403A4: 0xE5DCE001,  # compare second key byte
            0x13403B0: 0xE5DCC002,  # compare preview-state +0x70
            0x13403E0: 0xE3500062,  # wrapper accepts indices 0..98
            0x13403E8: 0xEAFFFFFE,  # missing key enters fail loop
            0x134064C: 0xE1D320B4,  # selected row width
            0x1340650: 0xE1C420B2,  # descriptor +2
            0x1340654: 0xE1D330B6,  # selected row height
            0x1340658: 0xE1C430B4,  # descriptor +4
            0x133E798: 0xEB003895,  # hand populated descriptor to processor
            0x134CA4C: 0xE1D180B2,  # processor reads descriptor width
            0x134CA50: 0xE1D120B4,  # processor reads descriptor height
        },
        "preview_descriptor_dual_lookup_primary_words": {
            0x133E704: 0xE3A04000,  # loop-zero value
            0x133E72C: 0xE1A06004,  # retained zero for second descriptor lookup
            0x133E780: 0xEB00079F,  # first descriptor-to-dimension lookup
            0x133E798: 0xEB003895,  # first dimension processor call
            0x133E7B8: 0xE54B6096,  # force second descriptor bypass byte to zero
            0x133E7C8: 0xEB00078D,  # second descriptor-to-dimension lookup
            0x133E7D8: 0xEB003885,  # second dimension processor call
            0x1340630: 0xEBFFFF64,  # both use GFX's 99-row preview key table
        },
        "preview_state_producer_primary_words": {
            0x1335748: 0xE30B3F40,  # getter targets global 0x01babf40
            0x1335750: 0xE5D30016,  # getter reads global +0x16
            0x1335768: 0xE30B3F40,  # setter targets same global
            0x1335770: 0xE5C30016,  # setter writes global +0x16
            0x13368C0: 0xE92D4830,  # preview-state constructor entry
            0x1336990: 0xE5D52016,  # read global +0x16
            0x1336994: 0xE5C42070,  # copy into destination +0x70
        },
        "preview_state_producer_secondary_words": {
            0x2310DEC: 0xE591178C,  # load active preview-state pointer
            0x2310DF0: 0xE5821008,  # cache pointer at 0x03823270+8
            0x23116DC: 0xE5934008,  # retrieve cached active pointer
            0x2311788: 0xE1A00004,  # pass it to constructor
            0x231178C: 0xEBC0944B,  # cross-partition constructor call
        },
        "preview_state_source_global": 0x01BABF56,
        "preview_lookup_caller_words": {
            0x2316BE4: 0xE595C78C,  # shared preview-state pointer
            0x2316BE8: 0xE5DC3070,  # preview row code
            0x2316BFC: 0xE58DC000,  # fifth tuple field
            0x2316C00: 0xEBC0A5F0,  # cross-partition lookup
        },
        "preview_pointer_array_id200_publication_words": {
            0x2308180: 0xE92D4870,  # homologous publisher entry
            0x2308194: 0xE1D310B0,  # temporary-block ID
            0x2308198: 0xE3510C02,  # requires ID 0x200
            0x230819C: 0x0A000002,
            0x23081B4: 0xE593000C,  # first payload word
            0x23081C0: 0xE5931010,  # second payload word
            0x23081C8: 0xE5933014,  # third payload word
            0x23081CC: 0xE5823790,  # array base at shared global +0x790
            0x2316BDC: 0xE1A04000,  # first caller argument retained in r4
            0x2316C04: 0xE1A09000,  # lookup row retained in r9
            0x2316CB4: 0xE5932790,  # load published array base
            0x2316CB8: 0xE3A03063,  # 99-row plane stride
            0x2316CBC: 0xE0299493,  # row + 99 * first argument
            0x2316CC0: 0xE2899004,  # four-entry prefix
            0x2316CC4: 0xE7921109,  # select runtime pointer
        },
        "vg_selector_source_words": {
            0x22FE904: 0xE5DBC004,  # selector reads first stack argument as row code
            0x22FEB10: 0xE5D20070,  # preview state +0x70 supplies row code
            0x22FEB20: 0xE2033202,  # graphics-mode bit gate
            0x22FEB28: 0x13A00001,  # may override row code with one
            0x22FEB4C: 0xE58D0000,  # preview row code -> first stack argument
            0x22FEB54: 0xEBFFFF68,  # selector call
        },
        "recbf_script_table_address": 0x27BC2A4,
        "recbf_script_count": 47,
        "recbf_script_terminator": 0x7C,
        "recbf_copy_crop_raw_command": 0x19,
        "recbf_resize_yc_command": 0x1A,
        "recbf_copy_crop_raw_modes": [3, 26, 39, 41],
        "recbf_resize_yc_modes": [28, 40, 42],
        "recbf_short_crop_event_id": 71,
        "recbf_short_crop_mode": 26,
        "recbf_short_crop_script": bytes.fromhex("19 1b 7b 7c"),
        "recbf_short_crop_builder": 0x2369AE0,
        "recbf_short_crop_builder_bl_count": 34,
        "recbf_short_crop_dispatch_span": (0x237A274, 0x237ABB0),
        "recbf_short_crop_data_words": {
            0x27B6D58: 71,  # event descriptor ID
            0x27B6D6C: 0x237A274,  # event callback
            0x237A328: 0x237A8F0,  # event-71 dispatch slot
            0x27B9AF0: 15, 0x27B9AF4: 0x27B8A80,
            0x27B9AF8: 13, 0x27B9AFC: 0x27B8B74,
            0x27B9B28: 31, 0x27B9B2C: 0x27B8FB8,
            0x27B9B30: 33, 0x27B9B34: 0x27B90B4,
            0x27B8B98: 71, 0x27B8B9C: 0,  # group-13 event has no secondary predicate
            0x27B8AA4: 71, 0x27B8AA8: 0,  # group-15 event has no secondary predicate
            0x27B8FD0: 71, 0x27B8FD4: 0,  # group-31 event has no secondary predicate
            0x27B90B4: 71, 0x27B90B8: 0,  # group-33 event has no secondary predicate
            0x27BB250: 0x23728E4,  # indexed callback entry 13
            0x27BB260: 0,  # entry 15 has no direct function
            0x27BB2E0: 0x2373180,  # indexed callback entry 31
            0x27BB2F0: 0,  # entry 33 has no direct function
            0x27BC944: 0x0266DF84,  # command 0x1b shares YC-resize name
        },
        "recbf_short_crop_group_pointers": {
            15: 0x27B8A80, 13: 0x27B8B74,
            31: 0x27B8FB8, 33: 0x27B90B4,
        },
        "recbf_short_crop_gfx_prerequisite_words": {
            0x27B8AAC: 0x27B8B34,  # group 15 event-71 list
            0x27B8B34: 114, 0x27B8B38: 0xFFFFFFFF,
            0x27B8BA0: 0x27B8C28,  # group 13 event-71 list
            0x27B8C28: 114, 0x27B8C2C: 0xFFFFFFFF,
            0x27B8FD8: 0x27B9074,  # group 31 event-71 list
            0x27B9074: 239, 0x27B9078: 0xFFFFFFFF,
            0x27B90BC: 0x27B9138,  # group 33 event-71 list
            0x27B9138: 114, 0x27B913C: 0xFFFFFFFF,
            0x27BA9D4: 0x00219240,  # message command 0x9240, subtype 0x21
            0x27BA9D8: 46,  # wildcard selector
            0x27BA9DC: 114,  # bit ID
            0x27BA9E0: 0,  # no callback
            0x27BB1A4: 0,  # message-table terminator
        },
        "recbf_short_crop_gfx_message_writer_words": {
            0x2364C48: 0xE30A3004,  # receiver scans table at 0x027ba004
            0x2364C4C: 0xE340327B,
            0x2364C80: 0xE3090240,  # special command 0x9240
            0x2364CB4: 0xE1D230B2,  # compare table subtype
            0x2364CC4: 0xE353002E,  # selector 46 bypasses extra comparison
            0x2364D0C: 0xE0833204,  # 16-byte table stride
            0x2364ED8: 0xE5931008,  # bit ID from table row
            0x2364FCC: 0xEB00F258,  # set bit in an in-range slot
        },
        "recbf_short_crop_route_words": {
            0x237A8F0: 0xE3A0101A,  # request script mode 26
            0x237A8F4: 0xEBFFBC79,  # call request builder
            0x2369B48: 0xE1A01006,  # builder forwards mode
            0x235C7F0: 0xE5C45000,  # request byte 0 = script mode
            0x2382220: 0xE5D03000,  # sender reads that byte
        },
        "recbf_copy_crop_raw_strings": {
            0x266DF58: b"\x81\xa1recbfCopyCropRaw\0",
        },
        "recbf_copy_crop_raw_record_words": {
            0x27BC8FC: 0x266DF58,  # GFX table points to the same named stage
            0x27BC908: 0x00320019,  # command 0x19
            0x27BC914: 0x00000009,  # same record type 9
        },
        "recbf_geometry_event_words": {
            0x235E358: 0xE5D038DA,  # sender reads working-state aspect +0x8da
            0x235E35C: 0xE54B3014,  # places aspect in payload +4
            0x235E348: 0xE3700001,  # -1 selects fallback route
            0x235E3BC: 0xEBBF5EC1,  # fallback checks global gate
            0x235E3C4: 0x03A03000,  # gate value one forces payload code zero
            0x235E3D0: 0xEBBF5CDA,  # otherwise read global +0x16
            0x235E3D4: 0xE54B0014,  # copy it to payload +4
            0x235E3A0: 0xEB0090E1,  # calls event wrapper
            0x2382754: 0xE3013243,  # event ID 0x1243
            0x239494C: 0xE1D030B0,  # dispatcher reads event ID
            0x2394968: 0x02394984,  # case 1, event 0x1243
            0x2394988: 0xEBFFFF58,  # receiver 0x23946f0
            0x2394770: 0xE5910020,  # baseline buffer width field
            0x2394778: 0xE1A02004,  # native code 0 (r4 initialized to zero)
            0x239477C: 0xE5911024,  # baseline buffer height field
            0x2394780: 0xE1A000A0,  # halve width before helper
            0x2394784: 0xEBBEB4C7,  # baseline call to primary ratio helper
            0x2394788: 0xE5D52004,  # read payload aspect
            0x239478C: 0xE1520004,  # native aspect code 0 or alternate
            0x2394810: 0xEBBEB4A4,  # helper with payload aspect
            0x23947CC: 0xEBFFAF56,  # submit even-rounded geometry
            0x237A500: 0xEBFF8F8D,  # handler case calls sender
        },
        "recbf_geometry_event_registration_words": {
            0x27B6B78: 0x00000033,  # event ID 51
            0x27B6B8C: 0x0237A274,  # handler callback
            0x237A2D8: 0x0237A500,  # handler case 51 -> sender
        },
        "recbf_geometry_event_registration_id": 51,
        "develop_aspect_copy_words": {
            0x236C0A0: 0xE24B2034,  # converter output = frame - 0x34
            0x236C0B0: 0xEB0129C2,  # call converter
            0x236C1BC: 0xE24B1034,  # same buffer passed to initializer
            0x236C1C4: 0xEB00A1FC,
            0x2394A54: 0xE1A0100C,  # initializer forwards buffer
            0x2394A5C: 0xEB0079FF,
            0x23B33A8: 0xE5D13002,  # load output byte +2
            0x23B33AC: 0xE5C438DA,  # store in working state +0x8da
        },
        "geometry_code4_branch": True,
        "geometry_aspect_words": {
            0x232611C: 0xE5D438DA,  # read working-state aspect
            0x2326130: 0xE3530004,  # explicit code-4 branch
            0x2326134: 0x0A000025,
            0x23261D0: 0xE3A06018,  # 24 * width / 65
            0x23261D4: 0xE0060596,
            0x23261D8: 0xE30E207F,
            0x23261DC: 0xE3472E07,  # high half of /65 magic multiplier
            0x23261E0: 0xE0C32296,
            0x23261E4: 0xE1A06FC6,
            0x23261E8: 0xE06662C3,
            0x2326190: 0xE3510004,  # second explicit code-4 branch
            0x2326194: 0x0A000060,
            0x232631C: 0xE3A0C018,  # second 24 * width / 65
            0x2326320: 0xE00C009C,
            0x2326324: 0xE30E207F,
            0x2326328: 0xE3472E07,
            0x232632C: 0xE0C3229C,
            0x2326330: 0xE1A0CFCC,
            0x2326334: 0xE06C32C3,
        },
        "movie_geometry_caller_words": {
            0x23BD728: 0xEBFDA24F,  # recmvr geometry call
            0x23BD8F0: 0xE30008E0,  # diagnostic string low half
            0x23BD8F4: 0xE340027C,  # diagnostic string high half
            0x23C3D4C: 0xE3000A18,  # recmvs diagnostic string low half
            0x23C3D50: 0xE340027C,  # diagnostic string high half
            0x23C3D6C: 0xE3000A30,  # second diagnostic string low half
            0x23C3D70: 0xE340027C,  # diagnostic string high half
            0x23C4230: 0xEBFD878D,  # recmvs geometry call
        },
        "movie_geometry_diagnostic_strings": {
            0x27C08E0: b"recmvrSetSaclaCaptureInfo()\0",
            0x27C0A18: b"recmvsGetEmptyIndex()\0",
            0x27C0A30: b"recmvsCreateFrameInfo()\0",
        },
        "movie_geometry_caller_addresses": [0x23BD728, 0x23C4230],
        "movie_descriptor_caller_words": {
            0x23C8E00: 0xEBFD97B9,  # movie backup route calls descriptor wrapper
            0x23C8E1C: 0xE3020ABC,  # diagnostic string low half
            0x23C8E20: 0xE340027C,  # diagnostic string high half
        },
        "movie_descriptor_diagnostic_strings": {
            0x27C2ABC: b"recmvbkCalcMetaParam()\0",
        },
        "movie_descriptor_caller_addresses": [0x23C8E00],
        "descriptor_code4_branch": True,
        "descriptor_words": {
            0x232CED0: 0xE595383C,  # geometry field -> descriptor +0x30
            0x232CED4: 0xE5843030,
            0x232CF0C: 0xE5D538DA,  # aspect -> descriptor +0x4d
            0x232CF10: 0xE5C4304D,
            0x232EEF4: 0xEBFFF778,  # pack descriptor
            0x232EF18: 0xE1A00006,  # pass output descriptor to processor
            0x232EF1C: 0xEBFFFB83,
            0x232E85C: 0xE5D6204E,  # subtype gate before aspect arithmetic
            0x232E860: 0xE3520006,
            0x232E864: 0x0A000002,
            0x232E874: 0xE5D6304D,  # processor reads aspect
            0x232E888: 0xE3530004,  # code 4: 24 * width / 65
            0x232E890: 0x03A03018,
            0x232E894: 0x00030293,
            0x232E898: 0x030C20FD,
            0x232E89C: 0x034F2C0F,
            0x232E8A0: 0x00832392,
            0x232E8A4: 0x01A03323,
        },
    },
}
ASPECT_65_24_ROWS = {4: 0, 11: 1, 18: 2}  # image-size IDs -> O/P/Q
Q16_65_24 = round((65 / 24) * 65536)


def decode_partition(payload: bytes, offset: int) -> bytes:
    if offset + 20 > len(payload):
        raise ValueError("partition header outside payload")
    output_size, packed_size, blocks, block_size, flags = struct.unpack_from("<5I", payload, offset)
    if block_size != 0x4000 or flags != 4:
        raise ValueError("unexpected partition header variant")
    if packed_size < 20 or blocks != (packed_size + block_size - 1) // block_size:
        raise ValueError("transfer block count does not match compressed size")
    start = offset + 20
    end = offset + packed_size
    if end > len(payload):
        raise ValueError("compressed partition outside payload")
    return lzss_decode(payload[start:end], output_size)


def read_raw_partition(payload: bytes, offset: int, size: int) -> bytes:
    if offset < 0 or size <= 0 or offset + size > len(payload):
        raise ValueError("raw partition outside payload")
    return payload[offset:offset + size]


def parse_primary_records(image: bytes, offset: int) -> list[dict]:
    records = []
    for index in range(24):
        row_offset = offset + 20 * index
        id_value, code, width, height, flags = struct.unpack_from("<5I", image, row_offset)
        records.append({
            "index": index,
            "partition_offset": row_offset,
            "id": id_value,
            "code": code,
            "width": width,
            "height": height,
            "flags": flags,
            "enabled_byte": flags & 0xFF,
        })
    if {row["id"] for row in records} != set(range(24)):
        raise ValueError("primary table does not contain each image-size ID 0..23 once")
    return records


def read_aspect_dimension_grid(
    image: bytes, load_address: int, table_address: int, size_levels: int, aspect_columns: int
) -> list[list[int]]:
    """Read a row-major size-level × aspect table from the decoded primary image."""
    offset = table_address - load_address
    if size_levels < 1 or aspect_columns < 1 or offset < 0 or offset + 4 * size_levels * aspect_columns > len(image):
        raise ValueError("aspect dimension grid outside primary partition")
    return [
        list(struct.unpack_from("<" + "I" * aspect_columns, image, offset + 4 * row * aspect_columns))
        for row in range(size_levels)
    ]


def read_initial_parameter_record_bank(
    image: bytes, load_address: int, header_address: int, record_stride: int = 28,
) -> dict:
    """Inspect one immutable record bank, not its runtime contents."""
    if record_stride < 2 or record_stride > 256:
        raise ValueError("parameter record stride outside bound")
    offset = header_address - load_address
    if offset < 0 or offset + 12 > len(image):
        raise ValueError("parameter record bank header outside partition")
    count = struct.unpack_from("<I", image, offset)[0]
    pointer = struct.unpack_from("<I", image, offset + 8)[0]
    if count > 512:
        raise ValueError("parameter record bank count outside bound")
    subtypes: dict[int, int] = {}
    if count:
        first = pointer - load_address
        if first < 0 or first + record_stride * count > len(image):
            raise ValueError("parameter record bank data outside partition")
        for index in range(count):
            subtype = image[first + record_stride * index + 1]
            subtypes[subtype] = subtypes.get(subtype, 0) + 1
    return {"count": count, "pointer": pointer, "subtypes": dict(sorted(subtypes.items()))}


def read_preview_key_table(image: bytes, load_address: int, table_address: int, count: int) -> list[dict]:
    """Read 8-byte state-to-dimension entries and their three compared key bytes."""
    offset = table_address - load_address
    if count < 1 or offset < 0 or offset + count * 8 > len(image):
        raise ValueError("preview key table outside primary partition")
    return [
        {
            "index": index,
            "key": list(image[offset + 8 * index:offset + 8 * index + 3]),
            "width": struct.unpack_from("<H", image, offset + 8 * index + 4)[0],
            "height": struct.unpack_from("<H", image, offset + 8 * index + 6)[0],
        }
        for index in range(count)
    ]


def preview_key_lookup_index(rows: list[dict], key: tuple[int, int, int], bypass: bool = False) -> int:
    """Model the pinned three-byte linear lookup; a miss returns len(rows).

    The primary wrapper spins on that miss. One secondary caller instead
    substitutes row zero. Neither behavior proves a live code-0 request.
    """
    if len(key) != 3 or any(not 0 <= value <= 255 for value in key):
        raise ValueError("preview key must be three bytes")
    if bypass:
        return 0
    return next((row["index"] for row in rows if row["key"] == list(key)), len(rows))


def addresses_share_4k_page(first: int, second: int) -> bool:
    """Compare a hypothetical 4 KiB mapping unit, not live MMU permissions."""
    if first < 0 or second < 0:
        raise ValueError("addresses must be nonnegative")
    return first // 4096 == second // 4096


def preview_parallel_extension_overlaps_next_array(
    first_word: int, original_count: int, proposed_count: int, next_array_first_word: int,
) -> list[int]:
    """Return added 32-bit word addresses at or beyond the next live array."""
    if first_word < 0 or next_array_first_word < 0 or first_word % 4 or next_array_first_word % 4:
        raise ValueError("parallel array addresses must be aligned and nonnegative")
    if original_count < 1 or proposed_count < original_count:
        raise ValueError("invalid parallel array counts")
    return [first_word + 4 * index for index in range(original_count, proposed_count)
            if first_word + 4 * index >= next_array_first_word]


def read_dimension_estimate_coeff_table(
    image: bytes, load_address: int, table_address: int, count: int
) -> list[dict]:
    """Read 16-byte width/height-keyed byte-count estimation records.

    The coefficient at +7 is overwritten at runtime from the key at +12;
    static bytes alone cannot establish the actual estimate.
    """
    offset = table_address - load_address
    if count < 1 or offset < 0 or offset + count * 16 > len(image):
        raise ValueError("dimension estimate table outside primary partition")
    rows = []
    for index in range(count):
        width, height, category, mode, selector, initial_coeff, divisor, property_key = struct.unpack_from(
            "<HHBBBBII", image, offset + index * 16
        )
        rows.append({
            "index": index,
            "width": width,
            "height": height,
            "category": category,
            "mode": mode,
            "selector": selector,
            "initial_coefficient": initial_coeff,
            "divisor": divisor,
            "runtime_property_key": property_key,
        })
    return rows


def arm_smlabb_record_index(first_selector: int, stride: int, second_selector: int) -> int:
    """Model the dispatcher's signed-low-halfword MLA followed by UXTH.

    This calculates a static condition, not a camera-observed selector value.
    """
    if any(not 0 <= value <= 0xFFFF for value in (first_selector, stride, second_selector)):
        raise ValueError("callback selectors and stride must be 16-bit values")

    def signed16(value: int) -> int:
        return value if value < 0x8000 else value - 0x10000

    return (signed16(first_selector) * signed16(stride) + second_selector) & 0xFFFF


def plan_x100v_preview_code4_row_reuse(
    image: bytes, load_address: int, table_address: int, count: int
) -> list[dict]:
    """Plan, but do not apply, six in-place still-size 16:9 -> 65:24 row edits.

    Heights are conditional candidates: ceil(width * 24 / 65) to an 8-pixel
    boundary, matching X100V's three observed 16:9 still-size rows. This
    does not establish a live-view sink or saved-file dimensions.
    """
    if count != 57:
        raise ValueError("X100V preview row-reuse plan requires 57 source rows")
    rows = read_preview_key_table(image, load_address, table_address, count)
    if any(row["key"][2] == 4 for row in rows):
        raise ValueError("source preview table already contains code-4 rows")
    source_heights = (3512, 2488, 1760)
    widths = (6240, 4416, 3120)
    result = []
    for level, (width, source_height) in enumerate(zip(widths, source_heights)):
        target_height = ((width * 24 + 65 * 8 - 1) // (65 * 8)) * 8
        matching = [row for row in rows if row["key"][0] == level and row["key"][2] == 2]
        if sorted(row["key"][1] for row in matching) != [0, 1]:
            raise ValueError(f"size level {level}: expected two 16:9 key variants")
        for row in sorted(matching, key=lambda item: item["index"]):
            if [row["width"], row["height"]] != [width, source_height]:
                raise ValueError(f"size level {level}: 16:9 reference dimensions changed")
            address = table_address + 8 * row["index"]
            offset = address - load_address
            original = image[offset:offset + 8]
            proposed = bytearray(original)
            proposed[2] = 4
            struct.pack_into("<H", proposed, 6, target_height)
            changes = [
                {"address": address + i, "before": original[i], "after": proposed[i]}
                for i in range(8) if original[i] != proposed[i]
            ]
            result.append({
                "index": row["index"],
                "key_before": row["key"],
                "key_after": [level, row["key"][1], 4],
                "width": width,
                "height": target_height,
                "source_hex": original.hex(),
                "candidate_hex": proposed.hex(),
                "changes": changes,
            })
    return result


def plan_x100v_preview_code4_zero_placeholder_reuse(image: bytes, source: dict) -> list[dict]:
    """Plan code-4 keys over six zero-dimension code-0 still placeholders.

    This preserves code-2 (16:9) keys and the 57-row count, but whether code-0
    placeholder keys are needed at runtime is unknown. It is not a safe patch.
    """
    load = source["primary_load"]
    table = source["preview_key_table"]
    if source["preview_key_count"] != 57:
        raise ValueError("X100V placeholder reuse requires 57 preview rows")
    records = parse_primary_records(image, source["primary_table"])
    code0 = sorted((row["code"] & 0xFF, row["enabled_byte"])
                   for row in records if row["code"] >> 8 == 0)
    if code0 != [(0, 0), (1, 0), (2, 0)]:
        raise ValueError("X100V code-0 still-size records are not all disabled")
    rows = read_preview_key_table(image, load, table, 57)
    if any(row["key"][2] == 4 for row in rows):
        raise ValueError("X100V preview table already has code-4 rows")
    widths = [pair[0] for pair in source["dimension_lookup_reference_code1"]]
    candidate_rows = [{**row, "key": row["key"][:]} for row in rows]
    result = []
    for level, width in enumerate(widths):
        height = ((width * 24 + 65 * 8 - 1) // (65 * 8)) * 8
        for variant in (1, 0):
            matching = [row for row in rows if row["key"] == [level, variant, 0]]
            if len(matching) != 1 or matching[0]["width"] != 0 or matching[0]["height"] != 0:
                raise ValueError("X100V code-0 preview placeholder differs")
            row = matching[0]
            address = table + 8 * row["index"]
            offset = address - load
            original = image[offset:offset + 8]
            proposed = bytearray(original)
            proposed[2] = 4
            struct.pack_into("<HH", proposed, 4, width, height)
            candidate_rows[row["index"]]["key"][2] = 4
            result.append({
                "index": row["index"],
                "key_before": row["key"],
                "key_after": [level, variant, 4],
                "width": width,
                "height": height,
                "source_hex": original.hex(),
                "candidate_hex": proposed.hex(),
                "changes": [
                    {"address": address + index, "before": original[index], "after": proposed[index]}
                    for index in range(8) if original[index] != proposed[index]
                ],
            })
    for row in result:
        old_key = tuple(row["key_before"])
        new_key = tuple(row["key_after"])
        if preview_key_lookup_index(rows, old_key) != row["index"]:
            raise ValueError("X100V code-0 preview key is not uniquely indexed")
        if preview_key_lookup_index(candidate_rows, old_key) != len(rows):
            raise ValueError("X100V old code-0 preview key unexpectedly survives")
        if preview_key_lookup_index(candidate_rows, new_key) != row["index"]:
            raise ValueError("X100V new code-4 preview key is not uniquely indexed")
        row["old_key_nonbypass_after_index"] = len(rows)
        row["old_key_bypass_after_index"] = 0
    return result


def plan_x100v_size_and_raw_crop_lookup_data(image: bytes, source: dict) -> list[dict]:
    """Plan exact-old-byte edits in decoded primary data; never write an update.

    These rows make the dormant aspect-4 sizes internally consistent with the
    RAW-crop dimension grids. The proposed heights are *candidates*, rounded
    upward to eight pixels; this does not establish finder or file behavior.
    The patched ARM helper instead rounds down to four pixels, producing
    medium height 1628 rather than this plan's 1632. Stock GFX also has
    helper/table differences at L/S, so equality is not an established
    invariant. Consumer semantics remain unresolved; table agreement alone
    does not prove matching saved-image geometry.
    """
    load = source["primary_load"]
    records = parse_primary_records(image, source["primary_table"])
    columns = source["dimension_lookup_columns"]
    if columns != 5:
        raise ValueError("X100V code-4 data plan requires five dimension columns")
    widths = read_aspect_dimension_grid(image, load, source["dimension_lookup_width"], 3, columns)
    heights = read_aspect_dimension_grid(image, load, source["dimension_lookup_height"], 3, columns)
    reference = source["dimension_lookup_reference_code1"]
    if [[widths[level][1], heights[level][1]] for level in range(3)] != reference:
        raise ValueError("X100V code-4 data plan: reference dimensions changed")
    if any(widths[level][4] or heights[level][4] for level in range(3)):
        raise ValueError("X100V code-4 data plan: target lookup cells are occupied")

    writes: list[dict] = []

    def add(label: str, offset: int, expected: bytes, replacement: bytes) -> None:
        if offset < 0 or offset + len(expected) > len(image) or len(expected) != len(replacement):
            raise ValueError(f"{label}: invalid patch extent")
        if image[offset:offset + len(expected)] != expected:
            raise ValueError(f"{label}: expected old bytes differ")
        if expected != replacement:
            writes.append({
                "field": label,
                "partition_offset": offset,
                "address": load + offset,
                "before_hex": expected.hex(),
                "after_hex": replacement.hex(),
            })

    for size_id, level in ASPECT_65_24_ROWS.items():
        record = next(row for row in records if row["id"] == size_id)
        if (record["code"], record["width"], record["height"], record["enabled_byte"]) != (
            (4 << 8) | level, 3120, 2080, 0
        ):
            raise ValueError(f"X100V code-4 data plan: size ID {size_id} changed")
        width = reference[level][0]
        height = ((width * 24 + 65 * 8 - 1) // (65 * 8)) * 8
        row_offset = record["partition_offset"]
        add(f"size-{size_id}-width", row_offset + 8, struct.pack("<I", 3120), struct.pack("<I", width))
        add(f"size-{size_id}-height", row_offset + 12, struct.pack("<I", 2080), struct.pack("<I", height))
        add(f"size-{size_id}-enabled", row_offset + 16, b"\x00", b"\x01")
        grid_index = 4 * (level * columns + 4)
        add(
            f"crop-width-{level}", source["dimension_lookup_width"] - load + grid_index,
            struct.pack("<I", 0), struct.pack("<I", width),
        )
        add(
            f"crop-height-{level}", source["dimension_lookup_height"] - load + grid_index,
            struct.pack("<I", 0), struct.pack("<I", height),
        )
    occupied: set[int] = set()
    for write in writes:
        extent = set(range(write["partition_offset"], write["partition_offset"] + len(bytes.fromhex(write["before_hex"]))))
        if occupied.intersection(extent):
            raise ValueError("X100V code-4 data plan: overlapping writes")
        occupied.update(extent)
    return writes


def read_vg_geometry_record(
    image: bytes, load_address: int, table_address: int, family: int, row: int
) -> dict[str, list[int]]:
    """Read the first 24 bytes of a 17-row, 32-byte VG geometry record."""
    offset = table_address - load_address + (17 * family + row) * 32
    if family not in range(3) or row not in range(17) or offset < 0 or offset + 32 > len(image):
        raise ValueError("VG geometry record outside secondary partition")
    fields = struct.unpack_from("<12H", image, offset)
    return {
        "outer": list(fields[0:4]),
        "inner": list(fields[4:8]),
        "source": list(fields[8:12]),
    }


def read_vg_selector_jump_rows(
    image: bytes, load_address: int, table_address: int, count: int = 7
) -> list[int]:
    """Decode an ARM pointer table whose targets begin with `mov r3,#row`."""
    table_offset = table_address - load_address
    if count <= 0 or table_offset < 0 or table_offset + 4 * count > len(image):
        raise ValueError("VG selector table outside partition")
    rows = []
    for index in range(count):
        target = struct.unpack_from("<I", image, table_offset + 4 * index)[0]
        instruction_offset = target - load_address
        if instruction_offset < 0 or instruction_offset + 4 > len(image):
            raise ValueError("VG selector target outside partition")
        word = struct.unpack_from("<I", image, instruction_offset)[0]
        if (word & 0xFFFFFF00) != 0xE3A03000 or (word & 0xFF) >= 17:
            raise ValueError("VG selector target is not a bounded row assignment")
        rows.append(word & 0xFF)
    return rows


def read_vg_channel_routes(
    image: bytes, load_address: int, descriptors_address: int, context_table_address: int
) -> list[dict[str, int]]:
    """Read three static descriptor IDs and their two-byte context-map entries."""
    descriptors_offset = descriptors_address - load_address
    context_offset = context_table_address - load_address
    if descriptors_offset < 0 or descriptors_offset + 3 * 16 > len(image) or context_offset < 0:
        raise ValueError("VG channel routing outside primary partition")
    routes = []
    for index in range(3):
        descriptor_id = image[descriptors_offset + 16 * index]
        mapped_offset = context_offset + 2 * descriptor_id + 1
        if mapped_offset >= len(image):
            raise ValueError("VG channel context map outside primary partition")
        routes.append({"descriptor_id": descriptor_id, "context_index": image[mapped_offset]})
    return routes


def read_crop_ratio_jump_target(image: bytes, load_address: int, helper_address: int, code: int) -> int:
    """Read a seven-entry ARM aspect dispatch target; this does not run geometry code."""
    if code not in range(1, 8):
        raise ValueError("crop ratio aspect code outside seven-way dispatch")
    offset = helper_address - load_address + 0x18 + 4 * (code - 1)
    if offset < 0 or offset + 4 > len(image):
        raise ValueError("crop ratio jump target outside primary partition")
    return struct.unpack_from("<I", image, offset)[0]


def encode_arm_unconditional_b(instruction_address: int, target_address: int) -> int:
    """Encode an ARM-state B immediate; addresses are absolute, not file offsets."""
    if instruction_address & 3 or target_address & 3:
        raise ValueError("ARM branch addresses must be word aligned")
    displacement = target_address - (instruction_address + 8)
    words = displacement // 4
    if not -(1 << 23) <= words < (1 << 23):
        raise ValueError("ARM branch target outside signed 24-bit reach")
    return 0xEA000000 | (words & 0xFFFFFF)


def scan_aligned_arm_cave_references(
    image: bytes, load_address: int, cave_start: int, cave_end: int
) -> dict[str, list[int]]:
    """Bounded scan of aligned literal words and ARM-state B/BL immediates.

    This excludes Thumb, indirect branches and constructed or relocated
    addresses; an empty result cannot establish that a code cave is free.
    """
    if cave_start & 3 or cave_end & 3 or cave_end <= cave_start:
        raise ValueError("invalid aligned code-cave interval")
    literals = []
    branches = []
    for offset in range(0, len(image) - 3, 4):
        word = struct.unpack_from("<I", image, offset)[0]
        address = load_address + offset
        if cave_start <= word < cave_end:
            literals.append(address)
        if ((word >> 25) & 7) == 5 and (word >> 28) != 15:
            displacement = word & 0xFFFFFF
            if displacement & 0x800000:
                displacement -= 0x1000000
            target = address + 8 + 4 * displacement
            if cave_start <= target < cave_end:
                branches.append(address)
    return {"literal_word_addresses": literals, "arm_b_bl_instruction_addresses": branches}


def plan_x100v_code4_ratio_stub(image: bytes, source: dict) -> dict:
    """Describe an isolated code-4 branch; do not modify any firmware bytes.

    The zero-filled candidate location is *not* proven executable or unused at
    runtime. This manifest is an investigation aid, not a boot-safe patch.
    """
    load = source["primary_load"]
    helper = source["crop_ratio_helper"]
    stub = source["crop_ratio_code4_stub_candidate"]
    pad_end = source["crop_ratio_code4_stub_pad_end"]
    default = source["crop_ratio_code4_target"]
    common = helper + 0x6C
    targets = [read_crop_ratio_jump_target(image, load, helper, code) for code in range(1, 8)]
    if targets != source["crop_ratio_dispatch_targets_expected"] or targets[3:6] != [default] * 3:
        raise ValueError("X100V ratio stub plan: original dispatch targets differ")
    for address, word in ((default, 0xE3A02003), (default + 4, 0xE3A0E004),
                          (common, 0xE00C0E91)):
        offset = address - load
        if offset < 0 or offset + 4 > len(image) or struct.unpack_from("<I", image, offset)[0] != word:
            raise ValueError("X100V ratio stub plan: original helper words differ")
    if (stub & 3 or pad_end & 3 or stub < load or pad_end > load + len(image)
            or pad_end - stub < 12 or helper <= stub < helper + 0x120):
        raise ValueError("X100V ratio stub plan: invalid candidate padding extent")
    if any(image[stub - load:pad_end - load]):
        raise ValueError("X100V ratio stub plan: candidate padding is occupied")
    words = [0xE3A02018, 0xE3A0E041, encode_arm_unconditional_b(stub + 8, common)]
    table_address = helper + 0x24
    writes = []
    for field, address, expected, replacement in (
        ("code-4-jump-target", table_address, struct.pack("<I", default), struct.pack("<I", stub)),
        ("code-4-ratio-stub", stub, bytes(12), struct.pack("<3I", *words)),
    ):
        offset = address - load
        if offset < 0 or offset + len(expected) > len(image) or image[offset:offset + len(expected)] != expected:
            raise ValueError(f"X100V ratio stub plan: {field} old bytes differ")
        writes.append({
            "field": field, "partition_offset": offset, "address": address,
            "before_hex": expected.hex(), "after_hex": replacement.hex(),
        })
    return {
        "writes": writes,
        "stub_words": [f"{word:#010x}" for word in words],
        "common_arithmetic_target": f"{common:#010x}",
        "unchanged_codes": [1, 2, 3, 5, 6, 7],
        "zero_padding_bytes_observed": pad_end - stub,
        "executable_mapping_verified": False,
        "runtime_reachability_verified": False,
    }


def read_arm_absolute_jump_table(
    image: bytes, load_address: int, table_address: int, count: int
) -> list[int]:
    """Read bounded absolute ARM branch targets, without inferring execution."""
    if count < 1 or count > 256 or table_address & 3:
        raise ValueError("invalid absolute jump-table bounds")
    offset = table_address - load_address
    if offset < 0 or offset + 4 * count > len(image):
        raise ValueError("absolute jump table outside partition")
    targets = list(struct.unpack_from(f"<{count}I", image, offset))
    if any(target & 3 or not load_address <= target < load_address + len(image) for target in targets):
        raise ValueError("absolute jump target outside partition")
    return targets


def find_q16_triplets(image: bytes, ratio_q16: int) -> list[dict]:
    """Find consecutive O/P/Q <uint16 width,height; uint32 ratio> rows."""
    marker = struct.pack("<I", ratio_q16)
    matches = []
    cursor = 0
    while True:
        marker_at = image.find(marker, cursor)
        if marker_at < 0:
            return matches
        cursor = marker_at + 1
        first = marker_at - 4
        if first < 0 or first + 24 > len(image):
            continue
        rows = [struct.unpack_from("<HHI", image, first + 8 * i) for i in range(3)]
        if all(row[2] == ratio_q16 and row[0] and row[1] for row in rows):
            matches.append({
                "partition_offset": first,
                "sizes": [[row[0], row[1]] for row in rows],
            })


def tables_consistent_and_enabled(selected: list[dict], ratio_rows: list[dict]) -> bool:
    primary_sizes = [[row["width"], row["height"]] for row in selected]
    return len(selected) == 3 and all(row["enabled_byte"] == 1 for row in selected) and any(
        found["sizes"] == primary_sizes for found in ratio_rows
    )


def select_enabled_size_id(records: list[dict], aspect: int, size_level: int) -> int | None:
    """Mirror the observed 24-row gate/code lookup, not camera execution."""
    for row in records:
        if row["enabled_byte"] != 1:
            continue
        if ((row["code"] >> 8) & 0xFF) == aspect and (row["code"] & 0xFF) == size_level:
            return row["id"]
    return None


def select_size_id_without_enabled_gate(records: list[dict], aspect: int, size_level: int) -> int | None:
    """Mirror the observed 24-row reverse lookup that does not read flags."""
    for row in records:
        if ((row["code"] >> 8) & 0xFF) == aspect and (row["code"] & 0xFF) == size_level:
            return row["id"]
    return None


def enabled_dimension_labels(records: list[dict]) -> list[dict]:
    """Mirror the observed enabled-row width-x-height list construction."""
    return [
        {"id": row["id"], "label": f'{row["width"]}x{row["height"]}'}
        for row in records if row["enabled_byte"] == 1
    ]


def decode_develop_aspect_jump_table(
    image: bytes, offset: int, count: int, target_outputs: dict[int, int]
) -> list[int]:
    """Read ARM jump-table targets with separately decoded case outputs."""
    if count < 1 or offset < 0 or offset + 4 * count > len(image):
        raise ValueError("develop-aspect jump table outside partition")
    targets = struct.unpack_from("<" + "I" * count, image, offset)
    unknown = set(targets) - target_outputs.keys()
    if unknown:
        raise ValueError(f"unknown develop-aspect jump target(s): {sorted(unknown)}")
    return [target_outputs[target] for target in targets]


def read_develop_aspect_case_outputs(
    image: bytes, load_address: int, case_addresses: dict[int, int]
) -> dict[int, int]:
    """Decode bounded ARM `mov r3,#code; strb r3,[r4,#2]; b` case bodies."""
    outputs = {}
    continuations = set()
    for address in case_addresses:
        offset = address - load_address
        if offset < 0 or offset + 12 > len(image):
            raise ValueError(f"develop-aspect case outside partition at {address:#x}")
        move, store, branch = struct.unpack_from("<III", image, offset)
        if move & 0xFFFFFF00 != 0xE3A03000 or store != 0xE5C43002 or branch & 0xFF000000 != 0xEA000000:
            raise ValueError(f"unexpected develop-aspect case body at {address:#x}")
        outputs[address] = move & 0xFF
        displacement = branch & 0xFFFFFF
        if displacement & 0x800000:
            displacement -= 0x1000000
        continuations.add(address + 16 + 4 * displacement)
    if len(continuations) != 1:
        raise ValueError("develop-aspect cases do not share a continuation")
    return outputs


def verify_hashed_ranges(image: bytes, load_address: int,
                         expected: dict[int, tuple[int, str]]) -> None:
    """Reject short/out-of-range slices as well as changed bytes."""
    for address, (size, digest) in expected.items():
        offset = address - load_address
        if size <= 0 or offset < 0 or offset + size > len(image):
            raise ValueError(f"hashed range outside image at {address:#x}")
        if hashlib.sha256(image[offset:offset + size]).hexdigest() != digest:
            raise ValueError(f"hashed range changed at {address:#x}")


def verify_arm_words(image: bytes, load_address: int, expected: dict[int, int]) -> None:
    """Pin observed ARM data-flow instructions to exact partition bytes.

    This only verifies a static instruction chain; it does not execute branches
    or establish a saved-file or finder consumer of the working-state field.
    """
    for address, word in expected.items():
        offset = address - load_address
        if offset < 0 or offset + 4 > len(image):
            raise ValueError(f"ARM instruction outside partition at {address:#x}")
        if struct.unpack_from("<I", image, offset)[0] != word:
            raise ValueError(f"ARM instruction mismatch at {address:#x}")


def verify_raw_partition_words(
    payload: bytes, offset: int, size: int, load: int,
    expected_digest: str, expected_words: dict[int, int],
) -> str:
    """Verify a bounded decoded raw extent and its static instructions only."""
    image = read_raw_partition(payload, offset, size)
    digest = hashlib.sha256(image).hexdigest()
    if digest != expected_digest:
        raise ValueError("raw partition digest mismatch")
    verify_arm_words(image, load, expected_words)
    return digest


def read_arm_bl_call_sites(image: bytes, load_address: int, target_address: int) -> list[int]:
    """Inventory aligned ARM BL sites to one target, including words in data.

    This is a bounded byte scan, not a function or reachability analysis. It
    excludes Thumb, BLX, register-indirect calls, and calls from other images.
    """
    if (load_address | target_address | len(image)) & 3:
        raise ValueError("ARM BL scan requires aligned addresses and image length")
    sites = []
    for offset in range(0, len(image), 4):
        word = struct.unpack_from("<I", image, offset)[0]
        if word >> 28 == 0xF or word & 0x0F000000 != 0x0B000000:
            continue
        displacement = word & 0xFFFFFF
        if displacement & 0x800000:
            displacement -= 0x1000000
        address = load_address + offset
        if address + 8 + 4 * displacement == target_address:
            sites.append(address)
    return sites


def verify_data_words(image: bytes, load_address: int, expected: dict[int, int]) -> None:
    """Pin static table/pointer values without treating them as instructions."""
    for address, word in expected.items():
        offset = address - load_address
        if offset < 0 or offset + 4 > len(image):
            raise ValueError(f"data word outside partition at {address:#x}")
        if struct.unpack_from("<I", image, offset)[0] != word:
            raise ValueError(f"data word mismatch at {address:#x}")


def read_indexed_dispatch_first_entries(
    image: bytes, load_address: int, table_address: int, entry_count: int
) -> list[dict[str, int]]:
    """Read one first ID/handler pair per state from a bounded pointer table.

    This does not enumerate later records in each state's list or prove that
    the runtime selects a state or dispatches a queued message.
    """
    if entry_count <= 0 or entry_count > 256 or table_address & 3:
        raise ValueError("invalid indexed dispatch table bounds")
    table_offset = table_address - load_address
    if table_offset < 0 or table_offset + entry_count * 4 > len(image):
        raise ValueError("indexed dispatch table outside partition")
    rows = []
    for state in range(entry_count):
        record_address = struct.unpack_from("<I", image, table_offset + state * 4)[0]
        record_offset = record_address - load_address
        if record_offset < 0 or record_offset + 8 > len(image):
            raise ValueError(f"indexed dispatch record outside partition for state {state}")
        message_id, handler = struct.unpack_from("<II", image, record_offset)
        rows.append({
            "state": state,
            "record_address": record_address,
            "message_id": message_id,
            "handler": handler,
        })
    return rows


def read_event_group_ids(image: bytes, load_address: int, address: int, max_entries: int = 64) -> list[int]:
    """Read a bounded array of 12-byte event subrecords, terminated by ID -1."""
    start = address - load_address
    if start < 0 or max_entries <= 0:
        raise ValueError("event group outside partition")
    ids = []
    for index in range(max_entries + 1):
        offset = start + index * 12
        if offset + 12 > len(image):
            raise ValueError("event group outside partition")
        event_id = struct.unpack_from("<I", image, offset)[0]
        if event_id == 0xFFFFFFFF:
            return ids
        if index == max_entries:
            raise ValueError("event group terminator missing")
        ids.append(event_id)
    raise AssertionError("unreachable event group bound")


def read_event_group_table(
    image: bytes, load_address: int, address: int,
    max_groups: int = 70, max_entries: int = 128,
) -> dict[int, list[int]]:
    """Read a bounded 8-byte group/pointer table and its 12-byte event arrays.

    This inventories static candidates only; it cannot establish enabled groups
    or events processed by other code paths.
    """
    start = address - load_address
    if start < 0 or max_groups <= 0:
        raise ValueError("event group table outside partition")
    groups = {}
    for index in range(max_groups + 1):
        offset = start + index * 8
        if offset + 8 > len(image):
            raise ValueError("event group table outside partition")
        group_id, pointer = struct.unpack_from("<II", image, offset)
        if group_id == 0xFFFFFFFF:
            return groups
        if index == max_groups:
            raise ValueError("event group table terminator missing")
        if group_id in groups:
            raise ValueError(f"duplicate event group {group_id}")
        groups[group_id] = read_event_group_ids(image, load_address, pointer, max_entries)
    raise AssertionError("unreachable event group table bound")


def read_recbf_message_bit_routes(
    image: bytes, load_address: int, address: int, max_entries: int = 300,
) -> list[dict[str, int]]:
    """Inventory 16-byte message rows terminated by command zero.

    Rows name candidate bit updates; this does not prove message delivery,
    selected slot, or a bit's value during a normal still capture.
    """
    start = address - load_address
    if start < 0 or max_entries <= 0:
        raise ValueError("Recbf message-bit table outside partition")
    rows = []
    for index in range(max_entries + 1):
        offset = start + 16 * index
        if offset + 16 > len(image):
            raise ValueError("Recbf message-bit table outside partition")
        command, subtype, selector, bit_id, callback = struct.unpack_from("<HHB3xII", image, offset)
        if command == 0:
            return rows
        if index == max_entries:
            raise ValueError("Recbf message-bit table terminator missing")
        rows.append({
            "index": index, "command": command, "subtype": subtype,
            "selector": selector, "bit_id": bit_id, "callback": callback,
        })
    raise AssertionError("unreachable message-bit table bound")


def read_recbf_completion_stage_subtypes(
    image: bytes, load_address: int, address: int, max_entries: int = 160,
) -> dict[int, tuple[int, int]]:
    """Read bounded 40-byte script-stage records; no runtime callback claim."""
    start = address - load_address
    if start < 0 or max_entries <= 0:
        raise ValueError("Recbf completion-stage table outside partition")
    stages = {}
    for index in range(max_entries + 1):
        offset = start + 40 * index
        if offset + 40 > len(image):
            raise ValueError("Recbf completion-stage table outside partition")
        command = image[offset]
        selector = image[offset + 16]
        if command == 0x9E and selector == 9:
            return stages
        if index == max_entries:
            raise ValueError("Recbf completion-stage terminator missing")
        if selector < 8:
            if selector in stages:
                raise ValueError(f"duplicate Recbf completion-stage selector {selector}")
            stages[selector] = struct.unpack_from("<HH", image, offset + 2)
    raise AssertionError("unreachable completion-stage table bound")


def read_recbf_script_table(
    image: bytes, load_address: int, address: int, count: int, terminator: int
) -> dict[int, bytes]:
    """Enumerate bounded, zero-based command streams; not runtime reachability."""
    offset = address - load_address
    if offset < 0 or offset + count * 8 > len(image) or not 0 <= terminator <= 255:
        raise ValueError("Recbf script table outside partition")
    scripts = {}
    for mode in range(count):
        entry_mode, pointer = struct.unpack_from("<II", image, offset + mode * 8)
        if entry_mode != mode:
            raise ValueError(f"Recbf script mode mismatch at {mode}")
        if mode == 0 and pointer != address + count * 8:
            raise ValueError("Recbf script table boundary mismatch")
        start = pointer - load_address
        if start < 0 or start >= len(image):
            raise ValueError(f"Recbf script pointer outside partition at mode {mode}")
        end = image.find(bytes([terminator]), start, min(start + 256, len(image)))
        if end < 0:
            raise ValueError(f"Recbf script terminator missing at mode {mode}")
        scripts[mode] = image[start:end + 1]
    return scripts


def verify_recbf_script_order(script: bytes, commands: tuple[int, ...]) -> None:
    positions = []
    for command in commands:
        if script.count(command) != 1:
            raise ValueError(f"Recbf script command {command:#x} missing or repeated")
        positions.append(script.index(command))
    if positions != sorted(positions) or len(set(positions)) != len(positions):
        raise ValueError("Recbf script command order changed")


def read_recbf_action_hits(
    image: bytes, load_address: int, address: int, rows: int, columns: int, action: int
) -> list[dict[str, int]]:
    """Find an action in a bounded two-byte event-row × state-column matrix."""
    offset = address - load_address
    if rows < 1 or columns < 1 or not 0 <= action <= 255 or offset < 0 or offset + 2 * rows * columns > len(image):
        raise ValueError("Recbf action matrix outside partition")
    hits = []
    for row in range(rows):
        for column in range(columns):
            action_byte, post_callback_code = struct.unpack_from("<BB", image, offset + 2 * (row * columns + column))
            if action_byte == action:
                hits.append({"event_row": row, "state_column": column, "post_callback_code": post_callback_code})
    return hits


def read_recbf_action_row(
    image: bytes, load_address: int, address: int, columns: int, row: int
) -> list[list[int]]:
    """Read one bounded two-byte controller row: callback index, post-callback code."""
    offset = address - load_address + 2 * columns * row
    if columns < 1 or row < 0 or offset < 0 or offset + 2 * columns > len(image):
        raise ValueError("Recbf action row outside partition")
    return [list(struct.unpack_from("<BB", image, offset + 2 * column)) for column in range(columns)]


def validate(path: Path, model: str) -> dict:
    source = SOURCES[model]
    original = path.read_bytes()
    digest = hashlib.sha256(original).hexdigest()
    if digest != source["sha256"]:
        raise ValueError(f"{model}: update hash mismatch; refusing pinned offsets")
    if struct.unpack_from("<I", original)[0] != 6:
        raise ValueError(f"{model}: unexpected update format")
    version = struct.unpack_from("<II", original, 516)
    if version != source["version"]:
        raise ValueError(f"{model}: update version mismatch")
    payload = bytes(byte ^ 0xFF for byte in original[HEADER_SIZE:])
    configuration_defaults = None
    if "configuration_defaults_offset" in source:
        configuration_defaults = read_raw_partition(
            payload, source["configuration_defaults_offset"], source["configuration_defaults_size"],
        )
        if hashlib.sha256(configuration_defaults).hexdigest() != source["configuration_defaults_sha256"]:
            raise ValueError("configuration defaults digest mismatch")
        if configuration_defaults[0x202:0x204] != bytes.fromhex("55aa"):
            raise ValueError("configuration defaults marker mismatch")
    kernel_digest = None
    if "kernel_partition_offset" in source:
        kernel_digest = verify_raw_partition_words(
            payload, source["kernel_partition_offset"], source["kernel_partition_size"],
            source["kernel_partition_load"], source["kernel_partition_sha256"],
            source["encoder_accessor_kernel_words"],
        )
    overlay_digest = None
    if "overlay_partition_offset" in source:
        overlay = read_raw_partition(payload, source["overlay_partition_offset"], source["overlay_partition_size"])
        overlay_digest = hashlib.sha256(overlay).hexdigest()
        if overlay_digest != source["overlay_partition_sha256"]:
            raise ValueError(f"{model}: raw overlay partition digest mismatch")
        verify_arm_words(overlay, source["overlay_partition_load"], source["exif_buffer_pack_overlay_words"])
        verify_arm_words(overlay, source["overlay_partition_load"], source["encoder_component_overlay_words"])
    volume_digest = None
    if "volume_partition_offset" in source:
        volume = read_raw_partition(payload, source["volume_partition_offset"], source["volume_partition_size"])
        volume_digest = hashlib.sha256(volume).hexdigest()
        if volume_digest != source["volume_partition_sha256"]:
            raise ValueError(f"{model}: raw volume partition digest mismatch")
        verify_data_words(volume, source["volume_partition_load"], source["volume_interface_words"])
        verify_arm_words(volume, source["volume_partition_load"], source["volume_method_words"])
        if "preview_cache_control_volume_ranges" in source:
            verify_hashed_ranges(volume, source["volume_partition_load"], source["preview_cache_control_volume_ranges"])
    primary = decode_partition(payload, source["primary_header"])
    secondary = decode_partition(payload, source["secondary_header"])
    primary_digest = hashlib.sha256(primary).hexdigest()
    secondary_digest = hashlib.sha256(secondary).hexdigest()
    if primary_digest != source["primary_sha256"] or secondary_digest != source["secondary_sha256"]:
        raise ValueError(f"{model}: decoded partition digest mismatch")
    if "preview_cache_control_primary_ranges" in source:
        verify_hashed_ranges(primary, source["primary_load"], source["preview_cache_control_primary_ranges"])
    if "preview_cache_descriptor_primary_ranges" in source:
        verify_hashed_ranges(primary, source["primary_load"], source["preview_cache_descriptor_primary_ranges"])
    if "preview_refresh_caller_primary_ranges" in source:
        verify_hashed_ranges(primary, source["primary_load"], source["preview_refresh_caller_primary_ranges"])
    if "preview_count_threshold_ranges" in source:
        verify_hashed_ranges(primary, source["primary_load"], source["preview_count_threshold_ranges"])
    if "preview_count_filter_ranges" in source:
        verify_hashed_ranges(primary, source["primary_load"], source["preview_count_filter_ranges"])
    if "encoder_component_primary_words" in source:
        verify_arm_words(primary, source["primary_load"], source["encoder_component_primary_words"])
        verify_arm_words(secondary, source["secondary_load"], source["encoder_component_secondary_words"])
    verify_arm_words(primary, source["primary_load"], source["crop_ratio_words"])
    common_offset = source["crop_ratio_helper"] + source["crop_ratio_common_body_offset"] - source["primary_load"]
    common_end = common_offset + source["crop_ratio_common_body_size"]
    if common_offset < 0 or common_end > len(primary):
        raise ValueError(f"{model}: crop ratio arithmetic body outside primary partition")
    common_body_digest = hashlib.sha256(primary[common_offset:common_end]).hexdigest()
    if common_body_digest != source["crop_ratio_common_body_sha256"]:
        raise ValueError(f"{model}: crop ratio arithmetic body digest mismatch")
    crop_ratio_targets = [
        read_crop_ratio_jump_target(primary, source["primary_load"], source["crop_ratio_helper"], code)
        for code in range(1, 8)
    ]
    if crop_ratio_targets != source["crop_ratio_dispatch_targets_expected"]:
        raise ValueError(f"{model}: crop ratio dispatch table changed")
    crop_ratio_code4_target = crop_ratio_targets[3]
    if crop_ratio_code4_target != source["crop_ratio_code4_target"]:
        raise ValueError(f"{model}: crop ratio code-4 jump target mismatch")
    crop_ratio_direct_bl_sites = {}
    if "crop_ratio_direct_bl_sites_expected" in source:
        crop_ratio_direct_bl_sites = {
            "primary": read_arm_bl_call_sites(primary, source["primary_load"], source["crop_ratio_helper"]),
            "secondary": read_arm_bl_call_sites(secondary, source["secondary_load"], source["crop_ratio_helper"]),
        }
        if crop_ratio_direct_bl_sites != source["crop_ratio_direct_bl_sites_expected"]:
            raise ValueError(f"{model}: crop ratio direct BL inventory changed")
    stub_adjacent_arm_bl_sites = {}
    if "crop_ratio_stub_adjacent_arm_function" in source:
        function = source["crop_ratio_stub_adjacent_arm_function"]
        if not addresses_share_4k_page(function, source["crop_ratio_code4_stub_candidate"]):
            raise ValueError(f"{model}: ratio stub and adjacent ARM function no longer share a 4 KiB page")
        verify_arm_words(primary, source["primary_load"], source["crop_ratio_stub_adjacent_arm_words"])
        stub_adjacent_arm_bl_sites = {
            "primary": read_arm_bl_call_sites(primary, source["primary_load"], function),
            "secondary": read_arm_bl_call_sites(secondary, source["secondary_load"], function),
        }
        if stub_adjacent_arm_bl_sites != source["crop_ratio_stub_adjacent_arm_bl_sites_expected"]:
            raise ValueError(f"{model}: ratio-stub-adjacent ARM call inventory changed")
    secondary_ratio_descriptor_targets = []
    secondary_ratio_descriptor_record_banks = []
    if "secondary_ratio_descriptor_table" in source:
        verify_arm_words(secondary, source["secondary_load"], source["secondary_ratio_descriptor_words"])
        secondary_ratio_descriptor_targets = read_arm_absolute_jump_table(
            secondary, source["secondary_load"], source["secondary_ratio_descriptor_table"], 7
        )
        if secondary_ratio_descriptor_targets != source["secondary_ratio_descriptor_targets_expected"]:
            raise ValueError(f"{model}: secondary ratio descriptor dispatch changed")
        if "secondary_ratio_descriptor_direct_bl_sites_expected" in source:
            sites = read_arm_bl_call_sites(secondary, source["secondary_load"], 0x1F689B0)
            if sites != source["secondary_ratio_descriptor_direct_bl_sites_expected"]:
                raise ValueError(f"{model}: secondary ratio descriptor call inventory changed")
        if "secondary_ratio_descriptor_constructor_gate_words" in source:
            verify_arm_words(
                secondary, source["secondary_load"],
                source["secondary_ratio_descriptor_constructor_gate_words"],
            )
            sites = read_arm_bl_call_sites(secondary, source["secondary_load"], 0x1ED8544)
            if sites != source["secondary_ratio_descriptor_wrapper_bl_sites_expected"]:
                raise ValueError(f"{model}: ratio wrapper call inventory changed")
            verify_arm_words(
                secondary, source["secondary_load"],
                source["secondary_ratio_descriptor_record_source_words"],
            )
            verify_arm_words(
                secondary, source["secondary_load"],
                source["secondary_ratio_descriptor_key43_subkey66_registration_words"],
            )
            verify_data_words(
                secondary, source["secondary_load"],
                source["secondary_ratio_descriptor_registration_event_group_data_words"],
            )
            sites = read_arm_bl_call_sites(secondary, source["secondary_load"], 0x1ED3BFC)
            if sites != source["secondary_ratio_descriptor_registration_bl_sites_expected"]:
                raise ValueError(f"{model}: parameter registration call inventory changed")
            verify_arm_words(
                secondary, source["secondary_load"],
                source["secondary_ratio_descriptor_cmd32_subtype5_words"],
            )
            sites = read_arm_bl_call_sites(secondary, source["secondary_load"], 0x1F3D940)
            if sites != source["secondary_ratio_descriptor_cmd32_wrapper_bl_sites_expected"]:
                raise ValueError(f"{model}: command-0x32 wrapper call inventory changed")
            verify_arm_words(
                secondary, source["secondary_load"],
                source["secondary_ratio_descriptor_shared_selector_subkey_words"],
            )
        if "secondary_ratio_descriptor_gfx_subtype2_record_words" in source:
            verify_arm_words(
                secondary, source["secondary_load"],
                source["secondary_ratio_descriptor_gfx_subtype2_record_words"],
            )
            for target, expected_key in (
                (0x23B12C8, "secondary_ratio_descriptor_gfx_builder_bl_sites_expected"),
                (0x2327FD4, "secondary_ratio_descriptor_gfx_wrapper_bl_sites_expected"),
                (0x2335E34, "secondary_ratio_descriptor_gfx_constructor_bl_sites_expected"),
            ):
                sites = read_arm_bl_call_sites(secondary, source["secondary_load"], target)
                if sites != source[expected_key]:
                    raise ValueError(f"{model}: GFX ratio-constructor call inventory changed for {target:#x}")
        if "secondary_ratio_descriptor_record_bank_headers_0_to_7" in source:
            for expected in source["secondary_ratio_descriptor_record_bank_headers_0_to_7"]:
                observed = read_initial_parameter_record_bank(
                    secondary, source["secondary_load"], expected["address"],
                    source.get("secondary_ratio_descriptor_record_stride", 28),
                )
                if observed != {key: expected[key] for key in ("count", "pointer", "subtypes")}:
                    raise ValueError(f"{model}: initial parameter bank {expected['bank']} changed")
                secondary_ratio_descriptor_record_banks.append({"bank": expected["bank"], **observed})
        if "secondary_ratio_descriptor_recbf_dispatch_words" in source:
            verify_arm_words(
                secondary, source["secondary_load"],
                source["secondary_ratio_descriptor_recbf_dispatch_words"],
            )
            verify_data_words(
                secondary, source["secondary_load"],
                source["secondary_ratio_descriptor_recbf_dispatch_data_words"],
            )
            sites = read_arm_bl_call_sites(secondary, source["secondary_load"], 0x1EE4678)
            if sites != source["secondary_ratio_descriptor_recbf_direct_bl_sites_expected"]:
                raise ValueError(f"{model}: Recbf descriptor-constructor call inventory changed")
    records = parse_primary_records(primary, source["primary_table"])
    if "dimension_lookup_width_words" in source:
        verify_arm_words(primary, source["primary_load"], source["dimension_lookup_width_words"])
    verify_arm_words(primary, source["primary_load"], source["dimension_lookup_height_words"])
    dimension_widths = read_aspect_dimension_grid(
        primary, source["primary_load"], source["dimension_lookup_width"],
        3, source["dimension_lookup_columns"],
    )
    dimension_heights = read_aspect_dimension_grid(
        primary, source["primary_load"], source["dimension_lookup_height"],
        3, source["dimension_lookup_columns"],
    )
    dimension_code4 = [
        [dimension_widths[level][4], dimension_heights[level][4]] for level in range(3)
    ]
    if dimension_code4 != source["dimension_lookup_code4_expected"]:
        raise ValueError(f"{model}: primary dimension lookup code-4 mismatch")
    if "dimension_lookup_reference_code1" in source:
        code1 = [[dimension_widths[level][1], dimension_heights[level][1]] for level in range(3)]
        if code1 != source["dimension_lookup_reference_code1"]:
            raise ValueError(f"{model}: primary dimension lookup reference mismatch")
    verify_arm_words(primary, source["primary_load"], source["preview_lookup_words"])
    if "preview_parallel_index_words" in source:
        verify_arm_words(primary, source["primary_load"], source["preview_parallel_index_words"])
    if "preview_capacity_count_words" in source:
        verify_arm_words(primary, source["primary_load"], source["preview_capacity_count_words"])
    preview_parallel_extension_overlaps: list[int] = []
    if "preview_parallel_following_array_words" in source:
        verify_arm_words(primary, source["primary_load"], source["preview_parallel_following_array_words"])
        verify_data_words(primary, source["primary_load"], source["preview_parallel_following_array_literals"])
        first_word = source["preview_parallel_first_word"]
        next_word = source["preview_parallel_following_array_first_word"]
        if first_word + 4 * source["preview_key_count"] != next_word:
            raise ValueError(f"{model}: preview cache does not abut the following array")
        preview_parallel_extension_overlaps = preview_parallel_extension_overlaps_next_array(
            first_word, source["preview_key_count"], source["preview_key_count"] + 6, next_word,
        )
        if preview_parallel_extension_overlaps != [next_word + 4 * index for index in range(6)]:
            raise ValueError(f"{model}: preview 63-row extension collision differs")
    if "preview_row_enumeration_words" in source:
        verify_arm_words(primary, source["primary_load"], source["preview_row_enumeration_words"])
        verify_arm_words(secondary, source["secondary_load"], source["preview_secondary_lookup_miss_words"])
    verify_arm_words(primary, source["primary_load"], source["preview_lookup_bypass_primary_words"])
    verify_arm_words(secondary, source["secondary_load"], source["preview_lookup_bypass_secondary_words"])
    verify_arm_words(primary, source["primary_load"], source["preview_bypass_global_accessor_words"])
    if "preview_mode_key227_fixed_object_words" in source:
        verify_arm_words(primary, source["primary_load"], source["preview_mode_key227_fixed_object_words"])
        verify_arm_words(secondary, source["secondary_load"], source["preview_mode_key227_fixed_object_secondary_words"])
        verify_arm_words(primary, source["primary_load"], source["preview_mode_fixed_object_cache_copy_words"])
    if "preview_state_producer_primary_words" in source:
        verify_arm_words(primary, source["primary_load"], source["preview_state_producer_primary_words"])
    if "preview_source_bridge_primary_words" in source:
        verify_arm_words(primary, source["primary_load"], source["preview_source_bridge_primary_words"])
        verify_arm_words(primary, source["primary_load"], source["preview_builder_alternate_staging_primary_words"])
        verify_data_words(primary, source["primary_load"], source["preview_builder_alternate_staging_primary_data_words"])
    verify_arm_words(secondary, source["secondary_load"], source["preview_lookup_caller_words"])
    if "preview_descriptor_bridge_primary_words" in source:
        verify_arm_words(primary, source["primary_load"], source["preview_descriptor_bridge_primary_words"])
        verify_arm_words(secondary, source["secondary_load"], source["preview_descriptor_bridge_secondary_words"])
    if "preview_descriptor_dual_lookup_primary_words" in source:
        verify_arm_words(primary, source["primary_load"], source["preview_descriptor_dual_lookup_primary_words"])
    preview_1159_message_row = None
    preview_1159_controller_rows = None
    preview_1159_event44_gate_direct_bl_sites: list[int] = []
    if "preview_lookup_pointer_handoff_words" in source:
        verify_arm_words(secondary, source["secondary_load"], source["preview_lookup_pointer_handoff_words"])
        verify_arm_words(secondary, source["secondary_load"], source["preview_1159_dispatch_controller_words"])
        verify_arm_words(secondary, source["secondary_load"], source["preview_1159_conditional_gate_alias_words"])
        verify_arm_words(secondary, source["secondary_load"], source["preview_1159_threshold_route_words"])
        verify_data_words(secondary, source["secondary_load"], source["preview_1159_threshold_route_data_words"])
        preview_1159_controller_rows = {
            "mode0_row5": read_recbf_action_row(secondary, source["secondary_load"], 0x22D76BC, 5, 5),
            "mode1_row2": read_recbf_action_row(secondary, source["secondary_load"], 0x22D7790, 5, 2),
            "mode5_row2": read_recbf_action_row(secondary, source["secondary_load"], 0x22D7984, 2, 2),
        }
        if preview_1159_controller_rows != {
            "mode0_row5": [[3, 1], [7, 253], [3, 1], [5, 1], [3, 1]],
            "mode1_row2": [[4, 255], [5, 1], [3, 1], [3, 1], [3, 1]],
            "mode5_row2": [[6, 255], [7, 1]],
        }:
            raise ValueError(f"{model}: preview 0x1159 controller rows changed")
        preview_1159_event44_gate_direct_bl_sites = [
            site for image, load in ((primary, source["primary_load"]), (secondary, source["secondary_load"]))
            for site in read_arm_bl_call_sites(image, load, 0x1F23C44)
        ]
        if preview_1159_event44_gate_direct_bl_sites != source["preview_1159_event44_gate_direct_bl_sites_expected"]:
            raise ValueError(f"{model}: event-44 gate direct call sites changed")
        preview_1159_rows = [
            row for row in read_recbf_message_bit_routes(
                secondary, source["secondary_load"], 0x22DCE30
            ) if row["command"] == 0x1159
        ]
        if preview_1159_rows != [
            {"index": 11, "command": 0x1159, "subtype": 0,
             "selector": 0, "bit_id": 0xFFFFFFFF, "callback": 0}
        ]:
            raise ValueError(f"{model}: preview 0x1159 dispatch row changed")
        preview_1159_message_row = preview_1159_rows[0]
        verify_arm_words(secondary, source["secondary_load"], source["preview_runtime_config_206_207_secondary_words"])
        verify_data_words(secondary, source["secondary_load"], source["preview_runtime_config_206_207_data_words"])
        verify_arm_words(secondary, source["secondary_load"], source["runtime_config_206_stack_words"])
    preview_config_copy_direct_bl_sites: list[int] = []
    if "preview_runtime_config_206_207_direct_bl_sites_expected" in source:
        for image, load in ((primary, source["primary_load"]), (secondary, source["secondary_load"])):
            preview_config_copy_direct_bl_sites.extend(read_arm_bl_call_sites(image, load, 0x1EA01D8))
        if preview_config_copy_direct_bl_sites != source["preview_runtime_config_206_207_direct_bl_sites_expected"]:
            raise ValueError(f"{model}: direct mapped-copy call-site inventory changed")
    if "preview_pointer_array_id200_publication_words" in source:
        verify_arm_words(secondary, source["secondary_load"], source["preview_pointer_array_id200_publication_words"])
        if "preview_pointer_array_id200_publication_data_words" in source:
            verify_data_words(secondary, source["secondary_load"], source["preview_pointer_array_id200_publication_data_words"])
    if "preview_pointer_publisher_callback_dispatch_words" in source:
        if "preview_cache_enable_dispatch_ranges" in source:
            verify_hashed_ranges(secondary, source["secondary_load"], source["preview_cache_enable_dispatch_ranges"])
            verify_data_words(secondary, source["secondary_load"], source["preview_cache_enable_dispatch_data_words"])
        if "preview_cache_descriptor_secondary_ranges" in source:
            verify_hashed_ranges(secondary, source["secondary_load"], source["preview_cache_descriptor_secondary_ranges"])
        if "preview_refresh_caller_secondary_ranges" in source:
            verify_hashed_ranges(secondary, source["secondary_load"], source["preview_refresh_caller_secondary_ranges"])
        verify_arm_words(secondary, source["secondary_load"], source["preview_pointer_publisher_callback_dispatch_words"])
        verify_data_words(secondary, source["secondary_load"], source["preview_pointer_publisher_callback_dispatch_data_words"])
        for address, expected in source["preview_pointer_publisher_callback_dispatch_record_prefixes"].items():
            observed = read_raw_partition(secondary, address - source["secondary_load"], len(expected))
            if observed != expected:
                raise ValueError(f"{model}: callback selector records changed at {address:#x}")
    if "preview_pointer_publisher_category22_trigger_words" in source:
        verify_arm_words(secondary, source["secondary_load"], source["preview_pointer_publisher_category22_trigger_words"])
    if "preview_pointer_publisher_conditional_channel7_bridge_words" in source:
        verify_arm_words(secondary, source["secondary_load"], source["preview_pointer_publisher_conditional_channel7_bridge_words"])
        verify_data_words(secondary, source["secondary_load"], source["preview_pointer_publisher_conditional_channel7_bridge_data_words"])
        for address, expected in source["preview_pointer_publisher_conditional_channel7_bridge_bytes"].items():
            observed = read_raw_partition(secondary, address - source["secondary_load"], len(expected))
            if observed != expected:
                raise ValueError(f"{model}: conditional channel-7 bridge records changed at {address:#x}")
    if "preview_pointer_publisher_channel7_filter_words" in source:
        verify_arm_words(secondary, source["secondary_load"], source["preview_pointer_publisher_channel7_filter_words"])
    if "preview_temp_block_header_init_words" in source:
        verify_arm_words(secondary, source["secondary_load"], source["preview_temp_block_header_init_words"])
    if "preview_temp_block_channel7_receiver_secondary_words" in source:
        verify_arm_words(secondary, source["secondary_load"], source["preview_temp_block_channel7_receiver_secondary_words"])
        verify_arm_words(primary, source["primary_load"], source["preview_temp_block_channel7_receiver_primary_words"])
    preview_id200_sender_direct_bl_sites: list[int] = []
    if "preview_id200_channel7_sender_secondary_words" in source:
        verify_arm_words(secondary, source["secondary_load"], source["preview_id200_channel7_sender_secondary_words"])
        verify_data_words(secondary, source["secondary_load"], source["preview_id200_channel7_sender_secondary_data_words"])
        verify_arm_words(secondary, source["secondary_load"], source["preview_id200_channel7_sender_object_prefix_copy_words"])
        verify_arm_words(primary, source["primary_load"], source["preview_id200_channel7_sender_primary_words"])
    if "preview_runtime_array_cache_export_primary_words" in source:
        verify_arm_words(primary, source["primary_load"], source["preview_cache_refresh_gate_primary_words"])
        for name, image in (("primary", primary), ("secondary", secondary)):
            verify_arm_words(image, source[f"{name}_load"], source[f"preview_runtime_array_cache_export_{name}_words"])
            verify_data_words(image, source[f"{name}_load"], source[f"preview_runtime_array_cache_export_{name}_data_words"])
        for image, load in ((primary, source["primary_load"]), (secondary, source["secondary_load"])):
            preview_id200_sender_direct_bl_sites.extend(read_arm_bl_call_sites(image, load, 0x1E441F4))
        if preview_id200_sender_direct_bl_sites != source["preview_id200_channel7_sender_direct_bl_sites_expected"]:
            raise ValueError(f"{model}: ID-0x200 sender direct-call inventory changed")
    preview_keys = read_preview_key_table(
        primary, source["primary_load"], source["preview_key_table"], source["preview_key_count"],
    )
    verify_arm_words(primary, source["primary_load"], source["dimension_estimate_coeff_words"])
    dimension_estimate_coeff_rows = read_dimension_estimate_coeff_table(
        primary, source["primary_load"], source["dimension_estimate_coeff_table"],
        source["dimension_estimate_coeff_count"],
    )
    estimate_property_keys = {row["runtime_property_key"] for row in dimension_estimate_coeff_rows}
    estimate_property_inventory = (len(estimate_property_keys), min(estimate_property_keys), max(estimate_property_keys))
    if "dimension_estimate_property_key_inventory_expected" in source:
        if estimate_property_inventory != source["dimension_estimate_property_key_inventory_expected"]:
            raise ValueError(f"{model}: estimator property-key inventory changed")
    if [preview_keys[0]["width"], preview_keys[0]["height"]] != [0, 0]:
        raise ValueError(f"{model}: preview bypass row-0 dimensions changed")
    preview_code4_keys = [row for row in preview_keys if row["key"][2] == 4]
    expected_preview_code4_count = 0 if model == "x100v_3_01" else 9
    if len(preview_code4_keys) != expected_preview_code4_count:
        raise ValueError(f"{model}: preview lookup code-4 row count mismatch")
    preview_row_reuse_candidate = (
        plan_x100v_preview_code4_row_reuse(
            primary, source["primary_load"], source["preview_key_table"], source["preview_key_count"]
        ) if model == "x100v_3_01" else []
    )
    preview_zero_placeholder_candidate = (
        plan_x100v_preview_code4_zero_placeholder_reuse(primary, source)
        if model == "x100v_3_01" else []
    )
    estimate_target_dimensions = (
        {(row["width"], row["height"]) for row in preview_row_reuse_candidate}
        if model == "x100v_3_01" else {tuple(pair) for pair in dimension_code4}
    )
    estimate_target_rows = [
        row for row in dimension_estimate_coeff_rows
        if (row["width"], row["height"]) in estimate_target_dimensions
    ]
    if [row["index"] for row in estimate_target_rows] != source["dimension_estimate_target_rows_expected"]:
        raise ValueError(f"{model}: 65:24 estimate coefficient rows changed")
    estimate_16_9_rows = []
    if "dimension_estimate_16_9_source_dimensions" in source:
        source_dimensions = {tuple(pair) for pair in source["dimension_estimate_16_9_source_dimensions"]}
        estimate_16_9_rows = [
            row for row in dimension_estimate_coeff_rows
            if (row["width"], row["height"]) in source_dimensions
        ]
        if [row["index"] for row in estimate_16_9_rows] != source["dimension_estimate_16_9_row_indices_expected"]:
            raise ValueError(f"{model}: 16:9 estimate coefficient row inventory changed")
    estimate_16_9_defaults = []
    if configuration_defaults is not None:
        for row in estimate_16_9_rows:
            key = row["runtime_property_key"]
            if not 0 <= key < len(configuration_defaults):
                raise ValueError("coefficient key outside configuration defaults")
            estimate_16_9_defaults.append({"row": row["index"], "key": key,
                                           "default_coefficient": configuration_defaults[key]})
        if [row["default_coefficient"] for row in estimate_16_9_defaults] != [48, 32] * 6:
            raise ValueError("16:9 configuration-default coefficients changed")
    if model == "gfx100_5_18":
        for level, dimensions in enumerate(dimension_code4):
            matches = [row for row in preview_code4_keys if row["key"][0] == level]
            if [row["key"][1] for row in matches] != [2, 1, 0] or any(
                [row["width"], row["height"]] != dimensions for row in matches
            ):
                raise ValueError(f"{model}: preview lookup code-4 dimension mismatch at level {level}")
    selected = []
    for id_value, size_level in ASPECT_65_24_ROWS.items():
        record = next(row for row in records if row["id"] == id_value)
        if record["code"] != (4 << 8) | size_level:
            raise ValueError(f"{model}: unexpected 65:24 code for ID {id_value}")
        selected.append(record)
    ratio_rows = find_q16_triplets(secondary, Q16_65_24)
    observed_case_outputs = read_develop_aspect_case_outputs(
        secondary, source["secondary_load"], source["develop_aspect_targets"],
    )
    if observed_case_outputs != source["develop_aspect_targets"]:
        raise ValueError(f"{model}: develop-aspect case output mismatch")
    develop_aspects = decode_develop_aspect_jump_table(
        secondary,
        source["develop_aspect_jump_offset"],
        source["develop_aspect_jump_count"],
        observed_case_outputs,
    )
    verify_arm_words(secondary, source["secondary_load"], source["develop_aspect_dispatch_words"])
    verify_arm_words(secondary, source["secondary_load"], source["develop_aspect_builder_words"])
    if "develop_record_builder_call_words" in source:
        verify_arm_words(secondary, source["secondary_load"], source["develop_record_builder_call_words"])
    jump_start = source["develop_aspect_jump_offset"]
    jump_end = jump_start + 4 * source["develop_aspect_jump_count"]
    first_case = min(source["develop_aspect_targets"])
    if jump_end != first_case - source["secondary_load"]:
        raise ValueError(f"{model}: aspect cases no longer abut jump table")
    verify_arm_words(secondary, source["secondary_load"], source["develop_aspect_copy_words"])
    verify_arm_words(secondary, source["secondary_load"], source["geometry_aspect_words"])
    if "geometry_call_words" in source:
        verify_arm_words(secondary, source["secondary_load"], source["geometry_call_words"])
    if "movie_geometry_caller_words" in source:
        verify_arm_words(secondary, source["secondary_load"], source["movie_geometry_caller_words"])
        for address, diagnostic in source["movie_geometry_diagnostic_strings"].items():
            offset = address - source["secondary_load"]
            if secondary[offset:offset + len(diagnostic)] != diagnostic:
                raise ValueError(f"{model}: movie geometry diagnostic mismatch at {address:#x}")
    if "movie_descriptor_caller_words" in source:
        verify_arm_words(secondary, source["secondary_load"], source["movie_descriptor_caller_words"])
        for address, diagnostic in source["movie_descriptor_diagnostic_strings"].items():
            offset = address - source["secondary_load"]
            if secondary[offset:offset + len(diagnostic)] != diagnostic:
                raise ValueError(f"{model}: movie descriptor diagnostic mismatch at {address:#x}")
    verify_arm_words(secondary, source["secondary_load"], source["descriptor_words"])
    verify_arm_words(secondary, source["secondary_load"], source["vg_geometry_words"])
    verify_arm_words(secondary, source["secondary_load"], source["vg_selector_source_words"])
    vg_selector_tables = None
    if "vg_selector_table_addresses" in source:
        verify_arm_words(secondary, source["secondary_load"], source["vg_selector_branch_words"])
        vg_selector_tables = [
            read_vg_selector_jump_rows(secondary, source["secondary_load"], address)
            for address in source["vg_selector_table_addresses"]
        ]
        if vg_selector_tables != source["vg_selector_table_expected"]:
            raise ValueError(f"{model}: VG selector branch table changed")
    if "preview_state_producer_secondary_words" in source:
        verify_arm_words(secondary, source["secondary_load"], source["preview_state_producer_secondary_words"])
    if "preview_source_bridge_secondary_words" in source:
        verify_arm_words(secondary, source["secondary_load"], source["preview_source_bridge_secondary_words"])
        verify_data_words(secondary, source["secondary_load"], source["preview_source_bridge_secondary_data_words"])
        verify_arm_words(secondary, source["secondary_load"], source["preview_builder_other_direct_callsite_words"])
        verify_data_words(secondary, source["secondary_load"], source["preview_builder_other_direct_callsite_data_words"])
    if "vg_packet_alternate_flag_words" in source:
        verify_arm_words(secondary, source["secondary_load"], source["vg_packet_alternate_flag_words"])
    vg_channel_routes = None
    if "vg_channel_descriptor_table" in source:
        verify_arm_words(secondary, source["secondary_load"], source["vg_channel_secondary_words"])
        verify_arm_words(primary, source["primary_load"], source["vg_channel_primary_words"])
        vg_channel_routes = read_vg_channel_routes(
            primary, source["primary_load"],
            source["vg_channel_descriptor_table"], source["vg_channel_context_table"],
        )
        if vg_channel_routes != source["vg_channel_routes_expected"]:
            raise ValueError(f"{model}: VG channel routing mismatch")
    if "vg_geometry_output_words" in source:
        verify_arm_words(secondary, source["secondary_load"], source["vg_geometry_output_words"])
        verify_arm_words(primary, source["primary_load"], source["vg_geometry_primary_sink_words"])
        verify_arm_words(primary, source["primary_load"], source["vg_geometry_primary_readback_words"])
        for target, expected_key in (
            (0x10F52FC, "vg_geometry_primary_getter_bl_sites_expected"),
            (0x10F5268, "vg_geometry_primary_setter_bl_sites_expected"),
        ):
            sites = [
                site for image, load in ((primary, source["primary_load"]),
                                         (secondary, source["secondary_load"]))
                for site in read_arm_bl_call_sites(image, load, target)
            ]
            if sites != source[expected_key]:
                raise ValueError(f"{model}: VG slot route direct-call inventory changed for {target:#x}")
    if "vg_geometry_diagnostic" in source:
        address, diagnostic = source["vg_geometry_diagnostic"]
        offset = address - source["secondary_load"]
        if secondary[offset:offset + len(diagnostic)] != diagnostic:
            raise ValueError(f"{model}: VG geometry diagnostic mismatch")
    vg_rows = {
        str(family): {
            str(row): read_vg_geometry_record(
                secondary, source["secondary_load"], source["vg_geometry_table"], family, row
            )
            for row in (4, 11)
        }
        for family in range(3)
    }
    for row, expected in ((4, [0, 195, 1024, 378]), (11, [0, 305, 1600, 590])):
        if vg_rows["0"][str(row)]["inner"] != expected:
            raise ValueError(f"{model}: VG family-0 aspect-4 rectangle mismatch")
    if model == "x100v_3_01":
        # In the zero-other-selector branch, code 2 selects row 2, not row 4.
        # Guard both rectangles before considering any preview-row redirection.
        row2 = read_vg_geometry_record(
            secondary, source["secondary_load"], source["vg_geometry_table"], 0, 2
        )
        if row2["outer"] != [0, 0, 900, 600] or row2["inner"] != [0, 47, 900, 506]:
            raise ValueError("x100v: VG family-0 16:9 row-2 rectangle mismatch")
        for row, outer, inner in (
            (9, [0, 54, 1280, 852], [0, 120, 1280, 720]),
            (11, [0, 0, 1600, 1200], [0, 305, 1600, 590]),
            (14, [904, 710, 375, 250], [904, 710, 375, 250]),
            (15, [904, 710, 375, 250], [904, 729, 375, 211]),
        ):
            record = read_vg_geometry_record(
                secondary, source["secondary_load"], source["vg_geometry_table"], 0, row
            )
            if record["outer"] != outer or record["inner"] != inner:
                raise ValueError(f"x100v: VG family-0 row-{row} rectangle mismatch")
    for family in (1, 2):
        for row in (4, 11):
            record = vg_rows[str(family)][str(row)]
            if record["inner"] != record["outer"]:
                raise ValueError(f"{model}: VG family-{family} aspect-4 rectangle changed")
    recbf_scripts = None
    recbf_mode3_action_hits = None
    recbf_mode4_action_hits = None
    if "recbf_copy_crop_raw_strings" in source:
        verify_data_words(secondary, source["secondary_load"], source["recbf_copy_crop_raw_record_words"])
        for address, diagnostic in source["recbf_copy_crop_raw_strings"].items():
            offset = address - source["secondary_load"]
            if secondary[offset:offset + len(diagnostic)] != diagnostic:
                raise ValueError(f"{model}: Recbf diagnostic mismatch at {address:#x}")
    if "recbf_geometry_event_words" in source:
        verify_arm_words(secondary, source["secondary_load"], source["recbf_geometry_event_words"])
    if "recbf_geometry_event_registration_words" in source:
        verify_data_words(secondary, source["secondary_load"], source["recbf_geometry_event_registration_words"])
    if "recbf_geometry_event_runtime_list_words" in source:
        verify_arm_words(secondary, source["secondary_load"], source["recbf_geometry_event_runtime_list_words"])
        verify_data_words(secondary, source["secondary_load"], source["recbf_geometry_event_runtime_list_data_words"])
        verify_arm_words(secondary, source["secondary_load"], source["recbf_geometry_event_group_47_gate_source_words"])
        verify_data_words(secondary, source["secondary_load"], source["recbf_geometry_event_group_47_gate_source_data_words"])
        group44 = read_event_group_ids(secondary, source["secondary_load"], source["recbf_geometry_event_group_44_address"])
        group47 = read_event_group_ids(secondary, source["secondary_load"], source["recbf_geometry_event_group_47_address"])
        if 44 in group44 or group47.count(44) != 2:
            raise ValueError(f"{model}: event-44 group membership mismatch")
    if "recbf_geometry_event_bitmap_words" in source:
        verify_arm_words(secondary, source["secondary_load"], source["recbf_geometry_event_bitmap_words"])
        verify_data_words(secondary, source["secondary_load"], source["recbf_geometry_event_bitmap_data_words"])
    if "recbf_script_table_address" in source:
        if "recbf_dispatch_words" in source:
            verify_arm_words(secondary, source["secondary_load"], source["recbf_dispatch_words"])
            verify_arm_words(secondary, source["secondary_load"], source["recbf_script_mode_selector_words"])
            verify_arm_words(secondary, source["secondary_load"], source["recbf_mode3_message_route_secondary_words"])
            verify_arm_words(primary, source["primary_load"], source["recbf_mode3_message_route_primary_words"])
            verify_data_words(secondary, source["secondary_load"], source["recbf_mode3_message_route_data_words"])
            if "recbf_mode3_action_gate_words" in source:
                verify_arm_words(secondary, source["secondary_load"], source["recbf_mode3_action_gate_words"])
                verify_data_words(secondary, source["secondary_load"], source["recbf_mode3_action_gate_data_words"])
                recbf_mode3_action_hits = read_recbf_action_hits(
                    secondary, source["secondary_load"], source["recbf_mode3_action_matrix"],
                    source["recbf_mode3_action_matrix_rows"], source["recbf_mode3_action_matrix_columns"], 8,
                )
                if recbf_mode3_action_hits != [
                    {"event_row": 5, "state_column": 1, "post_callback_code": 1},
                    {"event_row": 5, "state_column": 4, "post_callback_code": 1},
                ]:
                    raise ValueError(f"{model}: mode-3 action trigger cells changed")
            if "recbf_event_1232_final_route_words" in source:
                verify_arm_words(secondary, source["secondary_load"], source["recbf_event_1232_final_route_words"])
                verify_data_words(secondary, source["secondary_load"], source["recbf_event_1232_final_route_data_words"])
                for address, columns, row, expected in source["recbf_event_1232_final_route_rows"]:
                    observed = read_recbf_action_row(secondary, source["secondary_load"], address, columns, row)
                    if observed != expected:
                        raise ValueError(f"{model}: final controller route row mismatch at {address:#x}, row {row}")
            if "recbf_controller1_row5_producer_words" in source:
                verify_arm_words(secondary, source["secondary_load"], source["recbf_controller1_row5_producer_words"])
                verify_data_words(secondary, source["secondary_load"], source["recbf_controller1_row5_producer_data_words"])
                for address, columns, row, expected in source["recbf_controller1_row5_producer_rows"]:
                    observed = read_recbf_action_row(secondary, source["secondary_load"], address, columns, row)
                    if observed != expected:
                        raise ValueError(f"{model}: controller-1 row-5 producer mismatch at {address:#x}, row {row}")
            if "recbf_controller1_crop_column_predecessor_words" in source:
                verify_arm_words(secondary, source["secondary_load"], source["recbf_controller1_crop_column_predecessor_words"])
                for address, columns, row, expected in source["recbf_controller1_crop_column_predecessor_rows"]:
                    observed = read_recbf_action_row(secondary, source["secondary_load"], address, columns, row)
                    if observed != expected:
                        raise ValueError(f"{model}: controller-1 crop-column predecessor mismatch at {address:#x}, row {row}")
            if "recbf_event_1232_nested_route_words" in source:
                verify_arm_words(secondary, source["secondary_load"], source["recbf_event_1232_nested_route_words"])
                verify_data_words(secondary, source["secondary_load"], source["recbf_event_1232_nested_route_data_words"])
                for address, columns, row, expected in source["recbf_event_1232_nested_rows"]:
                    observed = read_recbf_action_row(secondary, source["secondary_load"], address, columns, row)
                    if observed != expected:
                        raise ValueError(f"{model}: nested controller row mismatch at {address:#x}, row {row}")
            if "recbf_event_1232_tagged_context_words" in source:
                verify_arm_words(secondary, source["secondary_load"], source["recbf_event_1232_tagged_context_words"])
                verify_data_words(secondary, source["secondary_load"], source["recbf_event_1232_tagged_context_data_words"])
                writer = source["recbf_tagged_context_writer"]
                primary_sites = read_arm_bl_call_sites(primary, source["primary_load"], writer)
                secondary_sites = read_arm_bl_call_sites(secondary, source["secondary_load"], writer)
                if primary_sites or secondary_sites != source["recbf_tagged_context_direct_calls_secondary"]:
                    raise ValueError(f"{model}: tagged-context direct writer callsites changed")
                for operation in ("remover", "reset"):
                    target = source[f"recbf_tagged_context_{operation}"]
                    primary_sites = read_arm_bl_call_sites(primary, source["primary_load"], target)
                    secondary_sites = read_arm_bl_call_sites(secondary, source["secondary_load"], target)
                    expected = source[f"recbf_tagged_context_direct_{operation}_calls_secondary"]
                    if primary_sites or secondary_sites != expected:
                        raise ValueError(f"{model}: tagged-context direct {operation} callsites changed")
            verify_arm_words(secondary, source["secondary_load"], source["recbf_aspect_lookup_secondary_words"])
            verify_arm_words(secondary, source["secondary_load"], source["recbf_crop_descriptor_branch_words"])
            if "recbf_crop_descriptor_guard_words" in source:
                verify_arm_words(secondary, source["secondary_load"], source["recbf_crop_descriptor_guard_words"])
            if "recbf_crop_descriptor_slot_gate_words" in source:
                verify_arm_words(secondary, source["secondary_load"], source["recbf_crop_descriptor_slot_gate_words"])
            if "recbf_b34_bit10_source_primary_words" in source:
                verify_arm_words(primary, source["primary_load"], source["recbf_b34_bit10_source_primary_words"])
                verify_arm_words(secondary, source["secondary_load"], source["recbf_b34_bit10_source_secondary_words"])
                verify_arm_words(secondary, source["secondary_load"], source["recbf_b34_bit10_indexed_input_words"])
                verify_arm_words(secondary, source["secondary_load"], source["recbf_b34_selector_writer_words"])
                verify_arm_words(secondary, source["secondary_load"], source["recbf_b34_mode6_registration_table_words"])
                verify_arm_words(secondary, source["secondary_load"], source["recbf_mode6_selected_record_geometry_words"])
                verify_arm_words(secondary, source["secondary_load"], source["recbf_mode6_geometry_callback_packet_words"])
                verify_arm_words(primary, source["primary_load"], source["recbf_mode6_geometry_payload_copy_primary_words"])
                verify_arm_words(primary, source["primary_load"], source["recbf_mode6_geometry_receive_copy_primary_words"])
                verify_arm_words(secondary, source["secondary_load"], source["recbf_mode6_geometry_channel64_receiver_secondary_words"])
                verify_data_words(secondary, source["secondary_load"], source["recbf_mode6_geometry_channel64_index7_destination_word"])
                verify_arm_words(secondary, source["secondary_load"], source["recbf_mode6_geometry_index7_downstream_copy_secondary_words"])
                verify_data_words(secondary, source["secondary_load"], source["recbf_mode6_geometry_index7_downstream_copy_destination_word"])
                verify_arm_words(secondary, source["secondary_load"], source["recbf_mode6_geometry_index7_indirect_callback_secondary_words"])
                verify_arm_words(secondary, source["secondary_load"], source["recbf_mode6_geometry_index7_indirect_callback_registration_words"])
                verify_arm_words(secondary, source["secondary_load"], source["recbf_mode6_geometry_registration_channel69_secondary_words"])
                verify_data_words(secondary, source["secondary_load"], source["recbf_mode6_geometry_registration_channel69_dispatch_data_words"])
                verify_arm_words(primary, source["primary_load"], source["recbf_mode6_geometry_registration_transport_header_primary_words"])
                verify_arm_words(secondary, source["secondary_load"], source["recbf_mode6_channel69_1529_sender_secondary_words"])
                verify_arm_words(secondary, source["secondary_load"], source["recbf_mode6_channel69_1529_handler_gate_secondary_words"])
                verify_arm_words(secondary, source["secondary_load"], source["recbf_mode6_state27_transition_secondary_words"])
                transition_calls = [
                    site for image, load in ((primary, source["primary_load"]), (secondary, source["secondary_load"]))
                    for site in read_arm_bl_call_sites(image, load, 0x2119480)
                ]
                if transition_calls != source["recbf_mode6_state27_transition_direct_bl_sites_expected"]:
                    raise ValueError(f"{model}: mode-6 state-27 producer direct BL callsites changed")
                nested_first_entries = read_indexed_dispatch_first_entries(
                    secondary, source["secondary_load"],
                    source["recbf_mode6_channel69_1529_nested_table_address"],
                    source["recbf_mode6_channel69_1529_nested_table_entries"],
                )
                runner_states = [
                    row["state"] for row in nested_first_entries
                    if row["message_id"] == 0x1529
                    and row["handler"] == source["recbf_mode6_channel69_1529_handler"]
                ]
                if runner_states != source["recbf_mode6_channel69_1529_runner_first_entry_states"]:
                    raise ValueError(f"{model}: channel-69 0x1529 runner first-entry states changed")
                accessor_calls = [
                    site for image, load in ((primary, source["primary_load"]), (secondary, source["secondary_load"]))
                    for site in read_arm_bl_call_sites(image, load, 0x1FDC714)
                ]
                if accessor_calls != source["recbf_mode6_geometry_index7_accessor_direct_bl_sites_expected"]:
                    raise ValueError(f"{model}: mode-6 index-7 accessor direct BL callsites changed")
                selector_writer_calls = [
                    site for image, load in ((primary, source["primary_load"]), (secondary, source["secondary_load"]))
                    for site in read_arm_bl_call_sites(image, load, 0x1F12698)
                ]
                if selector_writer_calls != source["recbf_selector_writer_direct_bl_sites_expected"]:
                    raise ValueError(f"{model}: selector-writer direct BL callsites changed")
                geometry_setup_calls = [
                    site for image, load in ((primary, source["primary_load"]), (secondary, source["secondary_load"]))
                    for site in read_arm_bl_call_sites(image, load, 0x1F1E800)
                ]
                if geometry_setup_calls != source["recbf_mode6_geometry_setup_direct_bl_sites_expected"]:
                    raise ValueError(f"{model}: mode-6 geometry-setup direct BL callsites changed")
                receive_calls = [
                    site for image, load in ((primary, source["primary_load"]), (secondary, source["secondary_load"]))
                    for site in read_arm_bl_call_sites(image, load, 0x113DA0C)
                ]
                if receive_calls != source["recbf_mode6_geometry_receive_direct_bl_sites_expected"]:
                    raise ValueError(f"{model}: generic receive direct BL callsites changed")
                callback_runner_calls = [
                    site for image, load in ((primary, source["primary_load"]), (secondary, source["secondary_load"]))
                    for site in read_arm_bl_call_sites(image, load, 0x21167EC)
                ]
                if callback_runner_calls != source["recbf_mode6_registration_callback_runner_direct_bl_sites_expected"]:
                    raise ValueError(f"{model}: mode-6 callback runner direct BL callsites changed")
            verify_arm_words(primary, source["primary_load"], source["recbf_aspect_lookup_primary_words"])
            verify_data_words(secondary, source["secondary_load"], source["recbf_dispatch_targets"])
            if "recbf_save_to_media_record_words" in source:
                verify_data_words(secondary, source["secondary_load"], source["recbf_compress_record_words"])
                verify_data_words(secondary, source["secondary_load"], source["recbf_compress_dispatch_targets"])
                verify_arm_words(secondary, source["secondary_load"], source["recbf_compress_descriptor_route_words"])
                verify_arm_words(secondary, source["secondary_load"], source["recbf_compress_result_slot_words"])
                verify_data_words(secondary, source["secondary_load"], source["recbf_save_to_media_record_words"])
                verify_data_words(secondary, source["secondary_load"], source["recbf_save_to_media_dispatch_targets"])
                verify_data_words(secondary, source["secondary_load"], source["recbf_mode4_action_data_words"])
                verify_arm_words(secondary, source["secondary_load"], source["recbf_save_to_media_route_words"])
                verify_arm_words(secondary, source["secondary_load"], source["recbf_save_jpeg_buffer_request_words"])
                verify_data_words(secondary, source["secondary_load"], source["recbf_exif_tag_buffer_handoff_record_words"])
                verify_arm_words(secondary, source["secondary_load"], source["recbf_exif_tag_buffer_handoff_words"])
                verify_arm_words(primary, source["primary_load"], source["recbf_save_primary_indirect_submit_words"])
                verify_arm_words(secondary, source["secondary_load"], source["recbf_mode4_message_route_secondary_words"])
                for address, diagnostic in source["recbf_save_to_media_strings"].items():
                    offset = address - source["secondary_load"]
                    if secondary[offset:offset + len(diagnostic)] != diagnostic:
                        raise ValueError(f"{model}: Recbf save diagnostic mismatch at {address:#x}")
                for address, diagnostic in source["recbf_exif_tag_strings"].items():
                    offset = address - source["secondary_load"]
                    if secondary[offset:offset + len(diagnostic)] != diagnostic:
                        raise ValueError(f"{model}: Recbf EXIF-tag diagnostic mismatch at {address:#x}")
                for address, diagnostic in source["recbf_compress_strings"].items():
                    offset = address - source["secondary_load"]
                    if secondary[offset:offset + len(diagnostic)] != diagnostic:
                        raise ValueError(f"{model}: Recbf compression diagnostic mismatch at {address:#x}")
                for address, columns, row, expected in source["recbf_mode4_action_rows"]:
                    observed = read_recbf_action_row(secondary, source["secondary_load"], address, columns, row)
                    if observed != expected:
                        raise ValueError(f"{model}: mode-4 action row mismatch at {address:#x}, row {row}")
                recbf_mode4_action_hits = read_recbf_action_hits(
                    secondary, source["secondary_load"], source["recbf_mode3_action_matrix"],
                    source["recbf_mode3_action_matrix_rows"], source["recbf_mode3_action_matrix_columns"], 5,
                )
                if recbf_mode4_action_hits != [
                    {"event_row": 2, "state_column": 6, "post_callback_code": 1},
                    {"event_row": 24, "state_column": 6, "post_callback_code": 1},
                ]:
                    raise ValueError(f"{model}: mode-4 save callback cells changed")
        recbf_scripts = read_recbf_script_table(
            secondary, source["secondary_load"],
            source["recbf_script_table_address"], source["recbf_script_count"],
            source["recbf_script_terminator"],
        )
        copy_modes = [mode for mode, script in recbf_scripts.items() if source["recbf_copy_crop_raw_command"] in script]
        resize_modes = [mode for mode, script in recbf_scripts.items() if source["recbf_resize_yc_command"] in script]
        if copy_modes != source["recbf_copy_crop_raw_modes"] or resize_modes != source["recbf_resize_yc_modes"]:
            raise ValueError(f"{model}: Recbf command membership mismatch")
        if "secondary_ratio_descriptor_recbf_command_modes_expected" in source:
            for command, expected_modes in source["secondary_ratio_descriptor_recbf_command_modes_expected"].items():
                modes = [mode for mode, script in recbf_scripts.items() if command in script]
                if modes != expected_modes:
                    raise ValueError(f"{model}: Recbf EXIF command {command:#x} membership changed")
            verify_recbf_script_order(recbf_scripts[35], (0x15, 0x30, 0x27))
            verify_recbf_script_order(recbf_scripts[37], (0x15, 0x31, 0x32))
            verify_recbf_script_order(recbf_scripts[4], (0x33, 0x30, 0x3C, 0x3D))
            verify_recbf_script_order(recbf_scripts[4], (0x27, 0x35, 0x3C, 0x3D))
            verify_recbf_script_order(recbf_scripts[4], (0x36, 0x27, 0x35, 0x3C))
            verify_recbf_script_order(recbf_scripts[35], (0x15, 0x27, 0x35))
        if "recbf_short_crop_mode" in source:
            verify_data_words(secondary, source["secondary_load"], source["recbf_short_crop_data_words"])
            verify_arm_words(secondary, source["secondary_load"], source["recbf_short_crop_route_words"])
            if "recbf_short_crop_group_callback_sweep_words" in source:
                verify_arm_words(secondary, source["secondary_load"], source["recbf_short_crop_group_callback_sweep_words"])
            if "recbf_short_crop_scheduler_words" in source:
                verify_arm_words(secondary, source["secondary_load"], source["recbf_short_crop_scheduler_words"])
            if "recbf_short_crop_event58_slot_guard_words" in source:
                verify_arm_words(secondary, source["secondary_load"], source["recbf_short_crop_event58_slot_guard_words"])
            if "recbf_short_crop_row_template_words" in source:
                verify_arm_words(secondary, source["secondary_load"], source["recbf_short_crop_row_template_words"])
            if "recbf_short_crop_prerequisite_builder_words" in source:
                verify_arm_words(secondary, source["secondary_load"], source["recbf_short_crop_prerequisite_builder_words"])
                verify_arm_words(primary, source["primary_load"], source["recbf_short_crop_prerequisite_fill_primary_words"])
            if "recbf_short_crop_231_exclusion_words" in source:
                verify_arm_words(secondary, source["secondary_load"], source["recbf_short_crop_231_exclusion_words"])
                dynamic_groups = read_event_group_table(secondary, source["secondary_load"], 0x22DC8B8)
                profile_groups = read_event_group_table(secondary, source["secondary_load"], 0x22DA848)
                if len(dynamic_groups) != 36 or len(profile_groups) != 6:
                    raise ValueError(f"{model}: short crop event-group table sizes changed")
                if {group for group, events in dynamic_groups.items() if 58 in events} != {13, 15, 34, 36}:
                    raise ValueError(f"{model}: short crop dynamic-group membership changed")
                for group, prefix in source.get(
                    "secondary_ratio_descriptor_registration_group_prefixes", {}
                ).items():
                    if dynamic_groups.get(group, [])[:len(prefix)] != prefix:
                        raise ValueError(f"{model}: registration/crop event order changed in group {group}")
                if {group for group, events in profile_groups.items() if 58 in events} != {1}:
                    raise ValueError(f"{model}: short crop profile-group membership changed")
                if any(event in events for groups in (dynamic_groups, profile_groups)
                       for events in groups.values() for event in (103, 231)):
                    raise ValueError(f"{model}: prerequisite IDs 103/231 now occur as listed events")
            if "recbf_short_crop_bit103_message_writer_words" in source:
                verify_arm_words(secondary, source["secondary_load"], source["recbf_short_crop_bit103_message_writer_words"])
                verify_arm_words(secondary, source["secondary_load"], source["recbf_short_crop_message_payload_bridge_words"])
                verify_data_words(secondary, source["secondary_load"], source["recbf_short_crop_message_payload_bridge_data_words"])
                verify_arm_words(secondary, source["secondary_load"], source["recbf_short_crop_923b_packet_constructor_words"])
                verify_arm_words(secondary, source["secondary_load"], source["recbf_short_crop_923b_callback_gate_words"])
                verify_data_words(secondary, source["secondary_load"], source["recbf_short_crop_923b_callback_dispatch_data_words"])
                verify_arm_words(secondary, source["secondary_load"], source["recbf_short_crop_mode21_callback_request_words"])
                verify_data_words(secondary, source["secondary_load"], source["recbf_short_crop_mode21_callback_request_data_words"])
                verify_arm_words(secondary, source["secondary_load"], source["recbf_short_crop_channel14_worker_words"])
                verify_data_words(secondary, source["secondary_load"], source["recbf_short_crop_channel14_script_dispatch_data_words"])
                verify_arm_words(secondary, source["secondary_load"], source["recbf_short_crop_completion_stage_words"])
                stage_subtypes = read_recbf_completion_stage_subtypes(
                    secondary, source["secondary_load"], 0x22DF464
                )
                expected_stages = {i: (0x126 + 2 * i, 0x127 + 2 * i) for i in range(8)}
                if stage_subtypes != expected_stages or any(
                    subtype in (0x1D, 0xED)
                    for pair in stage_subtypes.values() for subtype in pair
                ):
                    raise ValueError(f"{model}: completion-stage subtypes changed")
                verify_arm_words(secondary, source["secondary_load"], source["recbf_upstream_1218_callback_source_words"])
                verify_data_words(secondary, source["secondary_load"], source["recbf_upstream_1218_callback_source_data_words"])
                verify_arm_words(secondary, source["secondary_load"], source["recbf_upstream_1218_mode_gate_words"])
                verify_arm_words(secondary, source["secondary_load"], source["recbf_upstream_1218_slot_provenance_words"])
                verify_arm_words(secondary, source["secondary_load"], source["recbf_upstream_1218_mode7_dispatch_words"])
                verify_data_words(secondary, source["secondary_load"], source["recbf_upstream_1218_mode7_dispatch_data_words"])
                address, columns, row, expected = source["recbf_upstream_1218_mode7_dispatch_row"]
                if read_recbf_action_row(secondary, source["secondary_load"], address, columns, row) != expected:
                    raise ValueError(f"{model}: mode-7 event-0x11b9 callback row changed")
                verify_arm_words(secondary, source["secondary_load"], source["recbf_upstream_1218_event_11b9_nested_words"])
                verify_data_words(secondary, source["secondary_load"], source["recbf_upstream_1218_event_11b9_nested_data_words"])
                for address, columns, row, expected in source["recbf_upstream_1218_event_11b9_nested_rows"]:
                    if read_recbf_action_row(secondary, source["secondary_load"], address, columns, row) != expected:
                        raise ValueError(f"{model}: nested event-0x11b9 callback row changed at {address:#x}")
                verify_recbf_script_order(recbf_scripts[35], (0x0E, 0x15, 0x27, 0x9C))
                verify_recbf_script_order(recbf_scripts[37], (0x0E, 0x15, 0x9C))
                for mode in (36, 38):
                    verify_recbf_script_order(recbf_scripts[mode], (0x76, 0x0E, 0x9C))
                verify_arm_words(primary, source["primary_load"], source["recbf_short_crop_request_transport_copy_primary_words"])
                verify_arm_words(secondary, source["secondary_load"], source["recbf_short_crop_923b_slot_provenance_words"])
                verify_data_words(secondary, source["secondary_load"], source["recbf_short_crop_923b_slot_provenance_data_words"])
                verify_arm_words(secondary, source["secondary_load"], source["recbf_short_crop_message_receive_route_words"])
                verify_arm_words(secondary, source["secondary_load"], source["recbf_short_crop_channel7_default_send_words"])
                verify_arm_words(primary, source["primary_load"], source["recbf_short_crop_channel7_default_send_primary_words"])
                verify_arm_words(secondary, source["secondary_load"], source["recbf_short_crop_handled_bit_update_words"])
                message_rows = read_recbf_message_bit_routes(secondary, source["secondary_load"], 0x22DCE30)
                if "secondary_ratio_descriptor_registration_event_group_data_words" in source:
                    bit17_rows = [row for row in message_rows if row["bit_id"] == 17]
                    if bit17_rows != [
                        {"index": 39, "command": 0x11A3, "subtype": 0, "selector": 0,
                         "bit_id": 17, "callback": 0x1F31514},
                    ]:
                        raise ValueError(f"{model}: registration bit-17 message route changed")
                bit103_rows = [row for row in message_rows if row["bit_id"] == 103]
                event11b9_rows = [row for row in message_rows if row["command"] == 0x11B9]
                if event11b9_rows != [
                    {"index": 22, "command": 0x11B9, "subtype": 0, "selector": 0,
                     "bit_id": 0xFFFFFFFF, "callback": 0},
                ]:
                    raise ValueError(f"{model}: event-0x11b9 message route changed")
                if len(message_rows) != 275 or bit103_rows != [
                    {"index": 150, "command": 0x923B, "subtype": 0x1D, "selector": 42, "bit_id": 103, "callback": 0},
                    {"index": 254, "command": 0x923B, "subtype": 0xED, "selector": 42, "bit_id": 103, "callback": 0},
                ]:
                    raise ValueError(f"{model}: bit-103 message routes changed")
            if "recbf_short_crop_group_gate_words" in source:
                verify_arm_words(secondary, source["secondary_load"], source["recbf_short_crop_group_gate_words"])
            if "recbf_short_crop_gfx_prerequisite_words" in source:
                verify_data_words(secondary, source["secondary_load"], source["recbf_short_crop_gfx_prerequisite_words"])
                verify_arm_words(secondary, source["secondary_load"], source["recbf_short_crop_gfx_message_writer_words"])
                gfx_message_rows = read_recbf_message_bit_routes(
                    secondary, source["secondary_load"], 0x27BA004
                )
                bit114_rows = [row for row in gfx_message_rows if row["bit_id"] == 114]
                bit239_rows = [row for row in gfx_message_rows if row["bit_id"] == 239]
                if len(gfx_message_rows) != 282 or bit114_rows != [
                    {"index": 157, "command": 0x9240, "subtype": 0x21, "selector": 46, "bit_id": 114, "callback": 0},
                ] or bit239_rows:
                    raise ValueError(f"{model}: GFX short-crop message routes changed")
            short_mode = source["recbf_short_crop_mode"]
            if recbf_scripts[short_mode] != source["recbf_short_crop_script"]:
                raise ValueError(f"{model}: short crop script changed")
            call_sites = read_arm_bl_call_sites(
                secondary, source["secondary_load"], source["recbf_short_crop_builder"]
            )
            start, end = source["recbf_short_crop_dispatch_span"]
            if len(call_sites) != source["recbf_short_crop_builder_bl_count"] or not all(
                start <= site < end for site in call_sites
            ):
                raise ValueError(f"{model}: short crop request-builder direct call inventory changed")
            for group, pointer in source.get("recbf_short_crop_group_pointers", {}).items():
                if source["recbf_short_crop_event_id"] not in read_event_group_ids(
                    secondary, source["secondary_load"], pointer
                ):
                    raise ValueError(f"{model}: crop event missing from group {group}")
        if "recbf_save_to_media_modes" in source:
            for command, expected_modes in source["recbf_save_to_media_modes"].items():
                observed_modes = [mode for mode, script in recbf_scripts.items() if command in script]
                if observed_modes != expected_modes:
                    raise ValueError(f"{model}: Recbf save command {command:#x} membership mismatch")
            verify_recbf_script_order(recbf_scripts[source["recbf_crop_compress_mode"]], (0x15, 0x27))
            verify_recbf_script_order(recbf_scripts[source["recbf_compress_save_mode"]], (0x27, 0x3C, 0x3D))
    if "primary_aspect_state_bridge_words" in source:
        verify_arm_words(primary, source["primary_load"], source["primary_aspect_state_bridge_words"])
    if "primary_aspect_dispatch_words" in source:
        verify_arm_words(primary, source["primary_load"], source["primary_aspect_dispatch_words"])
    if "size_selection_bridge_words" in source:
        verify_arm_words(secondary, source["secondary_load"], source["size_selection_bridge_words"])
    if "secondary_aspect_enum_consumer_words" in source:
        verify_arm_words(secondary, source["secondary_load"], source["secondary_aspect_enum_consumer_words"])
    complete = tables_consistent_and_enabled(selected, ratio_rows)
    disabled = [row for row in records if row["enabled_byte"] != 1]
    size_crop_data_candidate = (
        plan_x100v_size_and_raw_crop_lookup_data(primary, source)
        if model == "x100v_3_01" else []
    )
    ratio_stub_candidate = (
        plan_x100v_code4_ratio_stub(primary, source)
        if model == "x100v_3_01" else None
    )
    if ratio_stub_candidate is not None:
        cave_start = source["crop_ratio_code4_stub_candidate"]
        cave_end = source["crop_ratio_code4_stub_pad_end"]
        bounded_scan = {
            name: scan_aligned_arm_cave_references(image, load, cave_start, cave_end)
            for name, image, load in (
                ("primary", primary, source["primary_load"]),
                ("secondary", secondary, source["secondary_load"]),
            )
        }
        if any(addresses for partition in bounded_scan.values() for addresses in partition.values()):
            raise ValueError("X100V ratio stub plan: decoded partition references candidate padding")
        ratio_stub_candidate["bounded_reference_scan"] = bounded_scan
    return {
        "model": model,
        "source_sha256": digest,
        "primary_partition_sha256": primary_digest,
        "kernel_partition_sha256": kernel_digest,
        "configuration_defaults_sha256": (hashlib.sha256(configuration_defaults).hexdigest()
                                           if configuration_defaults is not None else None),
        "dimension_estimate_16_9_configuration_defaults": estimate_16_9_defaults,
        "volume_partition_sha256": volume_digest,
        "overlay_partition_sha256": overlay_digest,
        "secondary_partition_sha256": secondary_digest,
        "primary_65_24_records": selected,
        "primary_dimension_lookup_65_24": dimension_code4,
        "primary_dimension_lookup_65_24_matches_size_records": dimension_code4 == [
            [record["width"], record["height"]] for record in selected
        ],
        "size_and_raw_crop_lookup_data_candidate": size_crop_data_candidate,
        "size_and_raw_crop_lookup_data_candidate_runtime_verified": False,
        "primary_code4_ratio_stub_candidate": ratio_stub_candidate,
        "ratio_stub_same_4k_page_as_directly_called_arm_function_static_verified": bool(stub_adjacent_arm_bl_sites),
        "ratio_stub_adjacent_arm_function_direct_bl_sites": {
            partition: [f"{site:#010x}" for site in sites]
            for partition, sites in stub_adjacent_arm_bl_sites.items()
        },
        "ratio_stub_live_executable_mapping_verified": False,
        "preview_key_table_row_count": len(preview_keys),
        "preview_key_table_row_codes": sorted({row["key"][2] for row in preview_keys}),
        "preview_key_table_code4_entries": preview_code4_keys,
        "preview_lookup_code4_has_key": bool(preview_code4_keys),
        "preview_code4_inplace_16_9_row_reuse_candidate": preview_row_reuse_candidate,
        "preview_code4_inplace_candidate_total_changed_bytes": sum(
            len(row["changes"]) for row in preview_row_reuse_candidate
        ),
        "preview_code4_inplace_candidate_runtime_verified": False,
        "preview_code4_zero_placeholder_reuse_candidate": preview_zero_placeholder_candidate,
        "preview_code4_zero_placeholder_candidate_total_changed_bytes": sum(
            len(row["changes"]) for row in preview_zero_placeholder_candidate
        ),
        "preview_code4_zero_placeholder_runtime_use_verified": False,
        "preview_code0_old_keys_nonbypass_miss_after_candidate": [
            {"key": row["key_before"], "index_after": row["old_key_nonbypass_after_index"]}
            for row in preview_zero_placeholder_candidate
        ],
        "preview_row_enumeration_includes_code0_static_verified": "preview_row_enumeration_words" in source,
        "preview_secondary_miss_falls_back_to_row0_static_verified": "preview_secondary_lookup_miss_words" in source,
        "preview_parallel_index_array_57_words_static_verified": "preview_parallel_index_words" in source,
        "preview_local_cache_capacity_count_producer_static_verified": "preview_capacity_count_words" in source,
        "preview_code2_cache_safe_for_code4_verified": False,
        "preview_63_row_inplace_extension_overlaps_next_array_words": [
            f"{address:#010x}" for address in preview_parallel_extension_overlaps
        ],
        "dimension_estimate_coeff_table_row_count": len(dimension_estimate_coeff_rows),
        "dimension_estimate_65_24_coefficient_row_indices": [row["index"] for row in estimate_target_rows],
        "dimension_estimate_16_9_coefficient_row_indices": [row["index"] for row in estimate_16_9_rows],
        "dimension_estimate_coeff_byte_overwritten_from_runtime_property": True,
        "dimension_estimate_coeff_runtime_property_values_verified": False,
        "dimension_estimate_property_key_inventory": {
            "unique_keys": estimate_property_inventory[0],
            "minimum": estimate_property_inventory[1], "maximum": estimate_property_inventory[2],
        },
        "dimension_estimate_all_keys_direct_buffer_offsets_static_verified": (
            "dimension_estimate_property_key_inventory_expected" in source
            and all(0 <= key < 0x3D000 for key in estimate_property_keys)
        ),
        "preview_lookup_selected_pointer_command_handoff_static_verified": "preview_lookup_pointer_handoff_words" in source,
        "preview_descriptor_same_function_bridge_static_verified": "preview_descriptor_bridge_primary_words" in source,
        "preview_descriptor_second_lookup_bypass_forced_zero_static_verified": "preview_descriptor_bridge_primary_words" in source,
        "preview_descriptor_same_first_key_requires_state_not_45": "preview_descriptor_bridge_primary_words" in source,
        "preview_descriptor_gfx_dual_lookup_homologue_static_verified": "preview_descriptor_dual_lookup_primary_words" in source,
        "preview_lookup_selected_word_copied_without_dereference_in_command_builder_static_verified": (
            "preview_lookup_pointer_handoff_words" in source
        ),
        "preview_1159_message_row_in_image": preview_1159_message_row,
        "preview_1159_generic_callback_absent_in_image": (
            preview_1159_message_row is not None and preview_1159_message_row["callback"] == 0
        ),
        "preview_1159_separate_controller_state5_static_verified": (
            "preview_1159_dispatch_controller_words" in source
        ),
        "preview_1159_controller_rows_in_image": preview_1159_controller_rows,
        "preview_1159_event44_gate_direct_bl_sites": [
            f"{site:#010x}" for site in preview_1159_event44_gate_direct_bl_sites
        ],
        "preview_1159_mode1_row2_excludes_direct_event44_gate_callback_static_verified": (
            preview_1159_controller_rows is not None
            and all(cell[0] != 2 for cell in preview_1159_controller_rows["mode1_row2"])
        ),
        "preview_1159_same_offset_as_event44_pointer_field_static_verified": (
            "preview_1159_conditional_gate_alias_words" in source
            and "recbf_geometry_event_group_47_gate_source_words" in source
        ),
        "preview_1159_word_to_threshold_field_conditional_static_verified": (
            "preview_1159_threshold_route_words" in source
        ),
        "preview_1159_to_event44_gate_execution_verified": False,
        "preview_1159_threshold_runtime_value_verified": False,
        "preview_1159_selected_word_effect_on_display_or_save_verified": False,
        "preview_runtime_config_206_207_copy_static_verified": "preview_runtime_config_206_207_secondary_words" in source,
        "preview_runtime_config_206_207_direct_bl_sites": [
            f"{site:#010x}" for site in preview_config_copy_direct_bl_sites
        ],
        "runtime_config_206_stack_static_verified": "runtime_config_206_stack_words" in source,
        "preview_temp_block_header_init_static_verified": "preview_temp_block_header_init_words" in source,
        "preview_temp_block_channel7_receiver_static_verified": "preview_temp_block_channel7_receiver_secondary_words" in source,
        "preview_id200_channel7_sender_static_verified": "preview_id200_channel7_sender_secondary_words" in source,
        "preview_runtime_array_57_word_capacity_cache_export_static_verified": "preview_runtime_array_cache_export_primary_words" in source,
        "preview_runtime_array_read_precedes_same_function_refresh_static_verified": "preview_runtime_array_cache_export_secondary_words" in source,
        "preview_runtime_array_active_freshness_verified": False,
        "preview_cache_preserve_clear_recompute_gate_static_verified": "preview_cache_refresh_gate_primary_words" in source,
        "preview_cache_enable_dispatch_static_verified": "preview_cache_enable_dispatch_ranges" in source,
        "preview_id200_channel7_sender_direct_bl_sites": [
            f"{site:#010x}" for site in preview_id200_sender_direct_bl_sites
        ],
        "preview_id200_sender_third_payload_word_source_addresses": (
            ["0x01734a8c", "0x02eea24c", "0x02eea24c"]
            if "preview_id200_channel7_sender_secondary_words" in source else []
        ),
        "preview_id200_sender_object_prefix_copy_stops_before_array_static_verified": (
            "preview_id200_channel7_sender_object_prefix_copy_words" in source
        ),
        "preview_lookup_pointer_array_id200_publication_static_verified": "preview_pointer_array_id200_publication_words" in source,
        "preview_pointer_publisher_callback_dispatch_static_verified": "preview_pointer_publisher_callback_dispatch_words" in source,
        "preview_pointer_publisher_category22_conditional_trigger_static_verified": "preview_pointer_publisher_category22_trigger_words" in source,
        "preview_pointer_publisher_conditional_channel7_bridge_static_verified": "preview_pointer_publisher_conditional_channel7_bridge_words" in source,
        "preview_pointer_publisher_channel7_filter_static_verified": "preview_pointer_publisher_channel7_filter_words" in source,
        "preview_pointer_publisher_category22_a1_b0_record_index": (
            arm_smlabb_record_index(1, 3, 0)
            if "preview_pointer_publisher_category22_trigger_words" in source else None
        ),
        "preview_pointer_array_id200_payload_source_verified": False,  # runtime payload contents, not sender address provenance
        "preview_lookup_selected_pointer_contents_verified": False,
        "preview_lookup_bypass_source_preview_plus_0x71_static_verified": True,
        "preview_lookup_bypass_runtime_value_verified": False,
        "preview_lookup_bypass_row0_dimensions": [preview_keys[0]["width"], preview_keys[0]["height"]],
        "preview_mode_key227_to_fixed_object_static_verified": "preview_mode_key227_fixed_object_words" in source,
        "preview_mode_key227_reads_runtime_buffer_static_verified": "preview_mode_key227_fixed_object_words" in source,
        "preview_mode_fixed_object_cache_copy_static_verified": "preview_mode_fixed_object_cache_copy_words" in source,
        "preview_bypass_global_direct_accessor_static_verified": "preview_bypass_global_accessor_words" in source,
        "preview_mode_fixed_object_to_active_preview_verified": False,
        "crop_ratio_helper_code4_jump_target": f"{crop_ratio_code4_target:#010x}",
        "crop_ratio_common_arithmetic_body_sha256": common_body_digest,
        "crop_ratio_helper_code4_width_height_ratio": source["crop_ratio_code4"],
        "crop_ratio_helper_code4_is_65_24": source["crop_ratio_code4"] == [65, 24],
        "secondary_ratio_descriptor_code4_target": (
            f"{secondary_ratio_descriptor_targets[4]:#010x}" if secondary_ratio_descriptor_targets else None
        ),
        "secondary_ratio_descriptor_code4_components": [24, 65] if secondary_ratio_descriptor_targets else None,
        "secondary_ratio_descriptor_static_verified": bool(secondary_ratio_descriptor_targets),
        "secondary_ratio_descriptor_saved_image_effect_verified": False,
        "secondary_ratio_descriptor_recbf_exif_route_static_verified": (
            "secondary_ratio_descriptor_recbf_dispatch_words" in source
        ),
        "secondary_ratio_descriptor_record_subtype2_gate_static_verified": (
            "secondary_ratio_descriptor_constructor_gate_words" in source
            or "secondary_ratio_descriptor_gfx_subtype2_record_words" in source
        ),
        "secondary_ratio_descriptor_record_subtype2_in_normal_still_verified": False,
        "secondary_ratio_descriptor_record_selected_via_mutable_registry_static_verified": (
            "secondary_ratio_descriptor_record_source_words" in source
        ),
        "secondary_ratio_descriptor_key43_subkey66_registration_static_match_verified": (
            "secondary_ratio_descriptor_key43_subkey66_registration_words" in source
        ),
        "secondary_ratio_descriptor_registration_precedes_crop_in_group13_15_static_verified": (
            "secondary_ratio_descriptor_registration_event_group_data_words" in source
            and "secondary_ratio_descriptor_registration_group_prefixes" in source
        ),
        "secondary_ratio_descriptor_key43_subkey66_same_runtime_object_verified": False,
        "secondary_ratio_descriptor_record_subtype_writer_identified": False,
        "secondary_ratio_descriptor_cmd32_subtype5_bypasses_ratio_builder_static_verified": (
            "secondary_ratio_descriptor_cmd32_subtype5_words" in source
        ),
        "secondary_ratio_descriptor_shared_command_subkeys_if_success_static_verified": (
            "secondary_ratio_descriptor_shared_selector_subkey_words" in source
        ),
        "secondary_ratio_descriptor_initial_bank_values_0_to_7": secondary_ratio_descriptor_record_banks,
        "secondary_ratio_descriptor_initial_banks_are_runtime_values": False,
        "crop_ratio_helper_dispatch_targets": [f"{target:#010x}" for target in crop_ratio_targets],
        "crop_ratio_helper_code4_shared_with_codes": [
            code for code, target in enumerate(crop_ratio_targets, 1)
            if code != 4 and target == crop_ratio_code4_target
        ],
        "crop_ratio_helper_code4_uses_out_of_range_default": (
            crop_ratio_code4_target == source["crop_ratio_helper"] + 0x34
        ),
        "crop_ratio_helper_direct_bl_sites": {
            partition: [f"{site:#010x}" for site in sites]
            for partition, sites in crop_ratio_direct_bl_sites.items()
        },
        "recbf_geometry_event_aspect_carrier_verified": "recbf_geometry_event_words" in source,
        "recbf_geometry_event_registration_id": source.get("recbf_geometry_event_registration_id"),
        "recbf_geometry_event_registration_verified": "recbf_geometry_event_registration_words" in source,
        "recbf_geometry_event_44_registration_verified": source.get("recbf_geometry_event_registration_id") == 44,
        "recbf_geometry_event_group_47_candidate_verified": "recbf_geometry_event_runtime_list_words" in source,
        "recbf_geometry_event_group_47_gate_source_verified": "recbf_geometry_event_group_47_gate_source_words" in source,
        "recbf_geometry_event_runtime_list_membership_verified": False,
        "recbf_geometry_event_scheduler_suppression_test_verified": "recbf_geometry_event_bitmap_words" in source,
        "recbf_geometry_event_saved_image_reachability_verified": False,
        "primary_disabled_ids": sorted(row["id"] for row in disabled),
        "primary_disabled_dimensions": sorted({(row["width"], row["height"]) for row in disabled}),
        "static_selection_model_65_24_ids": [
            select_enabled_size_id(records, 4, level) for level in range(3)
        ],
        "static_ungated_reverse_lookup_65_24_ids": [
            select_size_id_without_enabled_gate(records, 4, level) for level in range(3)
        ],
        "static_enabled_dimension_label_count": len(enabled_dimension_labels(records)),
        "develop_parameter_aspect_outputs": develop_aspects,
        "develop_parameter_16_9_alias_inputs": [index for index, code in enumerate(develop_aspects, 1) if code == 2],
        "observed_builder_seed_inputs": source["develop_aspect_builder_seed_inputs"],
        "observed_builder_seed_outputs": [
            develop_aspects[value - 1] for value in source["develop_aspect_builder_seed_inputs"]
        ],
        "develop_parameter_jump_table_span": {
            "partition_start": jump_start,
            "partition_end_exclusive": jump_end,
            "entry_count": source["develop_aspect_jump_count"],
            "first_case_ram_address": first_case,
            "in_place_expansion_bytes": 0,
        },
        "develop_parameter_has_65_24_code": 4 in develop_aspects,
        "develop_parameter_copy_to_working_state_verified": True,
        "observed_geometry_code4_branch": source["geometry_code4_branch"],
        "identified_movie_geometry_callers": [f"{address:#010x}" for address in source.get("movie_geometry_caller_addresses", [])],
        "identified_movie_descriptor_callers": [f"{address:#010x}" for address in source.get("movie_descriptor_caller_addresses", [])],
        "recbf_copy_crop_raw_named_record_verified": "recbf_copy_crop_raw_strings" in source,
        "recbf_script_count": source.get("recbf_script_count"),
        "recbf_copy_crop_raw_command": source.get("recbf_copy_crop_raw_command"),
        "recbf_resize_yc_command": source.get("recbf_resize_yc_command"),
        "recbf_copy_crop_raw_script_modes": source.get("recbf_copy_crop_raw_modes"),
        "recbf_resize_yc_script_modes": source.get("recbf_resize_yc_modes"),
        "recbf_script_mode_reachability_verified": False,
        "recbf_short_crop_event_id": source.get("recbf_short_crop_event_id"),
        "recbf_short_crop_script_mode": source.get("recbf_short_crop_mode"),
        "recbf_short_crop_event_to_request_static_verified": "recbf_short_crop_mode" in source,
        "recbf_short_crop_event_group_candidates": sorted(source.get("recbf_short_crop_group_pointers", {})),
        "recbf_short_crop_group_callback_sweep_static_verified": "recbf_short_crop_group_callback_sweep_words" in source,
        "recbf_short_crop_scheduler_static_verified": "recbf_short_crop_scheduler_words" in source,
        "recbf_short_crop_event58_slot_guard_success_static_verified": "recbf_short_crop_event58_slot_guard_words" in source,
        "recbf_short_crop_shared_row_template_static_verified": "recbf_short_crop_row_template_words" in source,
        "recbf_short_crop_event58_prerequisite_ids_static_verified": "recbf_short_crop_prerequisite_builder_words" in source,
        "recbf_short_crop_231_builder_exclusion_static_verified": "recbf_short_crop_231_exclusion_words" in source,
        "recbf_short_crop_103_231_absent_from_two_list_families_static_verified": "recbf_short_crop_231_exclusion_words" in source,
        "recbf_short_crop_bit103_message_writer_static_verified": "recbf_short_crop_bit103_message_writer_words" in source,
        "recbf_short_crop_923b_packet_layout_static_verified": "recbf_short_crop_923b_packet_constructor_words" in source,
        "recbf_short_crop_mode21_request_carries_923b_callback_static_verified": "recbf_short_crop_mode21_callback_request_words" in source,
        "recbf_short_crop_channel14_worker_to_script_static_verified": "recbf_short_crop_channel14_worker_words" in source,
        "recbf_short_crop_completion_stage_subtypes_do_not_match_bit103_static_verified": "recbf_short_crop_completion_stage_words" in source,
        "recbf_short_crop_mode21_request_downstream_of_event58_gate_static_verified": "recbf_short_crop_channel14_worker_words" in source,
        "recbf_upstream_1218_callback_source_static_verified": "recbf_upstream_1218_callback_source_words" in source,
        "recbf_upstream_1218_script_0e_76_to_bit103_subtypes_static_verified": "recbf_upstream_1218_callback_source_data_words" in source,
        "recbf_upstream_1218_mode_gate_static_verified": "recbf_upstream_1218_mode_gate_words" in source,
        "recbf_upstream_1218_packet_slot_provenance_static_verified": "recbf_upstream_1218_slot_provenance_words" in source,
        "recbf_upstream_1218_mode7_event_11b9_column0_static_verified": "recbf_upstream_1218_mode7_dispatch_words" in source,
        "recbf_upstream_1218_event_11b9_nested_route_static_verified": "recbf_upstream_1218_event_11b9_nested_words" in source,
        "recbf_upstream_1218_event_11b9_runtime_columns_and_delivery_verified": False,
        "recbf_upstream_1218_same_slot_before_event58_verified": False,
        "recbf_short_crop_request_transport_copies_payload_static_verified": "recbf_short_crop_request_transport_copy_primary_words" in source,
        "recbf_short_crop_bit103_callback_has_static_send_path_if_invoked": "recbf_short_crop_923b_callback_gate_words" in source,
        "recbf_short_crop_mode21_callback_subtype_1d_or_ed_invocation_verified": False,
        "recbf_short_crop_message_payload_to_match_fields_static_verified": "recbf_short_crop_message_payload_bridge_words" in source,
        "recbf_short_crop_923b_payload_context_to_bit_slot_static_verified": "recbf_short_crop_923b_slot_provenance_words" in source,
        "recbf_short_crop_channel7_receive_to_bit_table_static_verified": "recbf_short_crop_message_receive_route_words" in source,
        "recbf_short_crop_channel7_default_sender_alignment_static_verified": "recbf_short_crop_channel7_default_send_words" in source,
        "recbf_short_crop_1d_or_ed_message_delivery_same_slot_order_verified": False,
        "recbf_short_crop_handled_bit_update_not_gated_by_diagnostics_static_verified": "recbf_short_crop_handled_bit_update_words" in source,
        "recbf_short_crop_group_gate_static_verified": "recbf_short_crop_group_gate_words" in source,
        "recbf_short_crop_gfx_prerequisite_lists_static_verified": "recbf_short_crop_gfx_prerequisite_words" in source,
        "recbf_short_crop_gfx_bit114_message_writer_static_verified": "recbf_short_crop_gfx_message_writer_words" in source,
        "recbf_short_crop_gfx_bit114_same_slot_before_event71_verified": False,
        "recbf_short_crop_normal_still_reachability_verified": False,
        "recbf_script_mode_from_request_plus4_verified": "recbf_script_mode_selector_words" in source,
        "recbf_script_mode_descriptor_to_request_verified": "recbf_script_mode_selector_words" in source,
        "recbf_mode3_message_to_crop_script_static_path_verified": "recbf_mode3_message_route_secondary_words" in source and recbf_scripts is not None and source["recbf_copy_crop_raw_command"] in recbf_scripts[3],
        "recbf_mode3_action_trigger_cells": recbf_mode3_action_hits,
        "recbf_mode3_action_row5_controller1_cells_static_verified": recbf_mode3_action_hits is not None,
        "recbf_mode3_action_event_0x1232_trigger_candidate_bounded": False,
        "recbf_event_0x1232_final_controller0_to_controller2_column0_static_route_verified": "recbf_event_1232_final_route_words" in source,
        "recbf_event_0x1232_final_controller1_crop_gate_reachability_verified": False,
        "recbf_controller1_row5_action0_message_0x11a2_static_route_verified": "recbf_controller1_row5_producer_words" in source,
        "recbf_controller1_row5_action0_message_0x11a2_runtime_reachability_verified": False,
        "recbf_controller1_crop_column1_static_predecessor_verified": "recbf_controller1_crop_column_predecessor_words" in source,
        "recbf_controller1_crop_column4_static_predecessor_verified": "recbf_controller1_crop_column_predecessor_words" in source,
        "recbf_controller1_crop_columns_runtime_sequence_verified": False,
        "recbf_event_0x1232_nested_controller_static_path_verified": "recbf_event_1232_nested_route_words" in source,
        "recbf_event_0x1232_tagged_context_indirection_static_verified": "recbf_event_1232_tagged_context_words" in source,
        "recbf_event_0x1232_same_slot_tag1_registration_attempt_static_verified": "recbf_event_1232_tagged_context_words" in source,
        "recbf_event_0x1232_successful_tag1_prepend_then_lookup_same_slot_static_verified": "recbf_event_1232_tagged_context_words" in source,
        "recbf_event_0x1232_writer_status_ignored_and_second_lookup_static_verified": "recbf_event_1232_tagged_context_words" in source,
        "recbf_event_0x1232_second_lookup_result_forwarded_to_dispatcher_static_verified": "recbf_event_1232_tagged_context_words" in source,
        "recbf_event_0x1232_no_intervening_registry_mutation_verified": False,
        "recbf_event_0x1232_copy_index_equals_final_tag1_index_verified": False,
        "recbf_guarded_aspect_to_parameter_lookup_verified": "recbf_aspect_lookup_secondary_words" in source,
        "recbf_crop_command_centered_descriptor_rewrite_conditional_static_verified": "recbf_crop_descriptor_branch_words" in source,
        "recbf_crop_command_state29_flag2_blocks_centered_rewrite_static_verified": "recbf_crop_descriptor_branch_words" in source,
        "recbf_crop_command_state45_and_32_exceptions_static_verified": "recbf_crop_descriptor_guard_words" in source,
        "recbf_crop_code4_zero_dimension_hazard_if_rewrite_reached": (
            "recbf_crop_descriptor_guard_words" in source
            and dimension_code4 == [[0, 0], [0, 0], [0, 0]]
        ),
        "recbf_crop_command_descriptor_copy_to_context_conditional_static_verified": "recbf_crop_descriptor_branch_words" in source,
        "recbf_crop_command_f0_destination_requires_state25_26_or_b34_bit10_static_verified": "recbf_crop_descriptor_slot_gate_words" in source,
        "recbf_b34_bit10_from_input_plus222_bit1_static_verified": "recbf_b34_bit10_source_primary_words" in source,
        "recbf_b34_bit10_indexed_per_slot_input_address_static_verified": "recbf_b34_bit10_indexed_input_words" in source,
        "recbf_b34_index_selector_lookup_minus_one_writer_static_verified": "recbf_b34_selector_writer_words" in source,
        "recbf_b34_mode6_registration_precedes_ram_table_lookup_static_verified": "recbf_b34_mode6_registration_table_words" in source,
        "recbf_mode6_selected_record_to_default_aspect_geometry_static_verified": "recbf_mode6_selected_record_geometry_words" in source,
        "recbf_mode6_geometry_callback_message_submission_static_verified": "recbf_mode6_geometry_callback_packet_words" in source,
        "recbf_mode6_geometry_callback_payload_copy_path_static_verified": "recbf_mode6_geometry_payload_copy_primary_words" in source,
        "recbf_mode6_geometry_callback_channel64_index7_buffer_path_static_verified": "recbf_mode6_geometry_channel64_receiver_secondary_words" in source,
        "recbf_mode6_geometry_callback_index7_downstream_72_byte_copy_static_verified": "recbf_mode6_geometry_index7_downstream_copy_secondary_words" in source,
        "recbf_mode6_geometry_callback_index7_indirect_invocation_site_static_verified": "recbf_mode6_geometry_index7_indirect_callback_secondary_words" in source,
        "recbf_mode6_geometry_callback_index7_registration_packet_static_verified": "recbf_mode6_geometry_index7_indirect_callback_registration_words" in source,
        "recbf_mode6_geometry_registration_channel69_inbound_route_static_verified": "recbf_mode6_geometry_registration_channel69_secondary_words" in source,
        "recbf_mode6_geometry_registration_outbound_pointer_inbound_callback_slot_layout_static_verified": "recbf_mode6_geometry_registration_transport_header_primary_words" in source and "recbf_mode6_geometry_registration_channel69_secondary_words" in source,
        "recbf_mode6_geometry_registration_outbound_pointer_inbound_callback_slot_runtime_value_verified": False,
        "recbf_mode6_channel69_1529_runner_first_entry_states": source.get("recbf_mode6_channel69_1529_runner_first_entry_states", []),
        "recbf_mode6_channel69_1529_runner_first_entry_routes_static_verified": "recbf_mode6_channel69_1529_nested_table_address" in source,
        "recbf_mode6_state26_to_27_gated_transition_static_verified": "recbf_mode6_state27_transition_secondary_words" in source,
        "recbf_mode6_channel69_1529_runner_normal_still_execution_verified": False,
        "recbf_mode6_geometry_callback_executed_in_normal_still_verified": False,
        "recbf_conditional_descriptor_to_compression_dimensions_static_verified": "recbf_compress_descriptor_route_words" in source,
        "recbf_compression_result_slot_static_verified": "recbf_compress_result_slot_words" in source,
        "recbf_mode35_crop_before_compress_static_verified": "recbf_crop_compress_mode" in source,
        "recbf_mode4_compress_before_save_static_verified": "recbf_compress_save_mode" in source,
        "recbf_crop_and_compress_same_normal_still_verified": False,
        "recbf_save_to_media_commands_and_dispatch_static_verified": "recbf_save_to_media_record_words" in source,
        "recbf_save_to_media_script_modes": source.get("recbf_save_to_media_modes"),
        "recbf_mode4_message_to_save_script_static_path_verified": "recbf_mode4_message_route_secondary_words" in source and recbf_scripts is not None and 0x3C in recbf_scripts[4] and 0x3D in recbf_scripts[4],
        "recbf_mode4_save_callback_cells": recbf_mode4_action_hits,
        "recbf_crop_column4_to_save_column6_static_predecessor_verified": "recbf_mode4_action_rows" in source,
        "recbf_crop_to_save_same_still_sequence_verified": False,
        "recbf_save_to_media_indirect_submit_static_verified": "recbf_save_primary_indirect_submit_words" in source,
        "recbf_save_jpeg_buffer_request_static_verified": "recbf_save_jpeg_buffer_request_words" in source and volume_digest is not None,
        "recbf_exif_tag_to_overlay_buffer_pack_static_verified": "recbf_exif_tag_buffer_handoff_words" in source and overlay_digest is not None,
        "recbf_encoder_component_builder_static_verified": "encoder_component_overlay_words" in source and overlay_digest is not None,
        "recbf_encoder_direct_word_accessors_static_verified": kernel_digest is not None,
        "recbf_compression_final_component_result_copy_static_verified": "encoder_component_secondary_words" in source,
        "recbf_encoder_register_values_observed": False,
        "recbf_encoder_job_completion_same_shot_verified": False,
        "recbf_compression_to_save_buffer_same_shot_verified": False,
        "recbf_default_selector65_volume_method_static_verified": volume_digest is not None,
        "volume_query8_unit_and_status_static_verified": volume_digest is not None,
        "volume_query8_record_product_publication_static_verified": volume_digest is not None,
        "volume_query8_live_context_verified": False,
        "recbf_default_volume_pathname_service_requests_static_verified": volume_digest is not None and "recbf_save_primary_indirect_submit_words" in source,
        "recbf_raf_jpeg_writer_identity_verified": False,
        "recbf_centered_descriptor_rewrite_raf_or_jpeg_output_verified": False,
        "observed_primary_state_code4_default_zero": "primary_aspect_dispatch_words" in source,
        "observed_descriptor_code4_branch": source["descriptor_code4_branch"],
        "descriptor_aspect_branch_gated_by_subtype_6": True,
        "secondary_65_24_triplets": ratio_rows,
        "vg_geometry_aspect4_rows": vg_rows,
        "vg_selector_zero_and_nonzero_normal_rows": vg_selector_tables,
        "vg_selector_special_code2_row": 15 if vg_selector_tables is not None else None,
        "vg_selector_special_code4_fallback_row": 14 if vg_selector_tables is not None else None,
        "vg_selector_preview_state_plus_0x70_verified": True,
        "preview_state_plus_0x70_source_global": f"{source['preview_state_source_global']:#010x}" if "preview_state_source_global" in source else None,
        "preview_state_plus_0x70_source_verified": "preview_state_producer_primary_words" in source,
        "preview_source_object_to_global_code_verified": "preview_source_bridge_primary_words" in source and "preview_source_bridge_secondary_words" in source,
        "preview_source_object_parallel_aspect_and_code_copy_verified": "preview_source_bridge_primary_words" in source,
        "preview_aspect_and_code_pair_bidirectional_copy_verified": "preview_source_bridge_primary_words" in source and "preview_state_producer_primary_words" in source,
        "preview_source_object_active_preview_or_fallback_verified": "preview_source_bridge_secondary_words" in source,
        "preview_fallback_snapshot_copy_verified": "preview_source_bridge_secondary_words" in source and "preview_source_bridge_primary_words" in source,
        "preview_builder_four_direct_sources_bounded_verified": "preview_builder_other_direct_callsite_words" in source and "preview_source_bridge_secondary_words" in source,
        "preview_source_object_identity_with_still_carrier_verified": False,
        "recbf_event_fallback_reads_preview_code_source_verified": "preview_state_producer_primary_words" in source and "recbf_geometry_event_words" in source,
        "vg_packet_to_alternate_flag_verified": "vg_packet_alternate_flag_words" in source,
        "still_aspect_to_vg_selector_verified": False,
        "vg_static_channel_to_context_routes": vg_channel_routes,
        "vg_geometry_sink_reachability_verified": False,
        "size_tables_consistent_and_enabled": complete,
        "scope": "static size/lookup/VG geometry, preview-state row-code construction and active/fallback-object publication plus its conditional record-buffer event fallback, state-to-dimension key table and same-function descriptor bridge with forced non-bypass second lookup, channel-routing tables, crop-ratio jump target and event carrier, X100V conditional event-list candidate, event-58 bit-103 prerequisite and bit-231 builder exclusion with bounded absence of IDs 103/231 from two static list families, X100V 0x923b packet constructors/payload-copy field and slot-provenance layout plus mode-21 request-carried 0x923b callback and its bit-103 local send route if invoked, and conditional channel-7 default sender and receive-to-bit-table route, distinct enable/suppression bitmaps, pinned ARM instructions, event-58/X100V-mode-21 conditional scheduler-to-dispatch chain and event-71/GFX-mode-26 short-crop request analogue with bounded direct-call inventories, GFX event-71 bit-114/239 group lists and 0x9240/subtype-0x21 message-to-bit-114 route, conditional 0x1232 nested-controller-to-final-controller0 route, separate controller1 crop-script and save-script candidates with a possible column transition but no proven same-shot order, conditional crop-descriptor to compression-dimension path, Recbf command streams/diagnostics and default selector-65 volume-interface method, and movie-caller diagnostics only; no verified callback invocation with prerequisite subtype or same-slot delivery/order of short-crop prerequisite packets, still-menu source writer, finder-sink routing, ordinary-still script execution, event-44/58/71 runtime membership, RAF/JPEG writer identity, saved-file crop, or camera validation",
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--x100v", type=Path, required=True)
    parser.add_argument("--gfx100", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps({
        "x100v": validate(args.x100v, "x100v_3_01"),
        "gfx100": validate(args.gfx100, "gfx100_5_18"),
    }, indent=2))


if __name__ == "__main__":
    main()
