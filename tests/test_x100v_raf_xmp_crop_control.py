"""Independent bounded RAF/JPEG fixture for the synthetic XMP crop control."""

import struct
import xml.etree.ElementTree as ET

import pytest

from tools.x100v_raf_xmp_crop_control import make_control, xmp_extent


def fixture(*, xmp=True, padding=640):
    # Independently construct the RAF extent, JPEG APP1 length and XMP packet.
    packet = (b"<?xpacket begin=''?>\r\n"
              b'<x:xmpmeta xmlns:x="adobe:ns:meta/">'
              b'<rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">'
              b'<rdf:Description rdf:about=""><x:Rating>0</x:Rating>'
              b'</rdf:Description></rdf:RDF></x:xmpmeta>\r\n'
              + b" " * padding + b"<?xpacket end='w'?>")
    payload = (b"http://ns.adobe.com/xap/1.0/\x00" + packet) if xmp else b"other\x00"
    jpeg = b"\xff\xd8\xff\xe1" + struct.pack(">H", len(payload) + 2) + payload + b"\xff\xd9"
    result = bytearray(0x2000)
    result[:16] = b"FUJIFILMCCD-RAW "
    result[0x94:0x94 + len(jpeg)] = jpeg
    struct.pack_into(">6I", result, 0x54, 0x94, len(jpeg), 0x1000, 0x100, 0x1100, 0x100)
    return bytes(result)


def test_xmp_only_changes_inside_fixed_app1_and_has_centered_crop():
    source = fixture()
    output, (start, end) = make_control(source)
    assert len(output) == len(source)
    assert output[:start] == source[:start]
    assert output[end:] == source[end:]
    assert output[0x94:0x96] == b"\xff\xd8"
    assert output[0x94 + struct.unpack_from(">I", output, 0x58)[0] - 2:
                  0x94 + struct.unpack_from(">I", output, 0x58)[0]] == b"\xff\xd9"
    packet = output[start:end]
    document = packet[packet.index(b"<x:xmpmeta"):packet.index(b"</x:xmpmeta>") + 13]
    root = ET.fromstring(document)
    namespace = {"crs": "http://ns.adobe.com/camera-raw-settings/1.0/"}
    get = lambda name: root.find(".//crs:" + name, namespace).text
    assert get("HasCrop") == "True"
    assert get("CropLeft") == "0" and get("CropRight") == "1"
    top, bottom = float(get("CropTop")), float(get("CropBottom"))
    assert abs(top + bottom - 1) < 1e-9
    assert abs((bottom - top) * 4160 - 2304) < 0.001
    assert xmp_extent(output) == (start, end)


def test_rejects_missing_xmp_and_insufficient_padding():
    with pytest.raises(ValueError, match="one bounded XMP"):
        xmp_extent(fixture(xmp=False))
    with pytest.raises(ValueError, match="space padding"):
        make_control(fixture(padding=4))
