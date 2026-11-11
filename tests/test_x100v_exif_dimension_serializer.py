import struct
import pytest
from tools.x100v_exif_dimension_serializer import parse_entries


def test_literal_tiff_pair():
    assert parse_entries(bytes.fromhex("02a00400010000006018000003a004000100000000090000")) == (6240,2304)


@pytest.mark.parametrize("width,height", [(4416,1632),(3120,1152),(6240,4160),(0,0),(0xffffffff,0xffffffff)])
def test_long_value_round_trip(width,height):
    assert parse_entries(struct.pack("<HHIIHHII",0xa002,4,1,width,0xa003,4,1,height)) == (width,height)


@pytest.mark.parametrize("offset,value",[(0,0),(2,3),(4,2),(12,0),(14,3),(16,2)])
def test_reject_wrong_schema(offset,value):
    data=bytearray.fromhex("02a00400010000006018000003a004000100000000090000")
    data[offset]=value
    with pytest.raises(ValueError):parse_entries(bytes(data))


@pytest.mark.parametrize("size",[0,12,23,25])
def test_reject_wrong_length(size):
    with pytest.raises(ValueError):parse_entries(bytes(size))
