import pytest

from tools.x100v_exif_dimension_stage import VECTORS, verify_secondary


def test_independent_stock_dimension_vectors():
    assert VECTORS == ((6240, 3512), (4416, 2488), (3120, 1760),
                       (6240, 4160), (4416, 2944), (3120, 2080))


@pytest.mark.parametrize("image", (b"", bytes(4096), b"not firmware"))
def test_rejects_unrecognized_image(image):
    with pytest.raises(ValueError, match="unrecognized secondary"):
        verify_secondary(image)
