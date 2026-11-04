from glassbox.static.packer import detect
from glassbox.static.pe import parse_pe
from tests.fixtures.make_pe import build_pe


def test_detect_upx_from_sections_and_markers():
    data = build_pe(packed=True)
    info = parse_pe(data)

    packer = detect(data, info)

    assert packer.name == "UPX"
    assert packer.upx is True
    assert packer.confidence == "high"
    assert packer.evidence


def test_detect_no_packer():
    data = build_pe()
    info = parse_pe(data)

    packer = detect(data, info)

    assert packer.name is None
    assert packer.upx is False
    assert packer.confidence == "none"
