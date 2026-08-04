import pytest

from releaseguard.detectors import get_detector


def test_get_detector_rejects_unknown_backend():
    with pytest.raises(ValueError, match="Unknown detector backend"):
        get_detector("not-a-real-backend")
