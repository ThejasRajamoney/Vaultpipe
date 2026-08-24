import io

import pytest
from rich.console import Console

from vaultpipe import vaultpipe


class QuietProgress:
    def __init__(self, *args, **kwargs):
        pass

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        return False

    def add_task(self, *args, **kwargs):
        return 1

    def update(self, *args, **kwargs):
        pass


@pytest.fixture(autouse=True)
def quiet_output(monkeypatch):
    monkeypatch.setattr(vaultpipe, "Progress", QuietProgress)
    monkeypatch.setattr(
        vaultpipe,
        "console",
        Console(file=io.StringIO(), force_terminal=False, color_system=None),
    )
