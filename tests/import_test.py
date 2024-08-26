"""Basic import functionality."""

import rsp_jupyter_client


def test_import() -> None:
    """The test is really the above import."""
    jc = rsp_jupyter_client.RSPJupyterClient
    assert jc is not None
