from typer.testing import CliRunner

from sentinelscan.cli import app

runner = CliRunner()


def test_cli_requires_authorization_confirmation() -> None:
    result = runner.invoke(app, ["scan", "https://example.com"])
    assert result.exit_code != 0
    assert "--confirm-authorized is required" in result.output
