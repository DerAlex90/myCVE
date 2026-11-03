import sys

from fastapi.testclient import TestClient

from mycve.cli import main
from mycve.legal import AUTHOR, COPYRIGHT, LICENSE_ID
from mycve.server.api import create_app
from mycve.server.config import Settings


def test_public_license_is_accessible_without_workspace_key(engine):
    with TestClient(
        create_app(Settings(api_key="test-only-admin", _env_file=None), engine)
    ) as client:
        assert client.get("/api/overview").status_code == 401
        response = client.get("/api/license")
        assert response.status_code == 200
        assert response.json()["author"] == AUTHOR
        assert response.json()["license"] == LICENSE_ID
        document = client.get("/license")
        assert document.headers["content-type"].startswith("text/plain")
        assert (
            COPYRIGHT in document.text and "gesonderte schriftliche Vereinbarung" in document.text
        )


def test_license_cli_works_outside_the_project_without_configuration(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(sys, "argv", ["mycve", "license"])
    main()
    output = capsys.readouterr().out
    assert COPYRIGHT in output and LICENSE_ID in output
    assert not list(tmp_path.iterdir())
