"""Entry point: python -m app.main  (env: DEPLOYLENS_HOST, DEPLOYLENS_PORT, DEPLOYLENS_DB)."""
from __future__ import annotations

import os

from .http_api import make_server
from .service import ScanService
from .store import ScanStore


def main() -> None:
    host = os.environ.get("DEPLOYLENS_HOST", "127.0.0.1")
    port = int(os.environ.get("DEPLOYLENS_PORT", "8000"))
    db_path = os.environ.get("DEPLOYLENS_DB", os.path.join("data", "deploylens.db"))
    os.makedirs(os.path.dirname(os.path.abspath(db_path)), exist_ok=True)
    service = ScanService(ScanStore(db_path))
    server = make_server(service, host, port)
    print(f"DeployLens running at http://{host}:{port}  (db: {db_path})")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        service.store.close()


if __name__ == "__main__":
    main()
