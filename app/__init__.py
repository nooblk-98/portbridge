import logging

from flask import Flask

from app.core.bootstrap import bootstrap
from app.core.config import EnvConfigProvider
from app.core.iptables import IPTablesService
from app.core.providers import JsonFileStorage, SubprocessRunner
from app.core.wireguard import WireGuardService
from app.extensions import login_manager
from app.services.client_manager import ClientManager
from app.services.forwarding_manager import ForwardingManager


def create_app():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
    )

    config = EnvConfigProvider()
    if not config.admin_password or config.admin_password == "admin":
        raise RuntimeError("Set ADMIN_PASSWORD to a non-default password before starting PortBridge.")
    storage = JsonFileStorage(base_dir=str(config.data_dir))
    runner = SubprocessRunner()

    wg_service = WireGuardService(config=config, storage=storage, runner=runner)
    ipt_service = IPTablesService(config=config, storage=storage, runner=runner)
    forwarding_manager = ForwardingManager(ipt=ipt_service, storage=storage, config=config)
    client_manager = ClientManager(wg=wg_service, storage=storage, config=config, fwd=forwarding_manager)

    bootstrap(client_manager)

    app = Flask(__name__)
    app.secret_key = config.secret_key
    app.config.update(SESSION_COOKIE_SAMESITE="Lax", REMEMBER_COOKIE_SAMESITE="Lax")

    @app.after_request
    def security_headers(response):
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self' 'unsafe-eval'; "
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
            "font-src 'self' https://fonts.gstatic.com; img-src 'self' data:; "
            "object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"
        )
        return response

    app.extensions["config"] = config
    app.extensions["client_manager"] = client_manager
    app.extensions["forwarding_manager"] = forwarding_manager

    login_manager.init_app(app)

    from app.routes import api, auth, main

    app.register_blueprint(api.bp)
    app.register_blueprint(auth.bp)
    app.register_blueprint(main.bp)

    return app
