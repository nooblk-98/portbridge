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
    storage = JsonFileStorage(base_dir=str(config.data_dir))
    runner = SubprocessRunner()

    wg_service = WireGuardService(config=config, storage=storage, runner=runner)
    ipt_service = IPTablesService(config=config, storage=storage, runner=runner)
    forwarding_manager = ForwardingManager(ipt=ipt_service, storage=storage, config=config)
    client_manager = ClientManager(wg=wg_service, storage=storage, config=config, fwd=forwarding_manager)

    bootstrap(client_manager, forwarding_manager)

    app = Flask(__name__)
    app.secret_key = config.secret_key

    app.extensions["config"] = config
    app.extensions["client_manager"] = client_manager
    app.extensions["forwarding_manager"] = forwarding_manager

    login_manager.init_app(app)

    from app.routes import api, auth, main

    app.register_blueprint(api.bp)
    app.register_blueprint(auth.bp)
    app.register_blueprint(main.bp)

    return app
