import logging

from app.services.client_manager import ClientManager
from app.services.forwarding_manager import ForwardingManager


def bootstrap(client_manager: ClientManager, forwarding_manager: ForwardingManager) -> None:
    client_manager.bootstrap()
    forwarding_manager.apply_all()
    logging.info("Bootstrap complete")
