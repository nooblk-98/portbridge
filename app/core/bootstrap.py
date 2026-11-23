import logging

from app.services.client_manager import ClientManager


def bootstrap(client_manager: ClientManager) -> None:
    client_manager.bootstrap()
    logging.info("Bootstrap complete")
