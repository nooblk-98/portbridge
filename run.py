from app import create_app
from app.core.bootstrap import bootstrap

app = create_app()

if __name__ == "__main__":
    bootstrap(
        client_manager=app.extensions["client_manager"],
        forwarding_manager=app.extensions["forwarding_manager"],
    )
    app.run(host="0.0.0.0", port=app.extensions["config"].app_port)
