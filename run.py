
from app import create_app
from app.core.bootstrap import bootstrap
from app.core.config import APP_PORT

app = create_app()

if __name__ == "__main__":
    bootstrap()
    app.run(host="0.0.0.0", port=APP_PORT)
