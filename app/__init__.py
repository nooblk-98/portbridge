
import logging
from flask import Flask
from app.extensions import login_manager
from app.core.config import SECRET_KEY

def create_app():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
    )
    
    app = Flask(__name__)
    app.secret_key = SECRET_KEY

    login_manager.init_app(app)

    from app.routes import api, auth, main
    app.register_blueprint(api.bp)
    app.register_blueprint(auth.bp)
    app.register_blueprint(main.bp)

    return app
