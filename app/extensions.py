
from flask_login import LoginManager, UserMixin

login_manager = LoginManager()
login_manager.login_view = "auth.login_page" 

class User(UserMixin):
    def __init__(self, id):
        self.id = id

@login_manager.user_loader
def load_user(user_id):
    return User(user_id)
