from manager import create_app
from cli import db, client, user, token

app = create_app()
app.register_blueprint(db.bp)
app.register_blueprint(client.bp)
app.register_blueprint(user.bp)
app.register_blueprint(token.bp)
