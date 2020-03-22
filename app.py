from manager import create_app


app = create_app()


@app.cli.command(name='init-db')
def init_db():
    from manager.models import db
    db.create_all()
