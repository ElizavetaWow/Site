from app import app, db, cli
from app.models import User, Post, Master, Shedule

@app.shell_context_processor
def make_shell_context():
    return {'db': db, 'User': User, 'Post': Post, 'Master': Master, 'Shedule':Shedule}
