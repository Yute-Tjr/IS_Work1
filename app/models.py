from datetime import datetime, timezone

from markupsafe import escape

from .extensions import db


def _utcnow():
    return datetime.now(timezone.utc)


class User(db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(32), unique=True, nullable=False, index=True)
    # Only the bcrypt hash is stored, never the plaintext password
    password_hash = db.Column(db.String(60), nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), default=_utcnow, nullable=False)

    posts = db.relationship("Post", back_populates="author", cascade="all, delete-orphan")


class Post(db.Model):
    __tablename__ = "posts"

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    content = db.Column(db.Text, nullable=False)
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), default=_utcnow, nullable=False)

    author = db.relationship("User", back_populates="posts")

    def to_dict(self):
        # XSS protection: user-controlled text is HTML-escaped on output, so a client
        # that inserts it into a page renders "<script>" as text instead of running it.
        return {
            "id": self.id,
            "title": str(escape(self.title)),
            "content": str(escape(self.content)),
            "author": str(escape(self.author.username)),
            "created_at": self.created_at.isoformat(),
        }
