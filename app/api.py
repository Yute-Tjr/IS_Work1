"""Protected data endpoints. Every route here requires a valid JWT."""
from flask import Blueprint, g, jsonify, request

from .auth import require_jwt
from .extensions import db
from .models import Post

api_bp = Blueprint("api", __name__, url_prefix="/api")

# The JWT check is attached to the whole blueprint, so a new /api route
# cannot accidentally be left unprotected.
api_bp.before_request(require_jwt)

TITLE_MAX_LENGTH = 100
CONTENT_MAX_LENGTH = 2000
SEARCH_MAX_LENGTH = 100


@api_bp.get("/data")
def list_posts():
    """Return all posts, optionally filtered by ?q=<text in title>."""
    query = db.select(Post).order_by(Post.id)

    search = request.args.get("q", "").strip()
    if search:
        if len(search) > SEARCH_MAX_LENGTH:
            return jsonify(error=f"'q' must be at most {SEARCH_MAX_LENGTH} characters"), 400
        # SQLi protection: the ORM sends `search` as a bound parameter (LIKE ?), and
        # autoescape treats % and _ in the input as literal characters, not wildcards.
        query = query.where(Post.title.contains(search, autoescape=True))

    posts = db.session.execute(query).scalars().all()
    return jsonify(count=len(posts), items=[post.to_dict() for post in posts])


@api_bp.post("/data")
def create_post():
    """Create a post owned by the authenticated user."""
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify(error="Request body must be a JSON object"), 400

    title = data.get("title")
    content = data.get("content")
    if not isinstance(title, str) or not isinstance(content, str):
        return jsonify(error="'title' and 'content' are required strings"), 400
    title, content = title.strip(), content.strip()
    if not 1 <= len(title) <= TITLE_MAX_LENGTH:
        return jsonify(error=f"'title' must be 1-{TITLE_MAX_LENGTH} characters"), 400
    if not 1 <= len(content) <= CONTENT_MAX_LENGTH:
        return jsonify(error=f"'content' must be 1-{CONTENT_MAX_LENGTH} characters"), 400

    post = Post(title=title, content=content, author=g.current_user)
    db.session.add(post)
    db.session.commit()
    return jsonify(post.to_dict()), 201


@api_bp.delete("/data/<int:post_id>")
def delete_post(post_id):
    """Delete a post. Only its author may do this (A01: Broken Access Control)."""
    post = db.session.get(Post, post_id)
    if post is None:
        return jsonify(error="Post not found"), 404
    if post.author_id != g.current_user.id:
        return jsonify(error="You can only delete your own posts"), 403

    db.session.delete(post)
    db.session.commit()
    return "", 204
