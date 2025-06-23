# app.py - Main Flask Application

from flask import Flask, render_template, request, redirect, url_for, flash, abort, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime
from flask import send_from_directory
import os

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///knowledge_share.db'
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max upload size

# Ensure upload directory exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Initialize database
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Define User Roles
ROLE_STUDENT = 'student'
ROLE_FACULTY = 'faculty'
ROLE_ADMIN = 'admin'

# Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    role = db.Column(db.String(20), nullable=False, default=ROLE_STUDENT)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    uploads = db.relationship('Resource', backref='uploader', lazy=True)
    reviews = db.relationship('Review', backref='reviewer', lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Resource(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    file_path = db.Column(db.String(255), nullable=False)
    status = db.Column(db.String(20), default='pending')  # pending, approved, rejected
    category = db.Column(db.String(50))
    keywords = db.Column(db.String(255))
    uploader_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    upload_date = db.Column(db.DateTime, default=datetime.utcnow)
    reviews = db.relationship('Review', backref='resource', lazy=True, cascade='all, delete-orphan')

    def avg_rating(self):
        if not self.reviews:
            return 0
        return sum(review.rating for review in self.reviews) / len(self.reviews)

class Review(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text)
    rating = db.Column(db.Integer, nullable=False)  # 1-5 stars
    resource_id = db.Column(db.Integer, db.ForeignKey('resource.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Routes
@app.route('/')
def index():
    return render_template('index.html', now=datetime.now())

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            login_user(user)
            next_page = request.args.get('next')
            return redirect(next_page or url_for('dashboard'))
        else:
            flash('Invalid username or password')
    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        role = request.form.get('role', ROLE_STUDENT)
        
        # Basic validation
        if User.query.filter_by(username=username).first():
            flash('Username already exists')
            return render_template('register.html')
        
        if User.query.filter_by(email=email).first():
            flash('Email already exists')
            return render_template('register.html')
        
        # Create new user
        user = User(username=username, email=email, role=role)
        user.set_password(password)
        
        db.session.add(user)
        db.session.commit()
        
        flash('Registration successful. Please log in.')
        return redirect(url_for('login'))
    
    return render_template('register.html', now=datetime.now())

@app.context_processor
def inject_now():
    return {'now': datetime.now()}

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    if current_user.role == ROLE_ADMIN:
        return redirect(url_for('admin_dashboard'))
    elif current_user.role == ROLE_FACULTY:
        return redirect(url_for('faculty_dashboard'))
    else:
        return redirect(url_for('student_dashboard'))

@app.route('/student/dashboard')
@login_required
def student_dashboard():
    if current_user.role != ROLE_STUDENT and current_user.role != ROLE_FACULTY and current_user.role != ROLE_ADMIN:
        abort(403)
    
    approved_resources = Resource.query.filter_by(status='approved').all()
    my_uploads = Resource.query.filter_by(uploader_id=current_user.id).all()
    
    return render_template('student/dashboard.html', 
        resources=approved_resources, 
        my_uploads=my_uploads)

@app.route('/faculty/dashboard')
@login_required
def faculty_dashboard():
    if current_user.role != 'faculty':
        return redirect(url_for('login'))

    my_uploads = Resource.query.filter_by(uploader_id=current_user.id).all()

    # Filter and sort in Python for resources uploaded by the faculty
    approved_resources = [r for r in my_uploads if r.status == 'approved']
    top_5_resources = sorted(approved_resources, key=lambda r: r.avg_rating(), reverse=True)[:5]
    top_5_reviewed = sorted(approved_resources, key=lambda r: len(r.reviews), reverse=True)[:5]

    # Fetch recently uploaded resources for all users (approved and sorted by upload date)
    recent_uploads = Resource.query.filter_by(status='approved')\
                                   .order_by(Resource.upload_date.desc())\
                                   .limit(5).all()

    return render_template(
        'faculty/dashboard.html',
        resources=my_uploads,
        top_resources=top_5_resources,
        top_reviewed=top_5_reviewed,
        recent_uploads=recent_uploads  # Send the recent uploads to the template
    )

    



@app.route('/admin/dashboard')
@login_required
def admin_dashboard():
    if current_user.role != ROLE_ADMIN:
        abort(403)
    
    pending_resources = Resource.query.filter_by(status='pending').all()
    all_resources = Resource.query.all()
    all_users = User.query.all()
    
    return render_template('admin/dashboard.html', 
        pending_resources=pending_resources,
        all_resources=all_resources,
        users=all_users)

@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload_resource():
    if request.method == 'POST':
        title = request.form.get('title')
        description = request.form.get('description')
        category = request.form.get('category')
        keywords = request.form.get('keywords')
        
        if 'file' not in request.files:
            flash('No file part')
            return redirect(request.url)
        
        file = request.files['file']
        
        if file.filename == '':
            flash('No selected file')
            return redirect(request.url)
        
        if file:
            filename = secure_filename(file.filename)
            timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
            unique_filename = f"{timestamp}_{filename}"
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
            file.save(file_path)
            
            # Automatic approval for faculty uploads
            status = 'pending'
            if current_user.role == ROLE_FACULTY:
                status = 'approved'
            
            resource = Resource(
                title=title,
                description=description,
                file_path=file_path,
                category=category,
                keywords=keywords,
                uploader_id=current_user.id,
                status=status
            )
            
            db.session.add(resource)
            db.session.commit()
            
            flash('Resource uploaded successfully')
            return redirect(url_for('dashboard'))
    
    return render_template('upload.html')

@app.route('/resource/<int:resource_id>')
def view_resource(resource_id):
    resource = Resource.query.get_or_404(resource_id)
    
    # Only show approved resources to students, or let users see their own uploads
    if resource.status != 'approved' and resource.uploader_id != current_user.id and current_user.role != ROLE_ADMIN:
        abort(403)
    
    reviews = Review.query.filter_by(resource_id=resource_id).all()
    
    return render_template('resource.html', resource=resource, reviews=reviews)

@app.route('/resource/<int:resource_id>/download')
@login_required
def download_resource(resource_id):
    resource = Resource.query.get_or_404(resource_id)

    # Only approved resources can be downloaded by students, or users can download their own uploads
    if resource.status != 'approved' and resource.uploader_id != current_user.id and current_user.role != ROLE_ADMIN:
        abort(403)

    directory = os.path.dirname(resource.file_path)
    filename = os.path.basename(resource.file_path)

    if not os.path.exists(resource.file_path):
        flash('File not found.')
        return redirect(url_for('view_resource', resource_id=resource_id))

    return send_from_directory(directory=directory, path=filename, as_attachment=True)

@app.route('/resource/<int:resource_id>/review', methods=['POST'])
@login_required
def review_resource(resource_id):
    resource = Resource.query.get_or_404(resource_id)
    
    # Only approved resources can be reviewed
    if resource.status != 'approved':
        abort(403)
    
    rating = int(request.form.get('rating', 0))
    content = request.form.get('content', '')
    
    # Validate rating
    if rating < 1 or rating > 5:
        flash('Rating must be between 1 and 5')
        return redirect(url_for('view_resource', resource_id=resource_id))
    
    # Check if user has already reviewed this resource
    existing_review = Review.query.filter_by(
        resource_id=resource_id,
        user_id=current_user.id
    ).first()
    
    if existing_review:
        existing_review.rating = rating
        existing_review.content = content
        db.session.commit()
        flash('Your review has been updated')
    else:
        review = Review(
            rating=rating,
            content=content,
            resource_id=resource_id,
            user_id=current_user.id
        )
        db.session.add(review)
        db.session.commit()
        flash('Your review has been submitted')
    
    return redirect(url_for('view_resource', resource_id=resource_id))

@app.route('/admin/resource/<int:resource_id>/approve')
@login_required
def approve_resource(resource_id):
    if current_user.role != ROLE_ADMIN:
        abort(403)
    
    resource = Resource.query.get_or_404(resource_id)
    resource.status = 'approved'
    db.session.commit()
    
    flash(f'Resource "{resource.title}" has been approved')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/resource/<int:resource_id>/reject')
@login_required
def reject_resource(resource_id):
    if current_user.role != ROLE_ADMIN:
        abort(403)
    
    resource = Resource.query.get_or_404(resource_id)
    resource.status = 'rejected'
    db.session.commit()
    
    flash(f'Resource "{resource.title}" has been rejected')
    return redirect(url_for('admin_dashboard'))

@app.route('/search')
def search():
    query = request.args.get('q', '')
    
    if not query:
        return render_template('search.html', resources=[], query='')
    
    # Search in title, description, and keywords
    resources = Resource.query.filter(
        (Resource.title.contains(query) | 
         Resource.description.contains(query) | 
         Resource.keywords.contains(query)) &
        (Resource.status == 'approved')
    ).all()
    
    return render_template('search.html', resources=resources, query=query)

@app.route('/resource/<int:resource_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_resource(resource_id):
    resource = Resource.query.get_or_404(resource_id)
    
    # Only uploader or admin can edit
    if resource.uploader_id != current_user.id and current_user.role != ROLE_ADMIN:
        abort(403)
    
    if request.method == 'POST':
        resource.title = request.form.get('title')
        resource.description = request.form.get('description')
        resource.category = request.form.get('category')
        resource.keywords = request.form.get('keywords')
        
        # If file is being updated
        if 'file' in request.files and request.files['file'].filename:
            file = request.files['file']
            filename = secure_filename(file.filename)
            timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
            unique_filename = f"{timestamp}_{filename}"
            
            # Delete old file if it exists
            try:
                if os.path.exists(resource.file_path):
                    os.remove(resource.file_path)
            except:
                pass
            
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
            file.save(file_path)
            resource.file_path = file_path
            
            # Reset approval status if edited by faculty
            if current_user.role == ROLE_FACULTY or current_user.role == ROLE_STUDENT:
                resource.status = 'pending'
        
        db.session.commit()
        flash('Resource updated successfully')
        return redirect(url_for('view_resource', resource_id=resource_id))
    
    return render_template('edit_resource.html', resource=resource)

@app.route('/resource/<int:resource_id>/delete')
@login_required
def delete_resource(resource_id):
    resource = Resource.query.get_or_404(resource_id)
    
    # Only uploader or admin can delete
    if resource.uploader_id != current_user.id and current_user.role != ROLE_ADMIN:
        abort(403)
    
    # Delete file from storage
    try:
        if os.path.exists(resource.file_path):
            os.remove(resource.file_path)
    except:
        pass
    
    db.session.delete(resource)
    db.session.commit()
    
    flash('Resource deleted successfully')
    return redirect(url_for('dashboard'))

@app.route('/admin/users')
@login_required
def manage_users():
    if current_user.role != ROLE_ADMIN:
        abort(403)
    
    users = User.query.all()
    return render_template('admin/users.html', users=users)

@app.route('/admin/user/<int:user_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_user(user_id):
    if current_user.role != ROLE_ADMIN:
        abort(403)
    
    user = User.query.get_or_404(user_id)
    
    if request.method == 'POST':
        user.username = request.form.get('username')
        user.email = request.form.get('email')
        user.role = request.form.get('role')
        
        # Update password if provided
        password = request.form.get('password')
        if password:
            user.set_password(password)
        
        db.session.commit()
        flash('User updated successfully')
        return redirect(url_for('manage_users'))
    
    return render_template('admin/edit_user.html', user=user)

@app.route('/admin/user/<int:user_id>/delete')
@login_required
def delete_user(user_id):
    if current_user.role != ROLE_ADMIN:
        abort(403)

    if user_id == current_user.id:
        flash('You cannot delete your own account')
        return redirect(url_for('manage_users'))

    user = User.query.get_or_404(user_id)

    # Delete all reviews by the user
    reviews = Review.query.filter_by(user_id=user_id).all()
    for review in reviews:
        db.session.delete(review)

    # Delete all resources uploaded by the user
    resources = Resource.query.filter_by(uploader_id=user_id).all()
    for resource in resources:
        try:
            if os.path.exists(resource.file_path):
                os.remove(resource.file_path)
        except:
            pass
        db.session.delete(resource)

    # Finally, delete the user
    db.session.delete(user)
    db.session.commit()

    flash('User, their uploads, and reviews deleted successfully.')
    return redirect(url_for('manage_users'))


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        
        # Create admin user if it doesn't exist
        admin = User.query.filter_by(username='admin').first()
        if not admin:
            admin = User(
                username='admin',
                email='admin@example.com',
                role=ROLE_ADMIN
            )
            admin.set_password('admin')  # Change this in production!
            db.session.add(admin)
            db.session.commit()
            
    app.run(debug=True)