from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_cors import CORS
import jwt
import pyotp
import qrcode
import io
import base64
from datetime import datetime, timedelta
import os
from dotenv import load_dotenv
import pymysql

# Load environment variables
load_dotenv()

app = Flask(__name__)
CORS(app)  # Enable CORS for all routes

# Enable debug mode
app.debug = True

# Database configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:@localhost/flask_auth_db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'your-secret-key-here')
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY', 'jwt-secret-key-here')
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(minutes=10)

# Initialize SQLAlchemy with error handling
try:
    db = SQLAlchemy(app)
    print("Database initialized successfully!")
except Exception as e:
    print(f"Database connection error: {str(e)}")
    raise

# Models
class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    two_fa_secret = db.Column(db.String(32), nullable=True)
    is_verified = db.Column(db.Boolean, default=False)

class Product(db.Model):
    __tablename__ = 'products'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    price = db.Column(db.Float, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

# Helper functions
def generate_jwt_token(user_id):
    return jwt.encode(
        {'user_id': user_id, 'exp': datetime.utcnow() + app.config['JWT_ACCESS_TOKEN_EXPIRES']},
        app.config['JWT_SECRET_KEY'],
        algorithm='HS256'
    )

def verify_jwt_token(token):
    try:
        payload = jwt.decode(token, app.config['JWT_SECRET_KEY'], algorithms=['HS256'])
        return payload['user_id']
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

# Root route
@app.route('/')
def index():
    return jsonify({
        'message': 'Welcome to the Flask API',
        'status': 'running'
    })

# Error handlers
@app.errorhandler(404)
def not_found_error(error):
    return jsonify({
        'error': 'Not Found',
        'message': 'The requested URL was not found on the server.'
    }), 404

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return jsonify({
        'error': 'Internal Server Error',
        'message': 'An unexpected error has occurred.'
    }), 500

# Routes
@app.route('/register', methods=['POST'])
def register():
    print("Register endpoint hit")  # Debug print
    try:
        data = request.get_json()
        print(f"Received registration data: {data}")  # Debug print
        
        if not data or 'username' not in data or 'password' not in data:
            return jsonify({'error': 'Missing required fields'}), 400
        
        if User.query.filter_by(username=data['username']).first():
            return jsonify({'error': 'Username already exists'}), 400
        
        # Generate 2FA secret
        two_fa_secret = pyotp.random_base32()
        
        # Create new user
        new_user = User(
            username=data['username'],
            password_hash=generate_password_hash(data['password']),
            two_fa_secret=two_fa_secret
        )
        
        db.session.add(new_user)
        db.session.commit()
        
        # Generate QR code
        totp = pyotp.TOTP(two_fa_secret)
        provisioning_uri = totp.provisioning_uri(data['username'], issuer_name='YourApp')
        
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(provisioning_uri)
        qr.make(fit=True)
        
        img = qr.make_image(fill_color="black", back_color="white")
        buffered = io.BytesIO()
        img.save(buffered, format="PNG")
        qr_code = base64.b64encode(buffered.getvalue()).decode()
        
        return jsonify({
            'message': 'User registered successfully',
            'qr_code': qr_code,
            'secret': two_fa_secret
        }), 201
    except Exception as e:
        print(f"Registration error: {str(e)}")  # Debug print
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/verify-2fa', methods=['POST'])
def verify_2fa():
    try:
        data = request.get_json()
        
        if not data or 'username' not in data or 'code' not in data:
            return jsonify({'error': 'Missing required fields'}), 400
        
        user = User.query.filter_by(username=data['username']).first()
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        totp = pyotp.TOTP(user.two_fa_secret)
        if totp.verify(data['code']):
            user.is_verified = True
            db.session.commit()
            return jsonify({'message': '2FA verified successfully'}), 200
        
        return jsonify({'error': 'Invalid 2FA code'}), 400
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/login', methods=['POST'])
def login():
    print("Login endpoint hit")  # Debug print
    try:
        data = request.get_json()
        print(f"Received login data: {data}")  # Debug print
        
        if not data or 'username' not in data or 'password' not in data:
            return jsonify({'error': 'Missing required fields'}), 400
        
        user = User.query.filter_by(username=data['username']).first()
        if not user or not check_password_hash(user.password_hash, data['password']):
            return jsonify({'error': 'Invalid credentials'}), 401
        
        if not user.is_verified and '2fa_code' not in data:
            return jsonify({
                'message': '2FA code required',
                'require_2fa': True
            }), 200
        
        if '2fa_code' in data:
            totp = pyotp.TOTP(user.two_fa_secret)
            if not totp.verify(data['2fa_code']):
                return jsonify({'error': 'Invalid 2FA code'}), 401
        
        # Generate token
        token = jwt.encode(
            {
                'user_id': user.id,
                'exp': datetime.utcnow() + app.config['JWT_ACCESS_TOKEN_EXPIRES']
            },
            app.config['JWT_SECRET_KEY'],
            algorithm='HS256'
        )
        
        return jsonify({
            'message': 'Login successful',
            'token': token
        }), 200
        
    except Exception as e:
        print(f"Login error: {str(e)}")  # Debug print
        return jsonify({'error': str(e)}), 500

# Protected routes
@app.route('/products', methods=['GET'])
def get_products():
    try:
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'error': 'No token provided'}), 401
        
        user_id = verify_jwt_token(token)
        if not user_id:
            return jsonify({'error': 'Invalid or expired token'}), 401
        
        products = Product.query.all()
        return jsonify([{
            'id': product.id,
            'name': product.name,
            'description': product.description,
            'price': product.price,
            'created_at': product.created_at.isoformat()
        } for product in products]), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/products', methods=['POST'])
def create_product():
    try:
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'error': 'No token provided'}), 401
        
        user_id = verify_jwt_token(token)
        if not user_id:
            return jsonify({'error': 'Invalid or expired token'}), 401
        
        data = request.get_json()
        if not data or 'name' not in data or 'price' not in data:
            return jsonify({'error': 'Missing required fields'}), 400
        
        new_product = Product(
            name=data['name'],
            description=data.get('description', ''),
            price=float(data['price'])
        )
        
        db.session.add(new_product)
        db.session.commit()
        
        return jsonify({
            'id': new_product.id,
            'name': new_product.name,
            'description': new_product.description,
            'price': new_product.price,
            'created_at': new_product.created_at.isoformat()
        }), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/products/<int:product_id>', methods=['PUT'])
def update_product(product_id):
    try:
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'error': 'No token provided'}), 401
        
        user_id = verify_jwt_token(token)
        if not user_id:
            return jsonify({'error': 'Invalid or expired token'}), 401
        
        product = Product.query.get_or_404(product_id)
        data = request.get_json()
        
        if 'name' in data:
            product.name = data['name']
        if 'description' in data:
            product.description = data['description']
        if 'price' in data:
            product.price = float(data['price'])
        
        db.session.commit()
        
        return jsonify({
            'id': product.id,
            'name': product.name,
            'description': product.description,
            'price': product.price,
            'created_at': product.created_at.isoformat()
        }), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/products/<int:product_id>', methods=['DELETE'])
def delete_product(product_id):
    try:
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'error': 'No token provided'}), 401
        
        user_id = verify_jwt_token(token)
        if not user_id:
            return jsonify({'error': 'Invalid or expired token'}), 401
        
        product = Product.query.get_or_404(product_id)
        db.session.delete(product)
        db.session.commit()
        
        return jsonify({'message': 'Product deleted successfully'}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/check-user/<username>', methods=['GET'])
def check_user(username):
    try:
        user = User.query.filter_by(username=username).first()
        if user:
            return jsonify({
                'exists': True,
                'is_verified': user.is_verified,
                'has_2fa': bool(user.two_fa_secret)
            }), 200
        return jsonify({'exists': False}), 404
    except Exception as e:
        return jsonify({'error': str(e)}), 500

def init_db():
    try:
        with app.app_context():
            db.create_all()
            print("Database tables created successfully!")
    except Exception as e:
        print(f"Error creating database tables: {str(e)}")
        raise

if __name__ == '__main__':
    init_db()
    # Run the app on all network interfaces
    app.run(host='0.0.0.0', port=5000, debug=True)