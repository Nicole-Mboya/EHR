# Mental Health Web Application - Fixed Full Stack Integration
# Backend: Flask API with SQLAlchemy
# Frontend: Streamlit Web Interface with proper API integration

import os
import sys
from datetime import datetime, timedelta
import sqlite3
import hashlib
import secrets
from typing import Optional, Dict, List
import json
import threading
import time

# Backend Dependencies
from flask import Flask, request, jsonify, session
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash

# Frontend Dependencies
import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import requests
from streamlit_option_menu import option_menu

# ================================
# BACKEND - Flask API with Database
# ================================

# Flask App Configuration
app = Flask(__name__)
app.config['SECRET_KEY'] = 'mental-health-app-secret-key-2024'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///mental_health.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
CORS(app, supports_credentials=True)


# Database Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False)  # 'patient' or 'provider'
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Relationships
    mood_entries = db.relationship('MoodEntry', backref='user', lazy=True)
    journal_entries = db.relationship('JournalEntry', backref='user', lazy=True)
    appointments = db.relationship('Appointment', foreign_keys='Appointment.patient_id', backref='patient', lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'email': self.email,
            'role': self.role,
            'created_at': self.created_at.isoformat()
        }


class MoodEntry(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    mood_value = db.Column(db.Integer, nullable=False)  # 1-5 scale
    mood_emoji = db.Column(db.String(10), nullable=False)
    notes = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            'id': self.id,
            'user_id': self.user_id,
            'mood_value': self.mood_value,
            'mood_emoji': self.mood_emoji,
            'notes': self.notes,
            'created_at': self.created_at.isoformat()
        }


class JournalEntry(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    title = db.Column(db.String(200), nullable=False)
    content = db.Column(db.Text, nullable=False)
    privacy = db.Column(db.String(20), default='private')  # 'private' or 'shared'
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            'id': self.id,
            'user_id': self.user_id,
            'title': self.title,
            'content': self.content,
            'privacy': self.privacy,
            'created_at': self.created_at.isoformat()
        }


class Appointment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    patient_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    provider_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    appointment_date = db.Column(db.DateTime, nullable=False)
    duration = db.Column(db.Integer, default=60)  # minutes
    status = db.Column(db.String(20), default='scheduled')  # scheduled, completed, cancelled
    notes = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    provider = db.relationship('User', foreign_keys=[provider_id], backref='provider_appointments')

    def to_dict(self):
        return {
            'id': self.id,
            'patient_id': self.patient_id,
            'provider_id': self.provider_id,
            'appointment_date': self.appointment_date.isoformat(),
            'duration': self.duration,
            'status': self.status,
            'notes': self.notes,
            'created_at': self.created_at.isoformat(),
            'patient_name': self.patient.name,
            'provider_name': self.provider.name
        }


class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    read = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    sender = db.relationship('User', foreign_keys=[sender_id], backref='sent_messages')
    receiver = db.relationship('User', foreign_keys=[receiver_id], backref='received_messages')

    def to_dict(self):
        return {
            'id': self.id,
            'sender_id': self.sender_id,
            'receiver_id': self.receiver_id,
            'content': self.content,
            'read': self.read,
            'created_at': self.created_at.isoformat(),
            'sender_name': self.sender.name,
            'receiver_name': self.receiver.name
        }


# API Routes
@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json()

    # Validation
    if not all(key in data for key in ['name', 'email', 'password', 'role']):
        return jsonify({'error': 'Missing required fields'}), 400

    if User.query.filter_by(email=data['email']).first():
        return jsonify({'error': 'Email already registered'}), 400

    user = User(
        name=data['name'],
        email=data['email'],
        role=data['role']
    )
    user.set_password(data['password'])

    db.session.add(user)
    db.session.commit()

    return jsonify({'message': 'User registered successfully', 'user': user.to_dict()}), 201


@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()

    if not all(key in data for key in ['email', 'password']):
        return jsonify({'error': 'Email and password required'}), 400

    user = User.query.filter_by(email=data['email']).first()

    if user and user.check_password(data['password']):
        session['user_id'] = user.id
        session['user_email'] = user.email
        return jsonify({'message': 'Login successful', 'user': user.to_dict()}), 200

    return jsonify({'error': 'Invalid credentials'}), 401


@app.route('/api/logout', methods=['POST'])
def logout():
    session.clear()
    return jsonify({'message': 'Logged out successfully'}), 200


@app.route('/api/user/current', methods=['GET'])
def current_user():
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401

    user = User.query.get(session['user_id'])
    if user:
        return jsonify({'user': user.to_dict()}), 200
    return jsonify({'error': 'User not found'}), 404


@app.route('/api/mood', methods=['GET', 'POST'])
def mood_entries():
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401

    if request.method == 'POST':
        data = request.get_json()

        if not all(key in data for key in ['mood_value', 'mood_emoji']):
            return jsonify({'error': 'Missing required fields'}), 400

        mood_entry = MoodEntry(
            user_id=session['user_id'],
            mood_value=data['mood_value'],
            mood_emoji=data['mood_emoji'],
            notes=data.get('notes', '')
        )
        db.session.add(mood_entry)
        db.session.commit()
        return jsonify({'message': 'Mood entry saved', 'entry': mood_entry.to_dict()}), 201

    # GET request - get recent entries
    limit = request.args.get('limit', 10, type=int)
    entries = MoodEntry.query.filter_by(user_id=session['user_id']).order_by(MoodEntry.created_at.desc()).limit(
        limit).all()
    return jsonify({'entries': [entry.to_dict() for entry in entries]}), 200


@app.route('/api/journal', methods=['GET', 'POST'])
def journal_entries():
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401

    if request.method == 'POST':
        data = request.get_json()

        if not all(key in data for key in ['title', 'content']):
            return jsonify({'error': 'Title and content required'}), 400

        journal_entry = JournalEntry(
            user_id=session['user_id'],
            title=data['title'],
            content=data['content'],
            privacy=data.get('privacy', 'private')
        )
        db.session.add(journal_entry)
        db.session.commit()
        return jsonify({'message': 'Journal entry saved', 'entry': journal_entry.to_dict()}), 201

    # GET request
    limit = request.args.get('limit', 10, type=int)
    entries = JournalEntry.query.filter_by(user_id=session['user_id']).order_by(JournalEntry.created_at.desc()).limit(
        limit).all()
    return jsonify({'entries': [entry.to_dict() for entry in entries]}), 200


@app.route('/api/appointments', methods=['GET', 'POST'])
def appointments():
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401

    user = User.query.get(session['user_id'])

    if request.method == 'POST':
        data = request.get_json()

        if not all(key in data for key in ['provider_id', 'appointment_date']):
            return jsonify({'error': 'Provider and appointment date required'}), 400

        try:
            appointment_datetime = datetime.fromisoformat(data['appointment_date'].replace('Z', '+00:00'))
        except ValueError:
            return jsonify({'error': 'Invalid date format'}), 400

        appointment = Appointment(
            patient_id=data.get('patient_id', session['user_id']),
            provider_id=data['provider_id'],
            appointment_date=appointment_datetime,
            notes=data.get('notes', '')
        )
        db.session.add(appointment)
        db.session.commit()
        return jsonify({'message': 'Appointment scheduled', 'appointment': appointment.to_dict()}), 201

    # GET request
    if user.role == 'patient':
        appointments = Appointment.query.filter_by(patient_id=session['user_id']).order_by(
            Appointment.appointment_date.desc()).all()
    else:
        appointments = Appointment.query.filter_by(provider_id=session['user_id']).order_by(
            Appointment.appointment_date.desc()).all()

    return jsonify({'appointments': [apt.to_dict() for apt in appointments]}), 200


@app.route('/api/messages', methods=['GET', 'POST'])
def messages():
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401

    if request.method == 'POST':
        data = request.get_json()

        if not all(key in data for key in ['receiver_id', 'content']):
            return jsonify({'error': 'Receiver and content required'}), 400

        message = Message(
            sender_id=session['user_id'],
            receiver_id=data['receiver_id'],
            content=data['content']
        )
        db.session.add(message)
        db.session.commit()
        return jsonify({'message': 'Message sent', 'msg': message.to_dict()}), 201

    # GET request - get conversation with specific user or all messages
    other_user_id = request.args.get('with_user', type=int)

    if other_user_id:
        # Get conversation with specific user
        messages = Message.query.filter(
            ((Message.sender_id == session['user_id']) & (Message.receiver_id == other_user_id)) |
            ((Message.sender_id == other_user_id) & (Message.receiver_id == session['user_id']))
        ).order_by(Message.created_at.asc()).all()
    else:
        # Get all messages involving current user
        messages = Message.query.filter(
            (Message.sender_id == session['user_id']) | (Message.receiver_id == session['user_id'])
        ).order_by(Message.created_at.desc()).all()

    return jsonify({'messages': [msg.to_dict() for msg in messages]}), 200


@app.route('/api/users', methods=['GET'])
def get_users():
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401

    current_user = User.query.get(session['user_id'])
    if current_user.role == 'patient':
        # Patients can only see providers
        users = User.query.filter_by(role='provider').all()
    else:
        # Providers can see all users
        users = User.query.all()

    return jsonify({'users': [user.to_dict() for user in users]}), 200


@app.route('/api/stats', methods=['GET'])
def get_stats():
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401

    user = User.query.get(session['user_id'])
    stats = {}

    if user.role == 'patient':
        # Patient statistics
        mood_count = MoodEntry.query.filter_by(user_id=session['user_id']).count()
        journal_count = JournalEntry.query.filter_by(user_id=session['user_id']).count()
        appointment_count = Appointment.query.filter_by(patient_id=session['user_id']).count()

        # Calculate average mood over last 30 days
        thirty_days_ago = datetime.utcnow() - timedelta(days=30)
        recent_moods = MoodEntry.query.filter(
            MoodEntry.user_id == session['user_id'],
            MoodEntry.created_at >= thirty_days_ago
        ).all()

        avg_mood = sum(mood.mood_value for mood in recent_moods) / len(recent_moods) if recent_moods else 0

        stats = {
            'mood_entries': mood_count,
            'journal_entries': journal_count,
            'appointments': appointment_count,
            'average_mood': round(avg_mood, 1),
            'days_tracked': len(recent_moods)
        }
    else:
        # Provider statistics
        total_patients = User.query.filter_by(role='patient').count()
        today_appointments = Appointment.query.filter(
            Appointment.provider_id == session['user_id'],
            Appointment.appointment_date >= datetime.utcnow().date(),
            Appointment.appointment_date < datetime.utcnow().date() + timedelta(days=1)
        ).count()

        unread_messages = Message.query.filter(
            Message.receiver_id == session['user_id'],
            Message.read == False
        ).count()

        stats = {
            'total_patients': total_patients,
            'today_appointments': today_appointments,
            'unread_messages': unread_messages,
            'active_patients': total_patients  # Simplified
        }

    return jsonify({'stats': stats}), 200

@app.route('/api/health', methods=['GET'])
def health_check():
    """Simple health check endpoint"""
    return jsonify({'status': 'healthy', 'timestamp': datetime.utcnow().isoformat()}), 200


# Initialize database
def init_database():
    """Initialize database with sample data"""
    with app.app_context():
        db.create_all()
        
        # Create sample users if they don't exist
        if not User.query.filter_by(email='patient@example.com').first():
            patient = User(name='Alex Johnson', email='patient@example.com', role='patient')
            patient.set_password('password123')
            db.session.add(patient)

            provider = User(name='Dr. Sarah Smith', email='provider@example.com', role='provider')
            provider.set_password('password123')
            db.session.add(provider)

            db.session.commit()
            print("✅ Sample users created!")

# ================================
# FRONTEND - Streamlit Interface
# ================================

class MentalHealthApp:
    def __init__(self):
        codespace_name = os.getenv("CODESPACE_NAME")
        if codespace_name:
            self.api_base = f"https://{codespace_name}-5000.app.github.dev"
        else:
            self.api_base = "http://localhost:5000"


        # ✅ Initialize a persistent requests session
        self.session = requests.Session()


    def api_request(self, method, endpoint, **kwargs):
        url = f"{self.api_base}{endpoint}"
        try:
            if method.lower() == "get":
                response = self.session.get(url, **kwargs)
            elif method.lower() == "post":
                response = self.session.post(url, **kwargs)
            elif method.lower() == "put":
                response = self.session.put(url, **kwargs)
            elif method.lower() == "delete":
                response = self.session.delete(url, **kwargs)
            else:
                raise ValueError(f"Unsupported method: {method}")


            response.raise_for_status()
            return response.json()
        except Exception as e:
            print(f"Request failed: {e}")
            return None

# ================================
# MAIN EXECUTION
# ================================

# Global variable to track if Flask is running
flask_server_running = False
flask_thread = None

def run_flask_server():
    """Run Flask server in a thread"""
    global flask_server_running
    try:
        init_database()
        flask_server_running = True
        print("🔊 Flask Backend Server starting on port 5000")
        # Use 0.0.0.0 for Codespaces to allow external access
        app.run(debug=False, host='0.0.0.0', port=5000, use_reloader=False, threaded=True)
    except Exception as e:
        print(f"❌ Flask server error: {e}")
        flask_server_running = False

def start_flask_server():
    """Start Flask server in background thread"""
    global flask_thread, flask_server_running
    
    if flask_thread and flask_thread.is_alive():
        return True
    
    flask_thread = threading.Thread(target=run_flask_server, daemon=True)
    flask_thread.start()
    
    # Wait for server to start
    max_wait = 15  # Increased timeout for Codespaces
    wait_time = 0
    
    # Determine the correct health check URL
    codespace_name = os.environ.get('CODESPACE_NAME')
    if codespace_name:
        health_url = f"https://{codespace_name}-5000.app.github.dev/api/health"
    else:
        health_url = "http://127.0.0.1:5000/api/health"
    
    while wait_time < max_wait:
        try:
            response = requests.get(health_url, timeout=2)
            if response.status_code == 200:
                print("✅ Flask backend is running and accessible")
                return True
        except:
            pass
        
        time.sleep(0.5)
        wait_time += 0.5
    
    print("⚠️ Flask backend may not be fully ready yet...")
    return flask_server_running

def run_streamlit_app():
    """Run Streamlit frontend application"""
    mental_health_app = MentalHealthApp()
    mental_health_app.run()

app = MentalHealthApp()

if __name__ == "__main__":
    print("🚀 To run this application:")
    print("   streamlit run app.py")
    print("\n🔗 The app will be available at:")
    print("   http://localhost:8501")

# Simple Streamlit detection
try:
    if 'streamlit' in sys.modules or '_streamlit' in sys.modules:
        mental_health_app = MentalHealthApp()
        mental_health_app.run()
except:
    pass