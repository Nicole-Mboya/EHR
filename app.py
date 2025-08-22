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
        import os
        codespace_name = os.getenv("CODESPACE_NAME")
        if codespace_name:
            self.api_base = f"https://{codespace_name}-5000.app.github.dev"
        else:
            self.api_base = "http://localhost:5000"


    def init_session_state(self):
        """Initialize session state variables"""
        if 'logged_in' not in st.session_state:
            st.session_state.logged_in = False
        if 'user' not in st.session_state:
            st.session_state.user = None
        if 'auth_checked' not in st.session_state:
            st.session_state.auth_checked = False
        if 'flask_started' not in st.session_state:
            st.session_state.flask_started = False

    def ensure_flask_running(self):
        """Ensure Flask server is running"""
        if not st.session_state.flask_started:
            with st.spinner("🚀 Starting backend server..."):
                if start_flask_server():
                    st.session_state.flask_started = True
                    st.success("✅ Backend server is ready!")
                    time.sleep(1)
                    st.rerun()
                else:
                    st.error("❌ Failed to start backend server. Please try refreshing the page.")
                    st.stop()

    def api_request(self, endpoint, method='GET', data=None):
        """Make API requests to Flask backend with proper error handling"""
        try:
            url = f"{self.api_base}/{endpoint}"

            if method == 'GET':
                response = self.session.get(url)
            elif method == 'POST':
                response = self.session.post(url, json=data, headers={'Content-Type': 'application/json'})
            elif method == 'PUT':
                response = self.session.put(url, json=data, headers={'Content-Type': 'application/json'})
            elif method == 'DELETE':
                response = self.session.delete(url)

            if response.status_code < 400:
                return response.json(), True
            else:
                error_data = response.json() if response.content else {'error': 'Request failed'}
                return error_data, False

        except requests.exceptions.ConnectionError:
            return {'error': 'Cannot connect to server. Please ensure the Flask backend is running.'}, False
        except Exception as e:
            return {'error': f'Request failed: {str(e)}'}, False

    def check_authentication(self):
        """Check if user is authenticated with backend"""
        if not st.session_state.auth_checked:
            data, success = self.api_request('user/current')
            if success and 'user' in data:
                st.session_state.logged_in = True
                st.session_state.user = data['user']
            else:
                st.session_state.logged_in = False
                st.session_state.user = None
            st.session_state.auth_checked = True

    def login_page(self):
        """Login/Registration Page with actual API integration"""
        st.markdown("""
        <div style='text-align: center; padding: 2rem;'>
            <h1>🧠 MindCare</h1>
            <h3>Your Mental Health Companion</h3>
        </div>
        """, unsafe_allow_html=True)

        tab1, tab2 = st.tabs(["Login", "Register"])

        with tab1:
            st.subheader("Sign In")
            with st.form("login_form"):
                email = st.text_input("Email", value="patient@example.com")
                password = st.text_input("Password", type="password", value="password123")

                col1, col2 = st.columns(2)
                with col1:
                    login_submit = st.form_submit_button("Sign In", type="primary")
                with col2:
                    demo_provider = st.form_submit_button("Demo as Provider")

                if login_submit and email and password:
                    data, success = self.api_request('login', 'POST', {
                        'email': email,
                        'password': password
                    })

                    if success:
                        st.session_state.logged_in = True
                        st.session_state.user = data['user']
                        st.session_state.auth_checked = True
                        st.success("Login successful!")
                        st.rerun()
                    else:
                        st.error(f"Login failed: {data.get('error', 'Unknown error')}")

                if demo_provider:
                    data, success = self.api_request('login', 'POST', {
                        'email': 'provider@example.com',
                        'password': 'password123'
                    })

                    if success:
                        st.session_state.logged_in = True
                        st.session_state.user = data['user']
                        st.session_state.auth_checked = True
                        st.success("Logged in as provider!")
                        st.rerun()
                    else:
                        st.error(f"Provider login failed: {data.get('error', 'Unknown error')}")

        with tab2:
            st.subheader("Create Account")
            with st.form("register_form"):
                name = st.text_input("Full Name")
                reg_email = st.text_input("Email")
                reg_password = st.text_input("Password", type="password")
                reg_role = st.selectbox("Account Type", ["patient", "provider"])

                if st.form_submit_button("Create Account", type="primary"):
                    if name and reg_email and reg_password:
                        data, success = self.api_request('register', 'POST', {
                            'name': name,
                            'email': reg_email,
                            'password': reg_password,
                            'role': reg_role
                        })

                        if success:
                            st.success("Account created successfully! Please log in.")
                        else:
                            st.error(f"Registration failed: {data.get('error', 'Unknown error')}")
                    else:
                        st.error("Please fill in all fields!")

    def load_dashboard_data(self):
        """Load dashboard data from API"""
        if 'dashboard_data' not in st.session_state:
            stats_data, stats_success = self.api_request('stats')

            if stats_success:
                st.session_state.dashboard_data = stats_data['stats']
            else:
                st.session_state.dashboard_data = {}

    def patient_dashboard(self):
        """Patient Dashboard Interface with API integration"""
        st.sidebar.title("🧠 MindCare")
        st.sidebar.write(f"Welcome, {st.session_state.user['name']}!")

        menu_options = ["Overview", "Mood Tracker", "Journal", "Progress", "Appointments", "Messages"]
        selected = st.sidebar.selectbox("Navigation", menu_options)

        if st.sidebar.button("Logout"):
            self.api_request('logout', 'POST')
            st.session_state.logged_in = False
            st.session_state.user = None
            st.session_state.auth_checked = False
            st.rerun()

        self.load_dashboard_data()

        if selected == "Overview":
            self.patient_overview()
        elif selected == "Mood Tracker":
            self.mood_tracker()
        elif selected == "Journal":
            self.journal_page()
        elif selected == "Progress":
            self.progress_tracker()
        elif selected == "Appointments":
            self.appointments_page()
        elif selected == "Messages":
            self.messages_page()

    def patient_overview(self):
        """Patient Dashboard Overview with real data"""
        st.title("Welcome back!")

        # Load dashboard statistics
        dashboard_data = st.session_state.get('dashboard_data', {})

        # Statistics Cards
        col1, col2, col3, col4 = st.columns(4)

        with col1:
            st.metric("Days Tracked", dashboard_data.get('days_tracked', 0))
        with col2:
            avg_mood = dashboard_data.get('average_mood', 0)
            mood_emoji = "😢" if avg_mood < 2 else "😕" if avg_mood < 3 else "😐" if avg_mood < 4 else "😊" if avg_mood < 5 else "😄"
            st.metric("Average Mood", f"{mood_emoji} {avg_mood}")
        with col3:
            st.metric("Journal Entries", dashboard_data.get('journal_entries', 0))
        with col4:
            st.metric("Appointments", dashboard_data.get('appointments', 0))

        st.markdown("---")

        # Quick Actions
        st.subheader("Quick Actions")
        col1, col2, col3 = st.columns(3)

        with col1:
            if st.button("📝 Track Mood", use_container_width=True):
                st.session_state.quick_action = "mood"

        with col2:
            if st.button("📖 Write Journal", use_container_width=True):
                st.session_state.quick_action = "journal"

        with col3:
            if st.button("📅 View Appointments", use_container_width=True):
                st.session_state.quick_action = "appointments"

        # Handle quick actions
        if 'quick_action' in st.session_state:
            if st.session_state.quick_action == "mood":
                self.quick_mood_entry()
            elif st.session_state.quick_action == "journal":
                self.quick_journal_entry()
            del st.session_state.quick_action

        # Recent Activity from API
        st.subheader("Recent Activity")
        self.load_recent_activity()

    def quick_mood_entry(self):
        """Quick mood entry widget"""
        st.subheader("Quick Mood Entry")

        mood_options = {
            "😢 Very Sad": 1,
            "😕 Sad": 2,
            "😐 Neutral": 3,
            "😊 Happy": 4,
            "😄 Very Happy": 5
        }

        with st.form("quick_mood_form"):
            selected_mood = st.selectbox("How are you feeling?", list(mood_options.keys()))
            notes = st.text_input("Quick note (optional)")

            if st.form_submit_button("Save Mood"):
                mood_data = {
                    'mood_value': mood_options[selected_mood],
                    'mood_emoji': selected_mood.split()[0],
                    'notes': notes
                }

                data, success = self.api_request('mood', 'POST', mood_data)

                if success:
                    st.success("Mood saved successfully!")
                    # Refresh dashboard data
                    del st.session_state.dashboard_data
                    st.rerun()
                else:
                    st.error(f"Failed to save mood: {data.get('error', 'Unknown error')}")

    def quick_journal_entry(self):
        """Quick journal entry widget"""
        st.subheader("Quick Journal Entry")

        with st.form("quick_journal_form"):
            title = st.text_input("Title")
            content = st.text_area("What's on your mind?", height=100)

            if st.form_submit_button("Save Entry"):
                if title and content:
                    journal_data = {
                        'title': title,
                        'content': content,
                        'privacy': 'private'
                    }

                    data, success = self.api_request('journal', 'POST', journal_data)

                    if success:
                        st.success("Journal entry saved!")
                        # Refresh dashboard data
                        del st.session_state.dashboard_data
                        st.rerun()
                    else:
                        st.error(f"Failed to save entry: {data.get('error', 'Unknown error')}")
                else:
                    st.error("Please fill in both title and content!")

    def load_recent_activity(self):
        """Load recent activity from API"""
        # Load recent mood entries
        mood_data, mood_success = self.api_request('mood?limit=3')
        journal_data, journal_success = self.api_request('journal?limit=2')

        activities = []

        if mood_success and 'entries' in mood_data:
            for entry in mood_data['entries']:
                activities.append({
                    'type': 'mood',
                    'date': entry['created_at'],
                    'description': f"Mood tracked: {entry['mood_emoji']}",
                    'details': entry.get('notes', 'No notes')
                })

        if journal_success and 'entries' in journal_data:
            for entry in journal_data['entries']:
                activities.append({
                    'type': 'journal',
                    'date': entry['created_at'],
                    'description': f"Journal entry: {entry['title']}",
                    'details': entry['content'][:100] + "..." if len(entry['content']) > 100 else entry['content']
                })

        # Sort by date
        activities.sort(key=lambda x: x['date'], reverse=True)

        if activities:
            for activity in activities[:5]:  # Show last 5 activities
                try:
                    date_obj = datetime.fromisoformat(activity['date'].replace('Z', '+00:00'))
                    formatted_date = date_obj.strftime("%B %d, %Y at %I:%M %p")
                except:
                    formatted_date = activity['date']

                with st.expander(f"{formatted_date} - {activity['description']}"):
                    st.write(activity['details'])
        else:
            st.info("No recent activity. Start by tracking your mood or writing a journal entry!")

    def mood_tracker(self):
        """Mood Tracking Interface with API integration"""
        st.title("Mood Tracker")

        # Mood Selection
        st.subheader("How are you feeling today?")

        mood_options = {
            "Very Sad": {"emoji": "😢", "value": 1},
            "Sad": {"emoji": "😕", "value": 2},
            "Neutral": {"emoji": "😐", "value": 3},
            "Happy": {"emoji": "😊", "value": 4},
            "Very Happy": {"emoji": "😄", "value": 5}
        }

        col1, col2, col3, col4, col5 = st.columns(5)
        selected_mood = None

        for i, (mood_name, mood_data) in enumerate(mood_options.items()):
            col = [col1, col2, col3, col4, col5][i]
            with col:
                if st.button(f"{mood_data['emoji']} {mood_name}", use_container_width=True, key=f"mood_{i}"):
                    selected_mood = (mood_name, mood_data)

        # Notes
        notes = st.text_area("Additional Notes (Optional)",
                             placeholder="How was your day? Any specific triggers or positive moments?")

        # Save Button
        if st.button("Save Mood Entry", type="primary"):
            if selected_mood:
                mood_data = {
                    'mood_value': selected_mood[1]['value'],
                    'mood_emoji': selected_mood[1]['emoji'],
                    'notes': notes
                }

                data, success = self.api_request('mood', 'POST', mood_data)

                if success:
                    st.success("Mood entry saved successfully!")
                    # Clear the form by rerunning
                    st.rerun()
                else:
                    st.error(f"Failed to save mood: {data.get('error', 'Unknown error')}")
            else:
                st.error("Please select a mood first!")

        # Recent Entries from API
        st.subheader("Recent Mood Entries")

        mood_data, success = self.api_request('mood?limit=10')

        if success and 'entries' in mood_data and mood_data['entries']:
            for entry in mood_data['entries']:
                try:
                    date_obj = datetime.fromisoformat(entry['created_at'].replace('Z', '+00:00'))
                    formatted_date = date_obj.strftime("%B %d, %Y at %I:%M %p")
                except:
                    formatted_date = entry['created_at']

                mood_display = f"{entry['mood_emoji']} (Score: {entry['mood_value']}/5)"

                with st.expander(f"{formatted_date} - {mood_display}"):
                    if entry['notes']:
                        st.write(entry['notes'])
                    else:
                        st.write("No additional notes")
        else:
            st.info("No mood entries yet. Track your first mood above!")

    def journal_page(self):
        """Journal Interface with API integration"""
        st.title("Journal")

        # New Journal Entry
        st.subheader("New Journal Entry")

        with st.form("journal_form"):
            title = st.text_input("Title", placeholder="What's on your mind today?")
            content = st.text_area("Entry", placeholder="Write about your thoughts, feelings, experiences...",
                                   height=200)
            privacy = st.selectbox("Privacy", ["private", "shared"],
                                   format_func=lambda
                                       x: "Private (Only you can see)" if x == "private" else "Shared with provider")

            if st.form_submit_button("Save Entry", type="primary"):
                if title and content:
                    journal_data = {
                        'title': title,
                        'content': content,
                        'privacy': privacy
                    }

                    data, success = self.api_request('journal', 'POST', journal_data)

                    if success:
                        st.success("Journal entry saved successfully!")
                        st.rerun()
                    else:
                        st.error(f"Failed to save entry: {data.get('error', 'Unknown error')}")
                else:
                    st.error("Please fill in both title and content!")

        st.markdown("---")

        # Previous Entries from API
        st.subheader("Previous Entries")

        journal_data, success = self.api_request('journal?limit=20')

        if success and 'entries' in journal_data and journal_data['entries']:
            for entry in journal_data['entries']:
                try:
                    date_obj = datetime.fromisoformat(entry['created_at'].replace('Z', '+00:00'))
                    formatted_date = date_obj.strftime("%B %d, %Y at %I:%M %p")
                except:
                    formatted_date = entry['created_at']

                with st.expander(f"{formatted_date} - {entry['title']}"):
                    st.write(entry['content'])
                    privacy_display = "Private" if entry['privacy'] == 'private' else "Shared with provider"
                    st.caption(f"Privacy: {privacy_display}")
        else:
            st.info("No journal entries yet. Write your first entry above!")

    def progress_tracker(self):
        """Progress Tracking Interface with real data"""
        st.title("Progress Tracker")

        # Load mood data for progress analysis
        mood_data, success = self.api_request('mood?limit=30')

        if success and 'entries' in mood_data and mood_data['entries']:
            entries = mood_data['entries']

            # Convert to DataFrame for analysis
            df_data = []
            for entry in reversed(entries):  # Reverse to get chronological order
                try:
                    date_obj = datetime.fromisoformat(entry['created_at'].replace('Z', '+00:00'))
                    df_data.append({
                        'Date': date_obj.date(),
                        'Mood': entry['mood_value'],
                        'Notes': entry.get('notes', '')
                    })
                except:
                    continue

            if df_data:
                df = pd.DataFrame(df_data)

                # Progress Overview
                col1, col2 = st.columns(2)

                with col1:
                    current_avg = df['Mood'].mean()
                    st.metric("Average Mood (Recent)", f"{current_avg:.1f}/5")

                with col2:
                    total_entries = len(df)
                    st.metric("Total Entries", total_entries)

                # Mood Trend Chart
                st.subheader("Mood Trend Analysis")

                if len(df) >= 2:
                    fig = px.line(df, x='Date', y='Mood', title='Daily Mood Tracking',
                                  labels={'Mood': 'Mood Score (1-5)'})
                    fig.update_layout(height=400)
                    fig.update_yaxis(range=[0.5, 5.5])
                    st.plotly_chart(fig, use_container_width=True)

                    # Weekly average
                    if len(df) > 7:
                        st.subheader("Weekly Progress")
                        df['Week'] = df['Date'].apply(lambda x: x.strftime('%Y-W%U'))
                        weekly_avg = df.groupby('Week')['Mood'].mean().reset_index()
                        weekly_avg['Week_Label'] = weekly_avg['Week'].apply(lambda x: f"Week of {x.split('-W')[1]}")

                        fig_weekly = px.bar(weekly_avg, x='Week_Label', y='Mood',
                                            title='Weekly Average Mood',
                                            labels={'Mood': 'Average Mood Score'})
                        fig_weekly.update_layout(height=300)
                        fig_weekly.update_yaxis(range=[0, 5])
                        st.plotly_chart(fig_weekly, use_container_width=True)
                else:
                    st.info("Keep tracking your mood to see progress trends! You need at least 2 entries.")
            else:
                st.info("No valid mood data found for analysis.")
        else:
            st.info("Start tracking your mood to see your progress over time!")

        # Treatment Goals (static for demo, could be made dynamic)
        st.subheader("Treatment Goals")

        goals = [
            {"goal": "Track mood daily", "status": "In Progress", "progress": 75},
            {"goal": "Maintain regular journaling", "status": "In Progress", "progress": 60},
            {"goal": "Attend therapy sessions", "status": "On Track", "progress": 90},
            {"goal": "Practice mindfulness", "status": "Starting", "progress": 25}
        ]

        for goal in goals:
            col1, col2 = st.columns([3, 1])
            with col1:
                st.write(f"**{goal['goal']}**")
                st.progress(goal['progress'] / 100)
            with col2:
                if goal['status'] == 'Completed':
                    st.success(f"✅ {goal['status']}")
                elif goal['status'] == 'On Track':
                    st.info(f"📍 {goal['status']}")
                else:
                    st.warning(f"🔄 {goal['status']}")

    def appointments_page(self):
        """Appointments Management with API integration"""
        st.title("Appointments")

        tab1, tab2 = st.tabs(["Book New Appointment", "Your Appointments"])

        with tab1:
            st.subheader("Schedule New Appointment")

            # Get available providers
            users_data, users_success = self.api_request('users')

            if users_success and 'users' in users_data:
                providers = users_data['users']

                if providers:
                    with st.form("appointment_form"):
                        provider_options = {f"{p['name']} - {p['role'].title()}": p['id'] for p in providers}
                        selected_provider = st.selectbox("Provider", list(provider_options.keys()))

                        appointment_date = st.date_input("Date", min_value=datetime.now().date())
                        appointment_time = st.selectbox("Time", [
                            "09:00", "10:00", "11:00", "14:00", "15:00", "16:00"
                        ])

                        reason = st.text_area("Reason for Visit",
                                              placeholder="Brief description of what you'd like to discuss")

                        if st.form_submit_button("Book Appointment", type="primary"):
                            if selected_provider:
                                provider_id = provider_options[selected_provider]

                                # Combine date and time
                                appointment_datetime = datetime.combine(appointment_date,
                                                                        datetime.strptime(appointment_time,
                                                                                          "%H:%M").time())

                                appointment_data = {
                                    'provider_id': provider_id,
                                    'appointment_date': appointment_datetime.isoformat(),
                                    'notes': reason
                                }

                                data, success = self.api_request('appointments', 'POST', appointment_data)

                                if success:
                                    st.success(
                                        f"Appointment booked with {selected_provider.split(' - ')[0]} on {appointment_date} at {appointment_time}")
                                    st.rerun()
                                else:
                                    st.error(f"Failed to book appointment: {data.get('error', 'Unknown error')}")
                else:
                    st.info("No providers available for booking appointments.")
            else:
                st.error("Unable to load providers. Please try again.")

        with tab2:
            st.subheader("Your Appointments")

            # Load appointments from API
            appointments_data, success = self.api_request('appointments')

            if success and 'appointments' in appointments_data:
                appointments = appointments_data['appointments']

                if appointments:
                    for apt in appointments:
                        try:
                            apt_date = datetime.fromisoformat(apt['appointment_date'].replace('Z', '+00:00'))
                            formatted_date = apt_date.strftime("%B %d, %Y")
                            formatted_time = apt_date.strftime("%I:%M %p")

                            with st.container():
                                col1, col2 = st.columns([3, 1])

                                with col1:
                                    st.write(f"**{apt['provider_name']}**")
                                    st.write(f"📅 {formatted_date} at {formatted_time}")
                                    if apt.get('notes'):
                                        st.caption(apt['notes'])
                                    st.caption(f"Status: {apt['status'].title()}")

                                with col2:
                                    if apt['status'] == 'scheduled':
                                        if st.button("Cancel", key=f"cancel_{apt['id']}", type="secondary"):
                                            st.info("Cancellation functionality would be implemented here")

                                st.markdown("---")
                        except Exception as e:
                            st.error(f"Error displaying appointment: {str(e)}")
                else:
                    st.info("No appointments scheduled. Book your first appointment above!")
            else:
                st.error("Unable to load appointments. Please try again.")

    def messages_page(self):
        """Secure Messaging Interface with API integration"""
        st.title("Messages")

        # Get available users to message
        users_data, users_success = self.api_request('users')

        if not users_success:
            st.error("Unable to load contacts. Please try again.")
            return

        providers = users_data.get('users', [])

        if not providers:
            st.info("No providers available for messaging.")
            return

        # Select provider to message
        provider_options = {p['name']: p['id'] for p in providers}
        selected_provider_name = st.selectbox("Message with:", list(provider_options.keys()))
        selected_provider_id = provider_options[selected_provider_name]

        st.subheader(f"Conversation with {selected_provider_name}")

        # Load messages with selected provider
        messages_data, success = self.api_request(f'messages?with_user={selected_provider_id}')

        if success and 'messages' in messages_data:
            messages = messages_data['messages']

            # Display messages
            for msg in messages:
                try:
                    date_obj = datetime.fromisoformat(msg['created_at'].replace('Z', '+00:00'))
                    formatted_time = date_obj.strftime("%I:%M %p")
                except:
                    formatted_time = "Unknown time"

                is_sender = msg['sender_id'] == st.session_state.user['id']

                if is_sender:
                    st.markdown(f"""
                    <div style='text-align: right; margin: 10px 0;'>
                        <div style='background-color: #667eea; color: white; padding: 10px; border-radius: 10px; display: inline-block; max-width: 70%;'>
                            {msg['content']}
                        </div>
                        <div style='font-size: 0.8em; color: #666; margin-top: 2px;'>{formatted_time}</div>
                    </div>
                    """, unsafe_allow_html=True)
                else:
                    st.markdown(f"""
                    <div style='text-align: left; margin: 10px 0;'>
                        <div style='background-color: #f0f0f0; color: #333; padding: 10px; border-radius: 10px; display: inline-block; max-width: 70%;'>
                            {msg['content']}
                        </div>
                        <div style='font-size: 0.8em; color: #666; margin-top: 2px;'>{msg['sender_name']} • {formatted_time}</div>
                    </div>
                    """, unsafe_allow_html=True)

        # New message input
        st.markdown("---")
        with st.form("message_form"):
            new_message = st.text_area("Type your message here...", height=100)

            if st.form_submit_button("Send Message", type="primary"):
                if new_message:
                    message_data = {
                        'receiver_id': selected_provider_id,
                        'content': new_message
                    }

                    data, success = self.api_request('messages', 'POST', message_data)

                    if success:
                        st.success("Message sent successfully!")
                        st.rerun()
                    else:
                        st.error(f"Failed to send message: {data.get('error', 'Unknown error')}")
                else:
                    st.error("Please enter a message!")

    def provider_dashboard(self):
        """Healthcare Provider Dashboard with API integration"""
        st.sidebar.title("🧠 MindCare")
        st.sidebar.write("Provider Portal")
        st.sidebar.write(f"Welcome, {st.session_state.user['name']}!")

        menu_options = ["Overview", "Patients", "Appointments", "Messages"]
        selected = st.sidebar.selectbox("Navigation", menu_options)

        if st.sidebar.button("Logout"):
            self.api_request('logout', 'POST')
            st.session_state.logged_in = False
            st.session_state.user = None
            st.session_state.auth_checked = False
            st.rerun()

        self.load_dashboard_data()

        if selected == "Overview":
            self.provider_overview()
        elif selected == "Patients":
            self.provider_patients()
        elif selected == "Appointments":
            self.provider_appointments()
        elif selected == "Messages":
            self.provider_messages()

    def provider_overview(self):
        """Provider Dashboard Overview with real data"""
        st.title(f"Welcome, {st.session_state.user['name']}!")

        # Load provider statistics
        dashboard_data = st.session_state.get('dashboard_data', {})

        # Statistics
        col1, col2, col3, col4 = st.columns(4)

        with col1:
            st.metric("Active Patients", dashboard_data.get('active_patients', 0))
        with col2:
            st.metric("Today's Appointments", dashboard_data.get('today_appointments', 0))
        with col3:
            st.metric("Unread Messages", dashboard_data.get('unread_messages', 0))
        with col4:
            st.metric("Total Patients", dashboard_data.get('total_patients', 0))

        st.markdown("---")

        # Today's Appointments from API
        st.subheader("Today's Schedule")

        appointments_data, success = self.api_request('appointments')

        if success and 'appointments' in appointments_data:
            today = datetime.now().date()
            today_appointments = []

            for apt in appointments_data['appointments']:
                try:
                    apt_date = datetime.fromisoformat(apt['appointment_date'].replace('Z', '+00:00'))
                    if apt_date.date() == today:
                        today_appointments.append(apt)
                except:
                    continue

            if today_appointments:
                for appointment in today_appointments:
                    try:
                        apt_datetime = datetime.fromisoformat(appointment['appointment_date'].replace('Z', '+00:00'))
                        formatted_time = apt_datetime.strftime("%I:%M %p")
                        end_time = (apt_datetime + timedelta(minutes=appointment.get('duration', 60))).strftime(
                            "%I:%M %p")

                        with st.container():
                            col1, col2 = st.columns([3, 1])

                            with col1:
                                st.write(f"**{appointment['patient_name']} - Session**")
                                st.write(f"🕐 {formatted_time} - {end_time}")
                                if appointment.get('notes'):
                                    st.caption(appointment['notes'])

                            with col2:
                                if st.button("View Details", key=f"details_{appointment['id']}"):
                                    st.info("Patient details would be displayed here")

                            st.markdown("---")
                    except Exception as e:
                        st.error(f"Error displaying appointment: {str(e)}")
            else:
                st.info("No appointments scheduled for today.")
        else:
            st.error("Unable to load today's appointments.")

    def provider_patients(self):
        """Patient Management Interface with API integration"""
        st.title("Patient Management")

        # Get all users (patients for providers)
        users_data, success = self.api_request('users')

        if not success:
            st.error("Unable to load patient data.")
            return

        patients = [user for user in users_data.get('users', []) if user['role'] == 'patient']

        if not patients:
            st.info("No patients found.")
            return

        # Search functionality
        search_term = st.text_input("🔍 Search patients by name...")

        # Filter patients based on search
        if search_term:
            filtered_patients = [p for p in patients if search_term.lower() in p['name'].lower()]
        else:
            filtered_patients = patients

        st.subheader(f"Patients ({len(filtered_patients)})")

        for patient in filtered_patients:
            with st.expander(f"{patient['name']} - Patient ID: {patient['id']}"):
                col1, col2, col3 = st.columns(3)

                with col1:
                    st.write(f"**Email:** {patient['email']}")
                    st.write(f"**Joined:** {patient['created_at'][:10]}")

                with col2:
                    st.write(f"**Role:** {patient['role'].title()}")
                    st.write(f"**Status:** Active")

                with col3:
                    if st.button("Send Message", key=f"message_{patient['id']}"):
                        st.session_state.selected_patient_id = patient['id']
                        st.session_state.selected_patient_name = patient['name']
                    if st.button("View Records", key=f"records_{patient['id']}"):
                        st.session_state.view_records_patient = patient['id']

        # Handle message sending
        if 'selected_patient_id' in st.session_state:
            self.quick_message_form()

    def quick_message_form(self):
        """Quick message form for providers"""
        st.subheader(f"Send Message to {st.session_state.selected_patient_name}")

        with st.form("quick_message_form"):
            message_content = st.text_area("Message", height=100)

            col1, col2 = st.columns(2)
            with col1:
                send_button = st.form_submit_button("Send Message", type="primary")
            with col2:
                cancel_button = st.form_submit_button("Cancel")

            if send_button and message_content:
                message_data = {
                    'receiver_id': st.session_state.selected_patient_id,
                    'content': message_content
                }

                data, success = self.api_request('messages', 'POST', message_data)

                if success:
                    st.success("Message sent successfully!")
                    del st.session_state.selected_patient_id
                    del st.session_state.selected_patient_name
                    st.rerun()
                else:
                    st.error(f"Failed to send message: {data.get('error', 'Unknown error')}")

            if cancel_button:
                del st.session_state.selected_patient_id
                del st.session_state.selected_patient_name
                st.rerun()

    def provider_appointments(self):
        """Provider Appointment Management with API integration"""
        st.title("Appointment Management")

        # Load appointments
        appointments_data, success = self.api_request('appointments')

        if not success:
            st.error("Unable to load appointments.")
            return

        appointments = appointments_data.get('appointments', [])

        # Filter controls
        col1, col2 = st.columns(2)

        with col1:
            view_filter = st.selectbox("View", ["All Appointments", "Today", "This Week", "Upcoming"])

        with col2:
            status_filter = st.selectbox("Status", ["All", "Scheduled", "Completed", "Cancelled"])

        # Apply filters
        filtered_appointments = appointments

        if view_filter == "Today":
            today = datetime.now().date()
            filtered_appointments = [apt for apt in appointments
                                     if datetime.fromisoformat(
                    apt['appointment_date'].replace('Z', '+00:00')).date() == today]
        elif view_filter == "This Week":
            today = datetime.now().date()
            week_start = today - timedelta(days=today.weekday())
            week_end = week_start + timedelta(days=6)
            filtered_appointments = [apt for apt in appointments
                                     if week_start <= datetime.fromisoformat(
                    apt['appointment_date'].replace('Z', '+00:00')).date() <= week_end]
        elif view_filter == "Upcoming":
            now = datetime.now()
            filtered_appointments = [apt for apt in appointments
                                     if datetime.fromisoformat(apt['appointment_date'].replace('Z', '+00:00')) > now]

        if status_filter != "All":
            filtered_appointments = [apt for apt in filtered_appointments if apt['status'] == status_filter.lower()]

        st.markdown("---")

        # Display appointments
        if filtered_appointments:
            st.subheader(f"Appointments ({len(filtered_appointments)})")

            for apt in filtered_appointments:
                try:
                    apt_datetime = datetime.fromisoformat(apt['appointment_date'].replace('Z', '+00:00'))
                    formatted_date = apt_datetime.strftime("%B %d, %Y")
                    formatted_time = apt_datetime.strftime("%I:%M %p")

                    with st.container():
                        col1, col2 = st.columns([3, 1])

                        with col1:
                            st.write(f"**{apt['patient_name']} - Session**")
                            st.write(f"🕐 {formatted_date} at {formatted_time}")
                            if apt.get('notes'):
                                st.caption(f"Notes: {apt['notes']}")
                            st.caption(f"Status: {apt['status'].title()}")

                        with col2:
                            if apt['status'] == 'scheduled' and apt_datetime > datetime.now():
                                if st.button("Start Session", key=f"start_{apt['id']}", type="primary"):
                                    st.success("Session interface would open here!")
                            else:
                                if st.button("View Details", key=f"details_{apt['id']}"):
                                    st.info("Appointment details would be displayed here")

                        st.markdown("---")
                except Exception as e:
                    st.error(f"Error displaying appointment: {str(e)}")
        else:
            st.info("No appointments match the selected filters.")

    def provider_messages(self):
        """Provider Message Management with API integration"""
        st.title("Patient Messages")

        # Get all messages
        messages_data, success = self.api_request('messages')

        if not success:
            st.error("Unable to load messages.")
            return

        all_messages = messages_data.get('messages', [])

        # Group messages by conversation partner
        conversations = {}
        for msg in all_messages:
            other_user_id = msg['receiver_id'] if msg['sender_id'] == st.session_state.user['id'] else msg['sender_id']
            other_user_name = msg['receiver_name'] if msg['sender_id'] == st.session_state.user['id'] else msg[
                'sender_name']

            if other_user_id not in conversations:
                conversations[other_user_id] = {
                    'name': other_user_name,
                    'messages': [],
                    'unread_count': 0,
                    'last_message': None
                }

            conversations[other_user_id]['messages'].append(msg)

            if msg['receiver_id'] == st.session_state.user['id'] and not msg['read']:
                conversations[other_user_id]['unread_count'] += 1

            # Update last message (assuming messages are ordered by date)
            if not conversations[other_user_id]['last_message'] or msg['created_at'] > \
                    conversations[other_user_id]['last_message']['created_at']:
                conversations[other_user_id]['last_message'] = msg

        col1, col2 = st.columns([1, 2])

        with col1:
            st.subheader("Conversations")

            selected_conversation = st.session_state.get('selected_conversation_id', None)

            if conversations:
                for user_id, conv_data in conversations.items():
                    unread_indicator = f" ({conv_data['unread_count']} unread)" if conv_data['unread_count'] > 0 else ""
                    button_label = f"{conv_data['name']}{unread_indicator}"

                    if st.button(button_label, key=f"conv_{user_id}", use_container_width=True):
                        st.session_state.selected_conversation_id = user_id
                        st.session_state.selected_conversation_name = conv_data['name']
                        st.rerun()

                    # Show preview of last message
                    if conv_data['last_message']:
                        preview = conv_data['last_message']['content'][:50] + "..." if len(
                            conv_data['last_message']['content']) > 50 else conv_data['last_message']['content']
                        try:
                            msg_date = datetime.fromisoformat(
                                conv_data['last_message']['created_at'].replace('Z', '+00:00'))
                            time_str = msg_date.strftime("%m/%d %H:%M")
                        except:
                            time_str = "Unknown"
                        st.caption(f"{preview} • {time_str}")

                    st.markdown("---")
            else:
                st.info("No messages yet.")

        with col2:
            if 'selected_conversation_id' in st.session_state:
                conversation_id = st.session_state.selected_conversation_id
                conversation_name = st.session_state.selected_conversation_name

                st.subheader(f"Conversation with {conversation_name}")

                # Load conversation messages
                conv_messages_data, conv_success = self.api_request(f'messages?with_user={conversation_id}')

                if conv_success and 'messages' in conv_messages_data:
                    messages = conv_messages_data['messages']

                    # Display messages
                    for msg in messages:
                        try:
                            date_obj = datetime.fromisoformat(msg['created_at'].replace('Z', '+00:00'))
                            formatted_time = date_obj.strftime("%I:%M %p")
                        except:
                            formatted_time = "Unknown time"

                        is_sender = msg['sender_id'] == st.session_state.user['id']

                        if is_sender:
                            st.markdown(f"""
                            <div style='text-align: right; margin: 10px 0;'>
                                <div style='background-color: #667eea; color: white; padding: 10px; border-radius: 10px; display: inline-block; max-width: 70%;'>
                                    {msg['content']}
                                </div>
                                <div style='font-size: 0.8em; color: #666; margin-top: 2px;'>{formatted_time}</div>
                            </div>
                            """, unsafe_allow_html=True)
                        else:
                            st.markdown(f"""
                            <div style='text-align: left; margin: 10px 0;'>
                                <div style='background-color: #f0f0f0; color: #333; padding: 10px; border-radius: 10px; display: inline-block; max-width: 70%;'>
                                    {msg['content']}
                                </div>
                                <div style='font-size: 0.8em; color: #666; margin-top: 2px;'>{msg['sender_name']} • {formatted_time}</div>
                            </div>
                            """, unsafe_allow_html=True)

                # Reply form
                with st.form("provider_reply"):
                    reply = st.text_area("Type your response...", height=100)
                    if st.form_submit_button("Send Message", type="primary"):
                        if reply:
                            message_data = {
                                'receiver_id': conversation_id,
                                'content': reply
                            }

                            data, success = self.api_request('messages', 'POST', message_data)

                            if success:
                                st.success("Message sent!")
                                st.rerun()
                            else:
                                st.error(f"Failed to send message: {data.get('error', 'Unknown error')}")
            else:
                st.info("Select a conversation to view messages")

    def run(self):
        """Main application runner"""
        st.set_page_config(
            page_title="MindCare - Mental Health Platform",
            page_icon="🧠",
            layout="wide",
            initial_sidebar_state="expanded"
        )

        # Custom CSS for better styling
        st.markdown("""
        <style>
        .main {
            padding-top: 2rem;
        }
        .stButton > button {
            border-radius: 10px;
            height: 3em;
        }
        .metric-card {
            background-color: white;
            padding: 1rem;
            border-radius: 10px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        .message-bubble {
            padding: 10px;
            border-radius: 10px;
            margin: 5px 0;
            display: inline-block;
            max-width: 70%;
        }
        .user-message {
            background-color: #667eea;
            color: white;
            float: right;
            text-align: right;
        }
        .provider-message {
            background-color: #f0f0f0;
            color: #333;
            float: left;
            text-align: left;
        }
        </style>
        """, unsafe_allow_html=True)

        self.init_session_state()
        self.check_authentication()

        if not st.session_state.logged_in:
            self.login_page()
        else:
            if st.session_state.user['role'] == 'patient':
                self.patient_dashboard()
            else:
                self.provider_dashboard()


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