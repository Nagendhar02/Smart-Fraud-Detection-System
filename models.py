from extensions import db
from flask_login import UserMixin
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
import json

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_admin = db.Column(db.Boolean, default=False)
    
    profile = db.relationship('UserProfile', backref='user', uselist=False, cascade='all, delete-orphan')
    transactions = db.relationship('Transaction', backref='user', lazy='dynamic', cascade='all, delete-orphan')
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def get_transaction_count(self):
        """Get total number of transactions for this user"""
        return self.transactions.count()
    
    def get_approved_transaction_count(self):
        """Get number of approved transactions for this user"""
        return self.transactions.filter_by(status='approved').count()
    
    def is_new_user(self, threshold=5):
        """Check if user is considered 'new' based on transaction count"""
        return self.get_transaction_count() < threshold

    def __repr__(self):
        return f"<User {self.username}>"

class UserProfile(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    typical_locations = db.Column(db.Text)  # JSON string of common IP/location data
    avg_transaction_amount = db.Column(db.Float, default=0.0)
    max_transaction_amount = db.Column(db.Float, default=1000.0)
    common_categories = db.Column(db.Text)  # JSON string of preferred item categories
    transaction_frequency = db.Column(db.Integer, default=0)  # transactions per day
    known_user_agents = db.Column(db.Text)  # JSON list of known agents
    common_hours = db.Column(db.Text)       # JSON list of frequent hours
    device_fingerprints = db.Column(db.Text, default='[]')  # JSON list of device fingerprints
    
    device_fingerprints = db.Column(db.Text, default='[]')  # JSON list of device fingerprints
    login_attempts = db.Column(db.Text, default='[]')       # JSON list of recent login attempts
    failed_login_count = db.Column(db.Integer, default=0)
    last_password_reset = db.Column(db.DateTime)
    velocity_flags = db.Column(db.Text, default='[]')       # JSON list of velocity violations
    password_reset_attempts = db.Column(db.Text, default='[]')  # JSON list of password reset attempts
    known_payment_methods = db.Column(db.Text, default='[]')   # JSON list of known payment methods

    last_known_ip = db.Column(db.String(45))
    last_known_location = db.Column(db.String(255))

    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def get_typical_locations(self):
        if self.typical_locations:
            try:
                return json.loads(self.typical_locations)
            except:
                return []
        return []

    def set_typical_locations(self, locations):
        self.typical_locations = json.dumps(locations)

    def get_common_categories(self):
        if self.common_categories:
            try:
                return json.loads(self.common_categories)
            except:
                return []
        return []

    def set_common_categories(self, categories):
        self.common_categories = json.dumps(categories)

    def get_known_user_agents(self):
        if self.known_user_agents:
            try:
                return json.loads(self.known_user_agents)
            except:
                return []
        return []

    def set_known_user_agents(self, agents):
        self.known_user_agents = json.dumps(agents)

    def get_common_hours(self):
        if self.common_hours:
            try:
                return json.loads(self.common_hours)
            except:
                return []
        return []

    def set_common_hours(self, hours):
        self.common_hours = json.dumps(hours)
    
    def get_device_fingerprints(self):
        if self.device_fingerprints:
            try:
                return json.loads(self.device_fingerprints)
            except:
                return []
        return []
    
    def set_device_fingerprints(self, fingerprints):
        self.device_fingerprints = json.dumps(fingerprints)
    
    def get_login_attempts(self):
        if self.login_attempts:
            try:
                return json.loads(self.login_attempts)
            except:
                return []
        return []
    
    def set_login_attempts(self, attempts):
        self.login_attempts = json.dumps(attempts)
    
    def get_velocity_flags(self):
        if self.velocity_flags:
            try:
                return json.loads(self.velocity_flags)
            except:
                return []
        return []
    
    def set_velocity_flags(self, flags):
        self.velocity_flags = json.dumps(flags)
    
    def get_password_reset_attempts(self):
        if self.password_reset_attempts:
            try:
                return json.loads(self.password_reset_attempts)
            except:
                return []
        return []
    
    def set_password_reset_attempts(self, attempts):
        self.password_reset_attempts = json.dumps(attempts)
    
    def get_known_payment_methods(self):
        if self.known_payment_methods:
            try:
                return json.loads(self.known_payment_methods)
            except:
                return []
        return []
    
    def set_known_payment_methods(self, methods):
        self.known_payment_methods = json.dumps(methods)
    
    def get_transaction_hours_history(self):
        """Get historical transaction hours with counts"""
        # This would be implemented to return hour frequency data
        # For now, return empty dict
        return {}


class Transaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    
    amount = db.Column(db.Float, nullable=False)
    item_name = db.Column(db.String(255), nullable=False)
    item_category = db.Column(db.String(100), nullable=False)
    
    card_last_four = db.Column(db.String(4))
    card_type = db.Column(db.String(20))  # credit, debit, prepaid, virtual_wallet
    
    ip_address = db.Column(db.String(45))
    location = db.Column(db.String(255))
    user_agent = db.Column(db.Text)
    
    fraud_score = db.Column(db.Float, default=0.0)
    status = db.Column(db.String(20), default='pending')  # pending, approved, flagged, blocked
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    processed_at = db.Column(db.DateTime)
    
    fraud_logs = db.relationship('FraudLog', backref='transaction', lazy='dynamic', cascade='all, delete-orphan')
    
    def get_status_color(self):
        colors = {
            'approved': 'success',
            'pending': 'warning',
            'flagged': 'danger',
            'blocked': 'dark'
        }
        return colors.get(self.status, 'secondary')
    
    def is_high_risk(self, threshold=0.7):
        return self.fraud_score >= threshold
    
    def can_be_approved(self):
        return self.status in ['pending', 'flagged']
    
    def can_be_blocked(self):
        return self.status != 'blocked'
    
    def validate_amount(self):
        return self.amount > 0 and self.amount <= 1000000  # Max $1M
    
    def get_risk_level(self):
        if self.fraud_score < 0.3:
            return 'Low'
        elif self.fraud_score < 0.6:
            return 'Medium'
        elif self.fraud_score < 0.8:
            return 'High'
        else:
            return 'Critical'

class FraudLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    transaction_id = db.Column(db.Integer, db.ForeignKey('transaction.id'), nullable=False)
    
    rule_triggered = db.Column(db.String(255))
    risk_factors = db.Column(db.Text)  # JSON string of risk factors
    confidence_score = db.Column(db.Float)
    
    location_anomaly = db.Column(db.Boolean, default=False)
    amount_anomaly = db.Column(db.Boolean, default=False)
    category_anomaly = db.Column(db.Boolean, default=False)
    frequency_anomaly = db.Column(db.Boolean, default=False)
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def get_risk_factors(self):
        if self.risk_factors:
            try:
                return json.loads(self.risk_factors)
            except:
                return []
        return []
    
    def set_risk_factors(self, factors):
        self.risk_factors = json.dumps(factors)
