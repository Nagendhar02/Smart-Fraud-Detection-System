from flask import render_template, request, redirect, url_for, flash, jsonify, current_app
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash
from extensions import db
from models import User, UserProfile, Transaction, FraudLog
from fraud_detector import FraudDetector
import logging
from datetime import datetime
import re
from email_handler import EmailHandler
import random
from flask import session

# Initialize fraud detector
fraud_detector = FraudDetector()

def register_routes(app):
    @app.route('/')
    def index():
        if current_user.is_authenticated:
            return redirect(url_for('dashboard'))
        return render_template('index.html')

    @app.route('/register', methods=['GET', 'POST'])
    def register():
        if request.method == 'POST':
            username = request.form.get('username')
            email = request.form.get('email')
            password = request.form.get('password')
            confirm_password = request.form.get('confirm_password')
            
            # Validation
            if not username or not email or not password:
                flash('All fields are required.', 'danger')
                return render_template('register.html')
            
            if password != confirm_password:
                flash('Passwords do not match.', 'danger')
                return render_template('register.html')
            
            if len(password) < 6:
                flash('Password must be at least 6 characters long.', 'danger')
                return render_template('register.html')
            
            # Check if user exists
            if User.query.filter_by(username=username).first():
                flash('Username already exists.', 'danger')
                return render_template('register.html')
            
            if User.query.filter_by(email=email).first():
                flash('Email already registered.', 'danger')
                return render_template('register.html')
            
            # Create user
            user = User()
            user.username = username
            user.email = email
            user.set_password(password)
            
            # Make first user admin
            if User.query.count() == 0:
                user.is_admin = True
            
            db.session.add(user)
            db.session.flush()
            
            # Create user profile
            profile = UserProfile()
            profile.user_id = user.id
            profile.last_known_ip = get_client_ip()
            profile.last_known_location = get_location_from_ip(profile.last_known_ip)
            
            db.session.add(profile)
            db.session.commit()
            
            flash('Registration successful! Please log in.', 'success')

            emailer = EmailHandler(current_app._get_current_object())

            subject = "🎉 Welcome to FraudGuard!"
            recipients = [user.email]

            # Simple text email body with emojis
            body = f"""
                Hi {user.username}, 🎊

                Congratulations! 🎉 Your account has been successfully created at FraudGuard. ✅

                You can now log in using your email and password to start using our platform.  

                If you did not register for this account, please ignore this email or contact our support team.  

                Thank you,  
                The FraudGuard Team 🛡️
                """

            emailer.send_email(subject, recipients, body)
            

            return redirect(url_for('login'))
        
        return render_template('register.html')

    @app.route('/login', methods=['GET', 'POST'])
    def login():
        if request.method == 'POST':
            username = request.form.get('username')
            password = request.form.get('password')
            
            if not username or not password:
                flash('Username and password are required.', 'danger')
                return render_template('login.html')
            
            user = User.query.filter_by(username=username).first()
            
            # Track login attempt
            login_attempt = {
                'timestamp': datetime.utcnow().isoformat(),
                'ip_address': get_client_ip(),
                'user_agent': request.headers.get('User-Agent', ''),
                'success': False,
                'username': username
            }
            
            if user and user.check_password(password):
                login_attempt['success'] = True
                login_user(user)
                flash('Logged in successfully.', 'success')
                # Update last known IP/location and track login
                if user.profile:
                    user.profile.last_known_ip = get_client_ip()
                    user.profile.last_known_location = get_location_from_ip(user.profile.last_known_ip)
                    user.profile.failed_login_count = 0  # Reset failed login count
                    
                    # Track successful login
                    login_attempts = user.profile.get_login_attempts() or []
                    login_attempts.append(login_attempt)
                    # Keep last 50 login attempts
                    user.profile.set_login_attempts(login_attempts[-50:])
                    
                    db.session.commit()
                
                next_page = request.args.get('next')
                return redirect(next_page) if next_page else redirect(url_for('dashboard'))
            else:
                # Track failed login attempt
                if user and user.profile:
                    user.profile.failed_login_count = (user.profile.failed_login_count or 0) + 1
                    login_attempts = user.profile.get_login_attempts() or []
                    login_attempts.append(login_attempt)
                    user.profile.set_login_attempts(login_attempts[-50:])
                    db.session.commit()
                    
                flash('Invalid username or password.', 'danger')
        
        return render_template('login.html')

    @app.route('/logout')
    @login_required
    def logout():
        logout_user()
        flash('You have been logged out.', 'info')
        return redirect(url_for('index'))

    @app.route('/dashboard')
    @login_required
    def dashboard():
        # Get user's recent transactions
        transactions = Transaction.query.filter_by(user_id=current_user.id)\
                                      .order_by(Transaction.created_at.desc())\
                                      .limit(10).all()
        
        # Get statistics
        total_transactions = Transaction.query.filter_by(user_id=current_user.id).count()
        flagged_transactions = Transaction.query.filter_by(user_id=current_user.id, status='flagged').count()
        blocked_transactions = Transaction.query.filter_by(user_id=current_user.id, status='blocked').count()
        
        return render_template('dashboard.html', 
                             transactions=transactions,
                             total_transactions=total_transactions,
                             flagged_transactions=flagged_transactions,
                             blocked_transactions=blocked_transactions)

    @app.route('/admin')
    @login_required
    def admin_dashboard():
        if not current_user.is_admin:
            flash('Access denied. Admin privileges required.', 'danger')
            return redirect(url_for('dashboard'))
        
        # Get all transactions with pagination
        page = request.args.get('page', 1, type=int)
        status_filter = request.args.get('status', 'all')
        
        query = Transaction.query
        if status_filter != 'all':
            query = query.filter_by(status=status_filter)
        
        transactions = query.order_by(Transaction.created_at.desc())\
                           .paginate(page=page, per_page=20, error_out=False)
        
        # Get statistics
        total_transactions = Transaction.query.count()
        flagged_count = Transaction.query.filter_by(status='flagged').count()
        blocked_count = Transaction.query.filter_by(status='blocked').count()
        approved_count = Transaction.query.filter_by(status='approved').count()
        
        return render_template('admin_dashboard.html',
                             transactions=transactions,
                             total_transactions=total_transactions,
                             flagged_count=flagged_count,
                             blocked_count=blocked_count,
                             approved_count=approved_count,
                             status_filter=status_filter)

    @app.route('/transaction', methods=['GET', 'POST'])
    @login_required
    def transaction():
        if request.method == 'POST':
            # Get form data
            amount = request.form.get('amount', type=float)
            item_name = request.form.get('item_name')
            item_category = request.form.get('item_category')
            card_number = request.form.get('card_number')

            transaction_code = f"TXN{random.randint(100000, 999999)}"
            session['transaction_code'] = transaction_code

            
            # Validation
            if not all([amount, item_name, item_category, card_number]):
                flash('All fields are required.', 'danger')
                return render_template('transaction.html')
            
            if amount is None or amount <= 0:
                flash('Amount must be greater than 0.', 'danger')
                return render_template('transaction.html')
            
            if not card_number or len(card_number) < 13 or not card_number.replace(' ', '').isdigit():
                flash('Invalid card number.', 'danger')
                return render_template('transaction.html')
            
            # Detect payment method type
            card_type = detect_payment_method(card_number)
            
            # Create transaction data for analysis
            transaction_data = {
                'amount': amount,
                'item_name': item_name,
                'item_category': item_category,
                'card_type': card_type,
                'ip_address': get_client_ip(),
                'location': get_location_from_ip(get_client_ip()),
                'user_agent': request.headers.get('User-Agent', '')
            }
            
            # Analyze for fraud
            try:
                fraud_score, status, risk_factors = fraud_detector.analyze_transaction(
                    transaction_data, current_user
                )
            except Exception as e:
                logging.error(f"Fraud analysis failed for user {current_user.id}: {e}")
                # Fallback to conservative approach
                fraud_score = 0.8
                status = 'flagged'
                risk_factors = ['System error during analysis']
            
            # Create transaction record
            transaction_record = Transaction()
            transaction_record.user_id = current_user.id
            transaction_record.amount = amount
            transaction_record.item_name = item_name
            transaction_record.item_category = item_category
            transaction_record.card_last_four = card_number.replace(' ', '')[-4:]
            transaction_record.card_type = card_type
            transaction_record.ip_address = transaction_data['ip_address']
            transaction_record.location = transaction_data['location']
            transaction_record.user_agent = transaction_data['user_agent']
            transaction_record.fraud_score = fraud_score
            transaction_record.status = status
            
            if status == 'approved':
                transaction_record.processed_at = datetime.utcnow()
            
            db.session.add(transaction_record)
            db.session.flush()
            
            # Create fraud log
            try:
                fraud_detector.create_fraud_log(transaction_record, fraud_score, risk_factors)
            except Exception as e:
                logging.error(f"Failed to create fraud log: {e}")
                # Continue processing even if fraud log fails
            
            # Update user baseline if approved
            if status == 'approved':
                try:
                    fraud_detector.update_user_baseline(current_user, transaction_record)
                except Exception as e:
                    logging.error(f"Failed to update user baseline: {e}")
                    # Don't fail the transaction for baseline update issues
            
            db.session.commit()
            emailer = EmailHandler(current_app._get_current_object())

            # Flash appropriate message
            if status == 'approved':
                flash('Transaction approved successfully!', 'success')

                subject = "✅ Your Transaction Has Been Approved!"
                recipients = [current_user.email]  # or user.email if you have a user object

                body = f"""
                Hi {current_user.username}, 🎉

                Good news! Your recent transaction has been successfully approved. ✅

                Transaction Details:
                - Product: {item_name} ({item_category})
                - Transaction ID: {transaction_code}
                - Amount: ₹{amount}
                - Status: Approved ✔️

                You can now continue using your account safely.  

                Thank you for using FraudGuard! 🛡️

                Best regards,  
                The FraudGuard Team
                """

                emailer.send_email(subject, recipients, body)

            elif status == 'flagged':
                flash('Transaction flagged for review. Please contact support if needed.', 'warning')
                # Inside your flagged transaction logic
                # admin = User.query.filter_by(is_admin=True).first()

                subject = "⚠️ Fraud Alert: Suspicious Transaction Detected!"
                recipients = ["fraud.detecting.team@gmail.com"]  # Admin email(s)

                # Simple text email body with emojis
                body = f"""
                        Dear Admin, 🚨

                        ⚠️ A transaction has been flagged as suspicious! 

                        Transaction Details:
                        - Product: {item_name} ({item_category})
                        - Transaction ID: {transaction_code}
                        - Amount: ₹{amount}
                        - Status: Flagged for Review ⚡

                        Please investigate this transaction immediately to ensure platform security. 🔒

                        Thank you,  
                        The FraudGuard Team 🛡️
                        """

                # Send email asynchronously
                emailer.send_email(subject, recipients, body)

                subject = "⚠️ Suspicious Transaction Detected"
                recipients = [current_user.email]  # Replace `user` with the transaction's user object

                body = f"""
                Hi {current_user.username}, 🚨

                We detected that a recent transaction on your account has been flagged as suspicious. 🛑

                Transaction Details:
                - Transaction ID: {session.get('transaction_code', None)}
                - Amount: ₹{amount}
                - Status: Under Investigation 🔍

                For your safety, this transaction will be reviewed before it is approved. 
                If you did not initiate this transaction, please contact our support team immediately. 📞

                Thank you for using FraudGuard! 🛡️

                Best regards,  
                The FraudGuard Team
                """

                emailer.send_email(subject, recipients, body)

            else:  # blocked
                flash('Transaction blocked due to security concerns. Please contact support.', 'danger')
            
            return redirect(url_for('dashboard'))
        
        return render_template('transaction.html')

    @app.route('/admin/transaction/<int:transaction_id>/approve', methods=['POST'])
    @login_required
    def approve_transaction(transaction_id):
        if not current_user.is_admin:
            return jsonify({'error': 'Access denied'}), 403
        
        try:
            transaction = Transaction.query.get_or_404(transaction_id)
            
            # Check if transaction is in valid state for approval
            if transaction.status not in ['pending', 'flagged']:
                flash(f'Transaction cannot be approved from {transaction.status} state.', 'warning')
                return redirect(url_for('admin_dashboard'))
            
            transaction.status = 'approved'
            transaction.processed_at = datetime.utcnow()
            
            # Update user baseline
            user = User.query.get(transaction.user_id)
            if user:
                try:
                    fraud_detector.update_user_baseline(user, transaction)
                except Exception as e:
                    logging.error(f"Failed to update baseline during approval: {e}")
                    # Don't fail approval for baseline update issues
            
            db.session.commit()
            flash('Transaction approved successfully.', 'success')
            emailer = EmailHandler(current_app._get_current_object())

            subject = "✅ Your Transaction Has Been Approved!"
            recipients = [transaction.user.email]  # Replace `user` with the transaction's user object

            body = f"""
            Hi {transaction.user.username}, 🎉

            Good news! Your recent transaction has been successfully approved. ✅

            Transaction Details:
            - Transaction ID: {session.get('transaction_code', transaction_id)}
            - Amount: ₹{transaction.amount}
            - Status: Approved ✔️

            You can now continue using your account safely.  

            Thank you for using FraudGuard! 🛡️

            Best regards,  
            The FraudGuard Team
            """

            emailer.send_email(subject, recipients, body)
            
        except Exception as e:
            logging.error(f"Error approving transaction {transaction_id}: {e}")
            db.session.rollback()
            flash('Error approving transaction. Please try again.', 'danger')
            
        return redirect(url_for('admin_dashboard'))

    @app.route('/admin/transaction/<int:transaction_id>/block', methods=['POST'])
    @login_required
    def block_transaction(transaction_id):
        if not current_user.is_admin:
            return jsonify({'error': 'Access denied'}), 403
        
        try:
            transaction = Transaction.query.get_or_404(transaction_id)
            
            # Check if transaction is in valid state for blocking
            if transaction.status == 'blocked':
                flash('Transaction is already blocked.', 'info')
                return redirect(url_for('admin_dashboard'))
            
            transaction.status = 'blocked'
            transaction.processed_at = datetime.utcnow()
            
            db.session.commit()
            flash('Transaction blocked successfully.', 'success')

            emailer = EmailHandler(current_app._get_current_object())

            subject = "🚫 Your Transaction Has Been Blocked"
            recipients = [transaction.user.email]

            body = f"""
            Hi {transaction.user.username}, ⚠️

            We wanted to inform you that your recent transaction has been blocked. 🛑

            Transaction Details:
            - Transaction ID: {session.get('transaction_code', transaction_id)}
            - Amount: ₹{transaction.amount}
            - Status: Blocked ❌

            If you believe this was a mistake or need assistance, please contact our support team immediately. 📞

            Thank you for using FraudGuard! 🛡️

            Best regards,  
            The FraudGuard Team
            """

            emailer.send_email(subject, recipients, body)

            
        except Exception as e:
            logging.error(f"Error blocking transaction {transaction_id}: {e}")
            db.session.rollback()
            flash('Error blocking transaction. Please try again.', 'danger')
            
        return redirect(url_for('admin_dashboard'))

    def get_client_ip():
        """Get client IP address"""
        if request.headers.get('X-Forwarded-For'):
            return request.headers.get('X-Forwarded-For').split(',')[0].strip()
        elif request.headers.get('X-Real-IP'):
            return request.headers.get('X-Real-IP')
        else:
            return request.remote_addr

    def get_location_from_ip(ip_address):
        """Get location from IP address (simplified implementation)"""
        if not ip_address or ip_address in ['127.0.0.1', 'localhost']:
            return 'Local'
        
        # In production, use a proper GeoIP service
        # For now, return a simple location based on IP pattern
        if ip_address.startswith('192.168.') or ip_address.startswith('10.'):
            return 'Private Network'
        else:
            return f'Location for {ip_address}'
    
    def detect_payment_method(card_number):
        """Detect payment method type from card number patterns"""
        if not card_number:
            return 'unknown'
            
        # Remove spaces and get first few digits
        clean_number = card_number.replace(' ', '')
        
        if len(clean_number) < 4:
            return 'unknown'
            
        first_digit = clean_number[0]
        first_two = clean_number[:2]
        first_four = clean_number[:4]
        
        # Basic card type detection (simplified)
        if first_digit == '4':
            return 'credit'  # Visa (usually credit)
        elif first_two in ['51', '52', '53', '54', '55'] or first_four[:2] == '22':
            return 'credit'  # Mastercard (usually credit)
        elif first_two in ['34', '37']:
            return 'credit'  # American Express
        elif first_four in ['6011'] or first_two == '65':
            return 'credit'  # Discover
        elif first_four.startswith('5') and len(clean_number) == 16:
            return 'debit'   # Could be debit Mastercard
        elif len(clean_number) == 19:  # Some prepaid cards are longer
            return 'prepaid'
        else:
            return 'unknown'

    # Error handlers
    @app.errorhandler(404)
    def not_found_error(error):
        return render_template('404.html'), 404

    @app.errorhandler(500)
    def internal_error(error):
        db.session.rollback()
        return render_template('500.html'), 500