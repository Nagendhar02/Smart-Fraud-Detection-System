# 🛡️ Fraud Detection System

A Flask-based web application for detecting and managing fraudulent transactions in real time.

## Features

- User authentication (Register / Login / Logout)
- Transaction monitoring dashboard
- Admin dashboard with full oversight
- Fraud detection engine (`fraud_detector.py`)
- Email alerts via Flask-Mail
- Database migrations with Flask-Migrate (Alembic)

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Backend | Python 3, Flask |
| Database | SQLAlchemy + SQLite |
| Auth | Flask-Login |
| Email | Flask-Mail |
| Frontend | Jinja2, HTML/CSS, JavaScript |
| Migrations | Flask-Migrate (Alembic) |

## Project Structure

```
fraud-detection-system/
├── app.py                  # App factory / configuration
├── main.py                 # Entry point
├── routes.py               # All route handlers
├── models.py               # Database models
├── extensions.py           # Flask extensions (db, login_manager, etc.)
├── fraud_detector.py       # Core fraud detection logic
├── email_handler.py        # Email alert logic
├── migrate_database.py     # DB migration helper script
├── requirements.txt        # Python dependencies
├── .env.example            # Environment variable template
├── migrations/             # Alembic migration files
├── scripts/                # Utility scripts
│   ├── add_card_type.py
│   └── smoke_check.py
├── static/
│   ├── css/style.css
│   └── js/main.js
└── templates/              # Jinja2 HTML templates
    ├── base.html
    ├── index.html
    ├── login.html
    ├── register.html
    ├── dashboard.html
    ├── admin_dashboard.html
    ├── transaction.html
    ├── 404.html
    └── 500.html
```

## Setup & Installation

### 1. Clone the repository

```bash
git clone https://github.com/YOUR_USERNAME/fraud-detection-system.git
cd fraud-detection-system
```

### 2. Create and activate a virtual environment

```bash
python -m venv venv

# On Windows
venv\Scripts\activate

# On macOS/Linux
source venv/bin/activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Set up environment variables

```bash
cp .env.example .env
```

Edit `.env` and fill in your actual Gmail credentials:

```
MAIL_SERVER=smtp.gmail.com
MAIL_PORT=465
MAIL_USE_SSL=True
MAIL_USERNAME=your_email@gmail.com
MAIL_PASSWORD=your_gmail_app_password
MAIL_DEFAULT_SENDER=your_email@gmail.com
```

> **Tip:** For `MAIL_PASSWORD`, use a [Gmail App Password](https://support.google.com/accounts/answer/185833), not your regular Gmail password.

### 5. Initialize the database

```bash
flask db upgrade
```

### 6. Run the application

```bash
python main.py
```

The app will be available at `http://127.0.0.1:5000`

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/your-feature`)
3. Commit your changes (`git commit -m 'Add your feature'`)
4. Push to the branch (`git push origin feature/your-feature`)
5. Open a Pull Request

## License

This project is open source and available under the [MIT License](LICENSE).
