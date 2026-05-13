// FraudGuard - Main JavaScript

document.addEventListener('DOMContentLoaded', function() {
    // Initialize tooltips
    var tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    var tooltipList = tooltipTriggerList.map(function (tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });

    // Auto-hide alerts after 5 seconds
    setTimeout(function() {
        var alerts = document.querySelectorAll('.alert-dismissible');
        alerts.forEach(function(alert) {
            var alertInstance = new bootstrap.Alert(alert);
            alertInstance.close();
        });
    }, 5000);

    // Smooth scrolling for anchor links
    document.querySelectorAll('a[href^="#"]').forEach(anchor => {
        anchor.addEventListener('click', function (e) {
            e.preventDefault();
            const target = document.querySelector(this.getAttribute('href'));
            if (target) {
                target.scrollIntoView({
                    behavior: 'smooth',
                    block: 'start'
                });
            }
        });
    });

    // Form validation enhancements
    const forms = document.querySelectorAll('.needs-validation');
    forms.forEach(function(form) {
        form.addEventListener('submit', function(event) {
            if (!form.checkValidity()) {
                event.preventDefault();
                event.stopPropagation();
            }
            form.classList.add('was-validated');
        });
    });

    // Real-time risk score updates (demo purposes)
    updateRiskScores();
    
    // Transaction amount formatting
    const amountInputs = document.querySelectorAll('input[name="amount"]');
    amountInputs.forEach(function(input) {
        input.addEventListener('blur', function() {
            if (this.value) {
                this.value = parseFloat(this.value).toFixed(2);
            }
        });
    });

    // Security status updates
    updateSecurityStatus();
});

// Update risk score visualizations
function updateRiskScores() {
    const riskBars = document.querySelectorAll('.progress-bar');
    riskBars.forEach(function(bar) {
        const width = bar.style.width;
        const percentage = parseInt(width);
        
        // Add animation
        bar.style.width = '0%';
        setTimeout(function() {
            bar.style.width = width;
            bar.style.transition = 'width 1s ease-in-out';
        }, 100);
        
        // Update color based on risk level
        bar.classList.remove('bg-success', 'bg-warning', 'bg-danger');
        if (percentage < 30) {
            bar.classList.add('bg-success');
        } else if (percentage < 60) {
            bar.classList.add('bg-warning');
        } else {
            bar.classList.add('bg-danger');
        }
    });
}

// Update security status indicators
function updateSecurityStatus() {
    const securityCards = document.querySelectorAll('.security-info .card');
    securityCards.forEach(function(card) {
        // Add subtle animation
        card.style.transform = 'scale(0.98)';
        setTimeout(function() {
            card.style.transform = 'scale(1)';
            card.style.transition = 'transform 0.3s ease';
        }, 200);
    });
}

// Transaction form enhancements
function initializeTransactionForm() {
    const form = document.getElementById('transactionForm');
    if (!form) return;

    // Add real-time validation
    const inputs = form.querySelectorAll('input, select');
    inputs.forEach(function(input) {
        input.addEventListener('input', function() {
            validateField(this);
        });
    });

    // Add security indicators
    addSecurityIndicators(form);
}

// Validate individual form fields
function validateField(field) {
    const value = field.value.trim();
    const fieldName = field.name;
    
    let isValid = true;
    let message = '';

    switch(fieldName) {
        case 'amount':
            const amount = parseFloat(value);
            if (amount <= 0) {
                isValid = false;
                message = 'Amount must be greater than 0';
            } else if (amount > 200000) {
                isValid = false;
                message = 'Amount exceeds maximum limit';
            }
            break;
            
        case 'card_number':
            const cardNumber = value.replace(/\s/g, '');
            if (cardNumber.length < 13 || cardNumber.length > 19) {
                isValid = false;
                message = 'Invalid card number length';
            } else if (!/^\d+$/.test(cardNumber)) {
                isValid = false;
                message = 'Card number must contain only digits';
            }
            break;
    }

    // Update field appearance
    if (isValid) {
        field.classList.remove('is-invalid');
        field.classList.add('is-valid');
    } else {
        field.classList.remove('is-valid');
        field.classList.add('is-invalid');
    }

    // Show/hide error message
    const feedback = field.parentElement.querySelector('.invalid-feedback');
    if (feedback) {
        feedback.textContent = message;
    }
}

// Add security indicators to transaction form
function addSecurityIndicators(form) {
    // Add SSL indicator
    const sslIndicator = document.createElement('div');
    sslIndicator.className = 'alert alert-success d-flex align-items-center mt-3';
    sslIndicator.innerHTML = `
        <i class="bi bi-shield-check me-2"></i>
        <small>Secure SSL encrypted connection active</small>
    `;
    
    // Add fraud detection indicator
    const fraudIndicator = document.createElement('div');
    fraudIndicator.className = 'alert alert-info d-flex align-items-center mt-2';
    fraudIndicator.innerHTML = `
        <i class="bi bi-cpu me-2"></i>
        <small>Real-time fraud detection monitoring this transaction</small>
    `;
    
    // Insert before submit button
    const submitButton = form.querySelector('button[type="submit"]');
    if (submitButton) {
        submitButton.parentElement.insertBefore(sslIndicator, submitButton);
        submitButton.parentElement.insertBefore(fraudIndicator, submitButton);
    }
}

// Admin dashboard enhancements
function initializeAdminDashboard() {
    // Add real-time updates simulation
    if (window.location.pathname.includes('/admin')) {
        setInterval(function() {
            updateTransactionCounts();
        }, 30000); // Update every 30 seconds
    }
}

// Simulate real-time transaction count updates
function updateTransactionCounts() {
    const statNumbers = document.querySelectorAll('.stat-number');
    statNumbers.forEach(function(stat) {
        const currentValue = parseInt(stat.textContent);
        // Simulate small random increases
        if (Math.random() > 0.7) {
            stat.textContent = currentValue + Math.floor(Math.random() * 3);
            
            // Add flash effect
            stat.style.background = 'rgba(37, 99, 235, 0.1)';
            setTimeout(function() {
                stat.style.background = 'transparent';
            }, 1000);
        }
    });
}

// Utility functions
function showNotification(message, type = 'info') {
    const notification = document.createElement('div');
    notification.className = `alert alert-${type} alert-dismissible fade show position-fixed`;
    notification.style.cssText = 'top: 20px; right: 20px; z-index: 9999; min-width: 300px;';
    notification.innerHTML = `
        ${message}
        <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
    `;
    
    document.body.appendChild(notification);
    
    // Auto-remove after 5 seconds
    setTimeout(function() {
        if (notification.parentElement) {
            notification.remove();
        }
    }, 5000);
}

function formatCurrency(amount) {
    return new Intl.NumberFormat('en-US', {
        style: 'currency',
        currency: 'USD'
    }).format(amount);
}

function formatDate(dateString) {
    return new Intl.DateTimeFormat('en-US', {
        year: 'numeric',
        month: 'short',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit'
    }).format(new Date(dateString));
}

// Initialize components based on current page
document.addEventListener('DOMContentLoaded', function() {
    initializeTransactionForm();
    initializeAdminDashboard();
});
