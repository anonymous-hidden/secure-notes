# 🔐 SecureNotes

A comprehensive, security-focused note-taking application with advanced enterprise-grade security features including Two-Factor Authentication, session management, threat detection, and post-quantum cryptography preparations.

## 🌟 Features

### Core Functionality
- **Encrypted Note Storage**: Military-grade AES encryption with Fernet and ChaCha20Poly1305
- **Rich Text Editing**: Full formatting support (bold, italic, underline, colors, fonts)
- **Multi-Note Management**: Organize notes with categories and advanced search
- **Auto-Save**: Configurable automatic saving every 30 seconds
- **Backup System**: Automatic backups with configurable retention
- **Import/Export**: Support for various file formats

### 🛡️ Advanced Security Features

#### 1. **Two-Factor Authentication (2FA/MFA)**
- TOTP-based authentication with QR code generation
- Authenticator app support (Google Authenticator, Authy, etc.)
- Backup recovery codes
- Rate limiting for 2FA attempts
- Complete 2FA management interface

#### 2. **Session Management & Auto-Lock**
- Configurable session timeouts (30 minutes default)
- Automatic lock after inactivity
- Session token management
- Real-time activity monitoring

#### 3. **Password Security**
- Integration with HaveIBeenPwned API for breach detection
- Enhanced password strength validation (12+ characters, complexity requirements)
- Real-time breach warnings during registration/login
- Secure password hashing with PBKDF2 (300,000 iterations)

#### 4. **Advanced Audit & Monitoring**
- Comprehensive security event logging
- Failed login attempt tracking with automatic lockout
- Rate limiting (5 attempts, 15-minute lockout)
- Security event viewer and export capabilities
- Timeline reconstruction for forensic analysis

#### 5. **Threat Detection & Response**
- Suspicious process monitoring
- Anomaly detection in user behavior
- Memory dump detection and prevention
- Real-time threat alerts and notifications

#### 6. **Post-Quantum Cryptography Readiness**
- Enhanced RSA keys (4096-bit) as transitional measure
- Framework prepared for future PQC algorithm integration
- Advanced asymmetric encryption capabilities

#### 7. **Compliance & Governance**
- Role-Based Access Control (RBAC)
- Data retention policies
- Compliance reporting (SOX, GDPR, HIPAA ready)
- Comprehensive audit trail generation

#### 8. **Anti-Forensics & Privacy Protection**
- Secure memory allocation and management
- Secure deletion with multiple overwrites
- Memory encryption capabilities
- Runtime protection measures
- Process isolation and sandboxing

#### 9. **Enterprise Features**
- HSM (Hardware Security Module) integration support
- Production/development mode configurations
- Encrypted security event logs
- Advanced compliance reporting
- Enterprise-grade session management

## 📋 Requirements

### System Requirements
- **Operating System**: Windows, macOS, or Linux
- **Python**: 3.8 or higher
- **RAM**: Minimum 512MB, Recommended 2GB+
- **Storage**: 50MB for application + space for encrypted notes

### Dependencies
```bash
pip install cryptography pillow pyotp qrcode[pil] requests psutil pycryptodome
