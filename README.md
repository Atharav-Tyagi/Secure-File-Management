Secure File Management System 🔒
Overview
The Secure File Management System is a C-based application that provides file encryption, decryption, secure deletion, authentication, and activity logging to enhance file security.

Features
🔐 User Authentication – Ensures only authorized users can access the system.

🔑 File Encryption & Decryption – Secures files using XOR-based encryption.

🗑 Secure File Deletion – Overwrites files before deletion to prevent recovery.

📜 Activity Logging – Tracks all file operations for monitoring and security.

✅ File Integrity Check – Detects unauthorized modifications.

🔒 Access Control – Restricts unauthorized file access.

Technologies Used
Programming Language: C

Encryption Method: XOR-based encryption

File Handling: Standard C File I/O

Logging System: Activity logging with timestamps

Authentication: Username-password-based login

Installation & Usage
1️⃣ Clone the Repository
git clone https://github.com/Atharav-Tyagi/Secure-File-Management.git
cd Secure-File-Management-System
2️⃣ Compile the Code
gcc code.c -o secure_file_manager
3️⃣ Run the Program
./secure_file_manager

How to Use?
User Authentication
Enter your username & password to access the system.

Default admin credentials: admin/admin123 (can be changed).

File Encryption & Decryption
Encrypt a file securely.

Decrypt the file to restore original data.

Secure File Deletion
Overwrites the file multiple times before deletion.

Activity Logging
Every action is logged in activity.log for monitoring.

Future Enhancements
🔹 Upgrade to AES encryption for better security.

🔹 Implement multi-factor authentication (MFA).

🔹 Add GUI support using a web-based interface.

🔹 Introduce secure cloud file storage integration.

GitHub Repository
Secure File Management System

