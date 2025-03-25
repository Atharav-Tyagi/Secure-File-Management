#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define MAX_USERS 5
#define MAX_FILENAME 256
#define LOG_FILE "security_log.txt"
#define ENCRYPTION_KEY "MySecretKey123"

typedef struct {
    char username[50];
    char password[50];
} User;

User users[MAX_USERS] = {
    {"admin", "admin123"},
    {"user1", "password1"},
};

int generate_otp() {
    srand(time(NULL));
    return (rand() % 9000) + 1000;
}

void log_event(const char *event) {
    FILE *log = fopen(LOG_FILE, "a");
    if (log == NULL) {
        printf("Error: Cannot open log file.\n");
        return;
    }
    time_t now;
    time(&now);
    fprintf(log, "[%s] %s\n", ctime(&now), event);
    fclose(log);
}

int authenticate() {
    char username[50], password[50];
    int otp, entered_otp;

    printf("\n--- Secure File Management System ---\n");
    printf("Enter Username: ");
    scanf("%s", username);
    printf("Enter Password: ");
    scanf("%s", password);

    int authenticated = 0;
    for (int i = 0; i < MAX_USERS; i++) {
        if (strcmp(users[i].username, username) == 0 && strcmp(users[i].password, password) == 0) {
            authenticated = 1;
            break;
        }
    }

    if (!authenticated) {
        log_event("Unauthorized login attempt detected.");
        printf("Invalid username or password! Access denied.\n");
        return 0;
    }

    otp = generate_otp();
    printf("\nYour OTP is: %d\n", otp);
    printf("Enter OTP: ");
    scanf("%d", &entered_otp);

    if (entered_otp != otp) {
        log_event("Failed OTP authentication attempt.");
        printf("Incorrect OTP! Access denied.\n");
        return 0;
    }

    log_event("User successfully authenticated.");
    printf("Login Successful!\n");
    return 1;
}

void log_activity(const char *username, const char *action, const char *filename) {
    FILE *log_file = fopen("activity.log", "a");
    if (!log_file) return;
    time_t now = time(NULL);
    fprintf(log_file, "%s - User: %s, Action: %s, File: %s\n", ctime(&now), username, action, filename);
    fclose(log_file);
}

void xor_encrypt_decrypt(const char *input_filename, const char *output_filename, const char *username) {
    FILE *input_file = fopen(input_filename, "rb");
    if (!input_file) {
        printf("File not found: %s\n", input_filename);
        return;
    }
    
    FILE *output_file = fopen(output_filename, "wb");
    if (!output_file) {
        printf("Error creating file: %s\n", output_filename);
        fclose(input_file);
        return;
    }
    
    unsigned char buffer[BUFFER_SIZE];
    size_t bytesRead;
    while ((bytesRead = fread(buffer, 1, BUFFER_SIZE, input_file)) > 0) {
        for (size_t i = 0; i < bytesRead; i++) {
            buffer[i] ^= XOR_KEY; 
        }
        fwrite(buffer, 1, bytesRead, output_file);
    }
    
    fclose(input_file);
    fclose(output_file);
    log_activity(username, "Encrypted/Decrypted", output_filename);
    printf("Operation completed successfully: %s -> %s\n", input_filename, output_filename);
}

int authenticate(char *logged_in_user) {
    char username[50], password[50];
    printf("Enter username: ");
    scanf("%s", username);
    printf("Enter password: ");
    scanf("%s", password);
    
    for (int i = 0; i < user_count; i++) {
        if (strcmp(users[i].username, username) == 0 && strcmp(users[i].password, password) == 0) {
            printf("Login successful!\n");
            strcpy(logged_in_user, username);
            return 1;
        }
    }
    printf("Invalid credentials!\n");
    return 0;
}

void secure_delete(const char *filename) {
    FILE *file = fopen(filename, "wb");
    if (!file) {
        printf("File not found: %s\n", filename);
        return;
    }
    char wipe[BUFFER_SIZE];
    memset(wipe, 0, BUFFER_SIZE);
    for (int i = 0; i < 3; i++) { 
        fwrite(wipe, 1, BUFFER_SIZE, file);
    }
    fclose(file);
    remove(filename);
    printf("File securely deleted: %s\n", filename);
}

void menu(const char *username) {
    int choice;
    char filename[MAX_FILENAME], output_filename[MAX_FILENAME];
    while (1) {
        printf("\nSecure File Management System\n");
        printf("1. Encrypt File\n");
        printf("2. Decrypt File\n");
        printf("3. Securely Delete File\n");
        printf("4. Exit\n");
        printf("Enter choice: ");
        scanf("%d", &choice);
        
        switch (choice) {
            case 1:
                printf("Enter filename to encrypt: ");
                scanf("%s", filename);
                xor_encrypt_decrypt(filename, "encrypted.dat", username);
                break;
            case 2:
                printf("Enter output filename for decrypted file: ");
                scanf("%s", output_filename);
                xor_encrypt_decrypt("encrypted.dat", output_filename, username);
                break;
            case 3:
                printf("Enter filename to securely delete: ");
                scanf("%s", filename);
                secure_delete(filename);
                break;
            case 4:
                exit(0);
            default:
                printf("Invalid choice!\n");
        }
    }
}

int main() {
    char logged_in_user[50];
    if (authenticate(logged_in_user)) {
        menu(logged_in_user);
    }
    return 0;
}
