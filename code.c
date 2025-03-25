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

void xor_encrypt_decrypt(const char *input_file, const char *output_file) {
    FILE *input = fopen(input_file, "rb");
    if (!input) {
        printf("Error: Cannot open file.\n");
        return;
    }

    FILE *output = fopen(output_file, "wb");
    if (!output) {
        fclose(input);
        printf("Error: Cannot create output file.\n");
        return;
    }

    char key[] = ENCRYPTION_KEY;
    int key_len = strlen(key);
    char buffer;
    int i = 0;

    while (fread(&buffer, 1, 1, input) == 1) {
        buffer ^= key[i % key_len];
        fwrite(&buffer, 1, 1, output);
        i++;
    }

    fclose(input);
    fclose(output);

    log_event("File encrypted/decrypted successfully.");
    printf("Operation completed successfully: %s\n", output_file);
}

void secure_delete(const char *filename) {
    FILE *file = fopen(filename, "rb+");
    if (!file) {
        printf("Error: Cannot open file for deletion.\n");
        return;
    }

    fseek(file, 0, SEEK_END);
    long size = ftell(file);
    fseek(file, 0, SEEK_SET);

    for (int pass = 0; pass < 5; pass++) {
        fseek(file, 0, SEEK_SET);
        for (long i = 0; i < size; i++) {
            fputc(rand() % 256, file);
        }
        fflush(file);
    }

    fclose(file);
    remove(filename);

    log_event("File securely deleted.");
    printf("File securely deleted!\n");
}

void view_logs() {
    FILE *log = fopen(LOG_FILE, "r");
    if (!log) {
        printf("No logs available.\n");
        return;
    }

    printf("\n--- Security Logs ---\n");
    char line[256];
    while (fgets(line, sizeof(line), log)) {
        printf("%s", line);
    }
    fclose(log);
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
