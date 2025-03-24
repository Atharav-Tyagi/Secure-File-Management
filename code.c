#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>

#define MAX_USERS 10
#define MAX_FILENAME 100
#define BUFFER_SIZE 1024
#define XOR_KEY 0x5A // Simple XOR encryption key

typedef struct {
    char username[50];
    char password[50];
} User;

User users[MAX_USERS] = { {"admin", "admin123"} };
int user_count = 1;

void log_activity(const char *username, const char *action, const char *filename) {
    FILE *log_file = fopen("activity.log", "a");
    if (!log_file) return;
    time_t now = time(NULL);
    fprintf(log_file, "%s - User: %s, Action: %s, File: %s\n", ctime(&now), username, action, filename);
    fclose(log_file);
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
                break;
            case 2:
                printf("Enter output filename for decrypted file: ");
                break;
            case 3:
                printf("Enter filename to securely delete: ");
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
