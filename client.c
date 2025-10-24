
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>
#include <windows.h>

#pragma comment(lib, "ws2_32.lib")

#define SERVER_PORT 12345
#define DEFAULT_SERVER_IP "127.0.0.1"
#define MAX_BUFFER_SIZE 1024

const char xorKey[] = "sanjana2025";

//declaration
void xorEncryptDecrypt(const unsigned char *input, int length, const char *key, unsigned char *output);
int initializeWinsock(void);
SOCKET connectToServer(const char *ip, int port);

int main(void) {
    if (initializeWinsock() != 0) return 1;

    char serverIP[64];
    printf("Enter server IP [%s]: ", DEFAULT_SERVER_IP);
    if (!fgets(serverIP, sizeof(serverIP), stdin)) return 1;
    serverIP[strcspn(serverIP, "\r\n")] = 0; // remove newline
    if (serverIP[0] == '\0') strcpy(serverIP, DEFAULT_SERVER_IP);

    SOCKET sock = connectToServer(serverIP, SERVER_PORT);
    if (sock == INVALID_SOCKET) {
        fprintf(stderr, "Unable to connect to server.\n");
        WSACleanup();
        return 1;
    }

    char message[MAX_BUFFER_SIZE];
    unsigned char encrypted[MAX_BUFFER_SIZE];
    unsigned char recvBuffer[MAX_BUFFER_SIZE];
    unsigned char decrypted[MAX_BUFFER_SIZE];

    while (1) {
        printf("Enter message (type 'quit' to exit): ");
        if (!fgets(message, sizeof(message), stdin)) break;
        message[strcspn(message, "\r\n")] = 0; 

        int msgLen = (int)strlen(message);
        if (msgLen == 0) continue;

        // Encrypting and sending message
        xorEncryptDecrypt((const unsigned char *)message, msgLen, xorKey, encrypted);
        send(sock, (const char *)encrypted, msgLen, 0);

        // Receive and decrypt response
        int bytesReceived = recv(sock, (char *)recvBuffer, MAX_BUFFER_SIZE, 0);
        if (bytesReceived <= 0) break;
        xorEncryptDecrypt(recvBuffer, bytesReceived, xorKey, decrypted);
        decrypted[bytesReceived < MAX_BUFFER_SIZE ? bytesReceived : MAX_BUFFER_SIZE - 1] = '\0';

        printf("%s\n", decrypted);

        if (strcmp(message, "quit") == 0) break;
    }

    closesocket(sock);
    WSACleanup();
    printf("Disconnected from server \n");
    return 0;
}

// XOR encryption and decryption function
void xorEncryptDecrypt(const unsigned char *input, int length, const char *key, unsigned char *output) {
    int keyLength = (int)strlen(key);
    for (int i = 0; i < length; ++i) {
        output[i] = input[i] ^ key[i % keyLength];
    }
}

//  Winsock
int initializeWinsock(void) {
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        fprintf(stderr, "WSAStartup is failed\n");
        return -1;
    }
    return 0;
}

// Connecting to server
SOCKET connectToServer(const char *ip, int port) {
    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) return INVALID_SOCKET;

    SOCKADDR_IN serverAddr = {0};
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(port);
    serverAddr.sin_addr.s_addr = inet_addr(ip);

    if (connect(sock, (struct sockaddr *)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
        closesocket(sock);
        return INVALID_SOCKET;
    }

    printf("Connected to server %s:%d \n", ip, port);
    return sock;
}
