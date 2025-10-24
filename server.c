
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>
#include <windows.h>

#pragma comment(lib, "ws2_32.lib")

#define SERVER_PORT 12345
#define MAX_BUFFER_SIZE 1024

const char xorKey[] = "sanjana2025"; // simple XOR key for demonstration

volatile LONG serverRunning = 1;
SOCKET listenSocket = INVALID_SOCKET;

// Function declarations
void xorEncryptDecrypt(const unsigned char *input, int length, const char *key, unsigned char *output);
DWORD WINAPI clientHandler(LPVOID arg);
int initializeWinsock(void);
SOCKET createServerSocket(int port);
BOOL WINAPI consoleEventHandler(DWORD ctrlType);

int main(void) {
    printf("Starting TCP server...\n");

    // Register console Control handler for shutdown
    SetConsoleCtrlHandler(consoleEventHandler, TRUE);

    
    if (initializeWinsock() != 0) {
        fprintf(stderr, "Failed to initialize Winsock.\n");
        return 1;
    }

    // server socket
    listenSocket = createServerSocket(SERVER_PORT);
    if (listenSocket == INVALID_SOCKET) {
        fprintf(stderr, "Failed to start server on port %d\n", SERVER_PORT);
        WSACleanup();
        return 1;
    }
    printf("Server is running on port %d\n", SERVER_PORT);

    while (InterlockedCompareExchange(&serverRunning, 1, 1)) {
        SOCKADDR_IN clientAddr;
        int addrLen = sizeof(clientAddr);

        SOCKET clientSock = accept(listenSocket, (struct sockaddr *)&clientAddr, &addrLen);
        if (clientSock == INVALID_SOCKET) {
            if (!serverRunning) break;
            Sleep(100);
            continue;
        }

        printf("New client is connected: %s:%d\n",
               inet_ntoa(clientAddr.sin_addr), ntohs(clientAddr.sin_port));

        SOCKET *clientPtr = malloc(sizeof(SOCKET));
        if (!clientPtr) {
            fprintf(stderr, "Memory allocation is failed for client socket \n");
            closesocket(clientSock);
            continue;
        }
        *clientPtr = clientSock;

        HANDLE thread = CreateThread(NULL, 0, clientHandler, clientPtr, 0, NULL);
        if (!thread) {
            fprintf(stderr, "Failed to create thread for clientc \n");
            closesocket(clientSock);
            free(clientPtr);
            continue;
        }
        CloseHandle(thread);
    }

    printf("Server is shutting down..\n");
    if (listenSocket != INVALID_SOCKET) closesocket(listenSocket);
    WSACleanup();
    return 0;
}

// Handling each client
DWORD WINAPI clientHandler(LPVOID arg) {
    SOCKET clientSock = *(SOCKET *)arg;
    free(arg);

    unsigned char recvBuffer[MAX_BUFFER_SIZE];
    unsigned char decrypted[MAX_BUFFER_SIZE];
    unsigned char encrypted[MAX_BUFFER_SIZE];

    while (1) {
        int bytesReceived = recv(clientSock, (char *)recvBuffer, MAX_BUFFER_SIZE, 0);
        if (bytesReceived <= 0) break;

        xorEncryptDecrypt(recvBuffer, bytesReceived, xorKey, decrypted);
        decrypted[bytesReceived < MAX_BUFFER_SIZE ? bytesReceived : MAX_BUFFER_SIZE - 1] = '\0';

        printf("Received from client : %s\n", decrypted);

        if (strncmp((char *)decrypted, "quit", 4) == 0) {
            const char *byeMsg = "Server:   Goodbye!";
            xorEncryptDecrypt((const unsigned char *)byeMsg, (int)strlen(byeMsg), xorKey, encrypted);
            send(clientSock, (const char *)encrypted, (int)strlen(byeMsg), 0);
            break;
        }

        const char *ack = "Server: Message has received successfully.";
        int ackLen = (int)strlen(ack);
        xorEncryptDecrypt((const unsigned char *)ack, ackLen, xorKey, encrypted);
        send(clientSock, (const char *)encrypted, ackLen, 0);
    }

    closesocket(clientSock);
    printf("Client disconnected \n");
    return 0;
}

// XOR encryption and decryption function
void xorEncryptDecrypt(const unsigned char *input, int length, const char *key, unsigned char *output) {
    int keyLength = (int)strlen(key);
    for (int i = 0; i < length; ++i) {
        output[i] = input[i] ^ key[i % keyLength];
    }
}

// Winsock
int initializeWinsock(void) {
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        fprintf(stderr, "WSAStartup failed \n");
        return -1;
    }
    return 0;
}

// server socket
SOCKET createServerSocket(int port) {
    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) return INVALID_SOCKET;

    SOCKADDR_IN serverAddr = {0};
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(port);
    serverAddr.sin_addr.s_addr = INADDR_ANY;

    if (bind(sock, (struct sockaddr *)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
        closesocket(sock);
        return INVALID_SOCKET;
    }
    if (listen(sock, SOMAXCONN) == SOCKET_ERROR) {
        closesocket(sock);
        return INVALID_SOCKET;
    }
    return sock;
}

// Handle Control +C and console closes
BOOL WINAPI consoleEventHandler(DWORD ctrlType) {
    if (ctrlType == CTRL_C_EVENT || ctrlType == CTRL_CLOSE_EVENT) {
        printf("\n server shutdown triggered \n");
        InterlockedExchange(&serverRunning, 0);
        if (listenSocket != INVALID_SOCKET) closesocket(listenSocket);
        return TRUE;
    }
    return FALSE;
}
