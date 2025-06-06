#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include "../includes/common.h"

// Funcion para cifrar los datos del usuario con AES-256-CBC
int encrypt_userdata(const UserData *ud, unsigned char *key, unsigned char *iv, unsigned char *cipher, int *cipherlen);

#define SERVER_IP "127.0.0.1"
#define PORT 4444

int main() {
    WSADATA wsa;
    SOCKET sock;
    struct sockaddr_in server;
    char dni[MAX_DNI];
    unsigned char sym_key[SYM_KEY_LEN], iv[IV_LEN];

    // Inicializa sockets en Windows
    WSAStartup(MAKEWORD(2,2), &wsa);
    sock = socket(AF_INET, SOCK_STREAM, 0);

    // Configura datos del servidor
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = inet_addr(SERVER_IP);
    server.sin_port = htons(PORT);

    connect(sock, (struct sockaddr*)&server, sizeof(server));

    // Paso 1: Solicita y envia DNI
    printf("Enter your DNI: ");
    fgets(dni, sizeof(dni), stdin);
    dni[strcspn(dni, "\n")] = 0; // Quita salto de linea
    send(sock, dni, strlen(dni), 0);

    // Paso 2: Recibe la clave simetrica y IV cifrados, los descifra con su clave privada
    int enc_key_len, enc_iv_len;
    recv(sock, (char*)&enc_key_len, sizeof(int), 0);
    unsigned char enc_key[256];
    recv(sock, (char*)enc_key, enc_key_len, 0);

    recv(sock, (char*)&enc_iv_len, sizeof(int), 0);
    unsigned char enc_iv[256];
    recv(sock, (char*)enc_iv, enc_iv_len, 0);

    // Carga clave privada desde archivo
    FILE *fp = fopen("keys/cliente_private.pem", "r");
    RSA *rsa_priv = PEM_read_RSAPrivateKey(fp, NULL, NULL, NULL);
    fclose(fp);
    RSA_private_decrypt(enc_key_len, enc_key, sym_key, rsa_priv, RSA_PKCS1_OAEP_PADDING);
    RSA_private_decrypt(enc_iv_len, enc_iv, iv, rsa_priv, RSA_PKCS1_OAEP_PADDING);
    RSA_free(rsa_priv);

    // Paso 3: Solicita los datos personales al usuario
    UserData u;
    strcpy(u.dni, dni);
    printf("Name: "); fgets(u.name, MAX_NAME, stdin); u.name[strcspn(u.name, "\n")] = 0;
    printf("Surname: "); fgets(u.surname, MAX_NAME, stdin); u.surname[strcspn(u.surname, "\n")] = 0;
    printf("Address: "); fgets(u.address, MAX_ADDR, stdin); u.address[strcspn(u.address, "\n")] = 0;
    printf("Postal code: "); fgets(u.postal_code, MAX_CP, stdin); u.postal_code[strcspn(u.postal_code, "\n")] = 0;

    // Paso 4: Cifra los datos personales usando AES-256-CBC
    unsigned char cipher[sizeof(UserData)+16];
    int cipherlen;
    encrypt_userdata(&u, sym_key, iv, cipher, &cipherlen);

    // Paso 5: Envia el tamano y los datos cifrados al servidor
    send(sock, (char*)&cipherlen, sizeof(int), 0);
    send(sock, (char*)cipher, cipherlen, 0);

    // Paso 6: Recibe confirmacion del servidor
    char buffer[256];
    int recvd = recv(sock, buffer, sizeof(buffer), 0);
    if (recvd > 0) {
        buffer[recvd] = 0;
        printf("Server: %s\n", buffer);
    }

    closesocket(sock);
    WSACleanup();
    return 0;
}

// Cifra los datos de usuario usando AES-256-CBC
int encrypt_userdata(const UserData *ud, unsigned char *key, unsigned char *iv, unsigned char *cipher, int *cipherlen) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len, total_len=0, final_len;

    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);
    EVP_EncryptUpdate(ctx, cipher, &len, (unsigned char*)ud, sizeof(UserData));
    total_len = len;
    EVP_EncryptFinal_ex(ctx, cipher+len, &final_len);
    total_len += final_len;
    EVP_CIPHER_CTX_free(ctx);
    *cipherlen = total_len;
    return 0;
}
