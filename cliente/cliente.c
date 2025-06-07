#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#define MAXLEN 4096

#pragma comment(lib, "ws2_32.lib")

// ---- FUNCIÓN DE CIFRADO AES ----
int cifrar_AES_256_CBC(const unsigned char *plaintext, int plaintext_len,
                       const unsigned char *key, const unsigned char *iv,
                       unsigned char *ciphertext) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len, ciphertext_len;
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);
    EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len);
    ciphertext_len = len;
    EVP_EncryptFinal_ex(ctx, ciphertext + len, &len);
    ciphertext_len += len;
    EVP_CIPHER_CTX_free(ctx);
    return ciphertext_len;
}

// ---- FUNCIÓN AUXILIAR PARA QUITAR \n ----
void quitar_newline(char *str) {
    size_t l = strlen(str);
    if(l > 0 && str[l-1] == '\n') str[l-1] = '\0';
}

int main() {
    // Inicializa WinSock
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2,2), &wsa) != 0) {
        printf("Error en WSAStartup\n");
        return 1;
    }

    // Crea socket
    SOCKET server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd == INVALID_SOCKET) {
        printf("No se pudo crear el socket\n");
        WSACleanup();
        return 1;
    }

    struct sockaddr_in server_addr;
    server_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(4444);

    // Conecta al servidor
    if (connect(server_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        printf("No se pudo conectar al servidor\n");
        closesocket(server_fd);
        WSACleanup();
        return 1;
    }
    printf("Conectado al servidor\n");

    ERR_load_crypto_strings();

    char dni[32];
    printf("Enter your DNI: ");
    scanf("%31s", dni);
    getchar(); // Limpiar buffer

    // 1. Enviar DNI al servidor
    if (send(server_fd, dni, strlen(dni), 0) <= 0) {
        printf("Error enviando DNI\n");
        closesocket(server_fd);
        WSACleanup();
        return 1;
    }
    printf("DNI enviado, esperando clave simetrica cifrada\n");

    // 2. Recibir longitud de clave simétrica cifrada
    int enc_sym_len = 0;
    int r = recv(server_fd, (char*)&enc_sym_len, sizeof(int), 0);
    printf("Resultado de recv(enc_sym_len): %d\n", r);
    if (r <= 0) {
        printf("Fallo en recv(enc_sym_len)\n");
        closesocket(server_fd);
        WSACleanup();
        return 1;
    }
    printf("Longitud clave simétrica cifrada recibida: %d\n", enc_sym_len);

    // 3. Recibir clave simétrica cifrada
    unsigned char enc_sym[MAXLEN] = {0};
    r = recv(server_fd, (char*)enc_sym, enc_sym_len, 0);
    printf("Resultado de recv(enc_sym): %d\n", r);
    if (r <= 0) {
        printf("Fallo en recv(enc_sym)\n");
        closesocket(server_fd);
        WSACleanup();
        return 1;
    }
    printf("Clave simétrica cifrada recibida\n");

    // 4. Recibir longitud de IV cifrado
    int enc_iv_len = 0;
    r = recv(server_fd, (char*)&enc_iv_len, sizeof(int), 0);
    printf("Resultado de recv(enc_iv_len): %d\n", r);
    if (r <= 0) {
        printf("Fallo en recv(enc_iv_len)\n");
        closesocket(server_fd);
        WSACleanup();
        return 1;
    }
    printf("Longitud IV cifrado recibida: %d\n", enc_iv_len);

    // 5. Recibir IV cifrado
    unsigned char enc_iv[MAXLEN] = {0};
    r = recv(server_fd, (char*)enc_iv, enc_iv_len, 0);
    printf("Resultado de recv(enc_iv): %d\n", r);
    if (r <= 0) {
        printf("Fallo en recv(enc_iv)\n");
        closesocket(server_fd);
        WSACleanup();
        return 1;
    }
    printf("IV cifrado recibido\n");

    // ----- DESCIFRAR CLAVE SIMÉTRICA E IV -----
    printf("Cargando clave privada del cliente\n");
    FILE *fp = fopen("keys/cliente_private.pem", "rb");
    if (!fp) {
        printf("No se pudo abrir la clave privada\n");
        closesocket(server_fd);
        WSACleanup();
        return 1;
    }

    // Lee todo el archivo en memoria
    fseek(fp, 0, SEEK_END);
    long len = ftell(fp);
    rewind(fp);
    char *key_data = malloc(len + 1);
    if (!key_data) {
        printf("No se pudo reservar memoria para la clave\n");
        fclose(fp);
        closesocket(server_fd);
        WSACleanup();
        return 1;
    }
    fread(key_data, 1, len, fp);
    key_data[len] = '\0';
    fclose(fp);

    // Usa un BIO en memoria
    BIO *bio = BIO_new_mem_buf(key_data, -1);
    EVP_PKEY *pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
    BIO_free(bio);
    free(key_data);

    if (!pkey) {
        printf("No se pudo leer la clave privada (BIO PKCS#8)\n");
        ERR_print_errors_fp(stderr);
        closesocket(server_fd);
        WSACleanup();
        return 1;
    }

    RSA *rsa_priv = EVP_PKEY_get1_RSA(pkey);
    EVP_PKEY_free(pkey);
    if (!rsa_priv) {
        printf("No se pudo extraer RSA de la clave privada\n");
        closesocket(server_fd);
        WSACleanup();
        return 1;
    }

    unsigned char sym_key[MAXLEN] = {0};
    int sym_key_len = RSA_private_decrypt(enc_sym_len, enc_sym, sym_key, rsa_priv, RSA_PKCS1_OAEP_PADDING);
    if (sym_key_len <= 0) {
        printf("Fallo en descifrado de clave simetrica\n");
        ERR_print_errors_fp(stderr);
        RSA_free(rsa_priv);
        closesocket(server_fd);
        WSACleanup();
        return 1;
    }
    printf("Clave simetrica descifrada correctamente\n");

    unsigned char iv[MAXLEN] = {0};
    int iv_len = RSA_private_decrypt(enc_iv_len, enc_iv, iv, rsa_priv, RSA_PKCS1_OAEP_PADDING);
    RSA_free(rsa_priv);
    if (iv_len <= 0) {
        printf("Fallo en descifrado de IV\n");
        ERR_print_errors_fp(stderr);
        closesocket(server_fd);
        WSACleanup();
        return 1;
    }
    printf("IV descifrado correctamente\n");

    // ----- PREGUNTAR POR CAMPOS -----
    char nombre[64], apellidos[128], direccion[128], cod_postal[16], dni_campo[32];
    printf("Nombre: ");         fgets(nombre, sizeof(nombre), stdin); quitar_newline(nombre);
    printf("Apellidos: ");      fgets(apellidos, sizeof(apellidos), stdin); quitar_newline(apellidos);
    printf("Dirección: ");      fgets(direccion, sizeof(direccion), stdin); quitar_newline(direccion);
    printf("Código Postal: ");  fgets(cod_postal, sizeof(cod_postal), stdin); quitar_newline(cod_postal);
    printf("DNI: ");            fgets(dni_campo, sizeof(dni_campo), stdin); quitar_newline(dni_campo);

    // ----- CONCATENAR TODOS LOS CAMPOS -----
    char datos_usuario[512];
    snprintf(datos_usuario, sizeof(datos_usuario), "%s;%s;%s;%s;%s",
        nombre, apellidos, direccion, cod_postal, dni_campo);

    // CIFRAR LOS DATOS DEL USUARIO CON AES-256-CBC
    unsigned char datos_cifrados[MAXLEN];
    int datos_cifrados_len = cifrar_AES_256_CBC(
        (unsigned char*)datos_usuario, strlen(datos_usuario),
        sym_key, iv, datos_cifrados
    );

    // ENVIAR LONGITUD Y DATOS CIFRADOS AL SERVIDOR
    send(server_fd, (char*)&datos_cifrados_len, sizeof(int), 0);
    send(server_fd, (char*)datos_cifrados, datos_cifrados_len, 0);

    printf("Datos cifrados y enviados al servidor correctamente.\n");

    closesocket(server_fd);
    WSACleanup();
    return 0;
}
