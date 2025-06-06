#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>          // Para sockets en Windows
#include <windows.h>           // Para hilos y sincronizacion en Windows
#include <process.h>           // Para _beginthread
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/err.h> 
#include "../includes/common.h"

// Parametros del servidor
#define PORT 4444
#define MAX_CLIENTS 10

// Base de datos de usuarios (array estatico)
UserReg usuarios[MAX_USERS];
int num_usuarios = 0;

// Proteccion para accesos concurrentes (varios hilos)
CRITICAL_SECTION cs;

// Prototipos de funciones
void handle_client(void *arg);
int save_user(UserReg *u);
RSA* load_public_key(const char *dni);
int decrypt_and_store(const unsigned char *cipher, int cipherlen, const unsigned char *sym_key, const unsigned char *iv, UserData *out);

int main() {
    WSADATA wsa;
    SOCKET server, client;
    struct sockaddr_in server_addr, client_addr;
    int client_len = sizeof(client_addr);

    // Inicializa sockets de Windows
    WSAStartup(MAKEWORD(2,2), &wsa);
    server = socket(AF_INET, SOCK_STREAM, 0);

    // Configura el servidor
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);

    bind(server, (struct sockaddr*)&server_addr, sizeof(server_addr));
    listen(server, MAX_CLIENTS);

    InitializeCriticalSection(&cs); // Para proteger el array de usuarios
    printf("Server ready on port %d...\n", PORT);

    // Bucle principal: acepta conexiones de clientes
    while(1) {
        client = accept(server, (struct sockaddr*)&client_addr, &client_len);
        if (client != INVALID_SOCKET) {
            // Reserva memoria para el socket del cliente
            SOCKET *pclient = malloc(sizeof(SOCKET));
            *pclient = client;
            // Crea un hilo para cada cliente
            _beginthread(handle_client, 0, pclient);
        }
    }
    DeleteCriticalSection(&cs);
    closesocket(server);
    WSACleanup();
    return 0;
}

void handle_client(void *arg) {
    SOCKET client = *((SOCKET*)arg);
    free(arg);
    char dni[MAX_DNI];
    int received;

    printf("Hilo cliente iniciado\n");

    // Paso 1: Recibe el DNI del cliente
    received = recv(client, dni, sizeof(dni), 0);
    if (received <= 0) { printf("Fallo en recv DNI\n"); closesocket(client); _endthread(); return; }
    dni[received] = '\0';
    printf("DNI recibido: %s\n", dni);

    // Paso 2: Carga la clave publica del usuario
    RSA *rsa_pub = load_public_key(dni);
    if (!rsa_pub) {
        printf("No se encontro la clave publica para %s\n", dni);
        closesocket(client); _endthread(); return;
    }
    printf("Clave publica cargada\n");

    // Paso 3: Genera clave simetrica y IV
    unsigned char sym_key[SYM_KEY_LEN], iv[IV_LEN];
    if (RAND_bytes(sym_key, SYM_KEY_LEN) != 1) { printf("Fallo en RAND_bytes (key)\n"); closesocket(client); _endthread(); return; }
    if (RAND_bytes(iv, IV_LEN) != 1) { printf("Fallo en RAND_bytes (iv)\n"); closesocket(client); _endthread(); return; }
    printf("Clave simetrica e IV generados\n");

    // Paso 4: Cifra la clave simetrica y el IV
    unsigned char enc_key[256], enc_iv[256];
    int enc_key_len = RSA_public_encrypt(SYM_KEY_LEN, sym_key, enc_key, rsa_pub, RSA_PKCS1_OAEP_PADDING);
    int enc_iv_len = RSA_public_encrypt(IV_LEN, iv, enc_iv, rsa_pub, RSA_PKCS1_OAEP_PADDING);
    RSA_free(rsa_pub);

    if (enc_key_len == -1 || enc_iv_len == -1) {
        printf("Fallo en RSA_public_encrypt\n");
        closesocket(client); _endthread(); return;
    }
    printf("Clave simetrica cifrada\n");

    // Paso 5: Envia clave e IV cifrados
    send(client, (char*)&enc_key_len, sizeof(int), 0);
    send(client, (char*)enc_key, enc_key_len, 0);
    send(client, (char*)&enc_iv_len, sizeof(int), 0);
    send(client, (char*)enc_iv, enc_iv_len, 0);
    printf("Clave e IV enviados al cliente\n");

    // Paso 6: Recibe datos cifrados de usuario
    int cipherlen;
    received = recv(client, (char*)&cipherlen, sizeof(int), 0);
    if (received != sizeof(int)) { printf("Fallo en recv(cipherlen)\n"); closesocket(client); _endthread(); return; }
    unsigned char *cipher = malloc(cipherlen);
    if (!cipher) { printf("Fallo en malloc(cipher)\n"); closesocket(client); _endthread(); return; }
    received = recv(client, (char*)cipher, cipherlen, 0);
    if (received != cipherlen) { printf("Fallo en recv(cipher)\n"); free(cipher); closesocket(client); _endthread(); return; }
    printf("Datos cifrados recibidos\n");

    // Paso 7: Descifra datos usuario
    UserData user;
    if (decrypt_and_store(cipher, cipherlen, sym_key, iv, &user) != 0) {
        free(cipher);
        printf("Fallo en decrypt_and_store\n");
        closesocket(client); _endthread(); return;
    }
    printf("Datos usuario descifrados\n");
    free(cipher);

    // Paso 8: Guarda el usuario
    UserReg reg;
    reg.data = user;
    memcpy(reg.sym_key, sym_key, SYM_KEY_LEN);
    memcpy(reg.iv, iv, IV_LEN);

    EnterCriticalSection(&cs);
    save_user(&reg);
    LeaveCriticalSection(&cs);
    printf("Usuario guardado\n");

    // Paso 9: Confirma registro
    const char *msg = "Registration complete\n";
    send(client, msg, strlen(msg), 0);

    printf("Hilo cliente terminado\n");
    closesocket(client);
    _endthread();
}

// Guarda un usuario en el array (puedes agregar ordenacion aqui si quieres)
int save_user(UserReg *u) {
    if (num_usuarios >= MAX_USERS) return -1;
    usuarios[num_usuarios++] = *u;
    return 0;
}

// Carga la clave publica RSA del usuario a partir de su DNI
RSA* load_public_key(const char *dni) {
    char path[256];
    sprintf(path, "keys/users_public_keys/%s_public.pem", dni);
    printf("Intentando abrir archivo de clave publica: %s\n", path);
    FILE *fp = fopen(path, "r");
    if (!fp) {
        printf("No se pudo abrir el archivo %s\n", path);
        return NULL;
    }

    // PRIMERO intenta el formato moderno (BEGIN PUBLIC KEY)
    EVP_PKEY *evp_key = PEM_read_PUBKEY(fp, NULL, NULL, NULL);
    if (evp_key) {
        RSA *rsa = EVP_PKEY_get1_RSA(evp_key);
        EVP_PKEY_free(evp_key);
        fclose(fp);
        if (!rsa) {
            printf("No se pudo extraer RSA de la clave publica (EVP)\n");
            return NULL;
        }
        printf("Clave publica cargada correctamente (PUBKEY)\n");
        return rsa;
    }
    // Si no, intenta el formato antiguo (BEGIN RSA PUBLIC KEY)
    fseek(fp, 0, SEEK_SET); // vuelve al principio del archivo
    RSA *rsa = PEM_read_RSA_PUBKEY(fp, NULL, NULL, NULL);
    fclose(fp);
    if (!rsa) {
        printf("No se pudo leer la clave publica (ni PUBKEY ni RSA PUBKEY). Error OpenSSL:\n");
        ERR_print_errors_fp(stderr);
        return NULL;
    }
    printf("Clave publica cargada correctamente (RSA_PUBKEY)\n");
    return rsa;
}

// Descifra los datos del usuario recibidos usando AES-256-CBC
int decrypt_and_store(const unsigned char *cipher, int cipherlen, const unsigned char *sym_key, const unsigned char *iv, UserData *out) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int pt_len, final_len;
    unsigned char plaintext[sizeof(UserData)+16];

    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, sym_key, iv);
    EVP_DecryptUpdate(ctx, plaintext, &pt_len, cipher, cipherlen);
    EVP_DecryptFinal_ex(ctx, plaintext + pt_len, &final_len);
    EVP_CIPHER_CTX_free(ctx);

    memcpy(out, plaintext, sizeof(UserData)); // Copia los datos descifrados a la estructura
    return 0;
}
