#include <stdio.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/err.h>

int main() {
    const char *path = "keys/users_public_keys/12345678A_public.pem";
    printf("Intentando abrir archivo de clave publica: %s\n", path);

    FILE *fp = fopen(path, "r");
    if (!fp) {
        printf("No se pudo abrir el archivo %s\n", path);
        return 1;
    }

    EVP_PKEY *evp_key = PEM_read_PUBKEY(fp, NULL, NULL, NULL);
    if (!evp_key) {
        printf("No se pudo leer la clave publica en %s (PEM_read_PUBKEY fallo)\n", path);
        ERR_print_errors_fp(stderr);  
        fclose(fp);
        return 1;
    }
    RSA *rsa = EVP_PKEY_get1_RSA(evp_key);
    EVP_PKEY_free(evp_key);
    if (!rsa) {
        printf("No se pudo extraer RSA de la clave publica\n");
        ERR_print_errors_fp(stderr);
        return 1;
    }
    printf("Clave publica cargada correctamente (¡TODO OK!)\n");
    RSA_free(rsa);
    return 0;
}
