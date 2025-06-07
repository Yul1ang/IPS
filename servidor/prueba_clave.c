#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/err.h>

int main() {
    ERR_load_crypto_strings();
    const char *path = "keys/users_public_keys/12345678A_public.pem";
    printf("Intentando abrir archivo de clave publica: %s\n", path);

    FILE *fp = fopen(path, "rb");
    if (!fp) {
        perror("fopen");
        return 1;
    }

    // Leer todo el archivo en memoria
    fseek(fp, 0, SEEK_END);
    long len = ftell(fp);
    rewind(fp);
    char *data = malloc(len + 1);
    fread(data, 1, len, fp);
    data[len] = '\0';
    fclose(fp);

    // Usar un BIO de memoria
    BIO *bio = BIO_new_mem_buf(data, -1);
    EVP_PKEY *evp_key = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
    RSA *rsa = NULL;
    if (evp_key) {
        rsa = EVP_PKEY_get1_RSA(evp_key);
        EVP_PKEY_free(evp_key);
    }
    BIO_free(bio);
    free(data);

    if (!rsa) {
        printf("No se pudo leer la clave publica (BIO)\n");
        ERR_print_errors_fp(stderr);
        return 1;
    }
    printf("Clave publica cargada correctamente (¡TODO OK!)\n");
    RSA_free(rsa);
    return 0;
}
