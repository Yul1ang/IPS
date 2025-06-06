#ifndef COMMON_H
#define COMMON_H

#define MAX_USERS 100         // Maximo numero de usuarios que el servidor puede almacenar
#define MAX_DNI 16            // Longitud maxima del DNI
#define MAX_NAME 64           // Longitud maxima de nombre o apellido
#define MAX_ADDR 128          // Longitud maxima de direccion
#define MAX_CP 16             // Longitud maxima de codigo postal
#define SYM_KEY_LEN 32        // Tamaño de clave simetrica (32 bytes = 256 bits, AES-256)
#define IV_LEN 16             // Tamaño del IV para AES-256-CBC

// Estructura para los datos del usuario
typedef struct {
    char dni[MAX_DNI];
    char name[MAX_NAME];
    char surname[MAX_NAME];
    char address[MAX_ADDR];
    char postal_code[MAX_CP];
} UserData;

// Estructura para registro de usuario (en servidor)
typedef struct {
    UserData data;                  // Datos del usuario
    unsigned char sym_key[SYM_KEY_LEN]; // Clave simetrica del usuario
    unsigned char iv[IV_LEN];           // IV para cifrado AES
} UserReg;

#endif