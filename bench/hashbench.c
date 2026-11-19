/*
 * hashbench — mesure le débit de fonctions de hachage avec OpenSSL (EVP).
 * Usage : ./hashbench [durée_ms]   → JSON sur la sortie standard
 * Compilation : make   (gcc -O2 hashbench.c -lcrypto)
 */
#include <openssl/evp.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>
#include <openssl/crypto.h>

static double now_ms(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec * 1000.0 + t.tv_nsec / 1e6;
}

/* Hache des mots de passe courts en boucle pendant `ms` millisecondes. */
static double bench_digest(const char *name, double ms) {
    const EVP_MD *md = EVP_get_digestbyname(name);
    if (!md) return -1;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    unsigned char out[EVP_MAX_MD_SIZE], pw[16] = "motdepasse0000";
    unsigned int len;
    long n = 0;
    double start = now_ms(), end = start + ms;
    while (now_ms() < end) {
        for (int i = 0; i < 2000; i++, n++) {
            pw[10] = '0' + (n % 10); pw[11] = '0' + (n / 10 % 10);
            EVP_DigestInit_ex(ctx, md, NULL);
            EVP_DigestUpdate(ctx, pw, 14);
            EVP_DigestFinal_ex(ctx, out, &len);
        }
    }
    EVP_MD_CTX_free(ctx);
    return n / ((now_ms() - start) / 1000.0);
}

/* PBKDF2 : coût volontairement élevé (itérations). */
static double bench_pbkdf2(int iters, double ms) {
    unsigned char out[32], salt[16] = "selaleatoire1234";
    long n = 0;
    double start = now_ms(), end = start + ms;
    while (now_ms() < end) {
        PKCS5_PBKDF2_HMAC("motdepasse", 10, salt, 16, iters, EVP_sha256(), 32, out);
        n++;
    }
    return n / ((now_ms() - start) / 1000.0);
}

int main(int argc, char **argv) {
    double ms = argc > 1 ? atof(argv[1]) : 400;
    const char *algos[] = {"md5", "sha1", "sha256", "sha512"};
    printf("{\"engine\":\"C/OpenSSL %s\",\"results\":[", OpenSSL_version(OPENSSL_VERSION_STRING));
    for (int i = 0; i < 4; i++)
        printf("%s{\"algo\":\"%s\",\"per_sec\":%.0f}", i ? "," : "", algos[i], bench_digest(algos[i], ms));
    printf(",{\"algo\":\"pbkdf2_sha256_600k\",\"per_sec\":%.2f}", bench_pbkdf2(600000, ms * 2));
    printf("]}\n");
    return 0;
}
