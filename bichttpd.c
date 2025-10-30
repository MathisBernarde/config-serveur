#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <signal.h>
#include <time.h> // For logging timestamp

// --- NOUVEAUX INCLUDES POUR OPENSSL ---
#include <openssl/ssl.h>
#include <openssl/err.h>

#define BUFFER_SIZE 4096
#define DEFAULT_PORT 42116
#define CONFIG_LINE_MAX 256

// --- NOUVELLES VARIABLES GLOBALES ---
SSL_CTX *ctx = NULL; // Contexte global pour OpenSSL
char *log_filepath = NULL; // Chemin vers le fichier de log

// --- DÉCLARATIONS DE NOUVELLES FONCTIONS ---
void init_openssl();
SSL_CTX *create_context();
void configure_context(SSL_CTX *ctx);
void log_request(const char *request_line, const char *status);

// --- Fonction pour logger les requêtes ---
void log_request(const char *request_line, const char *status) {
    if (!log_filepath) return; // Ne rien faire si -l n'est pas utilisé

    FILE *logfile = fopen(log_filepath, "a");
    if (!logfile) {
        perror("fopen logfile");
        return;
    }

    // Le bot de test attend un format spécifique : "YYYY "REQUEST" STATUS"
    // On extrait la première ligne de la requête
    char first_line[BUFFER_SIZE];
    strncpy(first_line, request_line, sizeof(first_line));
    first_line[sizeof(first_line) - 1] = '\0';
    char *newline = strchr(first_line, '\n');
    if (newline) *newline = '\0';
    newline = strchr(first_line, '\r');
    if (newline) *newline = '\0';

    // Récupération de l'année
    time_t t = time(NULL);
    struct tm *tm_info = localtime(&t);
    int year = tm_info->tm_year + 1900;
    
    // Extraction du code de statut (ex: "200" depuis "200 OK")
    char status_code[4];
    sscanf(status, "%3s", status_code);

    fprintf(logfile, "%d \"%s\" %s\n", year, first_line, status_code);
    fclose(logfile);
}

// La fonction send_response est maintenant générique pour TCP ou TLS
void send_response(int fd, SSL *ssl, const char *status, const char *content_type, const char *body) {
    char header[BUFFER_SIZE];
    int length = body ? strlen(body) : 0;
    snprintf(header, sizeof(header),
             "HTTP/1.0 %s\r\n"
             "Content-Type: %s\r\n"
             "Content-Length: %d\r\n\r\n",
             status, content_type, length);

    if (ssl) { // Connexion TLS
        SSL_write(ssl, header, strlen(header));
        if (body) SSL_write(ssl, body, length);
    } else { // Connexion TCP standard
        write(fd, header, strlen(header));
        if (body) write(fd, body, length);
    }
}

// La fonction handle_client est maintenant générique pour TCP ou TLS
void handle_client(int client_fd, SSL *ssl) {
    char buffer[BUFFER_SIZE];
    int bytes;

    if (ssl) { // Connexion TLS
        bytes = SSL_read(ssl, buffer, sizeof(buffer) - 1);
    } else { // Connexion TCP standard
        bytes = read(client_fd, buffer, sizeof(buffer) - 1);
    }

    if (bytes <= 0) {
        if (ssl) {
            SSL_shutdown(ssl);
            SSL_free(ssl);
        }
        close(client_fd);
        exit(0);
    }
    buffer[bytes] = '\0';

    const char *status;
    const char *body;

    if (strncmp(buffer, "GET", 3) == 0) {
        status = "200 OK";
        body = "<html><body><h1>200 OK</h1></body></html>\n";
    } else {
        status = "400 Bad Request";
        body = "<html><body><h1>400 Bad Request</h1></body></html>\n";
    }

    log_request(buffer, status); // On logue la requête
    send_response(client_fd, ssl, status, "text/html", body);

    if (ssl) {
        SSL_shutdown(ssl);
        SSL_free(ssl);
    }
    close(client_fd);
    exit(0);
}


// --- Fonctions OpenSSL ---
void init_openssl() {
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
}

SSL_CTX *create_context() {
    const SSL_METHOD *method;
    SSL_CTX *new_ctx;

    method = TLS_server_method();
    new_ctx = SSL_CTX_new(method);
    if (!new_ctx) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    return new_ctx;
}

// On charge le certificat et la clé privée
void configure_context(SSL_CTX *ctx) {
    if (SSL_CTX_use_certificate_file(ctx, "server.crt", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    if (SSL_CTX_use_private_key_file(ctx, "server.key", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
}

// --- Fonction pour parser le fichier de configuration ---
int parse_config(const char *filepath) {
    FILE *file = fopen(filepath, "r");
    if (!file) {
        perror("fopen config");
        return -1; // Erreur
    }

    char line[CONFIG_LINE_MAX];
    int port_from_config = -1;
    int in_section = 0;

    while (fgets(line, sizeof(line), file)) {
        // Section [bichttpd]
        if (strstr(line, "[bichttpd]")) {
            in_section = 1;
            continue;
        }
        if (!in_section) continue;

        // Clé "port"
        if (sscanf(line, " port = %d", &port_from_config) == 1) {
            break; // Port trouvé, on arrête
        }
    }
    fclose(file);
    return port_from_config;
}


int main(int argc, char *argv[]) {
    int port = DEFAULT_PORT;
    char *config_filepath = NULL;
    int enable_tls = 0;
    int opt;

    // --- ÉTAPE 1: LIRE LE FICHIER DE CONFIG SI FOURNI ---
    // On doit le faire dans une boucle séparée pour trouver -c en premier
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-c") == 0 && (i + 1 < argc)) {
            config_filepath = argv[i + 1];
            break;
        }
    }

    if (config_filepath) {
        int parsed_port = parse_config(config_filepath);
        if (parsed_port != -1) {
            port = parsed_port;
        }
    }

    // --- ÉTAPE 2: PARSER LES AUTRES OPTIONS (qui peuvent écraser le .conf) ---
    while ((opt = getopt(argc, argv, "p:l:c:s")) != -1) {
        switch (opt) {
            case 'p': { /* Gère le port */
                char *endptr;
                long val = strtol(optarg, &endptr, 10);
                if (*endptr != '\0' || val <= 0 || val > 65535) {
                    fprintf(stderr, "Invalid argument\n");
                    return 1;
                }
                port = (int)val;
                break;
            }
            case 'l': // Option de log
                log_filepath = optarg;
                break;
            case 's': // Option TLS
                enable_tls = 1;
                break;
            case 'c': // Déjà géré, on l'ignore ici
                break;
            default:
                fprintf(stderr, "Invalid argument\n");
                return 1;
        }
    }

    // --- INITIALISATION DE TLS SI -s est activé ---
    if (enable_tls) {
        init_openssl();
        ctx = create_context();
        configure_context(ctx);
    }
    
    // --- Le reste est similaire : création du socket ---
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    // ... (code du socket, setsockopt, bind, listen)
     if (sockfd < 0) {
        perror("socket");
        return 1;
    }

    int reuse_opt = 1;
    setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &reuse_opt, sizeof(reuse_opt));

    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(port);

    if (bind(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("bind");
        return 1;
    }

    if (listen(sockfd, 10) < 0) {
        perror("listen");
        return 1;
    }

    printf("✅ Serveur en écoute sur le port %d... (TLS: %s)\n", port, enable_tls ? "Activé" : "Désactivé");
    signal(SIGCHLD, SIG_IGN);

    while (1) {
        int client_fd = accept(sockfd, NULL, NULL);
        if (client_fd < 0) continue;

        pid_t pid = fork();
        if (pid == 0) { // Processus enfant
            close(sockfd);
            SSL *ssl = NULL;
            if (enable_tls) {
                ssl = SSL_new(ctx);
                SSL_set_fd(ssl, client_fd);
                if (SSL_accept(ssl) <= 0) { // Handshake TLS
                    ERR_print_errors_fp(stderr);
                    close(client_fd);
                    exit(1);
                }
            }
            handle_client(client_fd, ssl);
        } else { // Processus parent
            close(client_fd);
        }
    }

    close(sockfd);
    if (ctx) SSL_CTX_free(ctx);
    EVP_cleanup();
    return 0;
}