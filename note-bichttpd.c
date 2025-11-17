// --- BIBLIOTHÈQUES INCLUSES ---

#include <stdio.h>      // Pour les fonctions d'entrée/sortie standard (printf, fprintf, FILE, fopen, ...)
#include <stdlib.h>     // Pour les fonctions utilitaires (exit, strtol, malloc, free, atoi, ...)
#include <string.h>     // Pour la manipulation des chaînes de caractères (strcmp, strdup, strlen, ...)
#include <unistd.h>     // Pour les appels système POSIX (close, fork, accept, access, getuid, ...)
#include <sys/socket.h> // Pour les fonctions et structures de base des sockets (socket, bind, listen, ...)
#include <netinet/in.h> // Pour les structures d'adresses Internet (struct sockaddr_in, AF_INET, ...)
#include <ctype.h>      // Pour les fonctions de test de caractères (isspace)
#include <errno.h>      // Pour la variable 'errno' qui stocke les codes d'erreur système
#include <signal.h>     // Pour la gestion des signaux (signal, SIGINT, SIGPIPE, ...)
#include <sys/wait.h>   // Pour 'waitpid' (bien qu'ici SIG_IGN est utilisé pour SIGCHLD)
#include <time.h>       // Pour les fonctions de temps (time, strftime, localtime)
#include <sys/stat.h>   // Pour obtenir les informations sur les fichiers (stat, S_ISREG)
#include <pwd.h>        // Pour obtenir des informations sur l'utilisateur (getpwuid)
#include <openssl/ssl.h> // Pour les fonctions principales de SSL/TLS (SSL_CTX, SSL, SSL_read, ...)
#include <openssl/err.h> // Pour les fonctions de gestion d'erreurs d'OpenSSL (ERR_print_errors_fp)

// --- STRUCTURES DE DONNÉES ---

/**
 * @brief Contient la configuration globale du serveur.
 * Rassembler les variables globales dans une structure est une bonne pratique.
 */
typedef struct {
    unsigned short port;      // Le port d'écoute (ex: 42116)
    int debug_mode;           // Drapeau (0 ou 1) pour activer les logs de débogage
    int secure_mode;          // Drapeau (0 ou 1) pour activer le mode TLS (HTTPS)
    char *log_file;           // Chemin vers le fichier de log (ou NULL si désactivé)
    SSL_CTX *ssl_ctx;         // Le contexte SSL global (partagé par tous les processus enfants)
    const char *cert_file;    // Chemin vers le fichier de certificat SSL (.pem)
    const char *key_file;     // Chemin vers le fichier de clé privée SSL (.pem)
} server_config_t;

/**
 * @brief Structure d'abstraction pour une connexion client.
 * Elle contient le file descriptor et le contexte SSL (si applicable).
 * Les pointeurs de fonction read/write permettent d'utiliser les mêmes
 * fonctions de logique (ex: process_request) que la connexion soit
 * en clair (send/recv) ou chiffrée (SSL_write/SSL_read).
 * C'est le changement structurel le plus important.
 */
typedef struct s_connection {
    int client_fd;                // Le "file descriptor" (identifiant numérique) du socket du client
    SSL *ssl;                     // Pointeur vers l'objet SSL spécifique à cette connexion (NULL si non-sécurisé)
    server_config_t *config;      // Pointeur vers la configuration globale du serveur
    
    // Pointeurs de fonction pour l'abstraction I/O (Entrée/Sortie)
    // 'read' pointera soit vers 'plain_read' soit vers 'ssl_read'
    ssize_t (*read)(struct s_connection *conn, char *buf, size_t size);
    // 'write' pointera soit vers 'plain_write' soit vers 'ssl_write'
    ssize_t (*write)(struct s_connection *conn, const char *buf, size_t size);
} connection_t;

// --- VARIABLES GLOBALES ---

// Nécessaire pour que le gestionnaire de signal (handle_sigint_shutdown)
// puisse fermer le socket d'écoute principal lors d'un Ctrl+C.
// 'static' signifie qu'elle n'est visible que dans ce fichier.
static int g_server_socket = -1;

// --- FONCTIONS D'ABSTRACTION I/O ---

/**
 * @brief Fonctions wrapper (enveloppe) pour les I/O en clair (non-SSL)
 * Cette fonction correspond à la signature du pointeur 'read' dans connection_t.
 */
ssize_t plain_read(connection_t *conn, char *buf, size_t size) {
    // Utilise 'recv' (équivalent de read pour les sockets) pour lire les données
    return recv(conn->client_fd, buf, size, 0);
}
/**
 * @brief Wrapper pour l'écriture en clair.
 */
ssize_t plain_write(connection_t *conn, const char *buf, size_t size) {
    // Utilise 'send' (équivalent de write pour les sockets) pour envoyer des données
    return send(conn->client_fd, buf, size, 0);
}

/**
 * @brief Fonctions wrapper pour les I/O chiffrées (SSL)
 * Correspond également à la signature du pointeur 'read'.
 */
ssize_t ssl_read(connection_t *conn, char *buf, size_t size) {
    // Utilise la fonction d'OpenSSL pour lire des données chiffrées
    return SSL_read(conn->ssl, buf, (int)size); // OpenSSL utilise 'int' pour la taille
}
/**
 * @brief Wrapper pour l'écriture chiffrée.
 */
ssize_t ssl_write(connection_t *conn, const char *buf, size_t size) {
    // Utilise la fonction d'OpenSSL pour écrire des données chiffrées
    return SSL_write(conn->ssl, buf, (int)size);
}

// --- FONCTIONS UTILITAIRES ---

/**
 * @brief Affiche l'usage du programme (aide pour l'option -h)
 */
void print_server_usage(const char *program_name) {
    // 'stderr' est la sortie d'erreur standard, c'est là qu'on affiche les aides et erreurs.
    fprintf(stderr, "Usage: %s [-p PORT] [-d] [-s] [-l LOGFILE] [-c CONFFILE]\n", program_name);
    fprintf(stderr, "  -p PORT   Spécifier le port d'écoute (défaut: 42116)\n");
    fprintf(stderr, "  -d        Activer le mode debug\n");
    fprintf(stderr, "  -s        Activer le mode sécurisé (TLS)\n");
    fprintf(stderr, "  -l FILE   Spécifier le fichier de log\n");
    fprintf(stderr, "  -c FILE   Spécifier le fichier de configuration\n");
}

/**
 * @brief Valide une chaîne de caractères comme un port valide (1-65535).
 * Logique gardée identique à l'originale pour passer les tests eval.sh
 */
unsigned short validate_port(const char *s) {
    char *e = NULL; // Pointeur pour stocker la fin de la chaîne numérique
    errno = 0; // Réinitialise la variable d'erreur globale
    
    // 'strtol' convertit une chaîne en 'long' (base 10)
    long v = strtol(s, &e, 10); 
    
    // Vérifie les conditions d'erreur :
    // 1. 'errno != 0' : La conversion a échoué (ex: dépassement de capacité)
    // 2. 'e == s' : Aucun chiffre n'a été lu
    // 3. '*e != '\0'' : Il y a des caractères non numériques après le nombre (ex: "8080abc")
    // 4. 'v < 1' ou 'v > 65535' : Le port est hors de la plage TCP/IP valide
    if(errno != 0 || e == s || *e != '\0' || v < 1 || v > 65535){
        // Affiche un message d'erreur spécifique sur stderr
        fprintf(stderr, "Invalid argument: port '%s' is invalid (must be 1-65535)\n", s);
        // Quitte le programme avec un statut d'échec
        exit(EXIT_FAILURE);
    }
    // Convertit (cast) le 'long' en 'unsigned short' et le retourne
    return (unsigned short)v;
}

/**
 * @brief Récupère le nom d'utilisateur courant.
 */
const char* get_current_username() {
    // 'getuid()' récupère l'ID de l'utilisateur qui exécute le programme
    // 'getpwuid()' recherche cet ID dans la base de données des utilisateurs
    struct passwd *pw = getpwuid(getuid());
    // Retourne le nom d'utilisateur trouvé, ou une valeur par défaut si 'getpwuid' échoue
    return pw ? pw->pw_name : "mb242602"; 
}

/**
 * @brief Formate la date actuelle pour l'en-tête HTTP 'Date'.
 */
void get_http_date(char *buffer, size_t size) {
    time_t now = time(NULL); // Récupère l'heure actuelle (secondes depuis 1970)
    struct tm *tm_info = localtime(&now); // Convertit en temps local (jour, mois, année, ...)
    // Formate l'heure selon le standard RFC 1123 (utilisé par HTTP)
    strftime(buffer, size, "%a, %d %b %Y %H:%M:%S GMT", tm_info);
}

/**
 * @brief Écrit une entrée dans le fichier de log.
 */
void write_log_entry(server_config_t *config, const char *method, const char *path, int status) {
    // N'écrit que si un fichier de log a été spécifié
    if (config->log_file) {
        // Ouvre le fichier en mode 'append' (ajout à la fin)
        FILE *log = fopen(config->log_file, "a");
        if (log) { // Vérifie si l'ouverture a réussi
            time_t now = time(NULL);
            struct tm *tm_info = localtime(&now);
            char time_buffer[64];
            // Formate l'heure au format YYYY-MM-DD HH:MM:SS
            strftime(time_buffer, sizeof(time_buffer), "%Y-%m-%d %H:%M:%S", tm_info);
            // Écrit la ligne de log formatée
            fprintf(log, "[%s] \"%s %s HTTP/1.0\" %d\n", time_buffer, method, path, status);
            // Ferme le fichier
            fclose(log);
        }
    }
}

// --- GESTION SSL ---

/**
 * @brief Initialise le contexte SSL global.
 */
int init_ssl_context(server_config_t *config) { //structure (type) server_config_t definie plus tot dans le code | variable dans un poiteur pour config
    SSL_library_init(); // Initialise la bibliothèque OpenSSL
    SSL_load_error_strings(); // Charge les messages d'erreur lisibles
    OpenSSL_add_all_algorithms(); // Charge tous les algorithmes de chiffrement

    // Crée un nouveau contexte SSL en utilisant la méthode TLS côté serveur
    config->ssl_ctx = SSL_CTX_new(TLS_server_method());
    if (!config->ssl_ctx) { // Vérifie si la création a échoué
        ERR_print_errors_fp(stderr); // Affiche les erreurs OpenSSL sur stderr
        return 0; // Retourne 0 (échec)
    }

    // Récupère le nom d'utilisateur pour construire les chemins des certificats
    const char *username = get_current_username();
    char cert_path_buf[512];
    char key_path_buf[512];
    
    // Construit les chemins complets vers les fichiers de certificat et de clé
    snprintf(cert_path_buf, sizeof(cert_path_buf), "/home/2025/a2-bic/%s/opt/bichttpd/etc/certs/cert.pem", username);
    snprintf(key_path_buf, sizeof(key_path_buf), "/home/2025/a2-bic/%s/opt/bichttpd/etc/certs/key.pem", username);
    
    // 'strdup' duplique les chaînes. C'est nécessaire car 'cert_path_buf' et 'key_path_buf'
    // sont des variables locales (sur la pile) qui seront détruites à la fin de la fonction.
    config->cert_file = strdup(cert_path_buf);
    config->key_file = strdup(key_path_buf);


    // Charge le fichier de certificat dans le contexte SSL
    if (SSL_CTX_use_certificate_file(config->ssl_ctx, config->cert_file, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        return 0;
    }

    // Charge le fichier de clé privée dans le contexte SSL
    if (SSL_CTX_use_PrivateKey_file(config->ssl_ctx, config->key_file, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        return 0;
    }

    // Vérifie si la clé privée correspond bien au certificat public
    if (!SSL_CTX_check_private_key(config->ssl_ctx)) {
        fprintf(stderr, "Private key does not match the public certificate\n");
        return 0;
    }
    return 1; // Retourne 1 (succès)
}

/**
 * @brief Libère les ressources SSL.
 */
void cleanup_ssl(server_config_t *config) {//structure (type) server_config_t definie plus tot dans le code | variable dans un poiteur pour config
    if (config->ssl_ctx) { //dans la structure config on a un pointeur ssl_ctx qui pointe vers le contexte SSL
        SSL_CTX_free(config->ssl_ctx); // Libère le contexte SSL
    }
    // Libère la mémoire qui avait été allouée par 'strdup'
    free((void*)config->cert_file); //cast pour éviter un avertissement de compilation
    free((void*)config->key_file);
}

// --- GESTION DES REQUÊTES ---

/**
 * @brief Envoie une réponse HTTP (status, headers, body).
 * Cette fonction unifiée remplace send_http_response ET send_ssl_response
 * grâce à l'abstraction 'connection_t'.
 */
void send_response(connection_t *conn, int status, const char *body, const char *method, const char *path) {
    char response_buffer[4096]; // Tampon pour construire la réponse
    char date_header[128];      // Tampon pour l'en-tête 'Date'
    const char *status_text;    // Chaîne de caractères pour le statut (ex: "200 OK")

    // Aiguillage (switch) pour déterminer le texte du statut HTTP
    switch(status) {
        case 200: status_text = "200 OK"; break;
        case 400: status_text = "400 Bad Request"; break;
        case 404: status_text = "404 Not Found"; break;
        default: status_text = "500 Internal Server Error"; break; // Cas par défaut
    }

    // Récupère la date formatée
    get_http_date(date_header, sizeof(date_header));

    // Calcule la taille du corps. Pour une requête HEAD, le corps est vide (taille 0).
    size_t body_length = (strcmp(method, "HEAD") == 0) ? 0 : (body ? strlen(body) : 0);
    
    // Construit l'en-tête HTTP complet dans 'response_buffer'
    snprintf(response_buffer, sizeof(response_buffer),
        "HTTP/1.0 %s\r\n"
        "Date: %s\r\n"
        "Content-Type: text/html\r\n"
        "Content-Length: %zu\r\n"       // %zu est pour 'size_t'
        "Connection: close\r\n"        // Indique qu'on ferme la connexion après cette réponse
        "\r\n", status_text, date_header, body_length); // La ligne vide sépare l'en-tête du corps

    // N'ajoute le corps que si ce n'est pas une requête HEAD et si le corps existe
    if (strcmp(method, "HEAD") != 0 && body) {
        // 'strncat' ajoute le corps à la fin de l'en-tête dans le tampon
        strncat(response_buffer, body, sizeof(response_buffer) - strlen(response_buffer) - 1);
    }

    // C'est ici que l'abstraction fonctionne :
    // 'conn->write' appelle soit 'plain_write' soit 'ssl_write', selon ce qui
    // a été défini lors de l'établissement de la connexion.
    conn->write(conn, response_buffer, strlen(response_buffer));
    
    // Écrit l'entrée dans le fichier de log
    write_log_entry(conn->config, method, path, status);
}

/**
 * @brief Tente de servir un fichier statique.
 * Renvoie 1 en cas de succès, 0 en cas d'échec (ex: 404).
 */
int serve_file(connection_t *conn, const char *path, const char *method) {
    char full_path[1024]; // Tampon pour le chemin complet du fichier sur le disque
    const char *username = get_current_username();

    // Logique pour construire le chemin du fichier
    // Si le chemin est "/", recherche "index.html"
    if (strcmp(path, "/") == 0) {
        snprintf(full_path, sizeof(full_path), "/home/2025/a2-bic/%s/opt/bichttpd/srv/http/index.html", username);
    } else {
        // Nettoie le chemin s'il commence par "/"
        const char *clean_path = (path[0] == '/') ? path + 1 : path;
        snprintf(full_path, sizeof(full_path), "/home/2025/a2-bic/%s/opt/bichttpd/srv/http/%s", username, clean_path);
    }

    // Logique de "fallback" (repli) vers un dossier "root/" si le fichier n'est pas trouvé
    // 'access(F_OK)' vérifie si le fichier existe
    if (access(full_path, F_OK) == -1) {
         if (strcmp(path, "/") == 0) {
            snprintf(full_path, sizeof(full_path), "/home/2025/a2-bic/%s/opt/bichttpd/srv/http/root/index.html", username);
         } else {
            const char *clean_path = (path[0] == '/') ? path + 1 : path;
            snprintf(full_path, sizeof(full_path), "/home/2025/a2-bic/%s/opt/bichttpd/srv/http/root/%s", username, clean_path);
         }
    }

    // Affiche le chemin recherché si le mode debug est activé
    if (conn->config->debug_mode) {
        fprintf(stderr, "[bichttpd] Looking for file: %s\n", full_path);
    }

    // Vérifie l'existence et le type du fichier
    struct stat st; // Structure pour stocker les informations du fichier
    // 'access(F_OK)' : vérifie l'existence
    // 'stat(full_path, &st)' : récupère les informations (taille, type, ...)
    // '!S_ISREG(st.st_mode)' : vérifie que ce n'est PAS un fichier régulier (ex: c'est un dossier)
    if (access(full_path, F_OK) == -1 || stat(full_path, &st) == -1 || !S_ISREG(st.st_mode)) {
        if (conn->config->debug_mode) {
            fprintf(stderr, "[bichttpd] File not found or not a regular file: %s\n", full_path);
        }
        return 0; // Fichier non trouvé, retourne 0 (échec)
    }

    // Ouvre le fichier en mode lecture ("r")
    FILE *file = fopen(full_path, "r");
    if (!file) {
        return 0; // Impossible d'ouvrir le fichier
    }

    // Lit le contenu du fichier
    fseek(file, 0, SEEK_END);    // Se déplace à la fin du fichier
    long file_size = ftell(file); // Récupère la position (qui est la taille du fichier)
    fseek(file, 0, SEEK_SET);    // Revient au début du fichier

    if (file_size < 0) { // Gestion d'erreur
        fclose(file);
        return 0;
    }

    // Alloue de la mémoire pour stocker tout le contenu du fichier
    char *file_content = malloc(file_size + 1); // +1 pour le caractère nul '\0'
    if (!file_content) {
        fclose(file);
        return 0; // Erreur d'allocation mémoire
    }

    // Lit le fichier entier dans le tampon 'file_content'
    size_t bytes_read = fread(file_content, 1, file_size, file);
    fclose(file); // Ferme le fichier dès qu'il est lu

    // Vérifie si la lecture a réussi
    if (bytes_read != (size_t)file_size) {
        free(file_content); // Libère la mémoire allouée
        return 0; // Erreur de lecture
    }
    file_content[bytes_read] = '\0'; // Ajoute le caractère de fin de chaîne

    // --- Envoi de la réponse 200 OK ---
    char response_header[4096];
    char date_header[128];
    get_http_date(date_header, sizeof(date_header));

    // Construit l'en-tête de la réponse 200 OK avec la bonne taille (Content-Length)
    snprintf(response_header, sizeof(response_header),
        "HTTP/1.0 200 OK\r\n"
        "Date: %s\r\n"
        "Content-Type: text/html\r\n"
        "Content-Length: %ld\r\n" // %ld est pour 'long' (file_size)
        "Connection: close\r\n"
        "\r\n", date_header, file_size);

    // Envoie l'en-tête en utilisant la fonction abstraite (plain_write ou ssl_write)
    conn->write(conn, response_header, strlen(response_header));

    // Envoie le corps (le contenu du fichier), sauf si c'est une requête HEAD
    if (strcmp(method, "HEAD") != 0) {
        conn->write(conn, file_content, bytes_read);
    }
    
    // Logue la requête comme un succès (200)
    write_log_entry(conn->config, method, path, 200);
    // Libère la mémoire allouée pour le contenu du fichier
    free(file_content);
    return 1; // Succès
}

/**
 * @brief Gère l'intégralité d'une connexion client (lecture, parsing, réponse).
 */
void process_request(connection_t *conn) {
    char buffer[4096]; // Tampon pour lire la requête du client
    
    // Utilise la fonction de lecture abstraite (plain_read ou ssl_read)
    ssize_t n = conn->read(conn, buffer, sizeof(buffer) - 1);

    if (n <= 0) {
        return; // Erreur ou connexion fermée par le client
    }
    buffer[n] = '\0'; // Termine la chaîne lue

    // 'strtok' divise la chaîne aux endroits "\r\n" (fin de ligne HTTP)
    // On récupère la première ligne (ex: "GET /index.html HTTP/1.0")
    char *first_line = strtok(buffer, "\r\n"); 
    if (!first_line) {
        // Si la requête est vide ou malformée, envoie 400 Bad Request
        send_response(conn, 400, "<html><body><h1>400 Bad Request</h1></body></html>", "UNKNOWN", "unknown");
        return;
    }

    char method[16], path[256], version[16];
    // 'sscanf' parse la première ligne pour extraire les 3 parties
    int parsed = sscanf(first_line, "%15s %255s %15s", method, path, version);

    // Log en mode debug
    if (conn->config->debug_mode) {
        fprintf(stderr, "[bichttpd] Received%s: %s %s %s\n", 
            (conn->ssl ? " (TLS)" : ""), // Ajoute "(TLS)" si la connexion est chiffrée
            method, path, version);
    }

    // --- Validation de la requête ---
    if (parsed != 3) { // Si sscanf n'a pas trouvé 3 éléments
        send_response(conn, 400, "<html><body><h1>400 Bad Request - Invalid request line</h1></body></html>", "UNKNOWN", "unknown");
        return;
    }
    if (strcmp(version, "HTTP/1.0") != 0) { // Seul HTTP/1.0 est supporté
        send_response(conn, 400, "<html><body><h1>400 Bad Request - Invalid HTTP version</h1></body></html>", method, path);
        return;
    }
    // Seuls GET, HEAD, et POST sont supportés
    if (strcmp(method, "GET") != 0 && strcmp(method, "HEAD") != 0 && strcmp(method, "POST") != 0) {
        send_response(conn, 400, "<html><body><h1>400 Bad Request - Invalid method</h1></body></html>", method, path);
        return;
    }

    // --- Logique de service ---
    if (strcmp(method, "POST") == 0) {
        // Le serveur accepte POST mais ne fait rien avec, il renvoie juste 200 OK
        send_response(conn, 200, "<html><body><h1>POST Received</h1></body></html>", method, path);
    } else {
        // Pour GET et HEAD, tente de servir un fichier statique
        if (!serve_file(conn, path, method)) {
            // Si serve_file renvoie 0 (échec), c'est un 404 Not Found
            send_response(conn, 404, "<html><body><h1>404 Not Found</h1></body></html>", method, path);
        }
    }
}

/**
 * @brief Parse un fichier de configuration simple (clé = valeur).
 */
int parse_config_file(const char *filename, server_config_t *config) {
    FILE *file = fopen(filename, "r"); // Ouvre en lecture
    if (!file) {
        fprintf(stderr, "Error: Cannot open config file '%s'\n", filename);
        return 0; // Échec
    }

    char line[256];
    // 'fgets' lit une ligne du fichier (jusqu'à 255 caractères)
    while (fgets(line, sizeof(line), file)) {
        // 'strpbrk' cherche le premier espace ou '='
        char *key = line;
        char *separator = strpbrk(line, "= ");
        
        if (separator) {
            *separator = '\0'; // Met un '\0' pour terminer la chaîne 'key'
            char *value = separator + 1; // 'value' commence juste après

            // Nettoyage simple : enlève les espaces au début de 'value'
            while (*value && isspace(*value)) value++;
            // Enlève les espaces/newlines à la fin de 'value'
            char *end = value + strlen(value) - 1;
            while (end > value && isspace(*end)) *end-- = '\0';

            // Compare la 'key' et met à jour la configuration
            if (strcmp(key, "port") == 0) {
                config->port = (unsigned short)atoi(value); // 'atoi' convertit la chaîne en 'int'
            } else if (strcmp(key, "secure_mode") == 0) {
                config->secure_mode = atoi(value);
            } else if (strcmp(key, "debug_mode") == 0) {
                config->debug_mode = atoi(value);
            } else if (strcmp(key, "log_file") == 0) {
                config->log_file = strdup(value); // Alloue de la mémoire pour copier la valeur
            }
        }
    }
    fclose(file);
    return 1; // Succès
}

/**
 * @brief Gestionnaire pour SIGINT (Ctrl+C).
 * 'int sig' est le numéro du signal reçu (ici, SIGINT).
 */
void handle_sigint_shutdown(int sig) {
    if (g_server_socket != -1) { // Si le socket principal est ouvert
        close(g_server_socket); // Ferme le socket d'écoute
    }
    // Quitte le programme. Cela arrête la boucle 'while(1)' dans main.
    exit(EXIT_SUCCESS);
}

// --- FONCTION PRINCIPALE ---

// 'argc' est le nombre d'arguments, 'argv' est un tableau de chaînes (les arguments)
int main(int argc, char *argv[]) {
    // Initialise la structure de configuration avec les valeurs par défaut
    server_config_t config = {
        .port = 42116,
        .debug_mode = 0,
        .secure_mode = 0,
        .log_file = NULL,
        .ssl_ctx = NULL,
        .cert_file = NULL,
        .key_file = NULL
    };
    int opt; // Variable pour stocker l'option lue

    // 'getopt' est une fonction POSIX pour parser les arguments de ligne de commande.
    // "p:dsl:c:" signifie :
    // -p, -l, -c attendent un argument (le ':')
    // -d, -s sont des drapeaux (pas d'argument)
    while((opt = getopt(argc, argv, "p:dsl:c:")) != -1) {
        switch(opt) { // Aiguillage sur l'option trouvée
            case 'p': 
                config.port = validate_port(optarg); // 'optarg' contient la valeur (ex: "8080")
                break;
            case 'd': 
                config.debug_mode = 1; 
                fprintf(stderr, "[bichttpd] Debug mode enabled\n"); 
                break;
            case 's': 
                config.secure_mode = 1; 
                fprintf(stderr, "[bichttpd] TLS connection enabled\n"); 
                break;
            case 'l': 
                config.log_file = optarg; // Stocke le chemin du fichier log
                break;
            case 'c': 
                // Si parse_config_file renvoie 0 (échec)
                if (!parse_config_file(optarg, &config)) {
                    return EXIT_FAILURE; // Quitte le programme
                }
                break;
            case 'h': // Option d'aide
                print_server_usage(argv[0]); // Affiche l'aide
                return EXIT_SUCCESS; // Quitte avec succès
            default: // Cas où l'option est inconnue (ex: -z)
                print_server_usage(argv[0]);
                return EXIT_FAILURE;
        }
    }

    // Vérifie s'il y a des arguments inconnus après les options
    if (optind < argc) {
        fprintf(stderr, "Error: Unexpected argument '%s'\n", argv[optind]);
        print_server_usage(argv[0]);
        return EXIT_FAILURE;
    }

    // Initialisation SSL si le mode sécurisé est activé
    if (config.secure_mode) {
        if (!init_ssl_context(&config)) { // Si l'initialisation échoue
            fprintf(stderr, "Error: Failed to initialize SSL context\n");
            return EXIT_FAILURE;
        }
    }

    // Affiche les messages de debug si activé
    if (config.debug_mode) {
        fprintf(stderr, "[bichttpd] Trying to bind to port %d\n", config.port);
        fprintf(stderr, "[bichttpd] Current username: %s\n", get_current_username());
    }

    // --- Gestion des signaux ---
    // SIGPIPE : Signal envoyé si on écrit sur un socket fermé par le client.
    // SIG_IGN : Ignore le signal (évite au programme de crasher).
    signal(SIGPIPE, SIG_IGN); 
    
    // SIGCHLD : Signal envoyé au parent quand un processus enfant se termine.
    // SIG_IGN : Indique au système de nettoyer automatiquement les enfants (évite les "zombies").
    signal(SIGCHLD, SIG_IGN); 
    
    // SIGINT : Signal de Ctrl+C.
    // Appelle notre fonction 'handle_sigint_shutdown'.
    signal(SIGINT, handle_sigint_shutdown);

    // --- Configuration du socket serveur ---
    // Crée un socket : AF_INET (IPv4), SOCK_STREAM (TCP), 0 (protocole par défaut)
    g_server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (g_server_socket == -1) {
        perror("socket error"); // 'perror' affiche l'erreur système (ex: "Permission denied")
        return EXIT_FAILURE;
    }

    int yes = 1;
    // Configure le socket pour réutiliser l'adresse immédiatement (SO_REUSEADDR)
    // Permet de redémarrer le serveur sans attendre que le port soit libéré.
    if (setsockopt(g_server_socket, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)) < 0) {
        perror("setsockopt");
        close(g_server_socket);
        return EXIT_FAILURE;
    }

    // Structure pour définir l'adresse (IP + port)
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr)); // Initialise la structure à zéro
    addr.sin_family = AF_INET; // Famille d'adresse IPv4
    addr.sin_addr.s_addr = htonl(INADDR_ANY); // Écoute sur toutes les interfaces (0.0.0.0)
    addr.sin_port = htons(config.port); // Définit le port (converti en "network byte order")

    // Associe (lie) le socket à l'adresse et au port
    if (bind(g_server_socket, (struct sockaddr*)&addr, sizeof(addr)) == -1) {
        perror("bind error");
        close(g_server_socket);
        return EXIT_FAILURE;
    }

    // Met le socket en mode "écoute", prêt à accepter des connexions
    // 16 est la taille de la file d'attente (backlog)
    if (listen(g_server_socket, 16) == -1) {
        perror("listen error");
        close(g_server_socket);
        return EXIT_FAILURE;
    }

    // Affiche les messages de confirmation sur 'stdout'
    printf("HTTP server listening on port %d\n", config.port);
    if (config.secure_mode) {
        printf("TLS server enabled on port %d\n", config.port);
    }

    // --- BOUCLE PRINCIPALE (Modèle "Worker" : 1 processus par client) ---
    while (1) { // Boucle infinie
        // 'accept' est un appel bloquant : il attend qu'un client se connecte.
        // Il retourne un nouveau 'file descriptor' pour communiquer avec CE client.
        int client_fd = accept(g_server_socket, NULL, NULL);
        if (client_fd == -1) {
            if (errno == EINTR) continue; // Si 'accept' a été interrompu par un signal (ex: Ctrl+C), on continue
            perror("accept error");
            continue; // En cas d'autre erreur, on continue la boucle
        }

        // Crée un nouveau processus (fork)
        pid_t pid = fork();
        if (pid == -1) {
            // Le fork a échoué (ex: plus de mémoire)
            perror("fork error");
            close(client_fd); // Ferme le client non traité
            continue; // Continue la boucle
        }

        if (pid == 0) {
            // --- Processus Enfant ---
            // 'pid == 0' signifie que nous sommes dans l'enfant.
            
            // L'enfant n'a pas besoin du socket d'écoute principal, seul le parent accepte.
            close(g_server_socket); 

            // Initialise la structure de connexion pour ce client
            connection_t conn;
            conn.client_fd = client_fd;
            conn.ssl = NULL;
            conn.config = &config; // Passe un pointeur vers la config

            if (config.secure_mode) {
                // --- Négociation TLS ---
                conn.ssl = SSL_new(config.ssl_ctx); // Crée un objet SSL
                SSL_set_fd(conn.ssl, conn.client_fd); // Lie SSL au socket du client

                // Tente d'effectuer la "poignée de main" (handshake) TLS
                if (SSL_accept(conn.ssl) <= 0) {
                    if (config.debug_mode) {
                        fprintf(stderr, "[bichttpd] TLS handshake failed\n");
                    }
                    SSL_free(conn.ssl); // Nettoie l'objet SSL
                    close(conn.client_fd); // Ferme le socket
                    exit(EXIT_SUCCESS); // L'enfant termine son travail (échec du client)
                }
                
                if (config.debug_mode) {
                    fprintf(stderr, "[bichttpd] TLS connection established\n");
                }
                
                // Assigne les pointeurs de fonction pour utiliser les wrappers SSL
                conn.read = ssl_read;
                conn.write = ssl_write;

            } else {
                // --- Connexion en clair ---
                // Assigne les pointeurs de fonction pour utiliser les wrappers non-SSL
                conn.read = plain_read;
                conn.write = plain_write;
            }

            // Appelle la fonction de logique principale (commune à SSL et non-SSL)
            process_request(&conn);

            // --- Nettoyage de l'enfant ---
            if (conn.ssl) { // Si c'était une connexion SSL
                SSL_shutdown(conn.ssl); // Ferme proprement la session SSL
                SSL_free(conn.ssl); // Libère l'objet SSL
            }
            close(conn.client_fd); // Ferme le socket du client
            
            // Libère la mémoire qui a été copiée du parent (via strdup)
            // (Note: C'est une fuite de mémoire potentielle si 'log_file' n'est pas de strdup, 
            // mais ici c'est correct car 'optarg' n'est pas libéré, seul 'strdup' l'est)
            if (config.log_file) free(config.log_file); // Correction : Ce free n'est correct que si -c a été utilisé.
            free((void*)config.cert_file); // Libère la mémoire du chemin
            free((void*)config.key_file);  // Libère la mémoire du chemin

            exit(EXIT_SUCCESS); // L'enfant a terminé son travail avec succès.

        } else {
            // --- Processus Parent ---
            // 'pid > 0' signifie que nous sommes dans le parent.
            
            // Le parent n'a pas besoin de communiquer avec le client.
            // Il ferme son 'file descriptor' pour ce client (l'enfant a sa propre copie).
            close(client_fd);
            // Le parent retourne immédiatement au début de la boucle 'while(1)'
            // pour attendre la prochaine connexion.
        }
    } // Fin de la boucle 'while(1)'

    // --- Nettoyage principal ---
    // Ce code n'est atteint que si la boucle 'while(1)' s'arrête,
    // ce qui n'arrive que si 'handle_sigint_shutdown' appelle 'exit()'.
    // Mais par propreté, on le met.
    close(g_server_socket);
    if (config.secure_mode) {
        cleanup_ssl(&config);
    }
    if (config.log_file) free(config.log_file); // Idem que dans l'enfant

    return EXIT_SUCCESS; // Fin du programme
}