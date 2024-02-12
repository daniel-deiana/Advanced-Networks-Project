#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
 
#define SERVER_PORT 1337
#define MESSAGE "Hello, server!"
#define BUFFER_SIZE 1024
 
int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Utilizzo: %s <indirizzo_ip_server>\n", argv[0]);
        exit(EXIT_FAILURE);
    }
    char *server_ip = argv[1];
    int sockfd;
    struct sockaddr_in server_addr;
    char buffer[BUFFER_SIZE] = {0};
 
    // Creazione del socket
    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("Errore nella creazione del socket");
        exit(EXIT_FAILURE);
    }
 
    // Inizializzazione dell'indirizzo del server
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(SERVER_PORT);
    if (inet_pton(AF_INET, server_ip, &server_addr.sin_addr) <= 0) {
        perror("Indirizzo del server non valido");
        exit(EXIT_FAILURE);
    }
 
    // Invio del messaggio al server
    if (sendto(sockfd, MESSAGE, strlen(MESSAGE), 0, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Errore nell'invio del messaggio al server");
        exit(EXIT_FAILURE);
    }
    printf("Messaggio inviato al server: %s\n", MESSAGE);
 
    // Ricezione della risposta dal server
    socklen_t addr_len = sizeof(server_addr);
    int bytes_received = recvfrom(sockfd, buffer, BUFFER_SIZE, 0, (struct sockaddr *)&server_addr, &addr_len);
    if (bytes_received < 0) {
        perror("Errore nella ricezione della risposta dal server");
        exit(EXIT_FAILURE);
    } else {
        buffer[bytes_received] = '\0'; // Aggiungi terminatore di stringa
        printf("Risposta ricevuta dal server: %s\n", buffer);
    }
 
    close(sockfd);
    return 0;
}
