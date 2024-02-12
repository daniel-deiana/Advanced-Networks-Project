#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
 
#define SERVER_PORT 1337
#define SECRET_WORD "Segreto"
#define BUFFER_SIZE 1024
 
int main() {
    int sockfd;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_len;
    char buffer[BUFFER_SIZE] = {0};
 
    // Creazione del socket
    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("Errore nella creazione del socket");
        exit(EXIT_FAILURE);
    }
 
    // Inizializzazione dell'indirizzo del server
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(SERVER_PORT);
 
    // Binding dell'indirizzo del server al socket
    if (bind(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Errore nel binding");
        exit(EXIT_FAILURE);
    }
 
    printf("Server in ascolto sulla porta %d...\n", SERVER_PORT);
 
    while (1) {
        // Ricezione del messaggio dal client
        client_len = sizeof(client_addr);
        int bytes_received = recvfrom(sockfd, buffer, BUFFER_SIZE, 0, (struct sockaddr *)&client_addr, &client_len);
        if (bytes_received < 0) {
            perror("Errore nella ricezione del messaggio dal client");
            exit(EXIT_FAILURE);
        }
 
        printf("Messaggio ricevuto dal client: %s\n", buffer);
 
        // Invio della parola segreta al client
        if (sendto(sockfd, SECRET_WORD, strlen(SECRET_WORD), 0, (struct sockaddr *)&client_addr, client_len) < 0) {
            perror("Errore nell'invio della risposta al client");
            exit(EXIT_FAILURE);
        }
 
        printf("Parola segreta inviata al client: %s\n", SECRET_WORD);
 
        // Resetta il buffer per il prossimo messaggio
        memset(buffer, 0, BUFFER_SIZE);
    }
 
    return 0;
}
 
