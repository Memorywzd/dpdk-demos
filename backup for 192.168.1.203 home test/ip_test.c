#include <stdio.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <pthread.h>

int fd3;

void* get3data()
{
    pthread_detach(pthread_self());
    char buf[1024];
    struct sockaddr_in client_addr;
    socklen_t len;
    while (1)
    {
        int count = recvfrom(fd3, buf, 1024, 0, (struct sockaddr *)&client_addr, &len);
        if(count == -1){
            printf("EOF.\n");
            return;
        }
        printf("192.168.1.2 from %s:%d :%s\n", inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port), buf);
        
    }
    
}

int main()
{
    int fd2 = socket(AF_INET, SOCK_DGRAM, 0);
    fd3 = socket(AF_INET, SOCK_DGRAM, 0);

    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = inet_addr("192.168.1.1");
    server_addr.sin_port = htons(5666);

    bind(fd2, (struct sockaddr *)&server_addr, sizeof(server_addr));

    server_addr.sin_addr.s_addr = inet_addr("192.168.1.2");
    bind(fd3, (struct sockaddr *)&server_addr, sizeof(server_addr));

    pthread_t tid;
    pthread_create(&tid, NULL, get3data, NULL);

    char buf[1024];
    struct sockaddr_in client_addr;
    socklen_t len;
    while (1)
    {
        int count = recvfrom(fd3, buf, 1024, 0, (struct sockaddr *)&client_addr, &len);
        if(count == -1){
            printf("EOF.\n");
            return;
        }
        printf("192.168.1.2 from %s:%d :%s\n", inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port), buf);
        
    }

}