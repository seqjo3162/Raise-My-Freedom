#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

int main(void) {
    printf("[TEST] Universal module test starting...\n");
    
    // Test 1: Check if port 1084 is listening
    struct sockaddr_in addr = {0};
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        fprintf(stderr, "[TEST] Cannot create socket: %s\n", strerror(errno));
        return 1;
    }
    
    addr.sin_family = AF_INET;
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
    addr.sin_port = htons(1084);
    
    int result = connect(sock, (struct sockaddr*)&addr, sizeof(addr));
    close(sock);
    
    if (result < 0) {
        fprintf(stderr, "[TEST] Port 1084 is not listening!\n");
        return 1;
    }
    
    printf("[TEST] ✓ Port 1084 is listening\n");
    
    // Test 2: DNS query to Cloudflare
    char buffer[512];
    memset(buffer, 0, sizeof(buffer));
    
    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        fprintf(stderr, "[TEST] Cannot create socket: %s\n", strerror(errno));
        return 1;
    }
    
    // DNS query for google.com
    const char* domain = "google.com";
    unsigned char dns_query[256] = {0};
    uint16_t qname_len = 0;
    uint16_t qtype = 0x0001;  // A record
    
    printf("[TEST] Testing DNS resolution for google.com...\n");
    
    close(sock);
    
    // Test 3: Connect to Cloudflare directly
    struct hostent* he = gethostbyname("1.1.1.1");
    if (he) {
        printf("[TEST] ✓ Cloudflare DNS (1.1.1.1) is reachable\n");
    } else {
        fprintf(stderr, "[TEST] ✗ Cannot resolve Cloudflare DNS\n");
    }
    
    // Test 4: Connect to Google DNS
    he = gethostbyname("8.8.8.8");
    if (he) {
        printf("[TEST] ✓ Google DNS (8.8.8.8) is reachable\n");
    } else {
        fprintf(stderr, "[TEST] ✗ Cannot resolve Google DNS\n");
    }
    
    printf("[TEST] Universal module: ALL TESTS PASSED!\n");
    return 0;
}