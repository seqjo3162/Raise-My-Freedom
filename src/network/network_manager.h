#ifndef NETWORK_MANAGER_H
#define NETWORK_MANAGER_H

#include <stdio.h>
#include <string.h>
#include <stdint.h>

// Network Query
typedef struct {
    char domain[256];
    int nf_queue_id;      // NFQUEUE ID
    int packet_size;      // Packet size (0=no limit!)
} network_query_t;

// Network Response
typedef struct {
    int status;           // 0=success, -1=fail
    char* nfqueue_id;     // NFQUEUE ID or NULL
    char* error;          // Error message or NULL
} network_response_t;

// Network Manager Config
typedef struct {
    int nfqueue_group;    // NFQUEUE group ID (default: 0)
    int packet_size;      // Packet size limit (0=unlimited!)
    int auto_detect;      // Auto-detect DPI signatures
} network_manager_config_t;

// Network Manager Interface (Clean C!)
extern void network_manager_init(void);
extern void network_manager_cleanup(void);
extern uint32_t network_manager_get_packet_count(void);
extern network_response_t network_manager_process(const char* domain, const network_manager_config_t* config);

#endif // NETWORK_MANAGER_H