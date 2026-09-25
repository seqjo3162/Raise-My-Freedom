#ifndef IPTABLES_MANAGER_H
#define IPTABLES_MANAGER_H

#include <stdbool.h>
#include <stdint.h>

// iptables rule check result
typedef struct {
    bool rules_exist;        // Whether iptables rules exist
    int rule_count;          // Number of matching rules found
    char blocked_ports[1024]; // Comma-separated list of blocked ports
} iptables_check_result_t;

// Initialize iptables manager
void iptables_manager_init(void);

// Cleanup iptables manager
void iptables_manager_cleanup(void);

// Check if iptables rules exist and analyze them
iptables_check_result_t iptables_check_rules(void);

// Get blocked traffic ports from iptables rules
const char* iptables_get_blocked_ports(void);

#endif // IPTABLES_MANAGER_H