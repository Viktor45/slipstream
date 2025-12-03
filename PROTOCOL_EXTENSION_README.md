# Slipstream Protocol Extension System

## Overview

A flexible system has been developed to add support for additional protocols to slipstream. This system allows new protocols to be added easily without modifying the core code.

## Supported Protocols

### 1. TCP (Default)
- **Usage**: Traditional TCP tunnel
- **Features**: Reliable connection, multiplexing support
- **Default Port**: 80

### 2. UDP
- **Usage**: Connectionless UDP tunnel
- **Features**: Fast, suitable for real-time data
- **Default Port**: 53

### 3. HTTP
- **Usage**: HTTP tunnel with request/response handling
- **Features**: HTTP headers support, request processing
- **Default Port**: 80

### 4. WebSocket
- **Usage**: WebSocket tunnel with full handshake
- **Features**: WebSocket frames support, automatic handshake
- **Default Port**: 80

## Architecture

### Main Files

```
include/
├── slipstream_protocols.h          # Core system interface
src/
├── slipstream_protocols.c          # Core system implementation
├── slipstream_udp_tunnel.c         # UDP tunneling implementation
├── slipstream_http_tunnel.c        # HTTP tunneling implementation
└── slipstream_websocket_tunnel.c   # WebSocket tunneling implementation
examples/
└── protocol_example.c              # Usage example
```

### Core Structures

#### `slipstream_protocol_type_t`
```c
typedef enum {
    SLIPSTREAM_PROTOCOL_TCP = 0,
    SLIPSTREAM_PROTOCOL_UDP = 1,
    SLIPSTREAM_PROTOCOL_HTTP = 2,
    SLIPSTREAM_PROTOCOL_HTTPS = 3,
    SLIPSTREAM_PROTOCOL_WEBSOCKET = 4,
    SLIPSTREAM_PROTOCOL_ICMP = 5,
    SLIPSTREAM_PROTOCOL_CUSTOM = 99
} slipstream_protocol_type_t;
```

#### `slipstream_protocol_handler_t`
```c
typedef struct {
    int (*init)(void* config);
    void (*cleanup)(void* config);
    int (*create_socket)(void* config, struct sockaddr_storage* target_addr);
    ssize_t (*handle_data)(void* config, int socket_fd, uint8_t* buffer, size_t buffer_size);
    ssize_t (*send_data)(void* config, int socket_fd, const uint8_t* data, size_t data_size);
    bool (*is_ready)(void* config, int socket_fd);
    void* (*get_config)(slipstream_protocol_type_t type);
} slipstream_protocol_handler_t;
```

## Usage

### 1. Basic Usage

```c
#include "slipstream_protocols.h"

// Initialize protocol manager
slipstream_protocol_manager_t manager;
slipstream_protocol_manager_init(&manager, SLIPSTREAM_PROTOCOL_UDP);

// Create socket
struct sockaddr_storage target_addr;
// ... set up address ...
int socket_fd = manager.handler->create_socket(manager.protocol_config, &target_addr);

// Send data
const char* data = "Hello World";
manager.handler->send_data(manager.protocol_config, socket_fd, 
                          (const uint8_t*)data, strlen(data));

// Cleanup
close(socket_fd);
slipstream_protocol_manager_cleanup(&manager);
```

### 2. UDP Tunnel Usage

```c
#include "slipstream_udp_tunnel.c"

// Create UDP tunnel context
slipstream_udp_context_t* udp_ctx;
struct sockaddr_storage target_addr;
// ... set up address ...

slipstream_udp_tunnel_create(&udp_ctx, &target_addr, stream_id);

// Start tunnel
int client_socket = accept(listen_socket, NULL, NULL);
slipstream_udp_tunnel_start(udp_ctx, client_socket);

// Cleanup
slipstream_udp_tunnel_destroy(udp_ctx);
```

### 3. HTTP Tunnel Usage

```c
#include "slipstream_http_tunnel.c"

// Create HTTP tunnel context
slipstream_http_context_t* http_ctx;
struct sockaddr_storage target_addr;
// ... set up address ...

slipstream_http_tunnel_create(&http_ctx, &target_addr, stream_id, false); // false = HTTP, true = HTTPS

// Start tunnel
int client_socket = accept(listen_socket, NULL, NULL);
slipstream_http_tunnel_start(http_ctx, client_socket);

// Cleanup
slipstream_http_tunnel_destroy(http_ctx);
```

### 4. WebSocket Tunnel Usage

```c
#include "slipstream_websocket_tunnel.c"

// Create WebSocket tunnel context
slipstream_websocket_context_t* ws_ctx;
struct sockaddr_storage target_addr;
// ... set up address ...

slipstream_websocket_tunnel_create(&ws_ctx, &target_addr, stream_id, "example.com", 80);

// Start tunnel
int client_socket = accept(listen_socket, NULL, NULL);
slipstream_websocket_tunnel_start(ws_ctx, client_socket);

// Cleanup
slipstream_websocket_tunnel_destroy(ws_ctx);
```

## Adding a New Protocol

### 1. Define the Protocol

```c
// In slipstream_protocols.h
typedef enum {
    // ... existing protocols ...
    SLIPSTREAM_PROTOCOL_MY_NEW_PROTOCOL = 6
} slipstream_protocol_type_t;
```

### 2. Create Implementation File

```c
// In src/slipstream_my_protocol.c
#include "slipstream_protocols.h"

// Define handler functions
static int my_protocol_init(void* config) {
    // Protocol initialization
    return 0;
}

static void my_protocol_cleanup(void* config) {
    // Protocol cleanup
}

static int my_protocol_create_socket(void* config, struct sockaddr_storage* target_addr) {
    // Create socket for protocol
    return socket(target_addr->ss_family, SOCK_STREAM, IPPROTO_TCP);
}

// ... remaining handler functions ...

// Define handler
static slipstream_protocol_handler_t my_protocol_handler = {
    .init = my_protocol_init,
    .cleanup = my_protocol_cleanup,
    .create_socket = my_protocol_create_socket,
    .handle_data = my_protocol_handle_data,
    .send_data = my_protocol_send_data,
    .is_ready = my_protocol_is_ready,
    .get_config = NULL
};
```

### 3. Update Core System

```c
// In slipstream_protocols.c
// Add new protocol to protocol_configs
static const slipstream_protocol_config_t protocol_configs[] = {
    // ... existing protocols ...
    {
        .type = SLIPSTREAM_PROTOCOL_MY_NEW_PROTOCOL,
        .name = "MY_PROTOCOL",
        .default_port = 8080,
        .requires_connection = true,
        .supports_multiplexing = true,
        .supports_reliability = true
    }
};

// Add handler in slipstream_protocol_manager_init
switch (protocol) {
    // ... existing cases ...
    case SLIPSTREAM_PROTOCOL_MY_NEW_PROTOCOL:
        manager->handler = &my_protocol_handler;
        break;
}
```

### 4. Update CMakeLists.txt

```cmake
# Add new file to COMMON_SOURCES
set(COMMON_SOURCES
    # ... existing files ...
    src/slipstream_my_protocol.c
    # ... remaining files ...
)
```

## Building and Testing

### 1. Build Project

```bash
mkdir build
cd build
cmake ..
make
```

### 2. Run Example

```bash
# Test TCP
./examples/protocol_example tcp 127.0.0.1 80

# Test UDP
./examples/protocol_example udp 127.0.0.1 53

# Test HTTP
./examples/protocol_example http 127.0.0.1 80

# Test WebSocket
./examples/protocol_example websocket 127.0.0.1 80
```

## Requirements

- **OpenSSL**: Required for WebSocket tunneling
- **pthread**: Required for threading
- **CMake 3.13+**: Required for building

## Advanced Features

### 1. Multiplexing Support
Protocols supporting multiplexing can handle multiple connections simultaneously.

### 2. Memory Management
The system automatically manages memory and includes cleanup functions.

### 3. Thread Safety
All operations are thread-safe using mutexes.

### 4. Error Handling
Comprehensive error handling system with clear messages.

## Future Developments

1. **ICMP Support**: Add ICMP tunneling support
2. **SCTP Support**: Add SCTP protocol support
3. **TLS Support**: Add TLS tunneling support
4. **Web Interface**: Add web interface for protocol management
5. **Performance Monitoring**: Add detailed performance statistics

## Contributing

To contribute to system development:

1. Fork the project
2. Create a new branch
3. Add the new protocol
4. Write tests
5. Submit a Pull Request

## License

This project is licensed under the same license as the original slipstream.