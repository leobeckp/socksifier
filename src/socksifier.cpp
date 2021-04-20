#include <winsock2.h>
#include <ws2tcpip.h>
#include <MSWSock.h>
#include <windows.h>

#include <detours/detours.h>

#include <spdlog/spdlog.h>
#include <spdlog/sinks/basic_file_sink.h>

#pragma comment(lib, "Ws2_32.lib")


typedef struct settings {
    int proxy_address;
    short proxy_port;
    short use_auth = 0;
    char proxy_username[255] = {0};
    char proxy_password[255] = {0};
} setting_t;

static setting_t settings;


#ifdef __cplusplus
extern "C" {
#endif

#pragma region TODO: redesign exposed settings

    __declspec(dllexport) void set_proxy_address(void * args)
    {
        settings.proxy_address = *((int *)args);
    }

    __declspec(dllexport) void set_proxy_port(void * args)
    {
        settings.proxy_port = *((short *)args);
    }

    __declspec(dllexport) void set_proxy_username(LPCSTR args)
    {
        settings.use_auth = 1;
        strcpy(settings.proxy_username, args);
    }

    __declspec(dllexport) void set_proxy_password(LPCSTR args)
    {
        settings.use_auth = 1;
        strcpy(settings.proxy_password, args);
    }

#pragma endregion 

    static int (WINAPI * real_connect)(SOCKET s, const struct sockaddr * name, int namelen) = connect;

    LPFN_CONNECTEX ConnectExPtr = NULL;

#ifdef __cplusplus
}
#endif


/**
 * \fn  static inline void LogWSAError()
 *
 * \brief   Send friendly name of WSA error message to default log.
 *
 * \author  Benjamin Höglinger-Stelzer
 * \date    23.07.2019
 */
static inline void LogWSAError()
{
    char *error = NULL;
    FormatMessageA(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL,
        WSAGetLastError(),
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPSTR)&error, 0, NULL);
    spdlog::error("Winsock error details: {} ({})", error, WSAGetLastError());
    LocalFree(error);
}

/**
 * \fn  static inline BOOL BindAndConnectExSync( SOCKET s, const struct sockaddr * name, int namelen )
 *
 * \brief   Bind and connect a non-blocking socket synchronously.
 *
 * \author  Benjamin Höglinger-Stelzer
 * \date    23.07.2019
 *
 * \param   s       A SOCKET to process.
 * \param   name    The const struct sockaddr *.
 * \param   namelen The sizeof(const struct sockaddr).
 *
 * \returns True if it succeeds, false if it fails.
 */
static inline BOOL BindAndConnectExSync(
    SOCKET s,
    const struct sockaddr * name,
    int namelen
)
{
    DWORD numBytes = 0, transfer = 0, flags = 0;
    OVERLAPPED overlapped = { 0 };
    overlapped.hEvent = CreateEvent(nullptr, FALSE, FALSE, nullptr);

    /* ConnectEx requires the socket to be initially bound. */
    {
        struct sockaddr_in addr;
        ZeroMemory(&addr, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = INADDR_ANY; // Any
        addr.sin_port = 0; // Any
        auto rc = bind(s, (SOCKADDR*)&addr, sizeof(addr));
        if (rc != 0) {
            spdlog::error("bind failed: {}", WSAGetLastError());
            LogWSAError();
            return FALSE;
        }
    }

    // 
    // Call ConnectEx with overlapped I/O
    // 
    if (!ConnectExPtr(
        s,
        name,
        namelen,
        NULL,
        0,
        &numBytes,
        &overlapped
    ) && WSAGetLastError() != WSA_IO_PENDING)
    {
        spdlog::error("ConnectEx failed: {}", WSAGetLastError());
        CloseHandle(overlapped.hEvent);
        return FALSE;
    }

    //
    // Wait for result
    // 
    const auto ret = WSAGetOverlappedResult(
        s,
        &overlapped,
        &transfer,
        TRUE,
        &flags
    );

    CloseHandle(overlapped.hEvent);
    return ret;
}

/**
 * \fn  static inline BOOL WSARecvSync( SOCKET s, PCHAR buffer, ULONG length )
 *
 * \brief   recv() in a blocking fashion.
 *
 * \author  Benjamin Höglinger-Stelzer
 * \date    23.07.2019
 *
 * \param   s       A SOCKET to process.
 * \param   buffer  The buffer.
 * \param   length  The length.
 *
 * \returns True if it succeeds, false if it fails.
 */
static inline BOOL WSARecvSync(
    SOCKET s,
    PCHAR buffer,
    ULONG length
)
{
    DWORD flags = 0, transfer = 0, numBytes = 0;
    WSABUF recvBuf;
    OVERLAPPED overlapped = { 0 };
    overlapped.hEvent = CreateEvent(nullptr, FALSE, FALSE, nullptr);

    recvBuf.buf = buffer;
    recvBuf.len = length;

    if (WSARecv(s, &recvBuf, 1, &numBytes, &flags, &overlapped, NULL) == SOCKET_ERROR)
    {
        if (WSAGetLastError() != WSA_IO_PENDING)
        {
            spdlog::error("WSARecv failed: {}", WSAGetLastError());
            CloseHandle(overlapped.hEvent);
            return FALSE;
        }
    }

    const auto ret = WSAGetOverlappedResult(
        s,
        &overlapped,
        &transfer,
        TRUE,
        &flags
    );

    CloseHandle(overlapped.hEvent);
    return ret;
}

/**
 * \fn  static inline BOOL WSASendSync( SOCKET s, PCHAR buffer, ULONG length )
 *
 * \brief   send() in a blocking fashion.
 *
 * \author  Benjamin Höglinger-Stelzer
 * \date    23.07.2019
 *
 * \param   s       A SOCKET to process.
 * \param   buffer  The buffer.
 * \param   length  The length.
 *
 * \returns True if it succeeds, false if it fails.
 */
static inline BOOL WSASendSync(
    SOCKET s,
    PCHAR buffer,
    ULONG length
)
{
    DWORD flags = 0, transfer = 0, numBytes = 0;
    WSABUF sendBuf;
    OVERLAPPED overlapped = { 0 };
    overlapped.hEvent = CreateEvent(nullptr, FALSE, FALSE, nullptr);

    sendBuf.buf = buffer;
    sendBuf.len = length;

    if (WSASend(s, &sendBuf, 1, &numBytes, 0, &overlapped, NULL) == SOCKET_ERROR)
    {
        if (WSAGetLastError() != WSA_IO_PENDING)
        {
            spdlog::error("WSASend failed: {}", WSAGetLastError());
            CloseHandle(overlapped.hEvent);
            return FALSE;
        }

    }

    const auto ret = WSAGetOverlappedResult(
        s,
        &overlapped,
        &transfer,
        TRUE,
        &flags
    );

    CloseHandle(overlapped.hEvent);
    return ret;
}

/**
 * \fn  int WINAPI my_connect(SOCKET s, const struct sockaddr * name, int namelen)
 *
 * \brief   Detoured connect function.
 *
 * \author  Benjamin Höglinger-Stelzer
 * \date    23.07.2019
 *
 * \param   s       A SOCKET to process.
 * \param   name    The name.
 * \param   namelen The namelen.
 *
 * \returns A WINAPI.
 */
int WINAPI my_connect(SOCKET s, const struct sockaddr * name, int namelen)
{
    spdlog::debug("my_connect called");

    //
    // One-time initialization
    // 
    static std::once_flag flag;
    std::call_once(flag, [&sock = s]()
    {
        spdlog::info("Requesting pointer to ConnectEx()");

        DWORD numBytes = 0;
        GUID guid = WSAID_CONNECTEX;

        //
        // Request ConnectEx function pointer
        // 
        const auto ret = WSAIoctl(
            sock,
            SIO_GET_EXTENSION_FUNCTION_POINTER,
            (void*)&guid,
            sizeof(guid),
            (void*)&ConnectExPtr,
            sizeof(ConnectExPtr),
            &numBytes,
            NULL,
            NULL
        );

        if (!ret)
        {
            spdlog::info("ConnectEx() pointer acquired");
        }
        else
        {
            spdlog::error("Failed to retrieve ConnectEx() pointer, error: {}", WSAGetLastError());
            ConnectExPtr = NULL;
        }
    });

    const struct sockaddr_in * dest = (const struct sockaddr_in *)name;

    char addr[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(dest->sin_addr), addr, INET_ADDRSTRLEN);
    const auto dest_port = ntohs(dest->sin_port);

    //
    // These destinations we don't usually wanna proxy
    // 
    if (ConnectExPtr == NULL || !strcmp(addr, "127.0.0.1") || !strcmp(addr, "0.0.0.0"))
    {
        return real_connect(s, name, namelen);
    }

    spdlog::info("Original connect destination: {}:{}", addr, dest_port);

    struct sockaddr_in proxy;
    proxy.sin_addr.s_addr = settings.proxy_address;
    proxy.sin_family = AF_INET;
    proxy.sin_port = settings.proxy_port;

    inet_ntop(AF_INET, &(proxy.sin_addr), addr, INET_ADDRSTRLEN);
    spdlog::info("Connecting to SOCKS proxy: {}:{}", addr, ntohs(proxy.sin_port));

    //
    // This handles non-blocking socket connections via extended Winsock API
    // 
    if (BindAndConnectExSync(
        s,
        reinterpret_cast<SOCKADDR *>(&proxy),
        sizeof(proxy)
    ))
    {
        spdlog::info("Proxy connection established");
    }
    else
    {
        spdlog::error("Proxy connection failed");
        LogWSAError();
        return SOCKET_ERROR;
    }

    //
    // Prepare greeting payload
    // 


    // SERVER AUTHENTICATION REQUEST
    // The client connects to the server, and sends a version
    // identifier/method selection message:
    //
    //      +----+----------+----------+
    //      |VER | NMETHODS | METHODS  |
    //      +----+----------+----------+
    //      | 1  |    1     | 1 to 255 |
    //      +----+----------+----------+
    char greetProxy[4];

    greetProxy[0] = 0x05; // Version (always 0x05)
    greetProxy[1] = 0x02; // Number of authentication methods (2 methods: none - 0, username/password - 2)
    greetProxy[2] = 0x00; // 0: NO AUTHENTICATION REQUIRED
    greetProxy[3] = 0x02; // 2: AUTH WITH USERNAME/PASSWORD

    //  SERVER AUTHENTICATION RESPONSE
    //  The server selects from one of the methods given in METHODS, and
    //  sends a METHOD selection message:
    //
    //     +----+--------+
    //     |VER | METHOD |
    //     +----+--------+
    //     | 1  |   1    |
    //     +----+--------+
    //
    //  If the selected METHOD is X'FF', none of the methods listed by the
    //  client are acceptable, and the client MUST close the connection.
    //
    //  The values currently defined for METHOD are:
    //   * X'00' NO AUTHENTICATION REQUIRED
    //   * X'01' GSSAPI
    //   * X'02' USERNAME/PASSWORD
    //   * X'03' to X'7F' IANA ASSIGNED
    //   * X'80' to X'FE' RESERVED FOR PRIVATE METHODS
    //   * X'FF' NO ACCEPTABLE METHODS

    char greetResponse[2] = { 0 };

    if (!WSASendSync(s, greetProxy, sizeof(greetProxy)))
    {
        spdlog::error("Failed to greet SOCKS proxy server");
        LogWSAError();
        return SOCKET_ERROR;
    }       

    if (!WSARecvSync(s, greetResponse, sizeof(greetResponse)))
    {
        spdlog::error("Proxy greeting failed on get response");
        LogWSAError();
        return SOCKET_ERROR;
    }    

    if(greetResponse[0] != 0x05)
    {
        spdlog::error("Proxy greeting failed: invalid version {}", greetResponse[0]);
        LogWSAError();
        return SOCKET_ERROR;
    }

    if(greetResponse[1] == 0xff)
    {
        spdlog::error("Proxy greeting failed: no auth method available");
        LogWSAError();
        return SOCKET_ERROR;
    }    

    if(greetResponse[1] == 0x02 && settings.use_auth == 0)
    {
        spdlog::error("Proxy greeting failed: requires username/password", greetResponse);
        LogWSAError();
        return SOCKET_ERROR;
    }

    spdlog::info("Proxy accepted greeting. Using username/password authentication: {}", (greetResponse[1] == 0x02 ? "Yes":"No")); 

    if(greetResponse[1] == 0x02 && settings.use_auth == 1)
    {
        int username_length = strlen(settings.proxy_username);
        int password_length = strlen(settings.proxy_password);

        if(username_length == 0 || password_length == 0)
        {
            spdlog::error("Invalid username/password provided for proxy");
            LogWSAError();
            return SOCKET_ERROR;
        }

        // USERNAME / PASSWORD SERVER REQUEST
        // Once the SOCKS V5 server has started, and the client has selected the
        // Username/Password Authentication protocol, the Username/Password
        // subnegotiation begins.  This begins with the client producing a
        // Username/Password request:
        //
        //       +----+------+----------+------+----------+
        //       |VER | ULEN |  UNAME   | PLEN |  PASSWD  |
        //       +----+------+----------+------+----------+
        //       | 1  |  1   | 1 to 255 |  1   | 1 to 255 |
        //       +----+------+----------+------+----------+

        char* proxyAuth = (char *)calloc(3 + username_length + password_length, sizeof(char));

        // for SOCKS5 username/password authentication the VER field must be set to 0x01
        //  http://en.wikipedia.org/wiki/SOCKS
        //      field 1: version number, 1 byte (must be 0x01)"
        proxyAuth[0] = 0x01;
        proxyAuth[1] = username_length;
        strncpy(proxyAuth + 2, settings.proxy_username, username_length);        
        proxyAuth[username_length + 2] = password_length;
        strncpy(proxyAuth + username_length + 3, settings.proxy_password, password_length);

        spdlog::info("Sending username {} and password {} auth to proxy", settings.proxy_username, settings.proxy_password);

        if (!WSASendSync(s, proxyAuth, 3 + username_length + password_length))
        {
            spdlog::error("Proxy auth failed on send username/password");
            LogWSAError();
            return SOCKET_ERROR;
        }

        // USERNAME / PASSWORD SERVER RESPONSE
        // The server verifies the supplied UNAME and PASSWD, and sends the
        // following response:
        //
        //   +----+--------+
        //   |VER | STATUS |
        //   +----+--------+
        //   | 1  |   1    |
        //   +----+--------+
        //
        // A STATUS field of X'00' indicates success. If the server returns a
        // `failure' (STATUS value other than X'00') status, it MUST close the
        // connection.

        char authResponse[2] = { 0 };

        if (!WSARecvSync(s, authResponse, sizeof(authResponse)))
        {
            spdlog::error("Proxy auth failed on get response");
            LogWSAError();
            return SOCKET_ERROR;
        }

        if(authResponse[1] != 0x00)
        {
            spdlog::error("Proxy auth failed. Invalid username or password: {0:x}", authResponse[1]);
            LogWSAError();
            return SOCKET_ERROR;
        }
    }   

    //
    // Prepare remote connect request
    // 
    char remoteBind[10];
    remoteBind[0] = 0x05; // Version (always 0x05)
    remoteBind[1] = 0x01; // Connect command
    remoteBind[2] = 0x00; // Reserved
    remoteBind[3] = 0x01; // Type (IP V4 address)
    remoteBind[4] = (dest->sin_addr.s_addr >> 0) & 0xFF;
    remoteBind[5] = (dest->sin_addr.s_addr >> 8) & 0xFF;
    remoteBind[6] = (dest->sin_addr.s_addr >> 16) & 0xFF;
    remoteBind[7] = (dest->sin_addr.s_addr >> 24) & 0xFF;
    remoteBind[8] = (dest->sin_port >> 0) & 0xFF;
    remoteBind[9] = (dest->sin_port >> 8) & 0xFF;

    spdlog::info("Sending connect request to proxy");

    if (WSASendSync(s, remoteBind, sizeof(remoteBind)))
    {
        char response[10] = { 0 };

        if (WSARecvSync(s, response, sizeof(response))
            && response[1] == 0x00 /* success value */)
        {
            spdlog::info("Remote connection established");
        }
        else
        {
            spdlog::error("Consuming proxy response failed");
            LogWSAError();
            return SOCKET_ERROR;
        }
    }
    else
    {
        spdlog::error("Failed to instruct proxy to remote connect");
        LogWSAError();
        return SOCKET_ERROR;
    }

    return ERROR_SUCCESS;
}


BOOL WINAPI DllMain(HINSTANCE dll_handle, DWORD reason, LPVOID reserved)
{
    if (DetourIsHelperProcess()) {
        return TRUE;
    }

    switch (reason) {
    case DLL_PROCESS_ATTACH:
        settings.proxy_address = 0x0100007F; // 127.0.0.1
        settings.proxy_port = 0x3804; // 1080
        settings.use_auth = 0;

        {
            auto logger = spdlog::basic_logger_mt(
                "socksifier",
                "socksifier.log"
            );

#if _DEBUG
            spdlog::set_level(spdlog::level::debug);
            logger->flush_on(spdlog::level::debug);
#else
            logger->flush_on(spdlog::level::info);
#endif

            spdlog::set_default_logger(logger);
    }

        DisableThreadLibraryCalls(dll_handle);
        DetourRestoreAfterWith();

        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        DetourAttach(&(PVOID)real_connect, my_connect);
        DetourTransactionCommit();

        break;

    case DLL_PROCESS_DETACH:
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        DetourDetach(&(PVOID)real_connect, my_connect);
        DetourTransactionCommit();
        break;
}
    return TRUE;
}
