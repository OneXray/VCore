/* Production artifact consumer. No runtime instance, sockets, or test features. */
#include <stdio.h>
#include <string.h>
#include "vcore.h"
#ifdef _WIN32
#include <windows.h>
#endif

int main(int argc, char **argv) {
#ifdef _WIN32
    if (argc != 2) return 10;
    HMODULE library = LoadLibraryExA(argv[1], NULL,
        LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_DEFAULT_DIRS);
    if (!library) return 11;
    /* memcpy avoids a nonportable data-pointer/function-pointer cast. */
    FARPROC invoke_address = GetProcAddress(library, "VCoreInvoke");
    FARPROC free_address = GetProcAddress(library, "VCoreFree");
    char *(*invoke)(const char *) = NULL;
    void (*release)(char *) = NULL;
    if (!invoke_address || !free_address) return 12;
    memcpy(&invoke, &invoke_address, sizeof(invoke));
    memcpy(&release, &free_address, sizeof(release));
#else
    (void)argc;
    (void)argv;
    char *(*invoke)(const char *) = VCoreInvoke;
    void (*release)(char *) = VCoreFree;
#endif
    for (unsigned i = 0; i < 1000; i++) {
        char *response = invoke("{\"apiVersion\":5,\"method\":\"version\",\"payload\":{}}");
        int valid = response && strstr(response, "\"success\":true")
            && strstr(response, "\"apiVersion\":5")
            && strstr(response, "\"configVersion\":31")
            && strstr(response, "VCore;engine=rust;coreVersion=0.1.0;invokeApiVersion=5;configVersion=31");
        release(response);
        if (!valid) return 20;
    }
    char *invalid = invoke("{\"apiVersion\":4,\"method\":\"version\",\"payload\":{}}");
    int rejected = invalid && strstr(invalid, "\"success\":false");
    release(invalid);
    if (!rejected) return 21;
    puts("PASS production ABI: 1000 version/free calls; incompatible API rejected");
#ifdef _WIN32
    FreeLibrary(library);
#endif
    return 0;
}
