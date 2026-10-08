#ifndef VOLE_H
#define VOLE_H

#ifdef __cplusplus
extern "C" {
#endif

/*
 * request_json must be a NUL-terminated UTF-8 JSON Invoke request. The
 * returned UTF-8 JSON string is independently allocated by Vole and must be
 * released with VoleFree. Invalid requests return failure JSON; NULL is
 * reserved for catastrophic allocation failure.
 */
char *VoleInvoke(const char *request_json);

/*
 * Windows package hosts use a separate revision-3 JSON contract for package
 * environment, VPN profile lifecycle, immutable Session Snapshot publication,
 * optional session backend processes, and StartupTask operations. The response
 * has the same allocation ownership as VoleInvoke and must be released with
 * VoleFree. The calling thread must either have no COM apartment initialized
 * or already be initialized as MTA; STA and ASTA callers are unsupported.
 */
#ifdef _WIN32
char *VoleWindowsVpnInvoke(const char *request_json);
#endif

/* A NULL response is ignored. Do not use the host allocator. */
void VoleFree(char *response);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* VOLE_H */
