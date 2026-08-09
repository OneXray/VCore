#ifndef VCORE_H
#define VCORE_H

#ifdef __cplusplus
extern "C" {
#endif

/*
 * request_json must be a NUL-terminated UTF-8 JSON Invoke request. The
 * returned UTF-8 JSON string is independently allocated by VCore and must be
 * released with VCoreFree. Invalid requests return failure JSON; NULL is
 * reserved for catastrophic allocation failure.
 */
char *VCoreInvoke(const char *request_json);

/* A NULL response is ignored. Do not use the host allocator. */
void VCoreFree(char *response);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* VCORE_H */
