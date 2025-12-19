#ifndef BASE64_H
#define BASE64_H

#ifdef __cplusplus
extern "C"
{
#endif

    char *base64_encode(const char *plain);
    char *base64_decode(const char *cipher);

#ifdef __cplusplus
}
#endif

#endif
