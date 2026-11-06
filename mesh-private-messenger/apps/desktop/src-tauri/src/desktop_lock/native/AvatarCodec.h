#ifndef MORSE_AVATAR_CODEC_H
#define MORSE_AVATAR_CODEC_H
#include "PrivateJob.h"
// Worker-only bounded native ImageIO import. Returned +1 JPEG buffer must be
// owned before the caller's final scope check and released on every path.
void *MDNativeAvatarEncode(MDPrivateScope scope,const uint8_t *bytes,uint64_t length);
const uint8_t *MDNativeAvatarBytes(void *encoded,uint64_t *length);
void MDNativeAvatarRelease(void *encoded);
#endif
