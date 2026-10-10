#pragma once

#include <android/log.h>

#define PROTECTOR_LOG_TAG "protector"

#ifdef NDEBUG
// Release build: strip all diagnostic logs — they leak protection internals.
#define PLOGD(...) ((void)0)
#define PLOGI(...) ((void)0)
#define PLOGW(...) ((void)0)
// Keep PLOGE for crash forensics (only fires right before a crash).
#define PLOGE(...) __android_log_print(ANDROID_LOG_ERROR, PROTECTOR_LOG_TAG, __VA_ARGS__)
#else
#define PLOGD(...) __android_log_print(ANDROID_LOG_DEBUG, PROTECTOR_LOG_TAG, __VA_ARGS__)
#define PLOGI(...) __android_log_print(ANDROID_LOG_INFO, PROTECTOR_LOG_TAG, __VA_ARGS__)
#define PLOGW(...) __android_log_print(ANDROID_LOG_WARN, PROTECTOR_LOG_TAG, __VA_ARGS__)
#define PLOGE(...) __android_log_print(ANDROID_LOG_ERROR, PROTECTOR_LOG_TAG, __VA_ARGS__)
#endif

#ifndef LIKELY
#define LIKELY(x)   __builtin_expect(!!(x), 1)
#endif
#ifndef UNLIKELY
#define UNLIKELY(x) __builtin_expect(!!(x), 0)
#endif

#define ARRAY_LEN(a) (sizeof(a) / sizeof((a)[0]))
