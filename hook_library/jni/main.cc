#include <android/log.h>

void hookFunc() {
    __android_log_print(ANDROID_LOG_VERBOSE, "HOOK", "[+] Function hooked successfully [!]");
}

