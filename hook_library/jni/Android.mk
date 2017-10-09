LOCAL_PATH := $(call my-dir)
include $(CLEAR_VARS)
LOCAL_SRC_FILES  := main.cc
LOCAL_MODULE     := hook
LOCAL_LDLIBS := -llog
include $(BUILD_SHARED_LIBRARY)