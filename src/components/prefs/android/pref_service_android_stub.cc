// Copyright 2024 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "components/prefs/android/pref_service_android.h"

PrefServiceAndroid::PrefServiceAndroid(PrefService* pref_service)
    : pref_service_(pref_service) {}

PrefServiceAndroid::~PrefServiceAndroid() = default;

// static
PrefService* PrefServiceAndroid::FromPrefServiceAndroid(
    const jni_zero::JavaRef<jobject>& obj) {
  return nullptr;
}

jni_zero::ScopedJavaLocalRef<jobject> PrefServiceAndroid::GetJavaObject() {
  return jni_zero::ScopedJavaLocalRef<jobject>();
}
