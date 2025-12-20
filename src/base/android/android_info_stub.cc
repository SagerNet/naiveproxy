// Copyright 2025 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/android/android_info.h"

#include <cstdlib>

#include "base/no_destructor.h"

int __system_property_get(const char* name, char* value);

namespace {

constexpr int kPropValueMax = 92;

std::string GetSystemProperty(const char* name) {
  char value[kPropValueMax];
  if (__system_property_get(name, value) > 0) {
    return std::string(value);
  }
  return std::string();
}

int GetSdkInt() {
  char value[kPropValueMax];
  if (__system_property_get("ro.build.version.sdk", value) > 0) {
    return std::atoi(value);
  }
  return 0;
}

}  // namespace

namespace base::android::android_info {

const std::string& device() {
  static const base::NoDestructor<std::string> s(
      GetSystemProperty("ro.product.device"));
  return *s;
}

const std::string& manufacturer() {
  static const base::NoDestructor<std::string> s(
      GetSystemProperty("ro.product.manufacturer"));
  return *s;
}

const std::string& model() {
  static const base::NoDestructor<std::string> s(
      GetSystemProperty("ro.product.model"));
  return *s;
}

const std::string& brand() {
  static const base::NoDestructor<std::string> s(
      GetSystemProperty("ro.product.brand"));
  return *s;
}

const std::string& android_build_id() {
  static const base::NoDestructor<std::string> s(
      GetSystemProperty("ro.build.id"));
  return *s;
}

const std::string& build_type() {
  static const base::NoDestructor<std::string> s(
      GetSystemProperty("ro.build.type"));
  return *s;
}

const std::string& board() {
  static const base::NoDestructor<std::string> s(
      GetSystemProperty("ro.product.board"));
  return *s;
}

const std::string& android_build_fp() {
  static const base::NoDestructor<std::string> s(
      GetSystemProperty("ro.build.fingerprint"));
  return *s;
}

int sdk_int() {
  static const int sdk = GetSdkInt();
  return sdk;
}

bool is_debug_android() {
  static const bool debug = GetSystemProperty("ro.debuggable") == "1";
  return debug;
}

const std::string& version_incremental() {
  static const base::NoDestructor<std::string> s(
      GetSystemProperty("ro.build.version.incremental"));
  return *s;
}

const std::string& hardware() {
  static const base::NoDestructor<std::string> s(
      GetSystemProperty("ro.hardware"));
  return *s;
}

const std::string& codename() {
  static const base::NoDestructor<std::string> s(
      GetSystemProperty("ro.build.version.codename"));
  return *s;
}

const std::string& soc_manufacturer() {
  static const base::NoDestructor<std::string> s(
      GetSystemProperty("ro.soc.manufacturer"));
  return *s;
}

const std::string& abi_name() {
  static const base::NoDestructor<std::string> s(
      GetSystemProperty("ro.product.cpu.abi"));
  return *s;
}

const std::string& security_patch() {
  static const base::NoDestructor<std::string> s(
      GetSystemProperty("ro.build.version.security_patch"));
  return *s;
}

void Set(const IAndroidInfo& info) {
  // No-op in stub - values are read from system properties
}

}  // namespace base::android::android_info
