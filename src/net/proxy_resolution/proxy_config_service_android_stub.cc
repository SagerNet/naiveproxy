// Copyright 2012 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Stub implementation of ProxyConfigServiceAndroid for use without JNI.
// Returns direct (no proxy) configuration.

#include "net/proxy_resolution/proxy_config_service_android.h"

#include "base/functional/callback.h"
#include "base/memory/ref_counted.h"
#include "net/proxy_resolution/proxy_config_with_annotation.h"

namespace net {

class ProxyConfigServiceAndroid::Delegate
    : public base::RefCountedThreadSafe<Delegate> {
 private:
  friend class base::RefCountedThreadSafe<Delegate>;
  ~Delegate() = default;
};

ProxyConfigServiceAndroid::ProxyConfigServiceAndroid(
    const scoped_refptr<base::SequencedTaskRunner>& main_task_runner,
    const scoped_refptr<base::SequencedTaskRunner>& jni_task_runner) {}

ProxyConfigServiceAndroid::ProxyConfigServiceAndroid(
    const scoped_refptr<base::SequencedTaskRunner>& main_task_runner,
    const scoped_refptr<base::SequencedTaskRunner>& jni_task_runner,
    GetPropertyCallback get_property_callback) {}

ProxyConfigServiceAndroid::~ProxyConfigServiceAndroid() = default;

void ProxyConfigServiceAndroid::set_exclude_pac_url(bool enabled) {}

void ProxyConfigServiceAndroid::AddObserver(Observer* observer) {}

void ProxyConfigServiceAndroid::RemoveObserver(Observer* observer) {}

ProxyConfigService::ConfigAvailability
ProxyConfigServiceAndroid::GetLatestProxyConfig(
    ProxyConfigWithAnnotation* config) {
  *config = ProxyConfigWithAnnotation::CreateDirect();
  return CONFIG_VALID;
}

std::string ProxyConfigServiceAndroid::SetProxyOverride(
    const std::vector<ProxyOverrideRule>& proxy_rules,
    const std::vector<std::string>& bypass_rules,
    const bool reverse_bypass,
    base::OnceClosure callback) {
  return "ProxyConfigServiceAndroid stub does not support SetProxyOverride";
}

void ProxyConfigServiceAndroid::ClearProxyOverride(base::OnceClosure callback) {
  std::move(callback).Run();
}

void ProxyConfigServiceAndroid::ProxySettingsChanged() {}

void ProxyConfigServiceAndroid::ProxySettingsChangedTo(
    const std::string& host,
    int port,
    const std::string& pac_url,
    const std::vector<std::string>& exclusion_list) {}

}  // namespace net
