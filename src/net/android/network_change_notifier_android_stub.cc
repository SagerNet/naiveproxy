// Copyright 2012 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/android/network_change_notifier_android.h"

#include "base/time/time.h"

namespace net {

// static
NetworkChangeNotifier::NetworkChangeCalculatorParams
NetworkChangeNotifierAndroid::NetworkChangeCalculatorParamsAndroid() {
  NetworkChangeCalculatorParams params;
  params.ip_address_offline_delay_ = base::Seconds(1);
  params.ip_address_online_delay_ = base::Seconds(1);
  params.connection_type_offline_delay_ = base::Seconds(0);
  params.connection_type_online_delay_ = base::Seconds(0);
  return params;
}

}  // namespace net
