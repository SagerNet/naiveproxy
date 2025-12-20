// Copyright 2024 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/android/input_hint_checker.h"

namespace base::android {

void InputHintChecker::InitializeFeatures() {
  // No-op for cronet builds - input hint checking is not needed
  // for network-only functionality.
}

}  // namespace base::android
