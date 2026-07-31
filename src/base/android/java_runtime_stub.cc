// Copyright 2024 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/android/java_runtime.h"

namespace base::android {

void JavaRuntime::GetMemoryUsage(uint64_t* total_memory,
                                 uint64_t* free_memory) {
  // No-op for cronet builds - no JVM available to query.
  // Return 0 for both values.
  *total_memory = 0;
  *free_memory = 0;
}

}  // namespace base::android
