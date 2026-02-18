// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef BASE_TRACE_EVENT_MEMORY_DUMP_PROVIDER_NAME_VARIANTS_H_
#define BASE_TRACE_EVENT_MEMORY_DUMP_PROVIDER_NAME_VARIANTS_H_

#include <string_view>

namespace trace_event_metrics {

// Chromium generates an allowlist for exact variant names from histograms
// metadata. In this trimmed Cronet tree that generation step is unavailable, so
// validate the expected histogram-name shape at compile time.
constexpr bool IsValidMemoryDumpProviderName(std::string_view name) {
  if (name.empty()) {
    return false;
  }
  for (char c : name) {
    const bool is_ascii_alpha =
        (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
    const bool is_ascii_digit = c >= '0' && c <= '9';
    if (!is_ascii_alpha && !is_ascii_digit && c != '_') {
      return false;
    }
  }
  return true;
}

}  // namespace trace_event_metrics

#endif  // BASE_TRACE_EVENT_MEMORY_DUMP_PROVIDER_NAME_VARIANTS_H_
