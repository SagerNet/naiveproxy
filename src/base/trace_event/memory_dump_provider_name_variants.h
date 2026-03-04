// Copyright 2025 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Stub header for cronet build - the full variants list is generated from
// memory/histograms.xml in the Chromium build.

#ifndef BASE_TRACE_EVENT_MEMORY_DUMP_PROVIDER_NAME_VARIANTS_H_
#define BASE_TRACE_EVENT_MEMORY_DUMP_PROVIDER_NAME_VARIANTS_H_

#include <string_view>

namespace base::trace_event_metrics {

consteval bool IsValidMemoryDumpProviderName(std::string_view name) {
  // In the cronet build, accept all provider names.
  return true;
}

}  // namespace base::trace_event_metrics

#endif  // BASE_TRACE_EVENT_MEMORY_DUMP_PROVIDER_NAME_VARIANTS_H_
