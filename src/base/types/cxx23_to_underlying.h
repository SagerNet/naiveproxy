// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef BASE_TYPES_CXX23_TO_UNDERLYING_H_
#define BASE_TYPES_CXX23_TO_UNDERLYING_H_

#include <type_traits>
#include <utility>

namespace base {

#if defined(__cpp_lib_to_underlying) && __cpp_lib_to_underlying >= 202102L
using std::to_underlying;
#else
template <typename Enum>
constexpr std::underlying_type_t<Enum> to_underlying(Enum e) noexcept {
  static_assert(std::is_enum_v<Enum>);
  return static_cast<std::underlying_type_t<Enum>>(e);
}
#endif

}  // namespace base

#endif  // BASE_TYPES_CXX23_TO_UNDERLYING_H_
