// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef BASE_TYPES_CXX23_IS_SCOPED_ENUM_H_
#define BASE_TYPES_CXX23_IS_SCOPED_ENUM_H_

#include <type_traits>

namespace base {

#if defined(__cpp_lib_is_scoped_enum) && __cpp_lib_is_scoped_enum >= 202011L
using std::is_scoped_enum;
using std::is_scoped_enum_v;
#else
template <typename T, bool = std::is_enum_v<T>>
struct is_scoped_enum : std::false_type {};

template <typename T>
struct is_scoped_enum<T, true>
    : std::bool_constant<!std::is_convertible_v<T, std::underlying_type_t<T>>> {
};

template <typename T>
inline constexpr bool is_scoped_enum_v = is_scoped_enum<T>::value;
#endif

}  // namespace base

#endif  // BASE_TYPES_CXX23_IS_SCOPED_ENUM_H_
