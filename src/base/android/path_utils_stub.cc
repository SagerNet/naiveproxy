// Copyright 2012 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/android/path_utils.h"

namespace base {
namespace android {

bool GetDataDirectory(FilePath* result) {
  return false;
}

bool GetCacheDirectory(FilePath* result) {
  return false;
}

bool GetThumbnailCacheDirectory(FilePath* result) {
  return false;
}

bool GetDownloadsDirectory(FilePath* result) {
  return false;
}

std::vector<FilePath> GetAllPrivateDownloadsDirectories() {
  return {};
}

std::vector<FilePath> GetSecondaryStorageDownloadDirectories() {
  return {};
}

bool GetNativeLibraryDirectory(FilePath* result) {
  return false;
}

bool GetExternalStorageDirectory(FilePath* result) {
  return false;
}

int64_t GetCacheQuotaBytes() {
  return -1;
}

}  // namespace android
}  // namespace base
