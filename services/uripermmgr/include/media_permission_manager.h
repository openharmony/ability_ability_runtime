/*
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef OHOS_ABILITY_RUNTIME_MEDIA_PERMISSION_MANAGER_H
#define OHOS_ABILITY_RUNTIME_MEDIA_PERMISSION_MANAGER_H

#include <sys/types.h>
#include <vector>
#include "uri.h"

#include "media_library_extend_manager.h"

namespace OHOS {
namespace AAFwk {
class MediaPermissionManager {
public:
    static MediaPermissionManager &GetInstance();
    std::vector<bool> CheckUriPermission(const std::vector<std::string> &uriVec, uint32_t callerTokenId, uint32_t flag);
    int32_t GrantUriPermission(const std::vector<std::string> &uris, uint32_t flag, uint32_t callerTokenId,
        uint32_t targetTokenId, int32_t hideSensitiveType);
    int32_t RevokeUriPermission(uint32_t callerTokenId, uint32_t targetTokenId, const std::string &uri);
    ~MediaPermissionManager() {};
    MediaPermissionManager(const MediaPermissionManager &mediaPermissionManager) = delete;
    const MediaPermissionManager &operator=(const MediaPermissionManager &mediaPermissionManager) = delete;

private:
    MediaPermissionManager();
    Media::MediaLibraryExtendManager *GetMediaLibraryManager();
    Media::PhotoPermissionType FlagToFileOpenMode(uint32_t flag);
    Media::HideSensitiveType ConvertHideSensitiveType(int32_t hideSensitiveType);
};

} // OHOS
} // AAFwk
#endif // OHOS_ABILITY_RUNTIME_MEDIA_PERMISSION_MANAGER_H