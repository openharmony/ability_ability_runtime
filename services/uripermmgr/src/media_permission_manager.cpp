
/*
* Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "media_permission_manager.h"

#include <sys/types.h>
#include <vector>

#include "ability_manager_errors.h"
#include "hilog_tag_wrapper.h"
#include "hitrace_meter.h"
#include "in_process_call_wrapper.h"
#include "iservice_registry.h"
#include "system_ability_definition.h"
#include "uri_permission_utils.h"
#include "want.h"
 
namespace OHOS {
namespace AAFwk {
 
MediaPermissionManager& MediaPermissionManager::GetInstance()
{
    static MediaPermissionManager mediaPermissionManager;
    return mediaPermissionManager;
}

MediaPermissionManager::MediaPermissionManager()
{
    TAG_LOGI(AAFwkTag::URIPERMMGR, "MediaPermissionManager init.");
    mediaLibraryManager_ = GetMediaLibraryManager();
}
 
Media::MediaLibraryManager *MediaPermissionManager::GetMediaLibraryManager()
{
    TAG_LOGI(AAFwkTag::URIPERMMGR, "GetMediaLibraryManager.");
    std::lock_guard<std::mutex> lock(mutex_);
    if (mediaLibraryManager_) {
        return mediaLibraryManager_;
    }
    mediaLibraryManager_ = Media::MediaLibraryManager::GetMediaLibraryManager();
    if (mediaLibraryManager_ == nullptr) {
        TAG_LOGE(AAFwkTag::URIPERMMGR, "GetMediaLibraryManager failed.");
        return mediaLibraryManager_;
    }
    mediaLibraryManager_->InitMediaLibraryManager();
    TAG_LOGI(AAFwkTag::URIPERMMGR, "InitMediaLibraryManager success!");
    return mediaLibraryManager_;
}

std::vector<bool> MediaPermissionManager::CheckUriPermission(const std::vector<Uri> &uriVec,
    uint32_t callerTokenId, uint32_t flag)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    std::vector<std::string> uriStrVec;
    std::vector<bool> results = std::vector<bool>(uriVec.size(), false);
    for (auto &uri: uriVec) {
        uriStrVec.emplace_back(uri.ToString());
    }
    flag &= (Want::FLAG_AUTH_READ_URI_PERMISSION | Want::FLAG_AUTH_WRITE_URI_PERMISSION);
    std::string bundleName = "";
    if (!UPMSUtils::GetBundleNameByTokenId(callerTokenId, bundleName)) {
        TAG_LOGW(AAFwkTag::URIPERMMGR, "Get bundle name failed.");
        return results;
    }
    std::string appId = "";
    if (UPMSUtils::GetAppIdByBundleName(bundleName, appId) != ERR_OK) {
        TAG_LOGW(AAFwkTag::URIPERMMGR, "Get appId by bundle failed.");
        return results;
    }
    auto mediaLibraryManager = GetMediaLibraryManager();
    if (mediaLibraryManager == nullptr) {
        TAG_LOGE(AAFwkTag::URIPERMMGR, "GetMediaLibraryManager failed.");
        return results;
    }
    TAG_LOGI(AAFwkTag::URIPERMMGR, "CheckPhotoUriPermission start.");
    auto ret = IN_PROCESS_CALL(mediaLibraryManager->CheckPhotoUriPermission(callerTokenId, appId, uriStrVec,
        results, flag));
    TAG_LOGI(AAFwkTag::URIPERMMGR, "CheckPhotoUriPermission finished.");
    if (ret != ERR_OK) {
        TAG_LOGE(AAFwkTag::URIPERMMGR, "Check photo uri permission failed, ret is %{public}d", ret);
        results = std::vector<bool>(uriStrVec.size(), false);
        return results;
    }
    if (results.size() != uriStrVec.size()) {
        TAG_LOGE(AAFwkTag::URIPERMMGR, "size of results is unexpected: %{public}zu", results.size());
        results = std::vector<bool>(uriStrVec.size(), false);
        return results;
    }
    return results;
}

} // OHOS
} // AAFwk