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

#include "uri_utils.h"

#include "ability_config.h"
#include "hilog_tag_wrapper.h"
#include "in_process_call_wrapper.h"
#include "uri_permission_manager_client.h"

namespace OHOS {
namespace AAFwk {
namespace {
const std::string PARAMS_URI = "ability.verify.uri";
const std::string DISTRIBUTED_FILES_PATH = "/data/storage/el2/distributedfiles/";
const int32_t MAX_URI_COUNT = 500;
constexpr int32_t API12 = 12;
constexpr int32_t API_VERSION_MOD = 100;
}

UriUtils::UriUtils() {}

UriUtils::~UriUtils() {}

UriUtils &UriUtils::GetInstance()
{
    static UriUtils utils;
    return utils;
}

std::vector<std::string> UriUtils::GetUriListFromWantDms(const Want &want)
{
    std::vector<std::string> uriVec = want.GetStringArrayParam(PARAMS_URI);
    TAG_LOGD(AAFwkTag::ABILITYMGR, "uriVec size: %{public}zu", uriVec.size());
    if (uriVec.size() > MAX_URI_COUNT) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "uri list size is more than %{public}u", MAX_URI_COUNT);
        return {};
    }
    std::vector<std::string> validUriVec;
    for (auto &&str : uriVec) {
        Uri uri(str);
        auto &&scheme = uri.GetScheme();
        TAG_LOGI(AAFwkTag::ABILITYMGR, "uri scheme: %{public}s", scheme.c_str());
        // only support file scheme
        if (scheme != "file") {
            TAG_LOGW(AAFwkTag::ABILITYMGR, "only support file uri");
            continue;
        }
        std::string srcPath = uri.GetPath();
        if (std::filesystem::exists(srcPath) && std::filesystem::is_symlink(srcPath)) {
            TAG_LOGE(AAFwkTag::ABILITYMGR, "soft links not allowed");
            continue;
        }
        std::string absolutePath;
        if (uri.IsRelative()) {
            char path[PATH_MAX] = {0};
            if (realpath(srcPath.c_str(), path) == nullptr) {
                TAG_LOGE(AAFwkTag::ABILITYMGR, "fail, errno :%{public}d", errno);
                continue;
            }
            absolutePath = path;
        } else {
            absolutePath = srcPath;
        }
        if (absolutePath.compare(0, DISTRIBUTED_FILES_PATH.size(), DISTRIBUTED_FILES_PATH) != 0) {
            TAG_LOGE(AAFwkTag::ABILITYMGR, "uri not distributed path");
            continue;
        }
        validUriVec.emplace_back(str);
    }
    TAG_LOGD(AAFwkTag::ABILITYMGR, "size of vaid uri is %{public}zu", validUriVec.size());
    return validUriVec;
}

void UriUtils::FilterUriWithPermissionDms(Want &want, uint32_t tokenId)
{
    TAG_LOGD(AAFwkTag::ABILITYMGR, "called");
    if ((want.GetFlags() & (Want::FLAG_AUTH_READ_URI_PERMISSION | Want::FLAG_AUTH_WRITE_URI_PERMISSION)) == 0) {
        TAG_LOGW(AAFwkTag::ABILITYMGR, "flag invalid");
        return;
    }
    auto uriVec = GetUriListFromWantDms(want);
    TAG_LOGI(AAFwkTag::ABILITYMGR, "uri valid uris size: %{public}zu", uriVec.size());
    if (uriVec.empty()) {
        TAG_LOGI(AAFwkTag::ABILITYMGR, "uriVec empty");
        want.SetParam(PARAMS_URI, uriVec);
        return;
    }
    auto checkResult = IN_PROCESS_CALL(UriPermissionManagerClient::GetInstance().CheckUriAuthorization(
        uriVec, want.GetFlags(), tokenId));
    std::vector<std::string> validUriVec;
    for (size_t i = 0; i < checkResult.size(); i++) {
        if (checkResult[i]) {
            validUriVec.emplace_back(uriVec[i]);
        }
    }
    TAG_LOGI(AAFwkTag::ABILITYMGR, "authorized uri size :%{public}zu", validUriVec.size());
    want.SetParam(PARAMS_URI, validUriVec);
}

bool UriUtils::CheckNonImplicitShareFileUri(const AbilityRequest &abilityRequest)
{
    if (abilityRequest.appInfo.apiTargetVersion % API_VERSION_MOD <= API12) {
        return true;
    }
    if (abilityRequest.want.GetElement().GetAbilityName().empty()) {
        return true;
    }
    bool isFileUri = !abilityRequest.want.GetUriString().empty() && abilityRequest.want.GetUri().GetScheme() == "file";
    if (!isFileUri && abilityRequest.want.GetStringArrayParam(AbilityConfig::PARAMS_STREAM).empty()) {
        return true;
    }
    auto flagReadWrite = Want::FLAG_AUTH_READ_URI_PERMISSION | Want::FLAG_AUTH_WRITE_URI_PERMISSION;
    if ((abilityRequest.want.GetFlags() & flagReadWrite) == 0) {
        return true;
    }
    TAG_LOGE(AAFwkTag::ABILITYMGR, "no permission");
    return false;
}

std::vector<Uri> UriUtils::GetPermissionedUriList(const std::vector<std::string> &uriVec,
    const std::vector<bool> &checkResults, Want &want)
{
    std::vector<Uri> permissionedUris;
    if (uriVec.size() != checkResults.size()) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "Invalid param: %{public}zu : %{public}zu",
            uriVec.size(), checkResults.size());
        return permissionedUris;
    }
    // process uri
    size_t startIndex = 0;
    if (!want.GetUriString().empty()) {
        if (checkResults[startIndex]) {
            permissionedUris.emplace_back(want.GetUri());
        } else if (want.GetUri().GetScheme() == "file") {
            // erase uri param
            want.SetUri("");
            TAG_LOGI(AAFwkTag::ABILITYMGR, "erase uri param.");
        }
        startIndex = 1;
    }
    // process param stream
    std::vector<std::string> paramStreamUris;
    for (size_t index = startIndex; index < checkResults.size(); index++) {
        auto uri = Uri(uriVec[index]);
        if (checkResults[index]) {
            permissionedUris.emplace_back(uri);
            paramStreamUris.emplace_back(uriVec[index]);
        } else if (uri.GetScheme() != "file") {
            paramStreamUris.emplace_back(uriVec[index]);
        }
    }
    if (paramStreamUris.size() != (checkResults.size() - startIndex)) {
        // erase old param stream and set new param stream
        want.RemoveParam(AbilityConfig::PARAMS_STREAM);
        want.SetParam(AbilityConfig::PARAMS_STREAM, paramStreamUris);
        TAG_LOGI(AAFwkTag::ABILITYMGR, "startIndex: %{public}zu, uriVec: %{public}zu, paramStreamUris: %{public}zu",
            startIndex, uriVec.size(), paramStreamUris.size());
    }
    return permissionedUris;
}

} // AAFwk
} // OHOS