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

#include "batch_uri.h"

#include "file_permission_manager.h"
#include "hilog_tag_wrapper.h"
#include "uri_permission_utils.h"

namespace OHOS {
namespace AAFwk {

int32_t BatchUri::Init(const std::vector<std::string> &uriVec, uint32_t mode,
    const std::string &callerAlterBundleName, const std::string &targetAlterBundleName)
{
    if (uriVec.empty()) {
        TAG_LOGE(AAFwkTag::URIPERMMGR, "uriVec is empty.");
        return 0;
    }
    totalUriCount = static_cast<int32_t>(uriVec.size());
    validUriCount = 0;
    checkResult = std::vector<bool>(totalUriCount, false);
    isDocsUriVec = std::vector<bool>(totalUriCount, false);
    isTargetBundleUri = std::vector<bool>(totalUriCount, false);
    bool isPrintAuthority = true;
    for (size_t index = 0; index < uriVec.size(); index++) {
        Uri uriInner = Uri(uriVec[index]);
        auto &&scheme = uriInner.GetScheme();
        if (isPrintAuthority) {
            TAG_LOGI(AAFwkTag::URIPERMMGR, "uri type: %{public}s.", uriInner.GetAuthority().c_str());
            isPrintAuthority = false;
        }
        if (scheme != "file") {
            TAG_LOGW(AAFwkTag::URIPERMMGR, "uri is invalid: %{private}s.", uriInner.ToString().c_str());
            continue;
        }
        validUriCount++;
        InitFileUriInfo(uriInner, index, mode, callerAlterBundleName, targetAlterBundleName);
    }
    TAG_LOGI(AAFwkTag::URIPERMMGR, "count of uri is %{public}d, count of valid uri is %{public}d.",
        totalUriCount, validUriCount);
    return validUriCount;
}

void BatchUri::InitFileUriInfo(Uri &uriInner, uint32_t index, const uint32_t mode,
    const std::string &callerAlterBundleName, const std::string &targetAlterBundleName)
{
    auto &&authority = uriInner.GetAuthority();
    TAG_LOGD(AAFwkTag::URIPERMMGR, "Authority of uri is %{public}s.", authority.c_str());
    // media uri
    if (authority == "media") {
        mediaUris.emplace_back(uriInner.ToString());
        mediaIndexes.emplace_back(index);
        return;
    }
    // bundle uri
    isTargetBundleUri[index] = (!targetAlterBundleName.empty() && authority == targetAlterBundleName);
    if (!callerAlterBundleName.empty() && authority == callerAlterBundleName) {
        checkResult[index] = true;
        if (isTargetBundleUri[index]) {
            TAG_LOGI(AAFwkTag::URIPERMMGR, "uri belong to targetBundle.");
            targetBundleUriCount++;
            return;
        }
        if (mode > 0) {
            // need set policy
            auto policyInfo = FilePermissionManager::GetPathPolicyInfoFromUri(uriInner, mode);
            selfBundlePolicyInfos.emplace_back(policyInfo);
        }
        return;
    }
    if (authority == "docs") {
        isDocsUriVec[index] = true;
    }
    // docs and bundle uri, need to check uri pemission
    otherUris.emplace_back(uriInner);
    otherIndexes.emplace_back(index);
}

void BatchUri::SetMediaUriCheckResult(const std::vector<bool> &mediaUriResult)
{
    for (size_t i = 0; i < mediaUriResult.size(); i++) {
        auto index = mediaIndexes[i];
        checkResult[index] = mediaUriResult[i];
    }
}

void BatchUri::SetOtherUriCheckResult(const std::vector<bool> &otherUriResult)
{
    for (size_t i = 0; i < otherUriResult.size(); i++) {
        auto index = otherIndexes[i];
        checkResult[index] = otherUriResult[i];
        if (checkResult[index] && isTargetBundleUri[index]) {
            targetBundleUriCount++;
        }
    }
}

int32_t BatchUri::GetMediaUriToGrant(std::vector<std::string> &uriVec)
{
    for (size_t i = 0; i < mediaIndexes.size(); i++) {
        if (checkResult[mediaIndexes[i]]) {
            uriVec.emplace_back(mediaUris[i]);
        }
    }
    return uriVec.size();
}

void BatchUri::GetNeedCheckProxyPermissionURI(std::vector<PolicyInfo> &proxyUrisByPolicy,
    std::vector<Uri> &proxyUrisByMap)
{
    // docs uri and bundle uri
    for (size_t i = 0; i < otherIndexes.size(); i++) {
        auto index = otherIndexes[i];
        if (!checkResult[index]) {
            proxyIndexesByPolicy.emplace_back(index);
            proxyUrisByPolicy.emplace_back(otherPolicyInfos[i]);
        }
    }
}

void BatchUri::SetCheckProxyByMapResult(std::vector<bool> &proxyResultByMap)
{
    for (size_t i = 0; i < proxyResultByMap.size(); i++) {
        auto index = proxyIndexesByMap[i];
        checkResult[index] = proxyResultByMap[i];
    }
    proxyIndexesByMap.clear();
}

void BatchUri::SetCheckProxyByPolicyResult(std::vector<bool> &proxyResultByPolicy)
{
    for (size_t i = 0; i < proxyResultByPolicy.size(); i++) {
        auto index = proxyIndexesByPolicy[i];
        checkResult[index] = proxyResultByPolicy[i];
    }
    proxyIndexesByPolicy.clear();
}

int32_t BatchUri::GetUriToGrantByMap(std::vector<std::string> &uriVec)
{
    return uriVec.size();
}

void BatchUri::SelectPermissionedUri(std::vector<Uri> &uris, std::vector<int32_t> &indexs,
    std::vector<std::string> &uriVec)
{
    for (size_t i = 0; i < indexs.size(); i++) {
        if (checkResult[indexs[i]]) {
            auto uriStr = uris[i].ToString();
            uriVec.emplace_back(uriStr);
        }
    }
}

int32_t BatchUri::GetUriToGrantByPolicy(std::vector<PolicyInfo> &docsPolicyInfoVec,
    std::vector<PolicyInfo> &bundlePolicyInfoVec)
{
    // bundleName + docs
    int32_t count = 0;
    for (auto &selfBundleUriPolicy : selfBundlePolicyInfos) {
        bundlePolicyInfoVec.emplace_back(selfBundleUriPolicy);
        count++;
    }
    for (size_t i = 0; i < otherPolicyInfos.size(); i++) {
        auto index = otherIndexes[i];
        if (!checkResult[index]) {
            continue;
        }
        // the uri belong to target app.
        if (isTargetBundleUri[index]) {
            continue;
        }
        TAG_LOGD(AAFwkTag::URIPERMMGR, "Add policy: path is %{private}s, mode is %{public}u.",
            otherPolicyInfos[i].path.c_str(), static_cast<uint32_t>(otherPolicyInfos[i].mode));
        if (isDocsUriVec[index]) {
            docsPolicyInfoVec.emplace_back(otherPolicyInfos[i]);
        } else {
            bundlePolicyInfoVec.emplace_back(otherPolicyInfos[i]);
        }
        count++;
    }
    return count;
}

bool BatchUri::GetUriToGrantByPolicy(std::vector<PolicyInfo> &policyVec)
{
    // self bundle uris
    for (const auto &selfBundleUriPolicy : selfBundlePolicyInfos) {
        policyVec.emplace_back(selfBundleUriPolicy);
    }
    for (size_t i = 0; i < otherPolicyInfos.size(); i++) {
        auto index = otherIndexes[i];
        if (!checkResult[index]) {
            return false;
        }
        // the uri belong to target app.
        if (isTargetBundleUri[index]) {
            continue;
        }
        policyVec.emplace_back(otherPolicyInfos[i]);
    }
    return true;
}

int32_t BatchUri::GetPermissionedUriCount()
{
    int32_t permissionedUriCount = 0;
    for (auto checkRes: checkResult) {
        if (checkRes) {
            permissionedUriCount++;
        }
    }
    return permissionedUriCount;
}

bool BatchUri::IsAllUriValid()
{
    return validUriCount == totalUriCount;
}

bool BatchUri::IsAllUriPermissioned()
{
    for (auto checkRes : checkResult) {
        if (!checkRes) {
            return false;
        }
    }
    return true;
}
} // OHOS
} // AAFwk