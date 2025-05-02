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

#include "uri_permission_utils.h"

#include "ability_manager_errors.h"
#include "accesstoken_kit.h"
#include "bundle_mgr_client.h"
#include "global_constant.h"
#include "hilog_tag_wrapper.h"
#include "in_process_call_wrapper.h"
#include "ipc_skeleton.h"
#include "os_account_manager_wrapper.h"
#include "permission_verification.h"
#include "tokenid_kit.h"
#include "mock_my_flag.h"

namespace OHOS {
namespace AAFwk {
using MyFlag = OHOS::AAFwk::MyFlag;

std::shared_ptr<AppExecFwk::BundleMgrHelper> UPMSUtils::ConnectManagerHelper()
{
    return bundleMgrHelper_;
}

bool UPMSUtils::SendShareUnPrivilegeUriEvent(uint32_t callerTokenId, uint32_t targetTokenId)
{
    return true;
}

bool UPMSUtils::SendSystemAppGrantUriPermissionEvent(uint32_t callerTokenId, uint32_t targetTokenId,
    const std::vector<Uri> &uriVec, const std::vector<bool> &resVec)
{
    return true;
}

bool UPMSUtils::CheckAndCreateEventInfo(uint32_t callerTokenId, uint32_t targetTokenId,
    EventInfo &eventInfo)
{
    return true;
}

int32_t UPMSUtils::GetCurrentAccountId()
{
    return 1;
}

bool UPMSUtils::IsFoundationCall()
{
    return true;
}

bool UPMSUtils::IsSAOrSystemAppCall()
{
    return MyFlag::isSAOrSystemAppCall_;
}

bool UPMSUtils::IsSystemAppCall()
{
    return MyFlag::isSystemAppCall_;
}

bool UPMSUtils::CheckIsSystemAppByBundleName(std::string &bundleName)
{
    return true;
}

bool UPMSUtils::GetBundleApiTargetVersion(const std::string &bundleName, int32_t &targetApiVersion)
{
    return true;
}

bool UPMSUtils::CheckIsSystemAppByTokenId(uint32_t tokenId)
{
    return false;
}

bool UPMSUtils::GetDirByBundleNameAndAppIndex(const std::string &bundleName, int32_t appIndex, std::string &dirName)
{
    return true;
}

bool UPMSUtils::GetAlterableBundleNameByTokenId(uint32_t tokenId, std::string &bundleName)
{
    bundleName = MyFlag::bundleName_;
    return true;
}

bool UPMSUtils::GetBundleNameByTokenId(uint32_t tokenId, std::string &bundleName)
{
    return false;
}

int32_t UPMSUtils::GetAppIdByBundleName(const std::string &bundleName, std::string &appId)
{
    return ERR_OK;
}

int32_t UPMSUtils::GetTokenIdByBundleName(const std::string &bundleName, int32_t appIndex, uint32_t &tokenId)
{
    return MyFlag::getTokenIdByBundleNameStatus_;
}

bool UPMSUtils::CheckUriTypeIsValid(Uri &uri)
{
    return MyFlag::isUriTypeValid_;
}

bool UPMSUtils::IsDocsCloudUri(Uri &uri)
{
    return MyFlag::isDocsCloudUri_;
}

std::shared_ptr<AppExecFwk::BundleMgrHelper> UPMSUtils::bundleMgrHelper_ = nullptr;
}  // namespace AAFwk
}  // namespace OHOS
