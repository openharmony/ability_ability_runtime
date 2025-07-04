/*
 * Copyright (c) 2022-2025 Huawei Device Co., Ltd.
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

#include "mock_quick_fix_util.h"

#include "hilog_tag_wrapper.h"
#include "if_system_ability_manager.h"
#include "iservice_registry.h"
#include "system_ability_definition.h"

namespace OHOS {
namespace AAFwk {
std::mutex QuickFixUtil::saMutex_;
std::unordered_map<int32_t, sptr<IRemoteObject>> QuickFixUtil::servicesMap_;
bool QuickFixUtil::setAppManagerProxyNull_ = false;
bool QuickFixUtil::setBundleMgrProxyNull_ = false;

sptr<IRemoteObject> QuickFixUtil::GetRemoteObjectOfSystemAbility(const int32_t systemAbilityId)
{
    std::lock_guard<std::mutex> lock(saMutex_);
    if (servicesMap_[systemAbilityId] == nullptr) {
        auto systemAbilityMgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
        if (systemAbilityMgr == nullptr) {
            TAG_LOGE(AAFwkTag::TEST, "Failed to get SystemAbilityManager.");
            return nullptr;
        }

        auto object = systemAbilityMgr->GetSystemAbility(systemAbilityId);
        servicesMap_[systemAbilityId] = object;
    }

    return servicesMap_[systemAbilityId];
}

sptr<AppExecFwk::IAppMgr> QuickFixUtil::GetAppManagerProxy()
{
    if (setAppManagerProxyNull_) {
        return nullptr;
    }
    return iface_cast<AppExecFwk::IAppMgr>(GetRemoteObjectOfSystemAbility(APP_MGR_SERVICE_ID));
}

sptr<AppExecFwk::IBundleMgr> QuickFixUtil::GetBundleManagerProxy()
{
    if (setBundleMgrProxyNull_) {
        return nullptr;
    }
    return iface_cast<AppExecFwk::IBundleMgr>(GetRemoteObjectOfSystemAbility(BUNDLE_MGR_SERVICE_SYS_ABILITY_ID));
}

sptr<AppExecFwk::IQuickFixManager> QuickFixUtil::GetBundleQuickFixMgrProxy()
{
    TAG_LOGD(AAFwkTag::TEST, "function called.");
    auto bundleMgr = GetBundleManagerProxy();
    if (bundleMgr == nullptr) {
        TAG_LOGE(AAFwkTag::TEST, "Failed to get bms.");
        return nullptr;
    }

    auto bundleQuickFixMgr = bundleMgr->GetQuickFixManagerProxy();
    if (bundleQuickFixMgr == nullptr) {
        TAG_LOGE(AAFwkTag::TEST, "Failed to get bundle quick fix manager.");
        return nullptr;
    }

    TAG_LOGD(AAFwkTag::TEST, "function finished.");
    return bundleQuickFixMgr;
}

void QuickFixUtil::RegisterSystemAbility(const int32_t systemAbilityId, sptr<IRemoteObject> object)
{
    std::lock_guard<std::mutex> lock(saMutex_);
    servicesMap_[systemAbilityId] = object;
}
} // namespace AAFwk
} // namespace OHOS
