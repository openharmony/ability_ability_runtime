/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "common_extension_manager.h"

#include "ability_cache_manager.h"
#include "ability_util.h"
#include "hilog_tag_wrapper.h"
#include "hitrace_meter.h"
#include "multi_instance_utils.h"
#include "ui_extension_utils.h"
#include "appfreeze_manager.h"

namespace OHOS {
namespace AAFwk {
namespace {
const std::string FRS_BUNDLE_NAME = "com.ohos.formrenderservice";
const std::string FRS_APP_INDEX = "ohos.extra.param.key.frs_index";
}

CommonExtensionManager::CommonExtensionManager(int userId) : AbilityConnectManager(userId)
{}

CommonExtensionManager::~CommonExtensionManager()
{}

void CommonExtensionManager::GetOrCreateServiceRecord(const AbilityRequest &abilityRequest,
    const bool isCreatedByConnect, std::shared_ptr<BaseExtensionRecord> &targetService, bool &isLoadedAbility)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    // lifecycle is not complete when window extension is reused
    bool noReuse = UIExtensionUtils::IsWindowExtension(abilityRequest.abilityInfo.extensionAbilityType);
    AppExecFwk::ElementName element(abilityRequest.abilityInfo.deviceId, GenerateBundleName(abilityRequest),
        abilityRequest.abilityInfo.name, abilityRequest.abilityInfo.moduleName);
    std::string serviceKey = element.GetURI();
    if (FRS_BUNDLE_NAME == abilityRequest.abilityInfo.bundleName) {
        serviceKey = element.GetURI() + std::to_string(abilityRequest.want.GetIntParam(FRS_APP_INDEX, 0));
    }
    {
        std::lock_guard lock(serviceMapMutex_);
        auto serviceMapIter = serviceMap_.find(serviceKey);
        targetService = serviceMapIter == serviceMap_.end() ? nullptr : serviceMapIter->second;
    }
    if (targetService == nullptr &&
        IsCacheExtensionAbilityByInfo(abilityRequest.abilityInfo)) {
        targetService = AbilityCacheManager::GetInstance().Get(abilityRequest);
        if (targetService != nullptr) {
            CallAddToServiceMap(serviceKey, targetService);
        }
    }
    if (noReuse && targetService) {
        if (IsSpecialAbility(abilityRequest.abilityInfo)) {
            TAG_LOGI(AAFwkTag::EXT, "removing ability: %{public}s/%{public}s",
                element.GetBundleName().c_str(),
                element.GetAbilityName().c_str());
        }
        RemoveServiceFromMapSafe(serviceKey);
    }
    isLoadedAbility = true;
    if (noReuse || targetService == nullptr) {
        targetService = BaseExtensionRecord::CreateBaseExtensionRecord(abilityRequest);
        CHECK_POINTER(targetService);
        targetService->SetOwnerMissionUserId(userId_);
        if (isCreatedByConnect) {
            targetService->SetCreateByConnectMode();
        }
        SetServiceAfterNewCreate(abilityRequest, *targetService);
        CallAddToServiceMap(serviceKey, targetService);
        isLoadedAbility = false;
    }
    TAG_LOGD(AAFwkTag::EXT, "service map add, serviceKey: %{public}s", serviceKey.c_str());
}

void CommonExtensionManager::SetServiceAfterNewCreate(const AbilityRequest &abilityRequest,
    BaseExtensionRecord &targetService)
{
    if (abilityRequest.abilityInfo.name == AbilityConfig::LAUNCHER_ABILITY_NAME) {
        targetService.SetLauncherRoot();
        if (abilityRequest.restart) {
            targetService.SetRestartTime(abilityRequest.restartTime);
            targetService.SetRestartCount(abilityRequest.restartCount);
        }
    } else if (IsAbilityNeedKeepAlive(BaseExtensionRecord::TransferToExtensionRecordBase(
        targetService.shared_from_this())) && abilityRequest.restart) {
        targetService.SetRestartTime(abilityRequest.restartTime);
        targetService.SetRestartCount(abilityRequest.restartCount);
    }
    if (MultiInstanceUtils::IsMultiInstanceApp(abilityRequest.appInfo)) {
        targetService.SetInstanceKey(MultiInstanceUtils::GetValidExtensionInstanceKey(abilityRequest));
    }
    if (targetService.IsSceneBoard()) {
        TAG_LOGI(AAFwkTag::EXT, "create sceneboard");
        sceneBoardTokenId_ = abilityRequest.appInfo.accessTokenId;
    }
}

int CommonExtensionManager::AttachAbilityThreadInner(const sptr<IAbilityScheduler> &scheduler,
    const sptr<IRemoteObject> &token)
{
    auto abilityRecord = GetExtensionByTokenFromServiceMap(token);
    if (abilityRecord == nullptr) {
        auto terminatingRecord = GetExtensionByTokenFromTerminatingMap(token);
        if (terminatingRecord != nullptr) {
            TAG_LOGW(AAFwkTag::EXT, "Ability:%{public}s/%{public}s, user:%{public}d",
                terminatingRecord->GetElementName().GetBundleName().c_str(),
                terminatingRecord->GetElementName().GetAbilityName().c_str(), userId_);
        }
        auto tmpRecord = Token::GetAbilityRecordByToken(token);
        if (tmpRecord && tmpRecord != terminatingRecord) {
            TAG_LOGW(AAFwkTag::EXT, "Token:%{public}s/%{public}s, user:%{public}d",
                tmpRecord->GetElementName().GetBundleName().c_str(),
                tmpRecord->GetElementName().GetAbilityName().c_str(), userId_);
        }
    }
    CHECK_POINTER_AND_RETURN(abilityRecord, ERR_INVALID_VALUE);
    std::string element = abilityRecord->GetURI();
    TAG_LOGD(AAFwkTag::EXT, "ability:%{public}s", element.c_str());
    abilityRecord->RemoveLoadTimeoutTask();
    AbilityRuntime::FreezeUtil::GetInstance().DeleteLifecycleEvent(token);
    abilityRecord->SetScheduler(scheduler);
    TAG_LOGD(AAFwkTag::EXT, "Inactivate");
    abilityRecord->Inactivate();
    return ERR_OK;
}

int CommonExtensionManager::GetOrCreateExtensionRecord(const AbilityRequest &abilityRequest,
    std::shared_ptr<BaseExtensionRecord> &targetService, bool &isLoadedAbility)
{
    GetOrCreateServiceRecord(abilityRequest, true, targetService, isLoadedAbility);
    CHECK_POINTER_AND_RETURN(targetService, ERR_INVALID_VALUE);
    return ERR_OK;
}
}  // namespace AAFwk
}  // namespace OHOS