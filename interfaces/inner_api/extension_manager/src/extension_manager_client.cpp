/*
 * Copyright (c) 2023-2025 Huawei Device Co., Ltd.
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

#include "ability_manager_errors.h"
#include "extension_ability_info.h"
#include "extension_manager_client.h"
#include "extension_manager_proxy.h"
#include "extension_running_info.h"
#include "hilog_tag_wrapper.h"
#include "hitrace_meter.h"
#include "iservice_registry.h"
#include "system_ability_definition.h"
#include "want.h"

namespace OHOS {
namespace AAFwk {
#define CHECK_POINTER_RETURN(object)                        \
if (!object) {                                          \
    TAG_LOGE(AAFwkTag::EXTMGR, "null proxy"); \
    return;                                             \
}

#define CHECK_POINTER_RETURN_NOT_CONNECTED(object)           \
    if (!object) {                                           \
        TAG_LOGE(AAFwkTag::EXTMGR, "null proxy"); \
        return ABILITY_SERVICE_NOT_CONNECTED;                \
    }

#define CHECK_POINTER_RETURN_INVALID_VALUE(object)           \
    if (!object) {                                           \
        TAG_LOGE(AAFwkTag::EXTMGR, "null proxy"); \
        return ERR_INVALID_VALUE;                            \
    }

ExtensionManagerClient& ExtensionManagerClient::GetInstance()
{
    static ExtensionManagerClient instance;
    return instance;
}

sptr<IExtensionManager> ExtensionManagerClient::GetExtensionManager()
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (proxy_ == nullptr) {
        Connect();
    }

    return proxy_;
}

void ExtensionManagerClient::Connect()
{
    auto systemManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (systemManager == nullptr) {
        TAG_LOGE(AAFwkTag::EXTMGR, "Get SAMgr failed");
        return;
    }
    auto remoteObj = systemManager->GetSystemAbility(ABILITY_MGR_SERVICE_ID);
    if (remoteObj == nullptr) {
        TAG_LOGE(AAFwkTag::EXTMGR, "Connect AMS failed");
        return;
    }

    deathRecipient_ = new ExtensionMgrDeathRecipient();
    if (remoteObj->IsProxyObject() && !remoteObj->AddDeathRecipient(deathRecipient_)) {
        TAG_LOGE(AAFwkTag::EXTMGR, "AddDeathRecipient failed");
        return;
    }

    proxy_ = sptr<IExtensionManager>(new ExtensionManagerProxy(remoteObj));
    TAG_LOGD(AAFwkTag::EXTMGR, "Connect AMS success");
}

void ExtensionManagerClient::ResetProxy(const wptr<IRemoteObject> &remote)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (proxy_ == nullptr) {
        TAG_LOGI(AAFwkTag::EXTMGR, "null proxy_, no need reset");
        return;
    }

    auto serviceRemote = proxy_->AsObject();
    if (serviceRemote != nullptr && serviceRemote == remote.promote()) {
        serviceRemote->RemoveDeathRecipient(deathRecipient_);
        proxy_ = nullptr;
    }
}

void ExtensionManagerClient::ExtensionMgrDeathRecipient::OnRemoteDied(const wptr<IRemoteObject> &remote)
{
    TAG_LOGI(AAFwkTag::EXTMGR, "called");
    ExtensionManagerClient::GetInstance().ResetProxy(remote);
}

ErrCode ExtensionManagerClient::ConnectServiceExtensionAbility(const Want &want,
    const sptr<IRemoteObject> &connect, int32_t userId)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    auto abms = GetExtensionManager();
    if (abms == nullptr) {
        TAG_LOGE(AAFwkTag::EXTMGR, "Connect failed, bundleName:%{public}s, abilityName:%{public}s.",
            want.GetElement().GetBundleName().c_str(), want.GetElement().GetAbilityName().c_str());
        return ABILITY_SERVICE_NOT_CONNECTED;
    }
    TAG_LOGD(AAFwkTag::EXTMGR, "name:%{public}s %{public}s, userId:%{public}d.",
        want.GetElement().GetBundleName().c_str(), want.GetElement().GetAbilityName().c_str(), userId);
    return abms->ConnectAbilityCommon(want, connect, nullptr, AppExecFwk::ExtensionAbilityType::SERVICE,
        userId, false);
}

ErrCode ExtensionManagerClient::ConnectServiceExtensionAbility(const Want &want,
    const sptr<IRemoteObject> &connect, const sptr<IRemoteObject> &callerToken, int32_t userId)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    auto abms = GetExtensionManager();
    if (abms == nullptr) {
        TAG_LOGE(AAFwkTag::EXTMGR, "Connect failed, bundleName:%{public}s, abilityName:%{public}s.",
            want.GetElement().GetBundleName().c_str(), want.GetElement().GetAbilityName().c_str());
        return ABILITY_SERVICE_NOT_CONNECTED;
    }
    TAG_LOGI(AAFwkTag::EXTMGR, "name:%{public}s %{public}s, userId:%{public}d.",
        want.GetElement().GetBundleName().c_str(), want.GetElement().GetAbilityName().c_str(), userId);
    return abms->ConnectAbilityCommon(
        want, connect, callerToken, AppExecFwk::ExtensionAbilityType::SERVICE, userId, false);
}

ErrCode ExtensionManagerClient::ConnectEnterpriseAdminExtensionAbility(const Want &want,
    const sptr<IRemoteObject> &connect, const sptr<IRemoteObject> &callerToken, int32_t userId)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    auto abms = GetExtensionManager();
    if (abms == nullptr) {
        TAG_LOGE(AAFwkTag::EXTMGR, "Connect failed, bundleName:%{public}s, abilityName:%{public}s.",
            want.GetElement().GetBundleName().c_str(), want.GetElement().GetAbilityName().c_str());
        return ABILITY_SERVICE_NOT_CONNECTED;
    }
    TAG_LOGI(AAFwkTag::EXTMGR, "name:%{public}s %{public}s, userId:%{public}d.",
        want.GetElement().GetBundleName().c_str(), want.GetElement().GetAbilityName().c_str(), userId);
    return abms->ConnectAbilityCommon(
        want, connect, callerToken, AppExecFwk::ExtensionAbilityType::ENTERPRISE_ADMIN, userId, true);
}

ErrCode ExtensionManagerClient::ConnectExtensionAbility(const Want &want, const sptr<IRemoteObject> &connect,
    int32_t userId)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    auto abms = GetExtensionManager();
    if (abms == nullptr) {
        TAG_LOGE(AAFwkTag::EXTMGR, "Connect failed, bundleName:%{public}s, abilityName:%{public}s",
            want.GetElement().GetBundleName().c_str(), want.GetElement().GetAbilityName().c_str());
        return ABILITY_SERVICE_NOT_CONNECTED;
    }

    TAG_LOGI(AAFwkTag::EXTMGR, "bundleName: %{public}s, abilityName: %{public}s, userId: %{public}d.",
        want.GetElement().GetBundleName().c_str(), want.GetElement().GetAbilityName().c_str(), userId);
    return abms->ConnectAbilityCommon(want, connect, nullptr, AppExecFwk::ExtensionAbilityType::UNSPECIFIED, userId);
}

ErrCode ExtensionManagerClient::DisconnectAbility(const sptr<IRemoteObject> &connect)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    auto abms = GetExtensionManager();
    CHECK_POINTER_RETURN_NOT_CONNECTED(abms);
    TAG_LOGI(AAFwkTag::EXTMGR, "call");
    return abms->DisconnectAbility(connect);
}

ErrCode ExtensionManagerClient::Release()
{
    TAG_LOGI(AAFwkTag::EXTMGR, "Release");
    return RemoveDeathRecipient();
}

ErrCode ExtensionManagerClient::RemoveDeathRecipient()
{
    TAG_LOGI(AAFwkTag::EXTMGR, "RemoveDeathRecipient");
    std::lock_guard<std::mutex> lock(mutex_);
    if (proxy_ == nullptr) {
        TAG_LOGW(AAFwkTag::EXTMGR, "null proxy_");
        return ERR_NULL_OBJECT;
    }
    if (deathRecipient_ == nullptr) {
        TAG_LOGW(AAFwkTag::EXTMGR, "null deathRecipient_");
        return ERR_NULL_OBJECT;
    }
    auto serviceRemote = proxy_->AsObject();
    if (serviceRemote == nullptr) {
        TAG_LOGW(AAFwkTag::EXTMGR, "null serviceRemote");
        return ERR_NULL_OBJECT;
    }
    bool ret = serviceRemote->RemoveDeathRecipient(deathRecipient_);
    if (!ret) {
        TAG_LOGW(AAFwkTag::EXTMGR, "RemoveDeathRecipient fail");
        return ERR_INVALID_VALUE;
    }
    proxy_ = nullptr;
    deathRecipient_ = nullptr;
    TAG_LOGI(AAFwkTag::EXTMGR, "RemoveDeathRecipient success");
    return ERR_OK;
}

ErrCode ExtensionManagerClient::StartExtensionAbility(const Want &want, sptr<IRemoteObject> callerToken,
    int32_t userId, AppExecFwk::ExtensionAbilityType extensionType)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    auto abms = GetExtensionManager();
    CHECK_POINTER_RETURN_NOT_CONNECTED(abms);
    TAG_LOGI(AAFwkTag::EXTMGR, "name:%{public}s %{public}s, userId=%{public}d.",
        want.GetElement().GetAbilityName().c_str(), want.GetElement().GetBundleName().c_str(), userId);
    return abms->StartExtensionAbility(want, callerToken, userId, extensionType);
}

ErrCode ExtensionManagerClient::StopExtensionAbility(const Want &want, sptr<IRemoteObject> callerToken,
    int32_t userId, AppExecFwk::ExtensionAbilityType extensionType)
{
    auto abms = GetExtensionManager();
    CHECK_POINTER_RETURN_NOT_CONNECTED(abms);
    TAG_LOGI(AAFwkTag::EXTMGR, "name:%{public}s %{public}s, userId=%{public}d.",
        want.GetElement().GetAbilityName().c_str(), want.GetElement().GetBundleName().c_str(), userId);
    return abms->StopExtensionAbility(want, callerToken, userId, extensionType);
}

ErrCode ExtensionManagerClient::GetExtensionRunningInfos(int upperLimit, std::vector<ExtensionRunningInfo> &info)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    auto abms = GetExtensionManager();
    CHECK_POINTER_RETURN_NOT_CONNECTED(abms);
    return abms->GetExtensionRunningInfos(upperLimit, info);
}

int32_t ExtensionManagerClient::TransferAbilityResultForExtension(const sptr<IRemoteObject> &callerToken,
    int32_t resultCode, const Want &want)
{
    auto abms = GetExtensionManager();
    CHECK_POINTER_RETURN_INVALID_VALUE(abms);
    return abms->TransferAbilityResultForExtension(callerToken, resultCode, want);
}
}  // namespace AAFwk
}  // namespace OHOS
