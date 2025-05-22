/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#include "ability_context_impl.h"

#include <native_engine/native_engine.h>

#include "ability_manager_client.h"
#include "hitrace_meter.h"
#include "connection_manager.h"
#include "dialog_request_callback_impl.h"
#include "dialog_ui_extension_callback.h"
#include "hilog_tag_wrapper.h"
#include "json_utils.h"
#include "remote_object_wrapper.h"
#include "request_constants.h"
#include "session_info.h"
#include "string_wrapper.h"
#ifdef SUPPORT_SCREEN
#include "session/host/include/zidl/session_interface.h"
#include "scene_board_judgement.h"
#include "ui_content.h"
#endif // SUPPORT_SCREEN
#include "want_params_wrapper.h"
#include "configuration_convertor.h"
#include "application_configuration_manager.h"

namespace OHOS {
namespace AbilityRuntime {
const size_t AbilityContext::CONTEXT_TYPE_ID(std::hash<const char*> {} ("AbilityContext"));
constexpr const char* START_ABILITY_TYPE = "ABILITY_INNER_START_WITH_ACCOUNT";
constexpr const char* UIEXTENSION_TARGET_TYPE_KEY = "ability.want.params.uiExtensionTargetType";
constexpr const char* FLAG_AUTH_READ_URI_PERMISSION = "ability.want.params.uriPermissionFlag";
constexpr const char* DISPOSED_PROHIBIT_BACK = "APPGALLERY_APP_DISPOSED_PROHIBIT_BACK";
constexpr const char* IS_WINDOWMODE_FOLLOWHOST = "ohos.uec.params.isWindowModeFollowHost";
constexpr const char* USE_GLOBAL_UICONTENT = "ohos.uec.params.useGlobalUIContent";
constexpr const int32_t ERR_NOT_SUPPORTED = -2;
const std::string JSON_KEY_ERR_MSG = "errMsg";

struct RequestResult {
    int32_t resultCode {0};
    AAFwk::Want resultWant;
    RequestDialogResultTask task;
};

Global::Resource::DeviceType AbilityContextImpl::GetDeviceType() const
{
    return (stageContext_ != nullptr) ? stageContext_->GetDeviceType() : Global::Resource::DeviceType::DEVICE_PHONE;
}

std::string AbilityContextImpl::GetBaseDir() const
{
    return stageContext_ ? stageContext_->GetBaseDir() : "";
}

std::string AbilityContextImpl::GetBundleCodeDir()
{
    return stageContext_ ? stageContext_->GetBundleCodeDir() : "";
}

std::string AbilityContextImpl::GetCacheDir()
{
    return stageContext_ ? stageContext_->GetCacheDir() : "";
}

std::string AbilityContextImpl::GetDatabaseDir()
{
    return stageContext_ ? stageContext_->GetDatabaseDir() : "";
}

int32_t AbilityContextImpl::GetSystemDatabaseDir(const std::string &groupId, bool checkExist, std::string &databaseDir)
{
    return stageContext_ ?
        stageContext_->GetSystemDatabaseDir(groupId, checkExist, databaseDir) : ERR_INVALID_VALUE;
}

std::string AbilityContextImpl::GetPreferencesDir()
{
    return stageContext_ ? stageContext_->GetPreferencesDir() : "";
}

int AbilityContextImpl::GetSystemPreferencesDir(const std::string &groupId, bool checkExist,
    std::string &preferencesDir)
{
    return stageContext_ ?
        stageContext_->GetSystemPreferencesDir(groupId, checkExist, preferencesDir) : ERR_INVALID_VALUE;
}

std::string AbilityContextImpl::GetGroupDir(std::string groupId)
{
    return stageContext_ ? stageContext_->GetGroupDir(groupId) : "";
}

std::string AbilityContextImpl::GetTempDir()
{
    return stageContext_ ? stageContext_->GetTempDir() : "";
}

std::string AbilityContextImpl::GetResourceDir(const std::string &moduleName)
{
    return stageContext_ ? stageContext_->GetResourceDir(moduleName) : "";
}

std::string AbilityContextImpl::GetFilesDir()
{
    return stageContext_ ? stageContext_->GetFilesDir() : "";
}

std::string AbilityContextImpl::GetDistributedFilesDir()
{
    return stageContext_ ? stageContext_->GetDistributedFilesDir() : "";
}

std::string AbilityContextImpl::GetCloudFileDir()
{
    return stageContext_ ? stageContext_->GetCloudFileDir() : "";
}

bool AbilityContextImpl::IsUpdatingConfigurations()
{
    return stageContext_ ? stageContext_->IsUpdatingConfigurations() : false;
}

bool AbilityContextImpl::PrintDrawnCompleted()
{
    return stageContext_ ? stageContext_->PrintDrawnCompleted() : false;
}

void AbilityContextImpl::SwitchArea(int mode)
{
    TAG_LOGD(AAFwkTag::CONTEXT, "mode:%{public}d", mode);
    if (stageContext_ != nullptr) {
        stageContext_->SwitchArea(mode);
    }
}

int AbilityContextImpl::GetArea()
{
    TAG_LOGD(AAFwkTag::CONTEXT, "called");
    if (stageContext_ == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null stageContext");
        return ContextImpl::EL_DEFAULT;
    }
    return stageContext_->GetArea();
}

std::string AbilityContextImpl::GetProcessName()
{
    return stageContext_ ? stageContext_->GetProcessName() : "";
}

ErrCode AbilityContextImpl::StartAbility(const AAFwk::Want& want, int requestCode)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    TAG_LOGD(AAFwkTag::CONTEXT, "called");
    ErrCode err = AAFwk::AbilityManagerClient::GetInstance()->StartAbility(want, token_, requestCode);
    if (err != ERR_OK) {
        TAG_LOGE(AAFwkTag::CONTEXT, "ret=%{public}d", err);
    }
    return err;
}

ErrCode AbilityContextImpl::StartAbilityAsCaller(const AAFwk::Want &want, int requestCode)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    TAG_LOGD(AAFwkTag::CONTEXT, "called");
    ErrCode err = AAFwk::AbilityManagerClient::GetInstance()->StartAbilityAsCaller(want, token_, nullptr, requestCode);
    if (err != ERR_OK) {
        TAG_LOGE(AAFwkTag::CONTEXT, "ret=%{public}d", err);
    }
    return err;
}

ErrCode AbilityContextImpl::StartAbilityWithAccount(const AAFwk::Want& want, int accountId, int requestCode)
{
    TAG_LOGD(AAFwkTag::CONTEXT, "called");
    (const_cast<Want &>(want)).SetParam(START_ABILITY_TYPE, true);
    ErrCode err = AAFwk::AbilityManagerClient::GetInstance()->StartAbility(want, token_, requestCode, accountId);
    if (err != ERR_OK) {
        TAG_LOGE(AAFwkTag::CONTEXT, "ret=%{public}d", err);
    }
    return err;
}

ErrCode AbilityContextImpl::StartAbility(const AAFwk::Want& want, const AAFwk::StartOptions& startOptions,
    int requestCode)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    TAG_LOGD(AAFwkTag::CONTEXT, "called");
    ErrCode err = AAFwk::AbilityManagerClient::GetInstance()->StartAbility(want, startOptions, token_, requestCode);
    if (err != ERR_OK) {
        TAG_LOGE(AAFwkTag::CONTEXT, "ret=%{public}d", err);
    }
    return err;
}

ErrCode AbilityContextImpl::StartAbilityAsCaller(const AAFwk::Want &want, const AAFwk::StartOptions &startOptions,
    int requestCode)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    TAG_LOGD(AAFwkTag::CONTEXT, "called");
    ErrCode err = AAFwk::AbilityManagerClient::GetInstance()->StartAbilityAsCaller(want,
        startOptions, token_, nullptr, requestCode);
    if (err != ERR_OK) {
        TAG_LOGE(AAFwkTag::CONTEXT, "ret=%{public}d", err);
    }
    return err;
}

ErrCode AbilityContextImpl::StartAbilityWithAccount(
    const AAFwk::Want& want, int accountId, const AAFwk::StartOptions& startOptions, int requestCode)
{
    TAG_LOGD(AAFwkTag::CONTEXT, "name:%{public}s %{public}s, accountId=%{public}d",
        want.GetElement().GetBundleName().c_str(), want.GetElement().GetAbilityName().c_str(), accountId);
    (const_cast<Want &>(want)).SetParam(START_ABILITY_TYPE, true);
    ErrCode err = AAFwk::AbilityManagerClient::GetInstance()->StartAbility(
        want, startOptions, token_, requestCode, accountId);
    if (err != ERR_OK) {
        TAG_LOGE(AAFwkTag::CONTEXT, "ret=%{public}d", err);
    }
    return err;
}

ErrCode AbilityContextImpl::StartAbilityForResult(const AAFwk::Want& want, int requestCode, RuntimeTask&& task)
{
    TAG_LOGD(AAFwkTag::CONTEXT, "called");
    resultCallbacks_.insert(make_pair(requestCode, std::move(task)));
    ErrCode err = AAFwk::AbilityManagerClient::GetInstance()->StartAbility(want, token_, requestCode, -1);
    if (err != ERR_OK && err != AAFwk::START_ABILITY_WAITING) {
        TAG_LOGE(AAFwkTag::CONTEXT, "ret=%{public}d", err);
        OnAbilityResultInner(requestCode, err, want);
    }
    return err;
}

ErrCode AbilityContextImpl::StartAbilityForResultWithAccount(
    const AAFwk::Want& want, const int accountId, int requestCode, RuntimeTask&& task)
{
    TAG_LOGD(AAFwkTag::CONTEXT, "accountId:%{private}d", accountId);
    resultCallbacks_.insert(make_pair(requestCode, std::move(task)));
    ErrCode err = AAFwk::AbilityManagerClient::GetInstance()->StartAbility(want, token_, requestCode, accountId);
    if (err != ERR_OK && err != AAFwk::START_ABILITY_WAITING) {
        TAG_LOGE(AAFwkTag::CONTEXT, "ret=%{public}d", err);
        OnAbilityResultInner(requestCode, err, want);
    }
    return err;
}

ErrCode AbilityContextImpl::StartAbilityForResult(const AAFwk::Want& want, const AAFwk::StartOptions& startOptions,
    int requestCode, RuntimeTask&& task)
{
    TAG_LOGD(AAFwkTag::CONTEXT, "called");
    resultCallbacks_.insert(make_pair(requestCode, std::move(task)));
    ErrCode err = AAFwk::AbilityManagerClient::GetInstance()->StartAbility(want, startOptions, token_, requestCode);
    if (err != ERR_OK && err != AAFwk::START_ABILITY_WAITING) {
        TAG_LOGE(AAFwkTag::CONTEXT, "ret=%{public}d", err);
        OnAbilityResultInner(requestCode, err, want);
        if (!startOptions.requestId_.empty()) {
            nlohmann::json jsonObject = nlohmann::json {
                { JSON_KEY_ERR_MSG, "Failed to call startAbilityForResult" },
            };
            OnRequestFailure(startOptions.requestId_, want.GetElement(), jsonObject.dump());
        }
    }
    return err;
}

ErrCode AbilityContextImpl::StartAbilityForResultWithAccount(
    const AAFwk::Want& want, int accountId, const AAFwk::StartOptions& startOptions,
    int requestCode, RuntimeTask&& task)
{
    TAG_LOGD(AAFwkTag::CONTEXT, "called");
    resultCallbacks_.insert(make_pair(requestCode, std::move(task)));
    ErrCode err = AAFwk::AbilityManagerClient::GetInstance()->StartAbility(
        want, startOptions, token_, requestCode, accountId);
    if (err != ERR_OK && err != AAFwk::START_ABILITY_WAITING) {
        TAG_LOGE(AAFwkTag::CONTEXT, "ret=%{public}d", err);
        OnAbilityResultInner(requestCode, err, want);
        if (!startOptions.requestId_.empty()) {
            nlohmann::json jsonObject = nlohmann::json {
                { JSON_KEY_ERR_MSG, "Failed to call startAbilityForResultWithAccount" },
            };
            OnRequestFailure(startOptions.requestId_, want.GetElement(), jsonObject.dump());
        }
    }
    return err;
}

ErrCode AbilityContextImpl::StartUIServiceExtensionAbility(const AAFwk::Want& want, int32_t accountId)
{
    TAG_LOGD(AAFwkTag::CONTEXT, "name:%{public}s %{public}s, accountId=%{public}d",
        want.GetElement().GetBundleName().c_str(), want.GetElement().GetAbilityName().c_str(), accountId);
    ErrCode err = AAFwk::AbilityManagerClient::GetInstance()->StartExtensionAbility(
        want, token_, accountId, AppExecFwk::ExtensionAbilityType::UI_SERVICE);
    if (err != ERR_OK) {
        TAG_LOGE(AAFwkTag::CONTEXT, "failed %{public}d", err);
    }
    return err;
}

ErrCode AbilityContextImpl::StartServiceExtensionAbility(const AAFwk::Want& want, int32_t accountId)
{
    TAG_LOGI(AAFwkTag::CONTEXT, "name:%{public}s %{public}s, accountId=%{public}d",
        want.GetElement().GetBundleName().c_str(), want.GetElement().GetAbilityName().c_str(), accountId);
    ErrCode err = AAFwk::AbilityManagerClient::GetInstance()->StartExtensionAbility(
        want, token_, accountId, AppExecFwk::ExtensionAbilityType::SERVICE);
    if (err != ERR_OK) {
        TAG_LOGE(AAFwkTag::CONTEXT, "failed:%{public}d", err);
    }
    return err;
}

ErrCode AbilityContextImpl::StopServiceExtensionAbility(const AAFwk::Want& want, int32_t accountId)
{
    TAG_LOGD(AAFwkTag::CONTEXT, "name:%{public}s %{public}s, accountId=%{public}d",
        want.GetElement().GetBundleName().c_str(), want.GetElement().GetAbilityName().c_str(), accountId);
    ErrCode err = AAFwk::AbilityManagerClient::GetInstance()->StopExtensionAbility(
        want, token_, accountId, AppExecFwk::ExtensionAbilityType::SERVICE);
    if (err != ERR_OK) {
        TAG_LOGE(AAFwkTag::CONTEXT, "failed %{public}d", err);
    }
    return err;
}

ErrCode AbilityContextImpl::TerminateAbilityWithResult(const AAFwk::Want& want, int resultCode)
{
    isTerminating_.store(true);
    if (isHook_ && hookOff_) {
        TAG_LOGW(AAFwkTag::CONTEXT, "is hook and hook off, skip TerminateSession");
        return ERR_OK;
    }
    auto sessionToken = GetSessionToken();
    if (sessionToken == nullptr) {
        TAG_LOGW(AAFwkTag::CONTEXT, "withResult null sessionToken");
    }
#ifdef SUPPORT_SCREEN
    if (Rosen::SceneBoardJudgement::IsSceneBoardEnabled() && sessionToken) {
        sptr<AAFwk::SessionInfo> info = sptr<AAFwk::SessionInfo>::MakeSptr();
        info->want = want;
        info->resultCode = resultCode;
        auto ifaceSessionToken = iface_cast<Rosen::ISession>(sessionToken);
        TAG_LOGI(AAFwkTag::CONTEXT, "scb call, TerminateAbilityWithResult");
        ErrCode ret = static_cast<int32_t>(ifaceSessionToken->TerminateSession(info));
        if (ret != ERR_OK) {
            TAG_LOGE(AAFwkTag::CONTEXT, "scb call, TerminateAbilityWithResult err: %{public}d", ret);
        }
        return ret;
    } else {
        ErrCode err = AAFwk::AbilityManagerClient::GetInstance()->TerminateAbility(token_, resultCode, &want);
        TAG_LOGI(AAFwkTag::CONTEXT, "ret=%{public}d", err);
        return err;
    }
#else
    ErrCode err = AAFwk::AbilityManagerClient::GetInstance()->TerminateAbility(token_, resultCode, &want);
    TAG_LOGI(AAFwkTag::CONTEXT, "ret=%{public}d", err);
    return err;
#endif
}

ErrCode AbilityContextImpl::BackToCallerAbilityWithResult(const AAFwk::Want& want, int resultCode, int64_t requestCode)
{
    ErrCode err = AAFwk::AbilityManagerClient::GetInstance()->BackToCallerAbilityWithResult(
        token_, resultCode, &want, requestCode);
    TAG_LOGI(AAFwkTag::CONTEXT, "ret:%{public}d", err);
    return static_cast<int32_t>(err);
}

void AbilityContextImpl::SetWeakSessionToken(const wptr<IRemoteObject>& sessionToken)
{
    std::lock_guard lock(sessionTokenMutex_);
    TAG_LOGD(AAFwkTag::CONTEXT, "called");
    sessionToken_ = sessionToken;
}

sptr<IRemoteObject> AbilityContextImpl::GetSessionToken()
{
    std::lock_guard lock(sessionTokenMutex_);
    TAG_LOGD(AAFwkTag::CONTEXT, "called");
    return sessionToken_.promote();
}

void AbilityContextImpl::SetAbilityRecordId(int32_t abilityRecordId)
{
    TAG_LOGD(AAFwkTag::CONTEXT, "abilityRecordId: %{public}d", abilityRecordId);
    abilityRecordId_ = abilityRecordId;
}

int32_t AbilityContextImpl::GetAbilityRecordId()
{
    return abilityRecordId_;
}

void AbilityContextImpl::OnAbilityResult(int requestCode, int resultCode, const AAFwk::Want& resultData)
{
    TAG_LOGD(AAFwkTag::CONTEXT, "called");
    auto callback = resultCallbacks_.find(requestCode);
    if (callback != resultCallbacks_.end()) {
        if (callback->second) {
            callback->second(resultCode, resultData, false);
        }
        resultCallbacks_.erase(requestCode);
    }
}

void AbilityContextImpl::OnAbilityResultInner(int requestCode, int resultCode, const AAFwk::Want& resultData)
{
    TAG_LOGD(AAFwkTag::CONTEXT, "called");
    auto callback = resultCallbacks_.find(requestCode);
    if (callback != resultCallbacks_.end()) {
        if (callback->second) {
            callback->second(resultCode, resultData, true);
        }
        resultCallbacks_.erase(requestCode);
    }
}

ErrCode AbilityContextImpl::ConnectAbility(const AAFwk::Want& want, const sptr<AbilityConnectCallback>& connectCallback)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    TAG_LOGI(AAFwkTag::CONTEXT, "caller:%{public}s, target:%{public}s",
        abilityInfo_ == nullptr ? "" : abilityInfo_->name.c_str(), want.GetElement().GetAbilityName().c_str());
    ErrCode ret = ConnectionManager::GetInstance().ConnectAbility(token_, want, connectCallback);
    if (ret != ERR_OK) {
        TAG_LOGE(AAFwkTag::CONTEXT, "failed %{public}d", ret);
    }
    return ret;
}

ErrCode AbilityContextImpl::ConnectAbilityWithAccount(const AAFwk::Want& want, int accountId,
    const sptr<AbilityConnectCallback>& connectCallback)
{
    TAG_LOGD(AAFwkTag::CONTEXT, "called");
    ErrCode ret =
        ConnectionManager::GetInstance().ConnectAbilityWithAccount(token_, want, accountId, connectCallback);
    if (ret != ERR_OK) {
        TAG_LOGE(AAFwkTag::CONTEXT, "failed %{public}d", ret);
    }
    return ret;
}

ErrCode AbilityContextImpl::ConnectUIServiceExtensionAbility(const AAFwk::Want& want,
    const sptr<AbilityConnectCallback>& connectCallback)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    TAG_LOGD(AAFwkTag::CONTEXT,
        "called, name:%{public}s", abilityInfo_ == nullptr ? "" : abilityInfo_->name.c_str());
    ErrCode ret = ConnectionManager::GetInstance().ConnectUIServiceExtensionAbility(token_, want, connectCallback);
    if (ret != ERR_OK) {
        TAG_LOGE(AAFwkTag::CONTEXT, "failed %{public}d", ret);
    }
    return ret;
}

void AbilityContextImpl::DisconnectAbility(const AAFwk::Want& want,
    const sptr<AbilityConnectCallback>& connectCallback, int32_t accountId)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    TAG_LOGI(AAFwkTag::CONTEXT, "DisconnectAbility, caller:%{public}s, target:%{public}s",
        abilityInfo_ == nullptr ? "" : abilityInfo_->name.c_str(), want.GetElement().GetAbilityName().c_str());
    ErrCode ret =
        ConnectionManager::GetInstance().DisconnectAbility(token_, want, connectCallback, accountId);
    if (ret != ERR_OK) {
        TAG_LOGE(AAFwkTag::CONTEXT, "error %{public}d", ret);
    }
}

std::string AbilityContextImpl::GetBundleName() const
{
    return stageContext_ ? stageContext_->GetBundleName() : "";
}

std::shared_ptr<AppExecFwk::ApplicationInfo> AbilityContextImpl::GetApplicationInfo() const
{
    return stageContext_ ? stageContext_->GetApplicationInfo() : nullptr;
}

std::string AbilityContextImpl::GetBundleCodePath() const
{
    return stageContext_ ? stageContext_->GetBundleCodePath() : "";
}

std::shared_ptr<AppExecFwk::HapModuleInfo> AbilityContextImpl::GetHapModuleInfo() const
{
    return stageContext_ ? stageContext_->GetHapModuleInfo() : nullptr;
}

std::shared_ptr<Global::Resource::ResourceManager> AbilityContextImpl::GetResourceManager() const
{
    if (abilityResourceMgr_) {
        return abilityResourceMgr_;
    }
    return stageContext_ ? stageContext_->GetResourceManager() : nullptr;
}

void AbilityContextImpl::SetAbilityResourceManager(
    std::shared_ptr<Global::Resource::ResourceManager> abilityResourceMgr)
{
    abilityResourceMgr_ = abilityResourceMgr;
}

void AbilityContextImpl::RegisterAbilityConfigUpdateCallback(
    AbilityConfigUpdateCallback abilityConfigUpdateCallback)
{
    abilityConfigUpdateCallback_ = abilityConfigUpdateCallback;
}

std::shared_ptr<AppExecFwk::Configuration> AbilityContextImpl::GetAbilityConfiguration() const
{
    return abilityConfiguration_;
}

void AbilityContextImpl::SetAbilityConfiguration(const AppExecFwk::Configuration &config)
{
    if (!abilityConfiguration_) {
        abilityConfiguration_ = std::make_shared<AppExecFwk::Configuration>(config);
        TAG_LOGI(AAFwkTag::CONTEXT, "abilityConfiguration: %{public}s", abilityConfiguration_->GetName().c_str());
        return;
    }
    std::vector<std::string> changeKeyV;
    abilityConfiguration_->CompareDifferent(changeKeyV, config);
    if (!changeKeyV.empty()) {
        abilityConfiguration_->Merge(changeKeyV, config);
    }
    TAG_LOGI(AAFwkTag::CONTEXT, "abilityConfiguration: %{public}s", abilityConfiguration_->GetName().c_str());
}

void AbilityContextImpl::SetAbilityColorMode(int32_t colorMode)
{
    TAG_LOGI(AAFwkTag::CONTEXT, "SetAbilityColorMode colorMode: %{public}d", colorMode);
    if (colorMode < -1 || colorMode > 1) {
        TAG_LOGE(AAFwkTag::CONTEXT, "colorMode error");
        return;
    }
    AppExecFwk::Configuration config;

    config.AddItem(AAFwk::GlobalConfigurationKey::SYSTEM_COLORMODE, AppExecFwk::GetColorModeStr(colorMode));
    config.AddItem(AAFwk::GlobalConfigurationKey::COLORMODE_IS_SET_BY_APP,
        AppExecFwk::ConfigurationInner::IS_SET_BY_APP);
    if (!abilityConfigUpdateCallback_) {
        TAG_LOGE(AAFwkTag::CONTEXT, "abilityConfigUpdateCallback_ nullptr");
        return;
    }
    abilityConfigUpdateCallback_(config);
}

std::shared_ptr<Context> AbilityContextImpl::CreateBundleContext(const std::string& bundleName)
{
    return stageContext_ ? stageContext_->CreateBundleContext(bundleName) : nullptr;
}

std::shared_ptr<Context> AbilityContextImpl::CreateModuleContext(const std::string& moduleName)
{
    return stageContext_ ? stageContext_->CreateModuleContext(moduleName) : nullptr;
}

std::shared_ptr<Context> AbilityContextImpl::CreateModuleContext(const std::string& bundleName,
    const std::string& moduleName)
{
    return stageContext_ ? stageContext_->CreateModuleContext(bundleName, moduleName) : nullptr;
}

std::shared_ptr<Global::Resource::ResourceManager> AbilityContextImpl::CreateModuleResourceManager(
    const std::string &bundleName, const std::string &moduleName)
{
    return stageContext_ ? stageContext_->CreateModuleResourceManager(bundleName, moduleName) : nullptr;
}

int32_t AbilityContextImpl::CreateSystemHspModuleResourceManager(const std::string &bundleName,
    const std::string &moduleName, std::shared_ptr<Global::Resource::ResourceManager> &resourceManager)
{
    return stageContext_ ? stageContext_->CreateSystemHspModuleResourceManager(bundleName, moduleName, resourceManager)
        : ERR_INVALID_VALUE;
}

void AbilityContextImpl::SetAbilityInfo(const std::shared_ptr<AppExecFwk::AbilityInfo>& abilityInfo)
{
    abilityInfo_ = abilityInfo;
}

std::shared_ptr<AppExecFwk::AbilityInfo> AbilityContextImpl::GetAbilityInfo() const
{
    return abilityInfo_;
}

void AbilityContextImpl::SetStageContext(const std::shared_ptr<AbilityRuntime::Context>& stageContext)
{
    stageContext_ = stageContext;
}

void AbilityContextImpl::SetConfiguration(const std::shared_ptr<AppExecFwk::Configuration>& config)
{
    config_ = config;
}

std::shared_ptr<AppExecFwk::Configuration> AbilityContextImpl::GetConfiguration() const
{
    return config_;
}

void AbilityContextImpl::MinimizeAbility(bool fromUser)
{
    TAG_LOGD(AAFwkTag::CONTEXT, "called");
    ErrCode err = AAFwk::AbilityManagerClient::GetInstance()->MinimizeAbility(token_, fromUser);
    if (err != ERR_OK) {
        TAG_LOGE(AAFwkTag::CONTEXT, "failed %{public}d", err);
    }
}

ErrCode AbilityContextImpl::OnBackPressedCallBack(bool &needMoveToBackground)
{
    TAG_LOGD(AAFwkTag::CONTEXT, "call");
    auto abilityCallback = abilityCallback_.lock();
    if (abilityCallback == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null abilityCallback");
        return ERR_INVALID_VALUE;
    }
#ifdef SUPPORT_SCREEN
    needMoveToBackground = abilityCallback->OnBackPress();
#endif
    return ERR_OK;
}

ErrCode AbilityContextImpl::MoveAbilityToBackground()
{
    TAG_LOGD(AAFwkTag::CONTEXT, "called");
    ErrCode err = AAFwk::AbilityManagerClient::GetInstance()->MoveAbilityToBackground(token_);
    if (err != ERR_OK) {
        TAG_LOGE(AAFwkTag::CONTEXT, "failed: %{public}d", err);
    }
    return err;
}

ErrCode AbilityContextImpl::MoveUIAbilityToBackground()
{
    TAG_LOGD(AAFwkTag::CONTEXT, "call");
    ErrCode err = AAFwk::AbilityManagerClient::GetInstance()->MoveUIAbilityToBackground(token_);
    if (err != ERR_OK) {
        TAG_LOGE(AAFwkTag::CONTEXT, "failed: %{public}d", err);
    }
    return err;
}

ErrCode AbilityContextImpl::TerminateSelf()
{
    TAG_LOGI(AAFwkTag::CONTEXT, "called");
    isTerminating_.store(true);
    auto sessionToken = GetSessionToken();
    if (sessionToken == nullptr) {
        TAG_LOGW(AAFwkTag::CONTEXT, "null sessionToken");
    }
    if (isHook_ && hookOff_) {
        TAG_LOGW(AAFwkTag::CONTEXT, "is hook and hook off, skip TerminateSession");
        return ERR_OK;
    }
#ifdef SUPPORT_SCREEN
    if (Rosen::SceneBoardJudgement::IsSceneBoardEnabled() && sessionToken) {
        TAG_LOGI(AAFwkTag::CONTEXT, "scb call, TerminateSelf: %{public}s",
            abilityInfo_ ? abilityInfo_->name.c_str() : "");
        AAFwk::Want resultWant;
        sptr<AAFwk::SessionInfo> info = sptr<AAFwk::SessionInfo>::MakeSptr();
        info->want = resultWant;
        info->resultCode = -1;
        auto ifaceSessionToken = iface_cast<Rosen::ISession>(sessionToken);
        ErrCode ret = static_cast<int32_t>(ifaceSessionToken->TerminateSession(info));
        if (ret != ERR_OK) {
            TAG_LOGE(AAFwkTag::CONTEXT, "scb call, TerminateSelf err: %{public}d", ret);
        }
        return ret;
    } else {
        AAFwk::Want resultWant;
        ErrCode err = AAFwk::AbilityManagerClient::GetInstance()->TerminateAbility(token_, -1, &resultWant);
        if (err != ERR_OK) {
            TAG_LOGE(AAFwkTag::CONTEXT, "failed:%{public}d", err);
        }
        return err;
    }
#else
    AAFwk::Want resultWant;
    ErrCode err = AAFwk::AbilityManagerClient::GetInstance()->TerminateAbility(token_, -1, &resultWant);
    if (err != ERR_OK) {
        TAG_LOGE(AAFwkTag::CONTEXT, "failed %{public}d", err);
    }
    return err;
#endif
}

ErrCode AbilityContextImpl::CloseAbility()
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    TAG_LOGD(AAFwkTag::CONTEXT, "called");
    isTerminating_.store(true);
    AAFwk::Want resultWant;
    ErrCode err = AAFwk::AbilityManagerClient::GetInstance()->CloseAbility(token_, -1, &resultWant);
    if (err != ERR_OK) {
        TAG_LOGE(AAFwkTag::CONTEXT, "failed: %{public}d", err);
    }
    return err;
}

sptr<IRemoteObject> AbilityContextImpl::GetToken()
{
    return token_;
}

ErrCode AbilityContextImpl::RestoreWindowStage(napi_env env, napi_value contentStorage)
{
    TAG_LOGD(AAFwkTag::CONTEXT, "called");
    if (isHook_) {
        TAG_LOGD(AAFwkTag::CONTEXT, "RestoreWindowStage is hook module");
        return ERR_NOT_SUPPORTED;
    }
    napi_ref value = nullptr;
    napi_create_reference(env, contentStorage, 1, &value);
    contentStorage_ = std::unique_ptr<NativeReference>(reinterpret_cast<NativeReference*>(value));
    return ERR_OK;
}

ErrCode AbilityContextImpl::StartAbilityByCall(
    const AAFwk::Want& want, const std::shared_ptr<CallerCallBack>& callback, int32_t accountId)
{
    if (localCallContainer_ == nullptr) {
        localCallContainer_ = std::make_shared<LocalCallContainer>();
        if (localCallContainer_ == nullptr) {
            TAG_LOGE(AAFwkTag::CONTEXT, "null localCallContainer_");
            return ERR_INVALID_VALUE;
        }
    }
    return localCallContainer_->StartAbilityByCallInner(want, callback, token_, accountId);
}

ErrCode AbilityContextImpl::ReleaseCall(const std::shared_ptr<CallerCallBack>& callback)
{
    TAG_LOGD(AAFwkTag::CONTEXT, "called");
    if (localCallContainer_ == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null localCallContainer_");
        return ERR_INVALID_VALUE;
    }
    return localCallContainer_->ReleaseCall(callback);
}

void AbilityContextImpl::ClearFailedCallConnection(const std::shared_ptr<CallerCallBack>& callback)
{
    TAG_LOGD(AAFwkTag::CONTEXT, "called");
    if (localCallContainer_ == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null localCallContainer_");
        return;
    }
    localCallContainer_->ClearFailedCallConnection(callback);
}

void AbilityContextImpl::RegisterAbilityCallback(std::weak_ptr<AppExecFwk::IAbilityCallback> abilityCallback)
{
    TAG_LOGD(AAFwkTag::CONTEXT, "called");
    abilityCallback_ = abilityCallback;
}

void AbilityContextImpl::SetWindowRectangleParams(AAFwk::Want &want)
{
    want.SetParam(RequestConstants::REQUEST_TOKEN_KEY, token_);
#ifdef SUPPORT_SCREEN
    int32_t left;
    int32_t top;
    int32_t width;
    int32_t height;
    GetWindowRect(left, top, width, height);
    want.SetParam(RequestConstants::WINDOW_RECTANGLE_LEFT_KEY, left);
    want.SetParam(RequestConstants::WINDOW_RECTANGLE_TOP_KEY, top);
    want.SetParam(RequestConstants::WINDOW_RECTANGLE_WIDTH_KEY, width);
    want.SetParam(RequestConstants::WINDOW_RECTANGLE_HEIGHT_KEY, height);
#endif // SUPPORT_SCREEN
}

ErrCode AbilityContextImpl::RequestDialogService(napi_env env, AAFwk::Want &want, RequestDialogResultTask &&task)
{
    SetWindowRectangleParams(want);
    auto resultTask =
        [env, outTask = std::move(task)](int32_t resultCode, const AAFwk::Want &resultWant) {
        auto retData = new (std::nothrow) RequestResult();
        if (retData == nullptr) {
            TAG_LOGE(AAFwkTag::CONTEXT, "null retData");
            return;
        }
        retData->resultCode = resultCode;
        retData->resultWant = resultWant;
        retData->task = std::move(outTask);

        uv_loop_s* loop = nullptr;
        napi_get_uv_event_loop(env, &loop);
        if (loop == nullptr) {
            TAG_LOGE(AAFwkTag::CONTEXT, "null loop");
            return;
        }
        auto work = new (std::nothrow) uv_work_t;
        if (work == nullptr) {
            TAG_LOGE(AAFwkTag::CONTEXT, "null work");
            return;
        }
        work->data = static_cast<void*>(retData);
        int rev = uv_queue_work_with_qos(
            loop,
            work,
            [](uv_work_t* work) {},
            RequestDialogResultJSThreadWorker,
            uv_qos_user_initiated);
        if (rev != 0) {
            delete retData;
            retData = nullptr;
            if (work != nullptr) {
                delete work;
                work = nullptr;
            }
        }
    };

    sptr<IRemoteObject> remoteObject = sptr<DialogRequestCallbackImpl>::MakeSptr(std::move(resultTask));
    want.SetParam(RequestConstants::REQUEST_CALLBACK_KEY, remoteObject);

    auto err = AAFwk::AbilityManagerClient::GetInstance()->RequestDialogService(want, token_);
    TAG_LOGD(AAFwkTag::CONTEXT, "ret=%{public}d", static_cast<int32_t>(err));
    return err;
}

ErrCode AbilityContextImpl::RequestDialogService(AAFwk::Want &want, RequestDialogResultTask &&task)
{
    SetWindowRectangleParams(want);
    sptr<IRemoteObject> remoteObject = sptr<DialogRequestCallbackImpl>::MakeSptr(std::move(task));
    want.SetParam(RequestConstants::REQUEST_CALLBACK_KEY, remoteObject);

    auto err = AAFwk::AbilityManagerClient::GetInstance()->RequestDialogService(want, token_);
    TAG_LOGD(AAFwkTag::CONTEXT, "ret=%{public}d", static_cast<int32_t>(err));
    return err;
}

ErrCode AbilityContextImpl::ReportDrawnCompleted()
{
    TAG_LOGD(AAFwkTag::CONTEXT, "called");
    return AAFwk::AbilityManagerClient::GetInstance()->ReportDrawnCompleted(token_);
}

void AbilityContextImpl::RequestDialogResultJSThreadWorker(uv_work_t* work, int status)
{
    TAG_LOGD(AAFwkTag::CONTEXT, "called");
    if (work == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null work");
        return;
    }
    if (work->data == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null work data");
        delete work;
        work = nullptr;
        return;
    }
    RequestResult* retCB = static_cast<RequestResult*>(work->data);
    if (retCB == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null retCB");
        delete work;
        work = nullptr;
        return;
    }

    if (retCB->task) {
        retCB->task(retCB->resultCode, retCB->resultWant);
    }

    delete retCB;
    retCB = nullptr;
    delete work;
    work = nullptr;
}

ErrCode AbilityContextImpl::GetMissionId(int32_t &missionId)
{
    TAG_LOGD(AAFwkTag::CONTEXT, "called");
    if (missionId_ != -1) {
        missionId = missionId_;
        return ERR_OK;
    }

    ErrCode err = AAFwk::AbilityManagerClient::GetInstance()->GetMissionIdByToken(token_, missionId);
    if (err != ERR_OK) {
        TAG_LOGE(AAFwkTag::CONTEXT, "failed %{public}d", err);
    } else {
        missionId_ = missionId;
        TAG_LOGD(AAFwkTag::CONTEXT, "missionId: %{public}d", missionId_);
    }
    return err;
}

ErrCode AbilityContextImpl::SetMissionContinueState(const AAFwk::ContinueState &state)
{
    TAG_LOGI(AAFwkTag::CONTEXT, "called, state: %{public}d", state);
    if (isHook_) {
        TAG_LOGD(AAFwkTag::CONTEXT, "SetMissionContinueState is hook module");
        return ERR_NOT_SUPPORTED;
    }
    auto sessionToken = GetSessionToken();
    ErrCode err = AAFwk::AbilityManagerClient::GetInstance()->SetMissionContinueState(token_, state, sessionToken);
    if (err != ERR_OK) {
        TAG_LOGE(AAFwkTag::CONTEXT, "failed: %{public}d", err);
        return err;
    }
    auto abilityCallback = abilityCallback_.lock();
    if (abilityCallback) {
        abilityCallback->SetContinueState(static_cast<int32_t>(state));
        TAG_LOGI(AAFwkTag::CONTEXT, "SetContinueState, state: %{public}d.", state);
    }
    return ERR_OK;
}

void AbilityContextImpl::InsertResultCallbackTask(int requestCode, RuntimeTask &&task)
{
    TAG_LOGD(AAFwkTag::CONTEXT, "called");
    resultCallbacks_.insert(make_pair(requestCode, std::move(task)));
}

void AbilityContextImpl::RemoveResultCallbackTask(int requestCode)
{
    TAG_LOGD(AAFwkTag::CONTEXT, "call");
    resultCallbacks_.erase(requestCode);
}

#ifdef SUPPORT_SCREEN
void AbilityContextImpl::GetWindowRect(int32_t &left, int32_t &top, int32_t &width, int32_t &height)
{
    TAG_LOGD(AAFwkTag::CONTEXT, "call");
    auto abilityCallback = abilityCallback_.lock();
    if (abilityCallback) {
        abilityCallback->GetWindowRect(left, top, width, height);
    }
}
#endif // SUPPORT_SCREEN
void AbilityContextImpl::RegisterAbilityLifecycleObserver(
    const std::shared_ptr<AppExecFwk::ILifecycleObserver> &observer)
{
    TAG_LOGD(AAFwkTag::CONTEXT, "called");
    auto abilityCallback = abilityCallback_.lock();
    if (abilityCallback == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null abilityCallback");
        return;
    }
    abilityCallback->RegisterAbilityLifecycleObserver(observer);
}

void AbilityContextImpl::UnregisterAbilityLifecycleObserver(
    const std::shared_ptr<AppExecFwk::ILifecycleObserver> &observer)
{
    TAG_LOGD(AAFwkTag::CONTEXT, "call");
    auto abilityCallback = abilityCallback_.lock();
    if (abilityCallback == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null abilityCallback");
        return;
    }
    abilityCallback->UnregisterAbilityLifecycleObserver(observer);
}

#ifdef SUPPORT_SCREEN
ErrCode AbilityContextImpl::SetMissionLabel(const std::string& label)
{
    TAG_LOGD(AAFwkTag::CONTEXT, "label:%{public}s", label.c_str());
    if (isHook_) {
        TAG_LOGD(AAFwkTag::CONTEXT, "SetMissionLabel is hook module");
        return ERR_NOT_SUPPORTED;
    }
    ErrCode err = AAFwk::AbilityManagerClient::GetInstance()->SetMissionLabel(token_, label);
    if (err != ERR_OK) {
        TAG_LOGE(AAFwkTag::CONTEXT, "failed %{public}d", err);
    } else {
        auto abilityCallback = abilityCallback_.lock();
        if (abilityCallback) {
            abilityCallback->SetMissionLabel(label);
        }
    }
    return err;
}

ErrCode AbilityContextImpl::SetMissionIcon(const std::shared_ptr<OHOS::Media::PixelMap>& icon)
{
    TAG_LOGD(AAFwkTag::CONTEXT, "call");
    ErrCode err = AAFwk::AbilityManagerClient::GetInstance()->SetMissionIcon(token_, icon);
    if (err != ERR_OK) {
        TAG_LOGE(AAFwkTag::CONTEXT, "failed %{public}d", err);
    } else {
        auto abilityCallback = abilityCallback_.lock();
        if (abilityCallback) {
            abilityCallback->SetMissionIcon(icon);
        }
    }
    return err;
}

ErrCode AbilityContextImpl::SetAbilityInstanceInfo(const std::string& label,
    std::shared_ptr<OHOS::Media::PixelMap> icon)
{
    TAG_LOGD(AAFwkTag::CONTEXT, "call");
    if (Rosen::SceneBoardJudgement::IsSceneBoardEnabled()) {
        auto ifaceSession = iface_cast<Rosen::ISession>(GetSessionToken());
        if (ifaceSession == nullptr) {
            TAG_LOGW(AAFwkTag::CONTEXT, "null ifaceSession");
            return ERR_INVALID_VALUE;
        }

        TAG_LOGI(AAFwkTag::CONTEXT, "SetSessionLabelAndIcon");
        auto errCode = ifaceSession->SetSessionLabelAndIcon(label, icon);
        if (errCode != Rosen::WSError::WS_OK) {
            TAG_LOGE(AAFwkTag::CONTEXT, "SetSessionLabelAndIcon err: %{public}d", static_cast<int32_t>(errCode));
        } else {
            auto abilityCallback = abilityCallback_.lock();
            if (abilityCallback) {
                abilityCallback->SetMissionLabel(label);
                abilityCallback->SetMissionIcon(icon);
            }
        }
        if (errCode == Rosen::WSError::WS_ERROR_INVALID_PERMISSION) {
            return AAFwk::CHECK_PERMISSION_FAILED;
        } else if (errCode == Rosen::WSError::WS_ERROR_SET_SESSION_LABEL_FAILED) {
            return AAFwk::INVALID_PARAMETERS_ERR;
        } else if (errCode == Rosen::WSError::WS_ERROR_DEVICE_NOT_SUPPORT) {
            return AAFwk::ERR_CAPABILITY_NOT_SUPPORT;
        }

        return static_cast<int32_t>(errCode);
    }
    return AAFwk::ERR_CAPABILITY_NOT_SUPPORT;
}

int AbilityContextImpl::GetCurrentWindowMode()
{
    auto abilityCallback = abilityCallback_.lock();
    if (abilityCallback == nullptr) {
        return AAFwk::AbilityWindowConfiguration::MULTI_WINDOW_DISPLAY_UNDEFINED;
    }
    return abilityCallback->GetCurrentWindowMode();
}

Ace::UIContent* AbilityContextImpl::GetUIContent()
{
    TAG_LOGD(AAFwkTag::CONTEXT, "call");
    auto abilityCallback = abilityCallback_.lock();
    if (abilityCallback == nullptr) {
        return nullptr;
    }

    return abilityCallback->GetUIContent();
}

ErrCode AbilityContextImpl::StartAbilityByType(const std::string &type,
    AAFwk::WantParams &wantParams, const std::shared_ptr<JsUIExtensionCallback> &uiExtensionCallbacks)
{
    TAG_LOGD(AAFwkTag::CONTEXT, "call");
    auto uiContent = GetUIContent();
    if (uiContent == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null uiContent");
        return ERR_INVALID_VALUE;
    }
    wantParams.SetParam(UIEXTENSION_TARGET_TYPE_KEY, AAFwk::String::Box(type));
    AAFwk::Want want;
    want.SetParams(wantParams);
    if (wantParams.HasParam(FLAG_AUTH_READ_URI_PERMISSION)) {
        int32_t flag = wantParams.GetIntParam(FLAG_AUTH_READ_URI_PERMISSION, 0);
        want.SetFlags(flag);
        wantParams.Remove(FLAG_AUTH_READ_URI_PERMISSION);
    }
    Ace::ModalUIExtensionCallbacks callback;
    callback.onError = [uiExtensionCallbacks](int32_t arg, const std::string &str1, const std::string &str2) {
        uiExtensionCallbacks->OnError(arg);
    };
    callback.onRelease = [uiExtensionCallbacks](int32_t arg) {
        uiExtensionCallbacks->OnRelease(arg);
    };
    callback.onResult = [uiExtensionCallbacks](int32_t arg1, const OHOS::AAFwk::Want arg2) {
        uiExtensionCallbacks->OnResult(arg1, arg2);
    };

    Ace::ModalUIExtensionConfig config;
    int32_t sessionId = uiContent->CreateModalUIExtension(want, callback, config);
    if (sessionId == 0) {
        TAG_LOGE(AAFwkTag::CONTEXT, "createModalUIExtension failed");
        return ERR_INVALID_VALUE;
    }
    uiExtensionCallbacks->SetUIContent(uiContent);
    uiExtensionCallbacks->SetSessionId(sessionId);
    return ERR_OK;
}

bool AbilityContextImpl::IsUIExtensionExist(const AAFwk::Want &want)
{
    TAG_LOGD(AAFwkTag::CONTEXT, "call");
    std::lock_guard lock(uiExtensionMutex_);
    for (const auto& iter : uiExtensionMap_) {
        if (iter.second.GetElement().GetBundleName() == want.GetElement().GetBundleName() &&
            iter.second.GetElement().GetModuleName() == want.GetElement().GetModuleName() &&
            iter.second.GetElement().GetAbilityName() == want.GetElement().GetAbilityName()) {
            return true;
        }
    }
    return false;
}

void AbilityContextImpl::EraseUIExtension(int32_t sessionId)
{
    TAG_LOGD(AAFwkTag::CONTEXT, "call");
    std::lock_guard lock(uiExtensionMutex_);
    auto iter = uiExtensionMap_.find(sessionId);
    if (iter != uiExtensionMap_.end()) {
        uiExtensionMap_.erase(sessionId);
    }
}

ErrCode AbilityContextImpl::CreateModalUIExtensionWithApp(const AAFwk::Want &want)
{
    TAG_LOGD(AAFwkTag::CONTEXT, "call");
    auto uiContent = GetUIContent();
    if (uiContent == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null uiContent");
        return ERR_INVALID_VALUE;
    }
    if (IsUIExtensionExist(want) && !want.GetBoolParam(USE_GLOBAL_UICONTENT, false)) {
        TAG_LOGD(AAFwkTag::CONTEXT, "exist uIExtension");
        return ERR_OK;
    }
    auto abilityCallback = abilityCallback_.lock();
    if (abilityCallback == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null abilityCallback");
        return ERR_INVALID_VALUE;
    }
    auto disposedCallback = std::make_shared<DialogUIExtensionCallback>(abilityCallback);
    Ace::ModalUIExtensionCallbacks callback;
    callback.onError = [disposedCallback](int32_t arg1, const std::string &str1, const std::string &str2) {
        disposedCallback->OnError();
    };
    callback.onRelease = [disposedCallback](int32_t arg1) {
        disposedCallback->OnRelease();
    };
    callback.onDestroy = [disposedCallback]() {
        disposedCallback->OnDestroy();
    };
    Ace::ModalUIExtensionConfig config;
    config.prohibitedRemoveByRouter = true;
    if (want.GetBoolParam(DISPOSED_PROHIBIT_BACK, false)) {
        config.isProhibitBack = true;
    }
    if (want.HasParameter(IS_WINDOWMODE_FOLLOWHOST)) {
        config.isWindowModeFollowHost = want.GetBoolParam(IS_WINDOWMODE_FOLLOWHOST, false);
    }
    int32_t sessionId = uiContent->CreateModalUIExtension(want, callback, config);
    if (sessionId == 0) {
        TAG_LOGE(AAFwkTag::CONTEXT, "failed");
        return ERR_INVALID_VALUE;
    }
    disposedCallback->SetUIContent(uiContent);
    disposedCallback->SetSessionId(sessionId);
    {
        std::lock_guard lock(uiExtensionMutex_);
        uiExtensionMap_.emplace(sessionId, want);
    }
    return ERR_OK;
}
#endif

ErrCode AbilityContextImpl::RequestModalUIExtension(const AAFwk::Want& want)
{
    ErrCode err = AAFwk::AbilityManagerClient::GetInstance()->RequestModalUIExtension(want);
    if (err != ERR_OK) {
        TAG_LOGE(AAFwkTag::CONTEXT, "failed %{public}d", err);
    }
    return err;
}

ErrCode AbilityContextImpl::ChangeAbilityVisibility(bool isShow)
{
    ErrCode err = AAFwk::AbilityManagerClient::GetInstance()->ChangeAbilityVisibility(token_, isShow);
    if (err != ERR_OK) {
        TAG_LOGE(AAFwkTag::CONTEXT, "failed %{public}d", err);
    }
    return err;
}

ErrCode AbilityContextImpl::AddFreeInstallObserver(const sptr<IFreeInstallObserver> &observer)
{
    ErrCode ret = AAFwk::AbilityManagerClient::GetInstance()->AddFreeInstallObserver(token_, observer);
    if (ret != ERR_OK) {
        TAG_LOGE(AAFwkTag::CONTEXT, "failed, ret: %{public}d", ret);
    }
    return ret;
}

ErrCode AbilityContextImpl::OpenAtomicService(AAFwk::Want& want, const AAFwk::StartOptions &options, int requestCode,
    RuntimeTask &&task)
{
    TAG_LOGD(AAFwkTag::CONTEXT, "called");
    resultCallbacks_.insert(make_pair(requestCode, std::move(task)));
    ErrCode err = AAFwk::AbilityManagerClient::GetInstance()->OpenAtomicService(want, options, token_, requestCode, -1);
    if (err != ERR_OK && err != AAFwk::START_ABILITY_WAITING) {
        TAG_LOGE(AAFwkTag::CONTEXT, "failed, ret=%{public}d", err);
        OnAbilityResultInner(requestCode, err, want);
    }
    return err;
}

void AbilityContextImpl::SetRestoreEnabled(bool enabled)
{
    if (isHook_) {
        TAG_LOGD(AAFwkTag::CONTEXT, "SetRestoreEnabled is hook module");
        return;
    }
    restoreEnabled_.store(enabled);
}

bool AbilityContextImpl::GetRestoreEnabled()
{
    return restoreEnabled_.load();
}

ErrCode AbilityContextImpl::OpenLink(const AAFwk::Want& want, int requestCode)
{
    TAG_LOGD(AAFwkTag::CONTEXT, "called");
    return AAFwk::AbilityManagerClient::GetInstance()->OpenLink(want, token_, -1, requestCode);
}

std::shared_ptr<AAFwk::Want> AbilityContextImpl::GetWant()
{
    auto abilityCallback = abilityCallback_.lock();
    if (abilityCallback == nullptr) {
        TAG_LOGW(AAFwkTag::CONTEXT, "null abilityCallback");
        return nullptr;
    }
    return abilityCallback->GetWant();
}

std::shared_ptr<Context> AbilityContextImpl::CreateAreaModeContext(int areaMode)
{
    return stageContext_ ? stageContext_->CreateAreaModeContext(areaMode) : nullptr;
}

#ifdef SUPPORT_GRAPHICS
std::shared_ptr<Context> AbilityContextImpl::CreateDisplayContext(uint64_t displayId)
{
    return stageContext_ ? stageContext_->CreateDisplayContext(displayId) : nullptr;
}
#endif

ErrCode AbilityContextImpl::RevokeDelegator()
{
    if (!Rosen::SceneBoardJudgement::IsSceneBoardEnabled()) {
        TAG_LOGE(AAFwkTag::CONTEXT, "capability not support");
        return AAFwk::ERR_CAPABILITY_NOT_SUPPORT;
    }
    if (!IsHook() || GetHookOff()) {
        TAG_LOGE(AAFwkTag::CONTEXT, "repeated called");
        return AAFwk::ERR_NOT_HOOK;
    }
    TAG_LOGI(AAFwkTag::CONTEXT, "RevokeDelegator called");
    ErrCode err = AAFwk::AbilityManagerClient::GetInstance()->RevokeDelegator(token_);
    if (err != ERR_OK) {
        TAG_LOGE(AAFwkTag::CONTEXT, "RevokeDelegator is failed:%{public}d", err);
        return err;
    }
    auto sessionToken = GetSessionToken();
    if (sessionToken == nullptr) {
        TAG_LOGW(AAFwkTag::CONTEXT, "null sessionToken");
        return ERR_INVALID_VALUE;
    }
    auto ifaceSessionToken = iface_cast<Rosen::ISession>(sessionToken);
    if (ifaceSessionToken == nullptr) {
        TAG_LOGW(AAFwkTag::CONTEXT, "null ifaceSessionToken");
        return ERR_INVALID_VALUE;
    }
    err = static_cast<int32_t>(ifaceSessionToken->NotifyDisableDelegatorChange());
    if (err != ERR_OK) {
        TAG_LOGE(AAFwkTag::CONTEXT, "scb call, revokeDelegator err: %{public}d", err);
        return AAFwk::ERR_FROM_WINDOW;
    }
    auto abilityCallback = abilityCallback_.lock();
    if (abilityCallback == nullptr) {
        TAG_LOGW(AAFwkTag::CONTEXT, "null abilityCallback");
        return ERR_INVALID_VALUE;
    }
    abilityCallback->NotifyWindowDestroy();
    SetHookOff(true);
    return ERR_OK;
}

ErrCode AbilityContextImpl::AddCompletionHandler(const std::string &requestId, OnRequestResult onRequestSucc,
    OnRequestResult onRequestFail)
{
    if (onRequestSucc == nullptr || onRequestFail == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "either func is null");
        return ERR_INVALID_VALUE;
    }
    std::lock_guard lock(onRequestResultMutex_);
    for (auto iter = onRequestResults_.begin(); iter != onRequestResults_.end(); iter++) {
        if ((*iter)->requestId_ == requestId) {
            TAG_LOGI(AAFwkTag::CONTEXT, "requestId=%{public}s already exists", requestId.c_str());
            return ERR_OK;
        }
    }
    onRequestResults_.emplace_back(std::make_shared<OnRequestResultElement>(requestId, onRequestSucc, onRequestFail));
    return ERR_OK;
}

void AbilityContextImpl::OnRequestSuccess(const std::string &requestId, const AppExecFwk::ElementName &element,
    const std::string &message)
{
    std::shared_ptr<OnRequestResultElement> result = nullptr;
    {
        std::lock_guard lock(onRequestResultMutex_);
        for (auto iter = onRequestResults_.begin(); iter != onRequestResults_.end(); iter++) {
            if ((*iter)->requestId_ == requestId) {
                result = *iter;
                onRequestResults_.erase(iter);
                break;
            }
        }
    }

    if (result != nullptr) {
        TAG_LOGI(AAFwkTag::CONTEXT, "requestId=%{public}s, call onRequestSuccess", requestId.c_str());
        result->onRequestSuccess_(element, message);
        return;
    }

    TAG_LOGE(AAFwkTag::CONTEXT, "requestId=%{public}s not exist", requestId.c_str());
}

void AbilityContextImpl::OnRequestFailure(const std::string &requestId, const AppExecFwk::ElementName &element,
    const std::string &message)
{
    std::shared_ptr<OnRequestResultElement> result = nullptr;
    {
        std::lock_guard lock(onRequestResultMutex_);
        for (auto iter = onRequestResults_.begin(); iter != onRequestResults_.end(); iter++) {
            if ((*iter)->requestId_ == requestId) {
                result = *iter;
                onRequestResults_.erase(iter);
                break;
            }
        }
    }

    if (result != nullptr) {
        TAG_LOGI(AAFwkTag::CONTEXT, "requestId=%{public}s, call onRequestFailure", requestId.c_str());
        result->onRequestFailure_(element, message);
        return;
    }

    TAG_LOGE(AAFwkTag::CONTEXT, "requestId=%{public}s not exist", requestId.c_str());
}


ErrCode AbilityContextImpl::StartAppServiceExtensionAbility(const AAFwk::Want& want)
{
    TAG_LOGI(AAFwkTag::CONTEXT, "StartAppServiceExtensionAbility, name:%{public}s %{public}s",
        want.GetElement().GetBundleName().c_str(), want.GetElement().GetAbilityName().c_str());
    ErrCode err = AAFwk::AbilityManagerClient::GetInstance()->StartExtensionAbility(
        want, token_, DEFAULT_INVAL_VALUE, AppExecFwk::ExtensionAbilityType::APP_SERVICE);
    if (err != ERR_OK) {
        TAG_LOGE(AAFwkTag::CONTEXT, "failed:%{public}d", err);
    }
    return err;
}

ErrCode AbilityContextImpl::StopAppServiceExtensionAbility(const AAFwk::Want& want)
{
    TAG_LOGD(AAFwkTag::CONTEXT, "StopAppServiceExtensionAbility, name:%{public}s %{public}s",
        want.GetElement().GetBundleName().c_str(), want.GetElement().GetAbilityName().c_str());
    ErrCode err = AAFwk::AbilityManagerClient::GetInstance()->StopExtensionAbility(
        want, token_, DEFAULT_INVAL_VALUE, AppExecFwk::ExtensionAbilityType::APP_SERVICE);
    if (err != ERR_OK) {
        TAG_LOGE(AAFwkTag::CONTEXT, "failed %{public}d", err);
    }
    return err;
}

ErrCode AbilityContextImpl::ConnectAppServiceExtensionAbility(const AAFwk::Want& want,
    const sptr<AbilityConnectCallback>& connectCallback)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    TAG_LOGI(AAFwkTag::CONTEXT, "ConnectAppServiceExtensionAbility, caller:%{public}s, target:%{public}s",
        abilityInfo_ == nullptr ? "" : abilityInfo_->name.c_str(), want.GetElement().GetAbilityName().c_str());
    ErrCode ret = ConnectionManager::GetInstance().ConnectAppServiceExtensionAbility(token_, want, connectCallback);
    if (ret != ERR_OK) {
        TAG_LOGE(AAFwkTag::CONTEXT, "failed %{public}d", ret);
    }
    return ret;
}
} // namespace AbilityRuntime
} // namespace OHOS
