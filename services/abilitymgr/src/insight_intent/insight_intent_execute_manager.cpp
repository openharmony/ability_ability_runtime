/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#include "insight_intent_execute_manager.h"

#include "ability_config.h"
#include "ability_util.h"
#include "ability_manager_errors.h"
#include "extract_insight_intent_profile.h"
#include "hilog_tag_wrapper.h"
#include "insight_intent_execute_callback_interface.h"
#include "insight_intent_db_cache.h"
#include "insight_intent_utils.h"
#include "permission_verification.h"
#include "want_params_wrapper.h"
#include "time_util.h"
#include "res_sched_util.h"

namespace OHOS {
namespace AAFwk {
namespace {
constexpr size_t INSIGHT_INTENT_EXECUTE_RECORDS_MAX_SIZE = 256;
constexpr char EXECUTE_INSIGHT_INTENT_PERMISSION[] = "ohos.permission.EXECUTE_INSIGHT_INTENT";
constexpr int32_t OPERATION_DURATION = 10000;
}
using namespace AppExecFwk;
using InsightIntentType = AbilityRuntime::InsightIntentType;
using ExtractInsightIntentInfo = AbilityRuntime::ExtractInsightIntentInfo;
using InsightIntentPageInfo = AbilityRuntime::InsightIntentPageInfo;
using InsightIntentFunctionInfo = AbilityRuntime::InsightIntentFunctionInfo;
using InsightIntentEntryInfo = AbilityRuntime::InsightIntentEntryInfo;

void InsightIntentExecuteRecipient::OnRemoteDied(const wptr<OHOS::IRemoteObject> &remote)
{
    TAG_LOGD(AAFwkTag::INTENT, "InsightIntentExecuteRecipient OnRemoteDied, %{public}" PRIu64, intentId_);
    auto object = remote.promote();
    if (object == nullptr) {
        TAG_LOGE(AAFwkTag::INTENT, "null object");
        return;
    }
    DelayedSingleton<InsightIntentExecuteManager>::GetInstance()->RemoteDied(intentId_);
}

InsightIntentExecuteManager::InsightIntentExecuteManager() = default;

InsightIntentExecuteManager::~InsightIntentExecuteManager() = default;

int32_t InsightIntentExecuteManager::CheckAndUpdateParam(uint64_t key, const sptr<IRemoteObject> &callerToken,
    const std::shared_ptr<AppExecFwk::InsightIntentExecuteParam> &param, std::string callerBundleName,
    const bool ignoreAbilityName)
{
    int32_t result = CheckCallerPermission();
    if (result != ERR_OK) {
        return result;
    }
    if (callerToken == nullptr) {
        TAG_LOGE(AAFwkTag::INTENT, "null callerToken");
        return ERR_INVALID_VALUE;
    }
    if (param == nullptr) {
        TAG_LOGE(AAFwkTag::INTENT, "null param");
        return ERR_INVALID_VALUE;
    }
    if (param->bundleName_.empty() || param->moduleName_.empty() ||
        (!ignoreAbilityName && param->abilityName_.empty()) || param->insightIntentName_.empty()) {
        TAG_LOGE(AAFwkTag::INTENT, "invalid param");
        return ERR_INVALID_VALUE;
    }
    uint64_t intentId = 0;
    result = AddRecord(key, callerToken, param->bundleName_, intentId, callerBundleName);
    if (result != ERR_OK) {
        return result;
    }

    param->insightIntentId_ = intentId;
    return ERR_OK;
}

int32_t InsightIntentExecuteManager::CheckAndUpdateWant(Want &want, ExecuteMode executeMode,
    std::string callerBundleName)
{
    auto uriVec = want.GetStringArrayParam(AbilityConfig::PARAMS_STREAM);
    auto uriVecTemp = want.GetStringArrayParam(INSIGHT_INTENT_EXECUTE_PARAM_URI);
    uriVec.insert(uriVec.begin(), uriVecTemp.begin(), uriVecTemp.end());
    want.SetParam(AbilityConfig::PARAMS_STREAM, uriVec);
    auto myflags = want.GetIntParam(INSIGHT_INTENT_EXECUTE_PARAM_FLAGS, 0);
    myflags |= want.GetFlags();
    want.SetFlags(myflags);

    int32_t result = IsValidCall(want);
    if (result != ERR_OK) {
        return result;
    }
    uint64_t intentId = 0;
    ElementName elementName = want.GetElement();
    result = AddRecord(0, nullptr, want.GetBundle(), intentId, callerBundleName);
    if (result != ERR_OK) {
        return result;
    }

    std::string srcEntry;
    auto ret = AbilityRuntime::InsightIntentUtils::GetSrcEntry(elementName,
        want.GetStringParam(INSIGHT_INTENT_EXECUTE_PARAM_NAME), executeMode, srcEntry);
    if (ret != ERR_OK || srcEntry.empty()) {
        TAG_LOGE(AAFwkTag::INTENT, "empty srcEntry");
        return ERR_INVALID_VALUE;
    }
    want.SetParam(INSIGHT_INTENT_SRC_ENTRY, srcEntry);
    want.SetParam(INSIGHT_INTENT_EXECUTE_PARAM_ID, std::to_string(intentId));
    want.SetParam(INSIGHT_INTENT_EXECUTE_PARAM_MODE, executeMode);
    TAG_LOGD(AAFwkTag::INTENT, "check done. insightIntentId: %{public}" PRIu64, intentId);
    return ERR_OK;
}

int32_t InsightIntentExecuteManager::AddRecord(uint64_t key, const sptr<IRemoteObject> &callerToken,
    const std::string &bundleName, uint64_t &intentId, const std::string &callerBundleName)
{
    std::lock_guard<ffrt::mutex> lock(mutex_);
    intentId = ++intentIdCount_;
    auto record = std::make_shared<InsightIntentExecuteRecord>();
    record->key = key;
    record->state = InsightIntentExecuteState::EXECUTING;
    record->callerToken = callerToken;
    record->bundleName = bundleName;
    record->callerBundleName = callerBundleName;
    if (callerToken != nullptr) {
        record->deathRecipient = sptr<InsightIntentExecuteRecipient>::MakeSptr(intentId);
        callerToken->AddDeathRecipient(record->deathRecipient);
    }

    // replace
    records_[intentId] = record;
    if (intentId > INSIGHT_INTENT_EXECUTE_RECORDS_MAX_SIZE) {
        // save the latest INSIGHT_INTENT_EXECUTE_RECORDS_MAX_SIZE records
        records_.erase(intentId - INSIGHT_INTENT_EXECUTE_RECORDS_MAX_SIZE);
    }
    TAG_LOGD(AAFwkTag::INTENT, "init done, records_ size: %{public}zu", records_.size());
    return ERR_OK;
}

int32_t InsightIntentExecuteManager::RemoveExecuteIntent(uint64_t intentId)
{
    std::lock_guard<ffrt::mutex> lock(mutex_);
    records_.erase(intentId);
    return ERR_OK;
}

int32_t InsightIntentExecuteManager::ExecuteIntentDone(uint64_t intentId, int32_t resultCode,
    const AppExecFwk::InsightIntentExecuteResult &result)
{
    std::lock_guard<ffrt::mutex> lock(mutex_);
    EventInfo eventInfo;
    auto findResult = records_.find(intentId);
    if (findResult == records_.end()) {
        TAG_LOGE(AAFwkTag::INTENT, "intent not found, id: %{public}" PRIu64, intentId);
        eventInfo.errReason = "intent not found";
        SendIntentReport(eventInfo, INTENT_NOT_EXIST);
        return ERR_INVALID_VALUE;
    }

    std::shared_ptr<InsightIntentExecuteRecord> record = findResult->second;
    if (record == nullptr) {
        TAG_LOGE(AAFwkTag::INTENT, "null record, id: %{public}" PRIu64, intentId);
        return ERR_INVALID_VALUE;
    }

    TAG_LOGD(AAFwkTag::INTENT, "callback start, id:%{public}" PRIu64, intentId);
    if (record->state != InsightIntentExecuteState::EXECUTING) {
        TAG_LOGW(AAFwkTag::INTENT, "insight intent execute state is not EXECUTING, id:%{public}" PRIu64, intentId);
        eventInfo.errReason = "intent state error";
        SendIntentReport(eventInfo, INTENT_STATE_NOT_EXECUTING);
        return ERR_INVALID_OPERATION;
    }
    record->state = InsightIntentExecuteState::EXECUTE_DONE;
    sptr<IInsightIntentExecuteCallback> remoteCallback = iface_cast<IInsightIntentExecuteCallback>(record->callerToken);
    if (remoteCallback == nullptr) {
        TAG_LOGE(AAFwkTag::INTENT, "intentExecuteCallback empty");
        return ERR_INVALID_VALUE;
    }
    remoteCallback->OnExecuteDone(record->key, resultCode, result);
    if (record->callerToken != nullptr) {
        record->callerToken->RemoveDeathRecipient(record->deathRecipient);
        record->callerToken = nullptr;
    }
    TAG_LOGD(AAFwkTag::INTENT, "execute done, records_ size: %{public}zu", records_.size());
    return ERR_OK;
}

int32_t InsightIntentExecuteManager::RemoteDied(uint64_t intentId)
{
    std::lock_guard<ffrt::mutex> lock(mutex_);
    auto result = records_.find(intentId);
    if (result == records_.end()) {
        TAG_LOGE(AAFwkTag::INTENT, "intent not found, id: %{public}" PRIu64, intentId);
        return ERR_INVALID_VALUE;
    }
    if (result->second == nullptr) {
        TAG_LOGE(AAFwkTag::INTENT, "null intent record , id: %{public}" PRIu64, intentId);
        return ERR_INVALID_VALUE;
    }
    result->second->callerToken = nullptr;
    result->second->state = InsightIntentExecuteState::REMOTE_DIED;
    return ERR_OK;
}

int32_t InsightIntentExecuteManager::GetBundleName(uint64_t intentId, std::string &bundleName) const
{
    std::lock_guard<ffrt::mutex> lock(mutex_);
    auto result = records_.find(intentId);
    if (result == records_.end()) {
        TAG_LOGE(AAFwkTag::INTENT, "intent not found, id: %{public}" PRIu64, intentId);
        return ERR_INVALID_VALUE;
    }
    if (result->second == nullptr) {
        TAG_LOGE(AAFwkTag::INTENT, "null intent record,id: %{public}" PRIu64, intentId);
        return ERR_INVALID_VALUE;
    }
    bundleName = result->second->bundleName;
    return ERR_OK;
}

int32_t InsightIntentExecuteManager::GetCallerBundleName(uint64_t intentId, std::string &callerBundleName) const
{
    std::lock_guard<ffrt::mutex> lock(mutex_);
    auto result = records_.find(intentId);
    if (result == records_.end()) {
        TAG_LOGE(AAFwkTag::INTENT, "intent not found, id: %{public}" PRIu64, intentId);
        return ERR_INVALID_VALUE;
    }
    if (result->second == nullptr) {
        TAG_LOGE(AAFwkTag::INTENT, "null intent record,id: %{public}" PRIu64, intentId);
        return ERR_INVALID_VALUE;
    }
    callerBundleName = result->second->callerBundleName;
    return ERR_OK;
}

int32_t InsightIntentExecuteManager::AddWantUirsAndFlagsFromParam(
    const std::shared_ptr<AppExecFwk::InsightIntentExecuteParam> &param, Want &want)
{
    if (param == nullptr) {
        TAG_LOGE(AAFwkTag::INTENT, "null param");
        return ERR_INVALID_VALUE;
    }
    if (param->uris_.size() > 0) {
        auto uriVec = want.GetStringArrayParam(AbilityConfig::PARAMS_STREAM);
        for (auto &uri : param->uris_) {
            if (!uri.empty()) {
                uriVec.insert(uriVec.begin(), uri);
            }
        }
        want.SetParam(AbilityConfig::PARAMS_STREAM, uriVec);
        auto flags = want.GetFlags();
        flags |= param->flags_;
        want.SetFlags(flags);
    }
    return ERR_OK;
}

int32_t InsightIntentExecuteManager::UpdateFuncDecoratorParams(
    const std::shared_ptr<AppExecFwk::InsightIntentExecuteParam> &param,
    ExtractInsightIntentInfo &info, Want &want)
{
    if (param->executeMode_ != AppExecFwk::ExecuteMode::UI_ABILITY_BACKGROUND) {
        TAG_LOGE(AAFwkTag::INTENT, "invalid execute mode %{public}d", param->executeMode_);
        return ERR_INVALID_VALUE;
    }

    std::string srcEntrance = info.decoratorFile;
    want.SetParam(INSIGHT_INTENT_SRC_ENTRANCE, srcEntrance);

    std::string className = info.decoratorClass;
    std::string methodName = info.genericInfo.get<InsightIntentFunctionInfo>().functionName;
    std::vector<std::string> methodParams = info.genericInfo.get<InsightIntentFunctionInfo>().functionParams;
    if (className.empty() || methodName.empty()) {
        TAG_LOGE(AAFwkTag::INTENT, "invalid func param");
        return ERR_INVALID_VALUE;
    }
    want.SetParam(INSIGHT_INTENT_FUNC_PARAM_CLASSNAME, className);
    want.SetParam(INSIGHT_INTENT_FUNC_PARAM_METHODNAME, methodName);
    want.SetParam(INSIGHT_INTENT_FUNC_PARAM_METHODPARAMS, methodParams);
    return ERR_OK;
}

int32_t InsightIntentExecuteManager::UpdatePageDecoratorParams(
    const std::shared_ptr<AppExecFwk::InsightIntentExecuteParam> &param,
    ExtractInsightIntentInfo &info, Want &want)
{
    if (param->executeMode_ != AppExecFwk::ExecuteMode::UI_ABILITY_FOREGROUND) {
        TAG_LOGE(AAFwkTag::INTENT, "invalid execute mode %{public}d", param->executeMode_);
        return ERR_INVALID_VALUE;
    }

    std::string srcEntrance = info.decoratorFile;
    want.SetParam(INSIGHT_INTENT_SRC_ENTRANCE, srcEntrance);

    std::string pagePath = info.genericInfo.get<InsightIntentPageInfo>().pageRouteName;
    std::string navigationId = info.genericInfo.get<InsightIntentPageInfo>().navigationId;
    std::string navDestinationName = info.genericInfo.get<InsightIntentPageInfo>().navDestination;
    std::string uiAbilityName = info.genericInfo.get<InsightIntentPageInfo>().uiAbility;
    if (pagePath.empty() || uiAbilityName != param->abilityName_) {
        TAG_LOGE(AAFwkTag::INTENT, "invalid page param, pagePath %{public}s, uiability %{public}s, %{public}s",
            pagePath.c_str(), uiAbilityName.c_str(), param->abilityName_.c_str());
        return ERR_INVALID_VALUE;
    }
    if (uiAbilityName.empty()) {
        auto bms = AbilityUtil::GetBundleManagerHelper();
        if (bms == nullptr) {
            TAG_LOGE(AAFwkTag::INTENT, "get bms failed");
            return ERR_INVALID_VALUE;
        }
        const int32_t userId = IPCSkeleton::GetCallingUid() / AppExecFwk::Constants::BASE_USER_RANGE;
        std::vector<AppExecFwk::AbilityInfo> abilityInfos;
        if (IN_PROCESS_CALL(bms->GetLauncherAbilityInfoSync(param->bundleName_, userId, abilityInfos)) != ERR_OK) {
            TAG_LOGE(AAFwkTag::INTENT, "get launcher ability info failed");
            return ERR_INVALID_VALUE;
        }
        for (auto &info: abilityInfos) {
            TAG_LOGD(AAFwkTag::INTENT, "moduleName %{public}s", param->moduleName_.c_str());
            if (info.moduleName == param->moduleName_) {
                TAG_LOGI(AAFwkTag::INTENT, "ability matched %{public}s", info.name.c_str());
                param->abilityName_ = info.name;
                break;
            }
        }
    }
    if (param->abilityName_.empty()) {
        TAG_LOGE(AAFwkTag::INTENT, "ability name empty");
        return ERR_INVALID_VALUE;
    }
    want.SetElementName("", param->bundleName_, param->abilityName_, param->moduleName_);
    want.SetParam(INSIGHT_INTENT_PAGE_PARAM_PAGEPATH, pagePath);
    want.SetParam(INSIGHT_INTENT_PAGE_PARAM_NAVIGATIONID, navigationId);
    want.SetParam(INSIGHT_INTENT_PAGE_PARAM_NAVDESTINATIONNAME, navDestinationName);
    return ERR_OK;
}

int32_t InsightIntentExecuteManager::UpdateEntryDecoratorParams(
    const std::shared_ptr<AppExecFwk::InsightIntentExecuteParam> &param,
    ExtractInsightIntentInfo &info, Want &want)
{
    TAG_LOGD(AAFwkTag::INTENT, "update entry params");
    std::string srcEntrance = info.decoratorFile;
    want.SetParam(INSIGHT_INTENT_SRC_ENTRANCE, srcEntrance);
    auto executeMode = param->executeMode_;
    std::vector<ExecuteMode> supportModes = info.genericInfo.get<InsightIntentEntryInfo>().executeMode;
    TAG_LOGD(AAFwkTag::INTENT, "support mode size %{public}zu", supportModes.size());
    bool found = std::find(supportModes.begin(), supportModes.end(), executeMode) != supportModes.end();
    if (!found) {
        TAG_LOGE(AAFwkTag::INTENT, "execute mode %{public}d mismatch", executeMode);
        return ERR_INVALID_VALUE;
    }
    return ERR_OK;
}

int32_t InsightIntentExecuteManager::CheckAndUpdateDecoratorParams(
    const std::shared_ptr<AppExecFwk::InsightIntentExecuteParam> &param,
    const AbilityRuntime::ExtractInsightIntentGenericInfo &decoratorInfo,
    Want &want)
{
    // ExtractInsightIntentGenericInfo don't satisfy for now
    ExtractInsightIntentInfo info;
    const int32_t userId = IPCSkeleton::GetCallingUid() / AppExecFwk::Constants::BASE_USER_RANGE;
    DelayedSingleton<AbilityRuntime::InsightIntentDbCache>::GetInstance()->GetInsightIntentInfo(
        param->bundleName_, param->moduleName_, param->insightIntentName_, userId, info);

    InsightIntentType type = InsightIntentType::DECOR_NONE;
    std::string decoratorType = info.genericInfo.decoratorType;
    TAG_LOGD(AAFwkTag::INTENT, "intentName %{public}s, decoratorType %{public}s", param->insightIntentName_.c_str(),
        decoratorType.c_str());
    static const std::unordered_map<std::string, InsightIntentType> mapping = {
        {AbilityRuntime::INSIGHT_INTENTS_DECORATOR_TYPE_LINK, InsightIntentType::DECOR_LINK},
        {AbilityRuntime::INSIGHT_INTENTS_DECORATOR_TYPE_PAGE, InsightIntentType::DECOR_PAGE},
        {AbilityRuntime::INSIGHT_INTENTS_DECORATOR_TYPE_ENTRY, InsightIntentType::DECOR_ENTRY},
        {AbilityRuntime::INSIGHT_INTENTS_DECORATOR_TYPE_FUNCTION, InsightIntentType::DECOR_FUNC},
        {AbilityRuntime::INSIGHT_INTENTS_DECORATOR_TYPE_FORM, InsightIntentType::DECOR_FORM}
    };
    auto it = mapping.find(decoratorType);
    if (it != mapping.end()) {
        type = it->second;
    }

    want.SetParam(INSIGHT_INTENT_DECORATOR_TYPE, static_cast<int>(type));
    TAG_LOGD(AAFwkTag::INTENT, "intentName %{public}s, type %{public}d", param->insightIntentName_.c_str(),
        static_cast<int8_t>(type));
    switch (type) {
        case InsightIntentType::DECOR_FUNC: {
            return UpdateFuncDecoratorParams(param, info, want);
        }
        case InsightIntentType::DECOR_PAGE: {
            return UpdatePageDecoratorParams(param, info, want);
        }
        case InsightIntentType::DECOR_ENTRY: {
            return UpdateEntryDecoratorParams(param, info, want);
        }
        case InsightIntentType::DECOR_NONE:
        case InsightIntentType::DECOR_LINK:
        case InsightIntentType::DECOR_FORM:
        default:
            break;
    }
    return ERR_OK;
}

int32_t InsightIntentExecuteManager::GenerateWant(
    const std::shared_ptr<AppExecFwk::InsightIntentExecuteParam> &param,
    const AbilityRuntime::ExtractInsightIntentGenericInfo &decoratorInfo,
    Want &want)
{
    if (param == nullptr) {
        TAG_LOGE(AAFwkTag::INTENT, "null param");
        return ERR_INVALID_VALUE;
    }
    want.SetElementName("", param->bundleName_, param->abilityName_, param->moduleName_);

    if (param->insightIntentParam_ != nullptr) {
        sptr<AAFwk::IWantParams> pExecuteParams = WantParamWrapper::Box(*param->insightIntentParam_);
        if (pExecuteParams != nullptr) {
            WantParams wantParams;
            wantParams.SetParam(INSIGHT_INTENT_EXECUTE_PARAM_PARAM, pExecuteParams);
            want.SetParams(wantParams);
        }
    }

    std::string srcEntry;
    auto ret = AbilityRuntime::InsightIntentUtils::GetSrcEntry(want.GetElement(), param->insightIntentName_,
        static_cast<AppExecFwk::ExecuteMode>(param->executeMode_), srcEntry);
    if (!srcEntry.empty()) {
        want.SetParam(INSIGHT_INTENT_SRC_ENTRY, srcEntry);
    } else if (decoratorInfo.decoratorType == "" && ret == ERR_INSIGHT_INTENT_GET_PROFILE_FAILED &&
        param->executeMode_ == AppExecFwk::ExecuteMode::UI_ABILITY_FOREGROUND) {
        TAG_LOGI(AAFwkTag::INTENT, "insight intent srcEntry invalid, try free install ondemand");
        std::string startTime = std::to_string(std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count());
        want.SetParam(Want::PARAM_RESV_START_TIME, startTime);
        want.AddFlags(Want::FLAG_INSTALL_ON_DEMAND);
    } else if (decoratorInfo.decoratorType == "") {
        // decoratorType is empty indicate no decorator
        TAG_LOGE(AAFwkTag::INTENT, "insight intent srcEntry invalid");
        return ERR_INVALID_VALUE;
    }

    want.SetParam(INSIGHT_INTENT_EXECUTE_PARAM_NAME, param->insightIntentName_);
    want.SetParam(INSIGHT_INTENT_EXECUTE_PARAM_MODE, param->executeMode_);
    want.SetParam(INSIGHT_INTENT_EXECUTE_PARAM_ID, std::to_string(param->insightIntentId_));
    if (param->displayId_ != INVALID_DISPLAY_ID) {
        want.SetParam(Want::PARAM_RESV_DISPLAY_ID, param->displayId_);
        TAG_LOGD(AAFwkTag::INTENT, "Generate want with displayId: %{public}d", param->displayId_);
    }

    ret = AddWantUirsAndFlagsFromParam(param, want);
    if (ret != ERR_OK) {
        return ret;
    }

    ret = CheckAndUpdateDecoratorParams(param, decoratorInfo, want);
    if (ret != ERR_OK) {
        // log has print in sub method
        return ret;
    }

    return ERR_OK;
}

int32_t InsightIntentExecuteManager::IsValidCall(const Want &want)
{
    std::string insightIntentName = want.GetStringParam(INSIGHT_INTENT_EXECUTE_PARAM_NAME);
    if (insightIntentName.empty()) {
        TAG_LOGE(AAFwkTag::INTENT, "empty insightIntentName");
        return ERR_INVALID_VALUE;
    }
    TAG_LOGD(AAFwkTag::INTENT, "insightIntentName: %{public}s", insightIntentName.c_str());

    int32_t ret = CheckCallerPermission();
    if (ret != ERR_OK) {
        return ret;
    }
    return ERR_OK;
}

int32_t InsightIntentExecuteManager::CheckCallerPermission()
{
    bool isSystemAppCall = PermissionVerification::GetInstance()->JudgeCallerIsAllowedToUseSystemAPI();
    if (!isSystemAppCall) {
        TAG_LOGE(AAFwkTag::INTENT, "system-api cannot use");
        return ERR_NOT_SYSTEM_APP;
    }

    bool isCallingPerm = PermissionVerification::GetInstance()->VerifyCallingPermission(
        EXECUTE_INSIGHT_INTENT_PERMISSION);
    if (!isCallingPerm) {
        TAG_LOGE(AAFwkTag::INTENT, "permission %{public}s verification failed", EXECUTE_INSIGHT_INTENT_PERMISSION);
        return ERR_PERMISSION_DENIED;
    }
    return ERR_OK;
}

void InsightIntentExecuteManager::SetIntentExemptionInfo(int32_t uid)
{
    std::lock_guard<ffrt::mutex> guard(intentExemptionLock_);
    std::map<int32_t, int64_t>::iterator iter = intentExemptionDeadlineTime_.find(uid);
    intentExemptionDeadlineTime_[uid] = AbilityRuntime::TimeUtil::CurrentTimeMillis();
}

bool InsightIntentExecuteManager::CheckIntentIsExemption(int32_t uid)
{
    std::lock_guard<ffrt::mutex> guard(intentExemptionLock_);
    if (intentExemptionDeadlineTime_.find(uid) != intentExemptionDeadlineTime_.end()) {
        if (AbilityRuntime::TimeUtil::CurrentTimeMillis() - INTENT_EXEMPTION_DURATION <=
            intentExemptionDeadlineTime_[uid]) {
            TAG_LOGD(AAFwkTag::ABILITYMGR, "exemption check uid:%{public}d", uid);
            return true;
        } else {
            intentExemptionDeadlineTime_.erase(uid);
            return false;
        }
    }
    return false;
}

std::map<int32_t, int64_t> InsightIntentExecuteManager::GetAllIntentExemptionInfo() const
{
    std::lock_guard<ffrt::mutex> guard(intentExemptionLock_);
    return intentExemptionDeadlineTime_;
}

void InsightIntentExecuteManager::SendIntentReport(EventInfo &eventInfo, int32_t errCode)
{
    eventInfo.errCode = errCode;
    EventReport::SendExecuteIntentEvent(EventName::EXECUTE_INSIGHT_INTENT_ERROR, HiSysEventType::FAULT, eventInfo);
}
} // namespace AAFwk
} // namespace OHOS
