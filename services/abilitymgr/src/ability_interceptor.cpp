/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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

#include "ability_interceptor.h"

#include <chrono>

#include "ability_info.h"
#include "ability_manager_errors.h"
#include "ability_record.h"
#include "accesstoken_kit.h"
#include "app_jump_control_rule.h"
#include "app_running_control_rule_result.h"
#include "bundle_constants.h"
#include "ecological_rule/ability_ecological_rule_mgr_service.h"
#include "hilog_tag_wrapper.h"
#include "hilog_wrapper.h"
#include "hitrace_meter.h"
#include "iservice_registry.h"
#include "in_process_call_wrapper.h"
#include "ipc_skeleton.h"
#include "modal_system_ui_extension.h"
#include "parameters.h"
#include "permission_constants.h"
#include "permission_verification.h"
#include "start_ability_utils.h"
#include "system_dialog_scheduler.h"
#include "want.h"
#include "want_params_wrapper.h"
namespace OHOS {
namespace AAFwk {

const std::string ACTION_MARKET_CROWDTEST = "ohos.want.action.marketCrowdTest";
const std::string ACTION_MARKET_DISPOSED = "ohos.want.action.marketDisposed";
const std::string PERMISSION_MANAGE_DISPOSED_APP_STATUS = "ohos.permission.MANAGE_DISPOSED_APP_STATUS";
const std::string JUMP_DIALOG_CALLER_BUNDLE_NAME = "interceptor_callerBundleName";
const std::string JUMP_DIALOG_CALLER_MODULE_NAME = "interceptor_callerModuleName";
const std::string JUMP_DIALOG_CALLER_LABEL_ID = "interceptor_callerLabelId";
const std::string JUMP_DIALOG_TARGET_MODULE_NAME = "interceptor_targetModuleName";
const std::string JUMP_DIALOG_TARGET_LABEL_ID = "interceptor_targetLabelId";
const std::string UNREGISTER_EVENT_TASK = "unregister event task";
const std::string UNREGISTER_TIMEOUT_OBSERVER_TASK = "unregister timeout observer task";
const std::string ABILITY_SUPPORT_ECOLOGICAL_RULEMGRSERVICE = "persist.sys.abilityms.support.ecologicalrulemgrservice";
const std::string IS_FROM_PARENTCONTROL = "ohos.ability.isFromParentControl";
const std::string INTERCEPT_PARAMETERS = "intercept_parammeters";
const std::string INTERCEPT_BUNDLE_NAME = "intercept_bundleName";
const std::string INTERCEPT_ABILITY_NAME = "intercept_abilityName";
const std::string INTERCEPT_MODULE_NAME = "intercept_moduleName";
const std::string BUNDLE_NAME_SCENEBOARD = "com.ohos.sceneboard";
constexpr int UNREGISTER_OBSERVER_MICRO_SECONDS = 5000;
#define RETURN_BY_ISEDM(object)                 \
    if (object) {                               \
        return ERR_EDM_APP_CONTROLLED;          \
    }                                           \
    return ERR_APP_CONTROLLED;

ErrCode CrowdTestInterceptor::DoProcess(const Want &want, int requestCode, int32_t userId, bool isForeground,
    const sptr<IRemoteObject> &callerToken)
{
    if (CheckCrowdtest(want, userId)) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "Crowdtest expired.");
#ifdef SUPPORT_GRAPHICS
        if (isForeground) {
            int ret = IN_PROCESS_CALL(AbilityUtil::StartAppgallery(want.GetBundle(), requestCode, userId,
                ACTION_MARKET_CROWDTEST));
            if (ret != ERR_OK) {
                TAG_LOGE(AAFwkTag::ABILITYMGR, "Crowdtest implicit start appgallery failed.");
                return ret;
            }
        }
#endif
        return ERR_CROWDTEST_EXPIRED;
    }
    return ERR_OK;
}

bool CrowdTestInterceptor::CheckCrowdtest(const Want &want, int32_t userId)
{
    // get crowdtest status and time
    AppExecFwk::ApplicationInfo appInfo;
    if (!StartAbilityUtils::GetApplicationInfo(want.GetBundle(), userId, appInfo)) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "failed to get application info.");
        return false;
    }

    auto appDistributionType = appInfo.appDistributionType;
    auto appCrowdtestDeadline = appInfo.crowdtestDeadline;
    int64_t now = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::
        system_clock::now().time_since_epoch()).count();
    if (appDistributionType == AppExecFwk::Constants::APP_DISTRIBUTION_TYPE_CROWDTESTING &&
        appCrowdtestDeadline < now) {
        TAG_LOGI(AAFwkTag::ABILITYMGR, "The application is expired, expired time is %{public}s",
            std::to_string(appCrowdtestDeadline).c_str());
        return true;
    }
    return false;
}

ErrCode ControlInterceptor::DoProcess(const Want &want, int requestCode, int32_t userId, bool isForeground,
    const sptr<IRemoteObject> &callerToken)
{
    AppExecFwk::AppRunningControlRuleResult controlRule;
    if (CheckControl(want, userId, controlRule)) {
        TAG_LOGI(AAFwkTag::ABILITYMGR, "The target application is intercpted. %{public}s",
            controlRule.controlMessage.c_str());
#ifdef SUPPORT_GRAPHICS
        if (!isForeground || controlRule.controlWant == nullptr) {
            TAG_LOGE(AAFwkTag::ABILITYMGR, "Can not start control want");
            RETURN_BY_ISEDM(controlRule.isEdm);
        }
        if (controlRule.controlWant->GetBoolParam(IS_FROM_PARENTCONTROL, false)) {
            auto controlWant = controlRule.controlWant;
            auto controlParam = controlWant->GetParams();
            sptr<AAFwk::IWantParams> interceptParam = WantParamWrapper::Box(want.GetParams());
            if (interceptParam != nullptr) {
                controlParam.SetParam(INTERCEPT_PARAMETERS, interceptParam);
            }
            controlWant->SetParams(controlParam);
            controlWant->SetParam(INTERCEPT_BUNDLE_NAME, want.GetElement().GetBundleName());
            controlWant->SetParam(INTERCEPT_ABILITY_NAME, want.GetElement().GetAbilityName());
            controlWant->SetParam(INTERCEPT_MODULE_NAME, want.GetElement().GetModuleName());
            controlRule.controlWant = controlWant;
        }
        int ret = IN_PROCESS_CALL(AbilityManagerClient::GetInstance()->StartAbility(*controlRule.controlWant,
            requestCode, userId));
        if (ret != ERR_OK) {
            TAG_LOGE(AAFwkTag::ABILITYMGR, "Control implicit start appgallery failed.");
            return ret;
        }
#endif
        RETURN_BY_ISEDM(controlRule.isEdm);
    }
    return ERR_OK;
}

bool ControlInterceptor::CheckControl(const Want &want, int32_t userId,
    AppExecFwk::AppRunningControlRuleResult &controlRule)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    // get bms
    auto bundleMgrHelper = AbilityUtil::GetBundleManagerHelper();
    if (bundleMgrHelper == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "The bundleMgrHelper is nullptr.");
        return false;
    }

    // get disposed status
    std::string bundleName = want.GetBundle();
    auto appControlMgr = bundleMgrHelper->GetAppControlProxy();
    if (appControlMgr == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "The appControlMgr is nullptr.");
        return false;
    }

    auto ret = IN_PROCESS_CALL(appControlMgr->GetAppRunningControlRule(bundleName, userId, controlRule));
    if (ret != ERR_OK) {
        TAG_LOGD(AAFwkTag::ABILITYMGR, "Get No AppRunningControlRule.");
        return false;
    }
    return true;
}

ErrCode DisposedRuleInterceptor::DoProcess(const Want &want, int requestCode, int32_t userId, bool isForeground,
    const sptr<IRemoteObject> &callerToken)
{
    TAG_LOGD(AAFwkTag::ABILITYMGR, "Call");
    AppExecFwk::DisposedRule disposedRule;
    if (CheckControl(want, userId, disposedRule)) {
        TAG_LOGI(AAFwkTag::ABILITYMGR,
            "The target ability is intercpted, disposedType is %{public}d, controlType is %{public}d, "
            "componentType is %{public}d.",
            disposedRule.disposedType, disposedRule.controlType, disposedRule.componentType);
#ifdef SUPPORT_GRAPHICS
        if (!isForeground || disposedRule.want == nullptr
            || disposedRule.disposedType == AppExecFwk::DisposedType::NON_BLOCK) {
            TAG_LOGE(AAFwkTag::ABILITYMGR, "Can not start disposed want");
            RETURN_BY_ISEDM(disposedRule.isEdm);
        }
        if (disposedRule.want->GetBundle() == want.GetBundle()) {
            TAG_LOGE(AAFwkTag::ABILITYMGR, "Can not start disposed want with same bundleName");
            RETURN_BY_ISEDM(disposedRule.isEdm);
        }
        if (disposedRule.componentType == AppExecFwk::ComponentType::UI_ABILITY) {
            int ret = IN_PROCESS_CALL(AbilityManagerClient::GetInstance()->StartAbility(*disposedRule.want,
                requestCode, userId));
            if (ret != ERR_OK) {
                TAG_LOGE(AAFwkTag::ABILITYMGR, "DisposedRuleInterceptor start ability failed.");
                return ret;
            }
        }
        if (disposedRule.componentType == AppExecFwk::ComponentType::UI_EXTENSION) {
            int ret = CreateModalUIExtension(*disposedRule.want, callerToken);
            if (ret != ERR_OK) {
                TAG_LOGE(AAFwkTag::ABILITYMGR, "failed to start disposed UIExtension");
                return ret;
            }
        }
#endif
        RETURN_BY_ISEDM(disposedRule.isEdm);
    }
    if (disposedRule.disposedType != AppExecFwk::DisposedType::NON_BLOCK) {
        return ERR_OK;
    }
    return StartNonBlockRule(want, disposedRule);
}

bool DisposedRuleInterceptor::CheckControl(const Want &want, int32_t userId,
    AppExecFwk::DisposedRule &disposedRule)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    // get bms
    auto bundleMgrHelper = AbilityUtil::GetBundleManagerHelper();
    if (bundleMgrHelper == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "The bundleMgrHelper is nullptr.");
        return false;
    }

    // get disposed status
    std::string bundleName = want.GetBundle();
    auto appControlMgr = bundleMgrHelper->GetAppControlProxy();
    if (appControlMgr == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "The appControlMgr is nullptr.");
        return false;
    }
    std::vector<AppExecFwk::DisposedRule> disposedRuleList;

    auto ret = IN_PROCESS_CALL(appControlMgr->GetAbilityRunningControlRule(bundleName,
        userId, disposedRuleList));
    if (ret != ERR_OK || disposedRuleList.empty()) {
        TAG_LOGD(AAFwkTag::ABILITYMGR, "Get No DisposedRule");
        return false;
    }

    for (auto &rule:disposedRuleList) {
        if (CheckDisposedRule(want, rule)) {
            disposedRule = rule;
            return true;
        }
    }
    int priority = -1;
    for (auto &rule : disposedRuleList) {
        if (rule.disposedType != AppExecFwk::DisposedType::NON_BLOCK) {
            return false;
        }
        if (rule.priority > priority) {
            priority = rule.priority;
            disposedRule = rule;
        }
    }
    return false;
}

bool DisposedRuleInterceptor::CheckDisposedRule(const Want &want, AppExecFwk::DisposedRule &disposedRule)
{
    if (disposedRule.disposedType == AppExecFwk::DisposedType::NON_BLOCK) {
        return false;
    }
    bool isAllowed = disposedRule.controlType == AppExecFwk::ControlType::ALLOWED_LIST;
    if (disposedRule.disposedType == AppExecFwk::DisposedType::BLOCK_APPLICATION) {
        return !isAllowed;
    }

    std::string moduleName = want.GetElement().GetModuleName();
    std::string abilityName = want.GetElement().GetAbilityName();

    for (auto elementName : disposedRule.elementList) {
        if (moduleName == elementName.GetModuleName()
            && abilityName == elementName.GetAbilityName()) {
            return !isAllowed;
        }
    }
    return isAllowed;
}

ErrCode DisposedRuleInterceptor::StartNonBlockRule(const Want &want, AppExecFwk::DisposedRule &disposedRule)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    TAG_LOGI(AAFwkTag::ABILITYMGR, "not block");
    if (disposedRule.want == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "Can not start disposed app, want is nullptr");
        return ERR_OK;
    }
    if (disposedRule.want->GetBundle() == want.GetBundle()) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "Can not start disposed app with same bundleName");
        return ERR_OK;
    }
    std::string bundleName = want.GetBundle();
    {
        std::lock_guard<ffrt::mutex> guard(observerLock_);
        if (disposedObserverMap_.find(bundleName) != disposedObserverMap_.end()) {
            TAG_LOGD(AAFwkTag::ABILITYMGR, "start same disposed app, do not need to register again");
            return ERR_OK;
        }
    }
    auto disposedObserver = sptr<DisposedObserver>::MakeSptr(disposedRule, shared_from_this());
    CHECK_POINTER_AND_RETURN(disposedObserver, ERR_INVALID_VALUE);
    sptr<OHOS::AppExecFwk::IAppMgr> appManager = GetAppMgr();
    CHECK_POINTER_AND_RETURN(appManager, ERR_INVALID_VALUE);
    std::vector<std::string> bundleNameList;
    bundleNameList.push_back(bundleName);
    int32_t ret = IN_PROCESS_CALL(appManager->RegisterApplicationStateObserver(disposedObserver, bundleNameList));
    if (ret != 0) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "register to appmanager failed. err:%{public}d", ret);
        disposedObserver = nullptr;
        return ret;
    }
    {
        std::lock_guard<ffrt::mutex> guard(observerLock_);
        disposedObserverMap_.emplace(bundleName, disposedObserver);
    }
    auto unregisterTask = [appManager, bundleName, interceptor = shared_from_this()] () {
        std::lock_guard<ffrt::mutex> guard{interceptor->observerLock_};
        auto iter = interceptor->disposedObserverMap_.find(bundleName);
        if (iter != interceptor->disposedObserverMap_.end()) {
            TAG_LOGE(AAFwkTag::ABILITYMGR, "start disposed app time out, need to unregister observer");
            IN_PROCESS_CALL(appManager->UnregisterApplicationStateObserver(iter->second));
            interceptor->disposedObserverMap_.erase(iter);
        }
    };
    taskHandler_->SubmitTask(unregisterTask, UNREGISTER_TIMEOUT_OBSERVER_TASK, UNREGISTER_OBSERVER_MICRO_SECONDS);
    return ERR_OK;
}

sptr<OHOS::AppExecFwk::IAppMgr> DisposedRuleInterceptor::GetAppMgr()
{
    OHOS::sptr<OHOS::ISystemAbilityManager> systemAbilityManager =
        OHOS::SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (!systemAbilityManager) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "get systemAbilityManager failed");
        return nullptr;
    }
    OHOS::sptr<OHOS::IRemoteObject> object = systemAbilityManager->GetSystemAbility(OHOS::APP_MGR_SERVICE_ID);
    if (!object) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "get systemAbilityManager failed");
        return nullptr;
    }
    sptr<OHOS::AppExecFwk::IAppMgr> appMgr = iface_cast<AppExecFwk::IAppMgr>(object);
    if (!appMgr || !appMgr->AsObject()) {
        return nullptr;
    }
    return appMgr;
}

void DisposedRuleInterceptor::UnregisterObserver(const std::string &bundleName)
{
    TAG_LOGD(AAFwkTag::ABILITYMGR, "Call");
    taskHandler_->CancelTask(UNREGISTER_TIMEOUT_OBSERVER_TASK);
    auto unregisterTask = [bundleName, interceptor = shared_from_this()] () {
        std::lock_guard<ffrt::mutex> guard{interceptor->observerLock_};
        auto iter = interceptor->disposedObserverMap_.find(bundleName);
        if (iter == interceptor->disposedObserverMap_.end()) {
            TAG_LOGE(AAFwkTag::ABILITYMGR, "Can not find observer");
        } else {
            auto disposedObserver = iter->second;
            CHECK_POINTER(disposedObserver);
            sptr<OHOS::AppExecFwk::IAppMgr> appManager = interceptor->GetAppMgr();
            CHECK_POINTER(appManager);
            IN_PROCESS_CALL(appManager->UnregisterApplicationStateObserver(disposedObserver));
            interceptor->disposedObserverMap_.erase(iter);
        }
    };
    taskHandler_->SubmitTask(unregisterTask, UNREGISTER_EVENT_TASK);
}

ErrCode DisposedRuleInterceptor::CreateModalUIExtension(const Want &want, const sptr<IRemoteObject> &callerToken)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    auto abilityRecord = Token::GetAbilityRecordByToken(callerToken);
    if (abilityRecord == nullptr) {
        auto systemUIExtension = std::make_shared<OHOS::Rosen::ModalSystemUiExtension>();
        return systemUIExtension->CreateModalUIExtension(want) ? ERR_OK : INNER_ERR;
    } else {
        return abilityRecord->CreateModalUIExtension(want);
    }
}

ErrCode EcologicalRuleInterceptor::DoProcess(const Want &want, int requestCode, int32_t userId, bool isForeground,
    const sptr<IRemoteObject> &callerToken)
{
    if (want.GetStringParam(Want::PARAM_RESV_CALLER_BUNDLE_NAME) ==
        want.GetElement().GetBundleName()) {
        TAG_LOGD(AAFwkTag::ABILITYMGR, "The same bundle, do not intercept.");
        return ERR_OK;
    }
    ErmsCallerInfo callerInfo;
    ExperienceRule rule;
    if (callerToken != nullptr) {
        auto abilityRecord = Token::GetAbilityRecordByToken(callerToken);
        if (abilityRecord && !abilityRecord->GetAbilityInfo().isStageBasedModel) {
            TAG_LOGD(AAFwkTag::ABILITYMGR, "callerModelType is FA.");
            callerInfo.callerModelType = ErmsCallerInfo::MODEL_FA;
        }
    }
    GetEcologicalCallerInfo(want, callerInfo, userId);
    std::string supportErms = OHOS::system::GetParameter(ABILITY_SUPPORT_ECOLOGICAL_RULEMGRSERVICE, "true");
    if (supportErms == "false") {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "Abilityms not support Erms between applications.");
        return ERR_OK;
    }

    int ret = IN_PROCESS_CALL(AbilityEcologicalRuleMgrServiceClient::GetInstance()->QueryStartExperience(want,
        callerInfo, rule));
    if (ret != ERR_OK) {
        TAG_LOGD(AAFwkTag::ABILITYMGR, "check ecological rule failed, keep going.");
        return ERR_OK;
    }
    TAG_LOGD(AAFwkTag::ABILITYMGR, "check ecological rule success");
    if (rule.isAllow) {
        TAG_LOGD(AAFwkTag::ABILITYMGR, "ecological rule is allow, keep going.");
        return ERR_OK;
    }
#ifdef SUPPORT_GRAPHICS
    if (isForeground && rule.replaceWant) {
        (const_cast<Want &>(want)) = *rule.replaceWant;
        (const_cast<Want &>(want)).SetParam("queryWantFromErms", true);
    }
#endif
    return ERR_ECOLOGICAL_CONTROL_STATUS;
}

void EcologicalRuleInterceptor::GetEcologicalCallerInfo(const Want &want, ErmsCallerInfo &callerInfo, int32_t userId)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    callerInfo.packageName = want.GetStringParam(Want::PARAM_RESV_CALLER_BUNDLE_NAME);
    callerInfo.uid = want.GetIntParam(Want::PARAM_RESV_CALLER_UID, IPCSkeleton::GetCallingUid());
    callerInfo.pid = want.GetIntParam(Want::PARAM_RESV_CALLER_PID, IPCSkeleton::GetCallingPid());
    callerInfo.targetAppType = ErmsCallerInfo::TYPE_INVALID;
    callerInfo.callerAppType = ErmsCallerInfo::TYPE_INVALID;
    callerInfo.targetLinkFeature = want.GetStringParam("send_to_erms_targetLinkFeature");
    callerInfo.targetAppDistType = want.GetStringParam("send_to_erms_targetAppDistType");
    (const_cast<Want &>(want)).RemoveParam("send_to_erms_targetLinkFeature");
    (const_cast<Want &>(want)).RemoveParam("send_to_erms_targetAppDistType");
    TAG_LOGD(AAFwkTag::ABILITYMGR, "get callerInfo targetLinkFeature is %{public}s, targetAppDistType is %{public}s",
        callerInfo.targetLinkFeature.c_str(), callerInfo.targetAppDistType.c_str());

    auto bundleMgrHelper = AbilityUtil::GetBundleManagerHelper();
    if (bundleMgrHelper == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "The bundleMgrHelper is nullptr.");
        return;
    }

    auto targetBundleType = static_cast<AppExecFwk::BundleType>(want.GetIntParam("send_to_erms_targetBundleType", -1));
    (const_cast<Want &>(want)).RemoveParam("send_to_erms_targetBundleType");
    if (targetBundleType == AppExecFwk::BundleType::ATOMIC_SERVICE) {
        TAG_LOGD(AAFwkTag::ABILITYMGR, "the target type  is atomic service");
        callerInfo.targetAppType = ErmsCallerInfo::TYPE_ATOM_SERVICE;
    } else if (targetBundleType == AppExecFwk::BundleType::APP) {
        TAG_LOGD(AAFwkTag::ABILITYMGR, "the target type is app");
        callerInfo.targetAppType = ErmsCallerInfo::TYPE_HARMONY_APP;
    }

    std::string callerBundleName;
    ErrCode err = IN_PROCESS_CALL(bundleMgrHelper->GetNameForUid(callerInfo.uid, callerBundleName));
    if (err != ERR_OK) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "Get callerBundleName failed,uid: %{public}d.", callerInfo.uid);
        return;
    }
    AppExecFwk::ApplicationInfo callerAppInfo;
    bool getCallerResult = IN_PROCESS_CALL(bundleMgrHelper->GetApplicationInfo(callerBundleName,
        AppExecFwk::ApplicationFlag::GET_BASIC_APPLICATION_INFO, userId, callerAppInfo));
    if (!getCallerResult) {
        TAG_LOGD(AAFwkTag::ABILITYMGR, "Get callerAppInfo failed.");
    } else if (callerAppInfo.bundleType == AppExecFwk::BundleType::ATOMIC_SERVICE) {
        TAG_LOGD(AAFwkTag::ABILITYMGR, "the caller type  is atomic service");
        callerInfo.callerAppType = ErmsCallerInfo::TYPE_ATOM_SERVICE;
    } else if (callerAppInfo.bundleType == AppExecFwk::BundleType::APP) {
        TAG_LOGD(AAFwkTag::ABILITYMGR, "the caller type is app");
        callerInfo.callerAppType = ErmsCallerInfo::TYPE_HARMONY_APP;
        if (callerInfo.packageName == "" && callerAppInfo.name == BUNDLE_NAME_SCENEBOARD) {
            callerInfo.packageName = BUNDLE_NAME_SCENEBOARD;
        }
    }
}

ErrCode AbilityJumpInterceptor::DoProcess(const Want &want, int requestCode, int32_t userId, bool isForeground,
    const sptr<IRemoteObject> &callerToken)
{
    if (!isForeground) {
        TAG_LOGI(AAFwkTag::ABILITYMGR, "This startup is not foreground, keep going.");
        return ERR_OK;
    }
    bool isStartIncludeAtomicService = AbilityUtil::IsStartIncludeAtomicService(want, userId);
    if (isStartIncludeAtomicService) {
        TAG_LOGI(AAFwkTag::ABILITYMGR, "This startup contain atomic service, keep going.");
        return ERR_OK;
    }
    // get bms
    auto bundleMgrHelper = AbilityUtil::GetBundleManagerHelper();
    if (bundleMgrHelper == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "The bundleMgrHelper is nullptr.");
        return ERR_OK;
    }
    AppExecFwk::AbilityInfo targetAbilityInfo;
    IN_PROCESS_CALL_WITHOUT_RET(bundleMgrHelper->QueryAbilityInfo(want,
        AppExecFwk::AbilityInfoFlag::GET_ABILITY_INFO_WITH_APPLICATION, userId, targetAbilityInfo));
    if (targetAbilityInfo.type != AppExecFwk::AbilityType::PAGE) {
        TAG_LOGI(AAFwkTag::ABILITYMGR, "Target is not page Ability, keep going, abilityType:%{public}d.",
            targetAbilityInfo.type);
        return ERR_OK;
    }
    AppExecFwk::AppJumpControlRule controlRule;
    if (CheckControl(bundleMgrHelper, want, userId, controlRule)) {
#ifdef SUPPORT_GRAPHICS
        TAG_LOGI(AAFwkTag::ABILITYMGR, "app jump need to be intercepted, caller:%{public}s, target:%{public}s",
            controlRule.callerPkg.c_str(), controlRule.targetPkg.c_str());
        auto sysDialogScheduler = DelayedSingleton<SystemDialogScheduler>::GetInstance();
        Want targetWant = want;
        Want dialogWant = sysDialogScheduler->GetJumpInterceptorDialogWant(targetWant);
        AbilityUtil::ParseJumpInterceptorWant(dialogWant, controlRule.callerPkg);
        LoadAppLabelInfo(dialogWant, controlRule, userId);
        int ret = IN_PROCESS_CALL(AbilityManagerClient::GetInstance()->StartAbility(dialogWant,
            requestCode, userId));
        if (ret != ERR_OK) {
            TAG_LOGI(AAFwkTag::ABILITYMGR, "appInterceptor Dialog StartAbility error, ret:%{public}d", ret);
            return ret;
        }
#endif
        return ERR_APP_JUMP_INTERCEPTOR_STATUS;
    }
    return ERR_OK;
}

bool AbilityJumpInterceptor::CheckControl(std::shared_ptr<AppExecFwk::BundleMgrHelper> &bundleMgrHelper,
    const Want &want, int32_t userId, AppExecFwk::AppJumpControlRule &controlRule)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    int callerUid = IPCSkeleton::GetCallingUid();
    std::string callerBundleName;
    auto result = IN_PROCESS_CALL(bundleMgrHelper->GetNameForUid(callerUid, callerBundleName));
    std::string targetBundleName = want.GetBundle();
    controlRule.callerPkg = callerBundleName;
    controlRule.targetPkg = targetBundleName;
    if (result != ERR_OK) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "GetBundleName from bms fail.");
        return false;
    }
    if (controlRule.callerPkg.empty() || controlRule.targetPkg.empty()) {
        TAG_LOGI(AAFwkTag::ABILITYMGR, "This startup is not explicitly, keep going.");
        return false;
    }
    if (controlRule.callerPkg == controlRule.targetPkg) {
        TAG_LOGI(AAFwkTag::ABILITYMGR, "Jump within the same app.");
        return false;
    }
    if (CheckIfJumpExempt(controlRule, userId)) {
        TAG_LOGI(AAFwkTag::ABILITYMGR, "Jump from or to system or exempt apps.");
        return false;
    }
    // get disposed status
    auto appControlMgr = bundleMgrHelper->GetAppControlProxy();
    if (appControlMgr == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "Get appControlMgr failed.");
        return false;
    }

    if (IN_PROCESS_CALL(appControlMgr->GetAppJumpControlRule(callerBundleName, targetBundleName,
        userId, controlRule)) != ERR_OK) {
        TAG_LOGI(AAFwkTag::ABILITYMGR, "No jump control rule found.");
        return true;
    }
    TAG_LOGI(AAFwkTag::ABILITYMGR, "Get appJumpControlRule, jumpMode:%d.", controlRule.jumpMode);
    return controlRule.jumpMode != AppExecFwk::AbilityJumpMode::DIRECT;
}

bool AbilityJumpInterceptor::CheckIfJumpExempt(AppExecFwk::AppJumpControlRule &controlRule, int32_t userId)
{
    if (CheckIfExemptByBundleName(controlRule.callerPkg,
        PermissionConstants::PERMISSION_EXEMPT_AS_CALLER, userId)) {
        TAG_LOGI(AAFwkTag::ABILITYMGR, "Jump from exempt caller app, No need to intercept.");
        return true;
    }
    if (CheckIfExemptByBundleName(controlRule.targetPkg,
        PermissionConstants::PERMISSION_EXEMPT_AS_TARGET, userId)) {
        TAG_LOGI(AAFwkTag::ABILITYMGR, "Jump to exempt target app, No need to intercept.");
        return true;
    }
    TAG_LOGI(AAFwkTag::ABILITYMGR, "Third-party apps jump to third-party apps.");
    return false;
}

bool AbilityJumpInterceptor::CheckIfExemptByBundleName(const std::string &bundleName,
    const std::string &permission, int32_t userId)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    AppExecFwk::ApplicationInfo appInfo;
    if (!StartAbilityUtils::GetApplicationInfo(bundleName, userId, appInfo)) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "failed to get application info.");
        return false;
    }

    if (appInfo.isSystemApp) {
        TAG_LOGI(AAFwkTag::ABILITYMGR, "Bundle:%{public}s is system app.", bundleName.c_str());
        return true;
    }
    int32_t ret = Security::AccessToken::AccessTokenKit::VerifyAccessToken(appInfo.accessTokenId, permission, false);
    if (ret == Security::AccessToken::PermissionState::PERMISSION_DENIED) {
        TAG_LOGD(AAFwkTag::ABILITYMGR, "VerifyPermission %{public}d: PERMISSION_DENIED.", appInfo.accessTokenId);
        return false;
    }
    TAG_LOGI(AAFwkTag::ABILITYMGR, "Bundle:%{public}s verify permission:%{public}s successed.", bundleName.c_str(),
        permission.c_str());
    return true;
}

bool AbilityJumpInterceptor::LoadAppLabelInfo(Want &want,
    AppExecFwk::AppJumpControlRule &controlRule, int32_t userId)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    AppExecFwk::ApplicationInfo callerAppInfo;
    StartAbilityUtils::GetApplicationInfo(controlRule.callerPkg, userId, callerAppInfo);
    AppExecFwk::ApplicationInfo targetAppInfo;
    StartAbilityUtils::GetApplicationInfo(controlRule.targetPkg, userId, callerAppInfo);
    want.SetParam(JUMP_DIALOG_CALLER_BUNDLE_NAME, controlRule.callerPkg);
    want.SetParam(JUMP_DIALOG_CALLER_MODULE_NAME, callerAppInfo.labelResource.moduleName);
    want.SetParam(JUMP_DIALOG_CALLER_LABEL_ID, callerAppInfo.labelId);
    want.SetParam(JUMP_DIALOG_TARGET_MODULE_NAME, targetAppInfo.labelResource.moduleName);
    want.SetParam(JUMP_DIALOG_TARGET_LABEL_ID, targetAppInfo.labelId);
    return true;
}
} // namespace AAFwk
} // namespace OHOS
