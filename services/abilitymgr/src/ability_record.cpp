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

#include "ability_record.h"

#include <singleton.h>

#include "ability_manager_service.h"
#include "ability_resident_process_rdb.h"
#include "ability_scheduler_stub.h"
#include "app_exit_reason_data_manager.h"
#include "app_utils.h"
#include "array_wrapper.h"
#include "accesstoken_kit.h"
#include "configuration_convertor.h"
#include "connection_state_manager.h"
#include "common_event_manager.h"
#include "error_msg_util.h"
#include "freeze_util.h"
#include "global_constant.h"
#include "hitrace_meter.h"
#include "image_source.h"
#include "keep_alive_process_manager.h"
#include "multi_instance_utils.h"
#include "os_account_manager_wrapper.h"
#include "ui_service_extension_connection_constants.h"
#include "res_sched_util.h"
#include "scene_board_judgement.h"
#include "startup_util.h"
#include "system_ability_token_callback.h"
#include "ui_extension_utils.h"
#include "uri_permission_manager_client.h"
#include "param.h"
#include "permission_constants.h"
#include "process_options.h"
#include "uri_utils.h"
#include "utils/state_utils.h"
#ifdef SUPPORT_GRAPHICS
#include "image_source.h"
#endif
#ifdef SUPPORT_SCREEN
#include "locale_config.h"
#endif

namespace OHOS {
using AbilityRuntime::FreezeUtil;
namespace AAFwk {
using namespace OHOS::Security;
using namespace OHOS::AAFwk::PermissionConstants;
using namespace OHOS::AbilityRuntime::GlobalConstant;
const std::string DEBUG_APP = "debugApp";
const std::string NATIVE_DEBUG = "nativeDebug";
const std::string PERF_CMD = "perfCmd";
const std::string ERROR_INFO_ENHANCE = "errorInfoEnhance";
const std::string MULTI_THREAD = "multiThread";
const std::string DMS_PROCESS_NAME = "distributedsched";
const std::string DMS_MISSION_ID = "dmsMissionId";
const std::string DMS_SRC_NETWORK_ID = "dmsSrcNetworkId";
const std::string ABILITY_OWNER_USERID = "AbilityMS_Owner_UserId";
const std::u16string SYSTEM_ABILITY_TOKEN_CALLBACK = u"ohos.aafwk.ISystemAbilityTokenCallback";
const std::string SHOW_ON_LOCK_SCREEN = "ShowOnLockScreen";
#ifdef WITH_DLP
const std::string DLP_BUNDLE_NAME = "com.ohos.dlpmanager";
#endif // WITH_DLP
const std::string COMPONENT_STARTUP_NEW_RULES = "component.startup.newRules";
const std::string KEY_MISSION_ID = "ohos.anco.param.missionId";
const std::string NEED_STARTINGWINDOW = "ohos.ability.NeedStartingWindow";
const std::string PARAMS_FILE_SAVING_URL_KEY = "pick_path_return";
const uint32_t RELEASE_STARTING_BG_TIMEOUT = 15000; // release starting window resource timeout.
const std::string SHELL_ASSISTANT_DIEREASON = "crash_die";
const std::string PARAM_MISSION_AFFINITY_KEY = "ohos.anco.param.missionAffinity";
const std::string DISTRIBUTED_FILES_PATH = "/data/storage/el2/distributedfiles/";
const std::string UIEXTENSION_ABILITY_ID = "ability.want.params.uiExtensionAbilityId";
const std::string UIEXTENSION_ROOT_HOST_PID = "ability.want.params.uiExtensionRootHostPid";
constexpr const char* PARAM_SEND_RESULT_CALLER_BUNDLENAME = "ohos.anco.param.sendResultCallderBundleName";
constexpr const char* PARAM_SEND_RESULT_CALLER_TOKENID = "ohos.anco.param.sendResultCallerTokenId";
constexpr const char* DLP_PARAMS_SECURITY_FLAG = "ohos.dlp.params.securityFlag";
// Developer mode param
constexpr const char* DEVELOPER_MODE_STATE = "const.security.developermode.state";
constexpr const char* APP_PROVISION_TYPE_DEBUG = "debug";
constexpr const char* DMS_CALLER_BUNDLE_NAME = "ohos.dms.param.sourceCallerBundleName";
constexpr const char* DMS_CALLER_ABILITY_NAME = "ohos.dms.param.sourceCallerAbilityName";
constexpr const char* DMS_CALLER_NATIVE_NAME = "ohos.dms.param.sourceCallerNativeName";
constexpr const char* DMS_CALLER_APP_ID = "ohos.dms.param.sourceCallerAppId";
constexpr const char* DMS_CALLER_APP_IDENTIFIER = "ohos.dms.param.sourceCallerAppIdentifier";
const int32_t SHELL_ASSISTANT_DIETYPE = 0;
int64_t AbilityRecord::abilityRecordId = 0;
const int32_t DEFAULT_USER_ID = 0;
const int32_t SEND_RESULT_CANCELED = -1;
const int VECTOR_SIZE = 2;
const int LOAD_TIMEOUT_ASANENABLED = 150;
const int TERMINATE_TIMEOUT_ASANENABLED = 150;
const int HALF_TIMEOUT = 2;
const int MAX_URI_COUNT = 500;
const int RESTART_SCENEBOARD_DELAY = 500;
constexpr int32_t DMS_UID = 5522;
constexpr int32_t SCHEDULER_DIED_TIMEOUT = 60000;

auto g_addLifecycleEventTask = [](sptr<Token> token, std::string &methodName) {
    CHECK_POINTER_LOG(token, "token is nullptr");
    std::string entry = std::string("AbilityRecord::") + methodName + "; the " + methodName + " lifecycle starts.";
    FreezeUtil::GetInstance().AddLifecycleEvent(token->AsObject(), entry);
};

Token::Token(std::weak_ptr<AbilityRecord> abilityRecord) : abilityRecord_(abilityRecord)
{}

Token::~Token()
{}

std::shared_ptr<AbilityRecord> Token::GetAbilityRecordByToken(const sptr<IRemoteObject> &token)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    if (token == nullptr) {
        return nullptr;
    }

    std::string descriptor = Str16ToStr8(token->GetObjectDescriptor());
    if (descriptor != "ohos.aafwk.AbilityToken") {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "descriptor:%{public}s",
            descriptor.c_str());
        return nullptr;
    }

    // Double check if token is valid
    sptr<IAbilityToken> theToken = iface_cast<IAbilityToken>(token);
    if (!theToken) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "input err");
        return nullptr;
    }
    std::u16string castDescriptor = theToken->GetDescriptor();
    if (castDescriptor != u"ohos.aafwk.AbilityToken") {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "Input token iface_cast error:%{public}s.", Str16ToStr8(castDescriptor).c_str());
        return nullptr;
    }

    return (static_cast<Token *>(token.GetRefPtr()))->GetAbilityRecord();
}

std::shared_ptr<AbilityRecord> Token::GetAbilityRecord() const
{
    return abilityRecord_.lock();
}

CallerRecord::CallerRecord(int requestCode, std::weak_ptr<AbilityRecord> caller)
    : requestCode_(requestCode), caller_(caller)
{
    auto callerAbilityRecord = caller.lock();
    if  (callerAbilityRecord != nullptr) {
        callerInfo_ = std::make_shared<CallerAbilityInfo>();
        callerInfo_->callerBundleName = callerAbilityRecord->GetAbilityInfo().bundleName;
        callerInfo_->callerAbilityName = callerAbilityRecord->GetAbilityInfo().name;
        callerInfo_->callerTokenId = callerAbilityRecord->GetApplicationInfo().accessTokenId;
        callerInfo_->callerUid =  callerAbilityRecord->GetUid();
        callerInfo_->callerPid =  callerAbilityRecord->GetPid();
        callerInfo_->callerAppCloneIndex = callerAbilityRecord->GetAppIndex();
    }
}

void LaunchDebugInfo::Update(const OHOS::AAFwk::Want &want)
{
    isDebugAppSet = want.HasParameter(DEBUG_APP);
    if (isDebugAppSet) {
        debugApp = want.GetBoolParam(DEBUG_APP, false);
    }
    isNativeDebugSet = want.HasParameter(NATIVE_DEBUG);
    if (isNativeDebugSet) {
        nativeDebug = want.GetBoolParam(NATIVE_DEBUG, false);
    }
    isPerfCmdSet = want.HasParameter(PERF_CMD);
    if (isPerfCmdSet) {
        perfCmd = want.GetStringParam(PERF_CMD);
    }
}

AbilityRecord::AbilityRecord(const Want &want, const AppExecFwk::AbilityInfo &abilityInfo,
    const AppExecFwk::ApplicationInfo &applicationInfo, int requestCode)
    : want_(want), abilityInfo_(abilityInfo), requestCode_(requestCode)
{
    abilityInfo_.applicationInfo = applicationInfo;
    recordId_ = abilityRecordId++;
    auto abilityMgr = DelayedSingleton<AbilityManagerService>::GetInstance();
    if (abilityMgr) {
        bool isRootLauncher = (abilityInfo_.applicationInfo.bundleName == LAUNCHER_BUNDLE_NAME);
        restartMax_ = AmsConfigurationParameter::GetInstance().GetMaxRestartNum(isRootLauncher);
        bool flag = abilityMgr->GetStartUpNewRuleFlag();
        want_.SetParam(COMPONENT_STARTUP_NEW_RULES, flag);
    }
    restartCount_ = restartMax_;
    isAppAutoStartup_ = want_.GetBoolParam(Want::PARAM_APP_AUTO_STARTUP_LAUNCH_REASON, false);
    if (want_.HasParameter(Want::PARAM_APP_AUTO_STARTUP_LAUNCH_REASON)) {
        want_.RemoveParam(Want::PARAM_APP_AUTO_STARTUP_LAUNCH_REASON);
    }
    SetDebugAppByWaitingDebugFlag();
    launchDebugInfo_.Update(want_);
}

AbilityRecord::~AbilityRecord()
{
    if (token_) {
        FreezeUtil::GetInstance().DeleteLifecycleEvent(token_->AsObject());
    }
    FreezeUtil::GetInstance().DeleteAppLifecycleEvent(GetPid());
    if (scheduler_ != nullptr && schedulerDeathRecipient_ != nullptr) {
        auto object = scheduler_->AsObject();
        if (object != nullptr) {
            object->RemoveDeathRecipient(schedulerDeathRecipient_);
        }
    }
    want_.CloseAllFd();
}

std::shared_ptr<AbilityRecord> AbilityRecord::CreateAbilityRecord(const AbilityRequest &abilityRequest)
{
    std::shared_ptr<AbilityRecord> abilityRecord = std::make_shared<AbilityRecord>(
        abilityRequest.want, abilityRequest.abilityInfo, abilityRequest.appInfo, abilityRequest.requestCode);
    CHECK_POINTER_AND_RETURN(abilityRecord, nullptr);
    abilityRecord->SetUid(abilityRequest.uid);
    int32_t appIndex = 0;
    (void)AbilityRuntime::StartupUtil::GetAppIndex(abilityRequest.want, appIndex);
    abilityRecord->SetAppIndex(appIndex);
    abilityRecord->SetSecurityFlag(abilityRequest.want.GetBoolParam(DLP_PARAMS_SECURITY_FLAG, false));
    abilityRecord->SetCallerAccessTokenId(abilityRequest.callerAccessTokenId);
    abilityRecord->sessionInfo_ = abilityRequest.sessionInfo;
    if (AppUtils::GetInstance().IsMultiProcessModel() && abilityRequest.abilityInfo.isStageBasedModel &&
        abilityRequest.abilityInfo.type == AppExecFwk::AbilityType::PAGE &&
        !abilityRequest.customProcess.empty()) {
            abilityRecord->SetCustomProcessFlag(abilityRequest.customProcess);
        }
    if (abilityRequest.sessionInfo != nullptr) {
        abilityRecord->instanceKey_ = abilityRequest.sessionInfo->instanceKey;
    }
    if (!abilityRecord->Init()) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "failed init");
        return nullptr;
    }
    if (abilityRequest.startSetting != nullptr) {
        TAG_LOGD(AAFwkTag::ABILITYMGR, "abilityRequest.startSetting...");
        abilityRecord->SetStartSetting(abilityRequest.startSetting);
    }
    if (abilityRequest.IsCallType(AbilityCallType::CALL_REQUEST_TYPE)) {
        TAG_LOGD(AAFwkTag::ABILITYMGR, "abilityRequest.callType is CALL_REQUEST_TYPE.");
        abilityRecord->SetStartedByCall(true);
    }
    abilityRecord->collaboratorType_ = abilityRequest.collaboratorType;
    abilityRecord->missionAffinity_ = abilityRequest.want.GetStringParam(PARAM_MISSION_AFFINITY_KEY);

    auto userId = abilityRequest.appInfo.uid / BASE_USER_RANGE;
    if ((userId == 0 ||
        AmsConfigurationParameter::GetInstance().InResidentWhiteList(abilityRequest.abilityInfo.bundleName)) &&
        DelayedSingleton<ResidentProcessManager>::GetInstance()->IsResidentAbility(
            abilityRequest.abilityInfo.bundleName, abilityRequest.abilityInfo.name, userId)) {
        abilityRecord->keepAliveBundle_ = true;
    }

    return abilityRecord;
}

bool AbilityRecord::Init()
{
    lifecycleDeal_ = std::make_unique<LifecycleDeal>();
    CHECK_POINTER_RETURN_BOOL(lifecycleDeal_);

    token_ = new (std::nothrow) Token(weak_from_this());
    CHECK_POINTER_RETURN_BOOL(token_);

    if (abilityInfo_.applicationInfo.isLauncherApp) {
        isLauncherAbility_ = true;
    }
    return true;
}

void AbilityRecord::SetUid(int32_t uid)
{
    uid_ = uid;
}

int32_t AbilityRecord::GetUid()
{
    return uid_;
}

int32_t AbilityRecord::GetPid()
{
    return pid_;
}

void AbilityRecord::LoadUIAbility()
{
    SetLoading(true);
    int loadTimeout = AmsConfigurationParameter::GetInstance().GetAppStartTimeoutTime() * LOAD_TIMEOUT_MULTIPLE;
    if (abilityInfo_.applicationInfo.asanEnabled || abilityInfo_.applicationInfo.tsanEnabled) {
        loadTimeout = AmsConfigurationParameter::GetInstance().GetAppStartTimeoutTime() * LOAD_TIMEOUT_ASANENABLED;
    } else {
        int coldStartTimeout =
            AmsConfigurationParameter::GetInstance().GetAppStartTimeoutTime() * COLDSTART_TIMEOUT_MULTIPLE;
        std::lock_guard guard(wantLock_);
        loadTimeout = want_.GetBoolParam("coldStart", false) ? coldStartTimeout : loadTimeout;
    }
    SendEvent(AbilityManagerService::LOAD_HALF_TIMEOUT_MSG, loadTimeout / HALF_TIMEOUT);
    SendEvent(AbilityManagerService::LOAD_TIMEOUT_MSG, loadTimeout);
    std::string methodName = "LoadAbility";
    g_addLifecycleEventTask(token_, methodName);
}

int AbilityRecord::LoadAbility(bool isShellCall)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    TAG_LOGI(AAFwkTag::ABILITYMGR, "LoadLifecycle: abilityName:%{public}s", abilityInfo_.name.c_str());
    startTime_ = AbilityUtil::SystemTimeMillis();
    CHECK_POINTER_AND_RETURN(token_, ERR_INVALID_VALUE);
    // only for UIAbility
    if (!IsDebug() && abilityInfo_.type != AppExecFwk::AbilityType::DATA) {
        LoadUIAbility();
    }

    std::string appName = abilityInfo_.applicationInfo.name;
    CHECK_TRUE_RETURN_RET(appName.empty(), ERR_INVALID_VALUE, "app name empty");
    CHECK_TRUE_RETURN_RET(!CanRestartRootLauncher(), ERR_INVALID_VALUE, "root launcher restart out of max");

    if (isRestarting_) {
        restartTime_ = AbilityUtil::SystemTimeMillis();
    }

    sptr<Token> callerToken = nullptr;
    if (!callerList_.empty() && callerList_.back()) {
        auto caller = callerList_.back()->GetCaller();
        if (caller) {
            callerToken = caller->GetToken();
        }
    }

    std::lock_guard guard(wantLock_);
    want_.SetParam(ABILITY_OWNER_USERID, ownerMissionUserId_);
    AbilityRuntime::LoadParam loadParam;
    loadParam.abilityRecordId = recordId_;
    loadParam.isShellCall = Rosen::SceneBoardJudgement::IsSceneBoardEnabled() ? isShellCall
        : AAFwk::PermissionVerification::GetInstance()->IsShellCall();
    loadParam.token = token_;
    loadParam.preToken = callerToken;
    loadParam.instanceKey = instanceKey_;
    loadParam.isCallerSetProcess = IsCallerSetProcess();
    loadParam.customProcessFlag = customProcessFlag_;
    want_.RemoveParam(Want::PARAM_APP_KEEP_ALIVE_ENABLED);
    if (KeepAliveProcessManager::GetInstance().IsKeepAliveBundle(abilityInfo_.applicationInfo.bundleName, -1)) {
        want_.SetParam(Want::PARAM_APP_KEEP_ALIVE_ENABLED, true);
        loadParam.isKeepAlive = true;
    }
    auto result = DelayedSingleton<AppScheduler>::GetInstance()->LoadAbility(
        loadParam, abilityInfo_, abilityInfo_.applicationInfo, want_);
    want_.RemoveParam(ABILITY_OWNER_USERID);
    want_.RemoveParam(Want::PARAMS_REAL_CALLER_KEY);
    if (DelayedSingleton<AppScheduler>::GetInstance()->IsAttachDebug(abilityInfo_.bundleName)) {
        SetAttachDebug(true);
    }
    return result;
}

bool AbilityRecord::CanRestartRootLauncher()
{
    if (isLauncherRoot_ && isRestarting_ && IsLauncherAbility() && (restartCount_ < 0)) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "root launcher restart out of max");
        return false;
    }
    return true;
}

bool AbilityRecord::CanRestartResident()
{
    auto isKeepAlive = GetKeepAlive();
    TAG_LOGD(AAFwkTag::ABILITYMGR, "isKeepAlive: %{public}d, isRestarting: %{public}d, restartCount: %{public}d",
        isKeepAlive, isRestarting_, restartCount_);
    if (isKeepAlive && isRestarting_ && (restartCount_ < 0)) {
        int restartIntervalTime = 0;
        auto abilityMgr = DelayedSingleton<AbilityManagerService>::GetInstance();
        if (abilityMgr) {
            restartIntervalTime = AmsConfigurationParameter::GetInstance().GetRestartIntervalTime();
        }
        TAG_LOGD(AAFwkTag::ABILITYMGR, "restartTime: %{public}lld, now: %{public}lld, intervalTine:%{public}d",
            static_cast<unsigned long long>(restartTime_),
            static_cast<unsigned long long>(AbilityUtil::SystemTimeMillis()), restartIntervalTime);
        if ((AbilityUtil::SystemTimeMillis() - restartTime_) < restartIntervalTime) {
            TAG_LOGE(AAFwkTag::ABILITYMGR, "resident restart out of max");
            return false;
        }
    }
    return true;
}

// only for UIAbility
void AbilityRecord::ForegroundAbility(uint32_t sceneFlag)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    isWindowStarted_ = true;
    TAG_LOGI(AAFwkTag::ABILITYMGR, "ForegroundLifecycle: name:%{public}s", abilityInfo_.name.c_str());
    CHECK_POINTER(lifecycleDeal_);

    // schedule active after updating AbilityState and sending timeout message to avoid ability async callback
    // earlier than above actions
#ifdef SUPPORT_SCREEN
    SetAbilityStateInner(AbilityState::FOREGROUNDING);
#endif // SUPPORT_SCREEN
    lifeCycleStateInfo_.sceneFlag = sceneFlag;
    Want want = GetWant();
    UpdateDmsCallerInfo(want);
    AbilityRuntime::ErrorMsgGuard errorMsgGuard(token_ ? token_->AsObject() : nullptr,
        reinterpret_cast<uintptr_t>(GetScheduler().GetRefPtr()), "ScheduleAbilityTransaction");
    lifecycleDeal_->ForegroundNew(want, lifeCycleStateInfo_, GetSessionInfo());
    SetIsNewWant(false);
    lifeCycleStateInfo_.sceneFlag = 0;
    lifeCycleStateInfo_.sceneFlagBak = 0;
    {
        std::lock_guard guard(wantLock_);
        InsightIntentExecuteParam::RemoveInsightIntent(want_);
        isLaunching_ = false;
    }
}

void AbilityRecord::ForegroundUIExtensionAbility(uint32_t sceneFlag)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    TAG_LOGI(AAFwkTag::ABILITYMGR, "ability:%{public}s", GetURI().c_str());
    CHECK_POINTER(lifecycleDeal_);

    // schedule active after updating AbilityState and sending timeout message to avoid ability async callback
    // earlier than above actions.
#ifdef SUPPORT_SCREEN
    SetAbilityStateInner(AbilityState::FOREGROUNDING);
#endif // SUPPORT_SCREEN
    lifeCycleStateInfo_.sceneFlag = sceneFlag;
    lifecycleDeal_->ForegroundNew(GetWant(), lifeCycleStateInfo_, GetSessionInfo());
    lifeCycleStateInfo_.sceneFlag = 0;
    lifeCycleStateInfo_.sceneFlagBak = 0;
    {
        std::lock_guard guard(wantLock_);
        InsightIntentExecuteParam::RemoveInsightIntent(want_);
        isLaunching_ = false;
    }
}

void AbilityRecord::ProcessForegroundAbility(uint32_t tokenId, uint32_t sceneFlag, bool isShellCall)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    std::string element = GetElementName().GetURI();
    TAG_LOGD(AAFwkTag::ABILITYMGR, "ability record: %{public}s", element.c_str());
    {
        std::lock_guard guard(wantLock_);
        GrantUriPermission(want_, abilityInfo_.applicationInfo.bundleName, false, tokenId);
    }

    if (isReady_) {
        PostForegroundTimeoutTask();
        if (IsAbilityState(AbilityState::FOREGROUND)) {
            TAG_LOGD(AAFwkTag::ABILITYMGR, "Activate %{public}s", element.c_str());
            ForegroundAbility(sceneFlag);
        } else {
            // background to active state
            TAG_LOGD(AAFwkTag::ABILITYMGR, "MoveToForeground, %{public}s", element.c_str());
            lifeCycleStateInfo_.sceneFlagBak = sceneFlag;
            std::string bundleName = GetAbilityInfo().bundleName;
            int32_t uid = GetUid();
            ResSchedUtil::GetInstance().ReportEventToRSS(uid, bundleName, "THAW_BY_FOREGROUND_ABILITY");
            SetAbilityStateInner(AbilityState::FOREGROUNDING);
            DelayedSingleton<AppScheduler>::GetInstance()->MoveToForeground(token_);
        }
    } else {
        TAG_LOGD(AAFwkTag::ABILITYMGR, "To load ability.");
        lifeCycleStateInfo_.sceneFlagBak = sceneFlag;
        LoadAbility(isShellCall);
    }
}

void AbilityRecord::PostForegroundTimeoutTask()
{
    if (IsDebug()) {
        return;
    }
    int foregroundTimeout =
        AmsConfigurationParameter::GetInstance().GetAppStartTimeoutTime() * FOREGROUND_TIMEOUT_MULTIPLE;
    if (InsightIntentExecuteParam::IsInsightIntentExecute(GetWant())) {
        foregroundTimeout = AmsConfigurationParameter::GetInstance().GetAppStartTimeoutTime() *
            INSIGHT_INTENT_TIMEOUT_MULTIPLE;
    }
    SendEvent(AbilityManagerService::FOREGROUND_HALF_TIMEOUT_MSG, foregroundTimeout / HALF_TIMEOUT);
    SendEvent(AbilityManagerService::FOREGROUND_TIMEOUT_MSG, foregroundTimeout);
    std::string methodName = "ProcessForegroundAbility";
    g_addLifecycleEventTask(token_, methodName);
    ResSchedUtil::GetInstance().ReportLoadingEventToRss(LoadingStage::FOREGROUND_BEGIN, GetPid(), GetUid(),
        foregroundTimeout, GetAbilityRecordId());
}

void AbilityRecord::RemoveForegroundTimeoutTask()
{
    auto handler = DelayedSingleton<AbilityManagerService>::GetInstance()->GetEventHandler();
    CHECK_POINTER(handler);
    handler->RemoveEvent(AbilityManagerService::FOREGROUND_HALF_TIMEOUT_MSG, GetAbilityRecordId());
    handler->RemoveEvent(AbilityManagerService::FOREGROUND_TIMEOUT_MSG, GetAbilityRecordId());
}

void AbilityRecord::RemoveLoadTimeoutTask()
{
    auto handler = DelayedSingleton<AbilityManagerService>::GetInstance()->GetEventHandler();
    CHECK_POINTER(handler);
    handler->RemoveEvent(AbilityManagerService::LOAD_HALF_TIMEOUT_MSG, GetAbilityRecordId());
    handler->RemoveEvent(AbilityManagerService::LOAD_TIMEOUT_MSG, GetAbilityRecordId());
}

void AbilityRecord::PostUIExtensionAbilityTimeoutTask(uint32_t messageId)
{
    if (IsDebug()) {
        return;
    }

    TAG_LOGD(AAFwkTag::ABILITYMGR, "post timeout %{public}d, id %{public}d", messageId, recordId_);
    switch (messageId) {
        case AbilityManagerService::LOAD_TIMEOUT_MSG: {
            uint32_t timeout = AmsConfigurationParameter::GetInstance().GetAppStartTimeoutTime() *
                static_cast<uint32_t>(LOAD_TIMEOUT_MULTIPLE);
            SendEvent(AbilityManagerService::LOAD_HALF_TIMEOUT_MSG, timeout / HALF_TIMEOUT, recordId_, true);
            SendEvent(AbilityManagerService::LOAD_TIMEOUT_MSG, timeout, recordId_, true);
            break;
        }
        case AbilityManagerService::FOREGROUND_TIMEOUT_MSG: {
            uint32_t timeout = AmsConfigurationParameter::GetInstance().GetAppStartTimeoutTime() *
                static_cast<uint32_t>(FOREGROUND_TIMEOUT_MULTIPLE);
            if (InsightIntentExecuteParam::IsInsightIntentExecute(GetWant())) {
                timeout = AmsConfigurationParameter::GetInstance().GetAppStartTimeoutTime() *
                    static_cast<uint32_t>(INSIGHT_INTENT_TIMEOUT_MULTIPLE);
            }
            SendEvent(AbilityManagerService::FOREGROUND_HALF_TIMEOUT_MSG, timeout / HALF_TIMEOUT, recordId_, true);
            SendEvent(AbilityManagerService::FOREGROUND_TIMEOUT_MSG, timeout, recordId_, true);
            ResSchedUtil::GetInstance().ReportLoadingEventToRss(LoadingStage::FOREGROUND_BEGIN, GetPid(), GetUid(),
                timeout, GetAbilityRecordId());
            break;
        }
        default: {
            break;
        }
    }
}

std::string AbilityRecord::GetLabel()
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    std::string strLabel = abilityInfo_.applicationInfo.label;

    if (abilityInfo_.resourcePath.empty()) {
        TAG_LOGW(AAFwkTag::ABILITYMGR, "resource path empty");
        return strLabel;
    }

#ifdef SUPPORT_SCREEN
    auto resourceMgr = CreateResourceManager();
    if (!resourceMgr) {
        return strLabel;
    }

    auto result = resourceMgr->GetStringById(abilityInfo_.applicationInfo.labelId, strLabel);
    if (result != OHOS::Global::Resource::RState::SUCCESS) {
        TAG_LOGW(AAFwkTag::ABILITYMGR, "%{public}s, fail", __func__);
    }

    InitColdStartingWindowResource(resourceMgr);
#endif

    return strLabel;
}

#ifdef SUPPORT_SCREEN
void AbilityRecord::ProcessForegroundAbility(const std::shared_ptr<AbilityRecord> &callerAbility, bool needExit,
    uint32_t sceneFlag)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    std::string element = GetElementName().GetURI();
    TAG_LOGD(AAFwkTag::ABILITYMGR, "SUPPORT_GRAPHICS: ability record: %{public}s", element.c_str());

    StartingWindowHot();
    auto flag = !IsForeground();
    NotifyAnimationFromTerminatingAbility(callerAbility, needExit, flag);
    PostCancelStartingWindowHotTask();

    PostForegroundTimeoutTask();
    if (IsAbilityState(AbilityState::FOREGROUND)) {
        TAG_LOGD(AAFwkTag::ABILITYMGR, "Activate %{public}s", element.c_str());
        ForegroundAbility(sceneFlag);
    } else {
        // background to active state
        TAG_LOGD(AAFwkTag::ABILITYMGR, "MoveToForeground, %{public}s", element.c_str());
        lifeCycleStateInfo_.sceneFlagBak = sceneFlag;
        DelayedSingleton<AppScheduler>::GetInstance()->MoveToForeground(token_);
    }
}

void AbilityRecord::NotifyAnimationFromTerminatingAbility(const std::shared_ptr<AbilityRecord>& callerAbility,
    bool needExit, bool flag)
{
    auto windowHandler = GetWMSHandler();
    if (!windowHandler) {
        TAG_LOGW(AAFwkTag::ABILITYMGR, "get WMS failed");
        return;
    }

    sptr<AbilityTransitionInfo> fromInfo = new AbilityTransitionInfo();
    if (callerAbility) {
        auto callerAbilityInfo = callerAbility->GetAbilityInfo();
        SetAbilityTransitionInfo(callerAbilityInfo, fromInfo);
        fromInfo->abilityToken_ = callerAbility->GetToken();
    }

    if (flag && needExit) {
        fromInfo->reason_ = TransitionReason::BACK_TRANSITION;
    } else if (flag && !needExit) {
        fromInfo->reason_ = TransitionReason::BACKGROUND_TRANSITION;
    } else {
        fromInfo->reason_ = TransitionReason::CLOSE;
    }

    auto toInfo = CreateAbilityTransitionInfo();
    SetAbilityTransitionInfo(abilityInfo_, toInfo);
    bool animaEnabled = false;
    windowHandler->NotifyWindowTransition(fromInfo, toInfo, animaEnabled);
}

void AbilityRecord::NotifyAnimationFromTerminatingAbility() const
{
    auto windowHandler = GetWMSHandler();
    if (!windowHandler) {
        TAG_LOGW(AAFwkTag::ABILITYMGR, "get WMS failed");
        return;
    }

    sptr<AbilityTransitionInfo> fromInfo = new AbilityTransitionInfo();
    SetAbilityTransitionInfo(fromInfo);
    fromInfo->reason_ = TransitionReason::CLOSE;
    bool animaEnabled = false;
    windowHandler->NotifyWindowTransition(fromInfo, nullptr, animaEnabled);
}

void AbilityRecord::NotifyAnimationFromMinimizeAbility(bool& animaEnabled)
{
    auto windowHandler = GetWMSHandler();
    if (!windowHandler) {
        TAG_LOGW(AAFwkTag::ABILITYMGR, "get WMS failed");
        return;
    }
    TAG_LOGI(AAFwkTag::ABILITYMGR, "Notify Animation From MinimizeAbility");
    sptr<AbilityTransitionInfo> fromInfo = new AbilityTransitionInfo();
    SetAbilityTransitionInfo(fromInfo);
    fromInfo->reason_ = TransitionReason::MINIMIZE;
    windowHandler->NotifyWindowTransition(fromInfo, nullptr, animaEnabled);
}

void AbilityRecord::SetAbilityTransitionInfo(sptr<AbilityTransitionInfo>& info) const
{
    info->abilityToken_ = token_;
    info->missionId_ = missionId_;
    info->abilityName_ = abilityInfo_.name;
    info->bundleName_ = abilityInfo_.bundleName;
    info->windowModes_ = abilityInfo_.windowModes;
    info->maxWindowRatio_ = abilityInfo_.maxWindowRatio;
    info->minWindowRatio_ = abilityInfo_.minWindowRatio;
    info->maxWindowWidth_ = abilityInfo_.maxWindowWidth;
    info->minWindowWidth_ = abilityInfo_.minWindowWidth;
    info->maxWindowHeight_ = abilityInfo_.maxWindowHeight;
    info->minWindowHeight_ = abilityInfo_.minWindowHeight;
    info->orientation_ = abilityInfo_.orientation;
    info->apiCompatibleVersion_ = abilityInfo_.applicationInfo.apiCompatibleVersion;
}

sptr<AbilityTransitionInfo> AbilityRecord::CreateAbilityTransitionInfo()
{
    sptr<AbilityTransitionInfo> info = new AbilityTransitionInfo();
    SetAbilityTransitionInfo(info);
    SetStartingWindow(true);
    return info;
}

void AbilityRecord::StartingWindowHot()
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    auto windowHandler = GetWMSHandler();
    if (!windowHandler) {
        TAG_LOGW(AAFwkTag::ABILITYMGR, "get WMS failed");
        return;
    }

    auto missionListWrap = DelayedSingleton<AbilityManagerService>::GetInstance()->GetMissionListWrap();
    if (missionListWrap == nullptr) {
        TAG_LOGW(AAFwkTag::ABILITYMGR, "null missionListWrap");
        return;
    }

    auto pixelMap = missionListWrap->GetSnapshot(missionId_);
    if (!pixelMap) {
        TAG_LOGW(AAFwkTag::ABILITYMGR, "get snapshot failed");
    }

    auto info = CreateAbilityTransitionInfo();
    TAG_LOGI(AAFwkTag::ABILITYMGR, "notify wms to start StartingWindow");
    windowHandler->StartingWindow(info, pixelMap);
}

void AbilityRecord::ProcessForegroundAbility(bool isRecent, const AbilityRequest &abilityRequest,
    std::shared_ptr<StartOptions> &startOptions, const std::shared_ptr<AbilityRecord> &callerAbility,
    uint32_t sceneFlag)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    std::string element = GetElementName().GetURI();
    TAG_LOGD(AAFwkTag::ABILITYMGR, "SUPPORT_GRAPHICS: ability record: %{public}s", element.c_str());
    {
        std::lock_guard guard(wantLock_);
        GrantUriPermission(want_, abilityInfo_.applicationInfo.bundleName, false, 0);
    }

    if (isReady_ && !GetRestartAppFlag()) {
        auto handler = DelayedSingleton<AbilityManagerService>::GetInstance()->GetTaskHandler();
        if (!handler) {
            TAG_LOGE(AAFwkTag::ABILITYMGR, "fail get AbilityEventHandler");
            return;
        }
        auto taskName = std::to_string(missionId_) + "_hot";
        handler->CancelTask(taskName);

        if (isWindowStarted_) {
            StartingWindowTask(isRecent, false, abilityRequest, startOptions);
            AnimationTask(isRecent, abilityRequest, startOptions, callerAbility);
            PostCancelStartingWindowHotTask();
        } else {
            StartingWindowTask(isRecent, true, abilityRequest, startOptions);
            AnimationTask(isRecent, abilityRequest, startOptions, callerAbility);
            PostCancelStartingWindowColdTask();
        }
        PostForegroundTimeoutTask();
        if (IsAbilityState(AbilityState::FOREGROUND)) {
            TAG_LOGD(AAFwkTag::ABILITYMGR, "Activate %{public}s", element.c_str());
            ForegroundAbility(sceneFlag);
        } else {
            // background to active state
            TAG_LOGD(AAFwkTag::ABILITYMGR, "MoveToForeground, %{public}s", element.c_str());
            lifeCycleStateInfo_.sceneFlagBak = sceneFlag;
            DelayedSingleton<AppScheduler>::GetInstance()->MoveToForeground(token_);
        }
    } else {
        TAG_LOGD(AAFwkTag::ABILITYMGR, "SUPPORT_GRAPHICS: to load ability.");
        lifeCycleStateInfo_.sceneFlagBak = sceneFlag;
        auto isSaCall = AAFwk::PermissionVerification::GetInstance()->IsSACall();
        auto needStartingWindow = abilityRequest.want.GetBoolParam(NEED_STARTINGWINDOW, true);
        if (!isSaCall || needStartingWindow) {
            StartingWindowTask(isRecent, true, abilityRequest, startOptions);
            AnimationTask(isRecent, abilityRequest, startOptions, callerAbility);
            PostCancelStartingWindowColdTask();
        }
        LoadAbility();
    }
}

std::shared_ptr<Want> AbilityRecord::GetWantFromMission() const
{
    auto missionListWrap = DelayedSingleton<AbilityManagerService>::GetInstance()->GetMissionListWrap();
    if (missionListWrap == nullptr) {
        TAG_LOGW(AAFwkTag::ABILITYMGR, "null missionListWrap");
        return nullptr;
    }

    InnerMissionInfo innerMissionInfo;
    int getMission = missionListWrap->GetInnerMissionInfoById(missionId_, innerMissionInfo);
    if (getMission != ERR_OK) {
        TAG_LOGE(
            AAFwkTag::ABILITYMGR, "no find mission info by missionId: %{public}d", missionId_);
        return nullptr;
    }

    return std::make_shared<Want>(innerMissionInfo.missionInfo.want);
}

void AbilityRecord::AnimationTask(bool isRecent, const AbilityRequest &abilityRequest,
    const std::shared_ptr<StartOptions> &startOptions, const std::shared_ptr<AbilityRecord> &callerAbility)
{
    TAG_LOGD(AAFwkTag::ABILITYMGR, "called");
    if (isRecent) {
        auto want = GetWantFromMission();
        NotifyAnimationFromRecentTask(startOptions, want);
    } else {
        if (!IsForeground()) {
            NotifyAnimationFromStartingAbility(callerAbility, abilityRequest);
        }
    }
}

void AbilityRecord::SetShowWhenLocked(const AppExecFwk::AbilityInfo &abilityInfo,
    sptr<AbilityTransitionInfo> &info) const
{
    for (const auto &data : abilityInfo.metaData.customizeData) {
        if (data.name == SHOW_ON_LOCK_SCREEN) {
            info->isShowWhenLocked_ = true;
            break;
        }
    }
}

void AbilityRecord::SetAbilityTransitionInfo(const AppExecFwk::AbilityInfo &abilityInfo,
    sptr<AbilityTransitionInfo> &info) const
{
    info->abilityName_ = abilityInfo.name;
    info->bundleName_ = abilityInfo.bundleName;
    info->windowModes_ = abilityInfo.windowModes;
    info->orientation_ = abilityInfo.orientation;
    info->apiCompatibleVersion_ = abilityInfo.applicationInfo.apiCompatibleVersion;
    SetShowWhenLocked(abilityInfo, info);
}

void AbilityRecord::NotifyAnimationFromRecentTask(const std::shared_ptr<StartOptions> &startOptions,
    const std::shared_ptr<Want> &want) const
{
    auto windowHandler = GetWMSHandler();
    if (!windowHandler) {
        TAG_LOGW(AAFwkTag::ABILITYMGR, "%{public}s, failed", __func__);
        return;
    }

    auto toInfo = CreateAbilityTransitionInfo(startOptions, want);
    toInfo->abilityToken_ = token_;
    toInfo->missionId_ = missionId_;
    SetAbilityTransitionInfo(abilityInfo_, toInfo);
    sptr<AbilityTransitionInfo> fromInfo = new AbilityTransitionInfo();
    fromInfo->isRecent_ = true;
    bool animaEnabled = false;
    windowHandler->NotifyWindowTransition(fromInfo, toInfo, animaEnabled);
}

void AbilityRecord::NotifyAnimationFromStartingAbility(const std::shared_ptr<AbilityRecord> &callerAbility,
    const AbilityRequest &abilityRequest) const
{
    auto windowHandler = GetWMSHandler();
    if (!windowHandler) {
        TAG_LOGW(AAFwkTag::ABILITYMGR, "%{public}s, failed", __func__);
        return;
    }

    sptr<AbilityTransitionInfo> fromInfo = new AbilityTransitionInfo();
    if (callerAbility) {
        auto callerAbilityInfo = callerAbility->GetAbilityInfo();
        SetAbilityTransitionInfo(callerAbilityInfo, fromInfo);
        fromInfo->abilityToken_ = callerAbility->GetToken();
    } else {
        fromInfo->abilityToken_ = abilityRequest.callerToken;
    }

    auto toInfo = CreateAbilityTransitionInfo(abilityRequest);
    toInfo->abilityToken_ = token_;
    toInfo->missionId_ = missionId_;
    SetAbilityTransitionInfo(abilityInfo_, toInfo);
    bool animaEnabled = false;
    windowHandler->NotifyWindowTransition(fromInfo, toInfo, animaEnabled);
}

void AbilityRecord::StartingWindowTask(bool isRecent, bool isCold, const AbilityRequest &abilityRequest,
    std::shared_ptr<StartOptions> &startOptions)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    TAG_LOGD(AAFwkTag::ABILITYMGR, "called");
    if (isRecent) {
        auto want = GetWantFromMission();
        if (isCold) {
            StartingWindowCold(startOptions, want, abilityRequest);
        } else {
            StartingWindowHot(startOptions, want, abilityRequest);
        }
    } else {
        std::shared_ptr<Want> want = nullptr;
        if (isCold) {
            StartingWindowCold(startOptions, want, abilityRequest);
        } else {
            StartingWindowHot(startOptions, want, abilityRequest);
        }
    }
}

void AbilityRecord::PostCancelStartingWindowHotTask()
{
    if (IsDebug()) {
        TAG_LOGI(AAFwkTag::ABILITYMGR, "debug mode, just return");
        return;
    }
    TAG_LOGI(AAFwkTag::ABILITYMGR, "call");
    auto handler = DelayedSingleton<AbilityManagerService>::GetInstance()->GetTaskHandler();
    CHECK_POINTER_LOG(handler, "Fail to get TaskHandler.");

    auto windowHandler = GetWMSHandler();
    CHECK_POINTER_LOG(windowHandler, "PostCancelStartingWindowColdTask, Get WMS handler failed.");

    auto abilityRecord(shared_from_this());
    auto delayTask = [windowHandler, abilityRecord] {
        if (windowHandler && abilityRecord && abilityRecord->IsStartingWindow() &&
            abilityRecord->GetAbilityState() != AbilityState::FOREGROUNDING) {
            TAG_LOGD(AAFwkTag::ABILITYMGR, "PostCancelStartingWindowHotTask, call windowHandler CancelStartingWindow.");
            windowHandler->CancelStartingWindow(abilityRecord->GetToken());
            abilityRecord->SetStartingWindow(false);
        }
    };
    auto taskName = std::to_string(missionId_) + "_hot";
    int foregroundTimeout =
        AmsConfigurationParameter::GetInstance().GetAppStartTimeoutTime() * FOREGROUND_TIMEOUT_MULTIPLE;
    handler->SubmitTask(delayTask, taskName, foregroundTimeout);
}

void AbilityRecord::PostCancelStartingWindowColdTask()
{
    if (IsDebug()) {
        TAG_LOGI(AAFwkTag::ABILITYMGR, "debug mode, just return");
        return;
    }
    TAG_LOGD(AAFwkTag::ABILITYMGR, "called");
    auto handler = DelayedSingleton<AbilityManagerService>::GetInstance()->GetTaskHandler();
    CHECK_POINTER_LOG(handler, "Fail to get TaskHandler.");

    auto windowHandler = GetWMSHandler();
    CHECK_POINTER_LOG(windowHandler, "PostCancelStartingWindowColdTask, Get WMS handler failed.");

    auto abilityRecord(shared_from_this());
    auto delayTask = [windowHandler, abilityRecord] {
        if (windowHandler && abilityRecord && abilityRecord->IsStartingWindow() &&
            (abilityRecord->GetScheduler() == nullptr ||
            abilityRecord->GetAbilityState() != AbilityState::FOREGROUNDING)) {
            TAG_LOGD(AAFwkTag::ABILITYMGR,
                "PostCancelStartingWindowColdTask, call windowHandler CancelStartingWindow.");
            windowHandler->CancelStartingWindow(abilityRecord->GetToken());
            abilityRecord->SetStartingWindow(false);
        }
    };
    auto taskName = std::to_string(missionId_) + "_cold";
    int loadTimeout = AmsConfigurationParameter::GetInstance().GetAppStartTimeoutTime() * LOAD_TIMEOUT_MULTIPLE;
    handler->SubmitTask(delayTask, taskName, loadTimeout);
}

sptr<IWindowManagerServiceHandler> AbilityRecord::GetWMSHandler() const
{
    auto abilityMgr = DelayedSingleton<AbilityManagerService>::GetInstance();
    if (!abilityMgr) {
        TAG_LOGW(AAFwkTag::ABILITYMGR, "%{public}s, fail", __func__);
        return nullptr;
    }
    return abilityMgr->GetWMSHandler();
}

void AbilityRecord::SetWindowModeAndDisplayId(sptr<AbilityTransitionInfo> &info,
    const std::shared_ptr<Want> &want) const
{
    if (!want) {
        TAG_LOGW(AAFwkTag::ABILITYMGR, "%{public}s, want invalid", __func__);
        return;
    }
    auto mode = want->GetIntParam(Want::PARAM_RESV_WINDOW_MODE, -1);
    auto displayId = want->GetIntParam(Want::PARAM_RESV_DISPLAY_ID, -1);
    if (mode != -1) {
        TAG_LOGI(AAFwkTag::ABILITYMGR, "%{public}s: origin window mode: %{public}d", __func__, mode);
        info->mode_ = static_cast<uint32_t>(mode);
    }
    if (displayId != -1) {
        info->displayId_ = static_cast<uint64_t>(displayId);
    }
}

sptr<AbilityTransitionInfo> AbilityRecord::CreateAbilityTransitionInfo(
    const std::shared_ptr<StartOptions> &startOptions, const std::shared_ptr<Want> &want) const
{
    sptr<AbilityTransitionInfo> info = new AbilityTransitionInfo();
    if (startOptions != nullptr) {
        info->mode_ = static_cast<uint32_t>(startOptions->GetWindowMode());
        TAG_LOGI(AAFwkTag::ABILITYMGR, "window mode:%{public}d", info->mode_);
        info->displayId_ = static_cast<uint64_t>(startOptions->GetDisplayID());
    } else {
        SetWindowModeAndDisplayId(info, want);
    }
    return info;
}

sptr<AbilityTransitionInfo> AbilityRecord::CreateAbilityTransitionInfo(const AbilityRequest &abilityRequest) const
{
    sptr<AbilityTransitionInfo> info = new AbilityTransitionInfo();
    auto abilityStartSetting = abilityRequest.startSetting;
    if (abilityStartSetting) {
        auto windowMode = abilityStartSetting->GetProperty(AbilityStartSetting::WINDOW_MODE_KEY);
        auto displayId = abilityStartSetting->GetProperty(AbilityStartSetting::WINDOW_DISPLAY_ID_KEY);
        try {
            info->mode_ = static_cast<uint32_t>(std::stoi(windowMode));
            info->displayId_ = static_cast<uint64_t>(std::stoi(displayId));
        } catch (...) {
            TAG_LOGW(AAFwkTag::ABILITYMGR, "windowMode: stoi(%{public}s) failed", windowMode.c_str());
            TAG_LOGW(AAFwkTag::ABILITYMGR, "displayId: stoi(%{public}s) failed", displayId.c_str());
        }
    } else {
        SetWindowModeAndDisplayId(info, std::make_shared<Want>(abilityRequest.want));
    }
    return info;
}

std::shared_ptr<Global::Resource::ResourceManager> AbilityRecord::CreateResourceManager() const
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    UErrorCode status = U_ZERO_ERROR;
    icu::Locale locale = icu::Locale::forLanguageTag(Global::I18n::LocaleConfig::GetSystemLocale(), status);
    std::unique_ptr<Global::Resource::ResConfig> resConfig(Global::Resource::CreateResConfig());
    resConfig->SetLocaleInfo(locale);
    AppExecFwk::Configuration cfg;
    if (DelayedSingleton<AbilityManagerService>::GetInstance()->GetConfiguration(cfg) == 0) {
        std::string colormode = cfg.GetItem(AAFwk::GlobalConfigurationKey::SYSTEM_COLORMODE);
        TAG_LOGD(AAFwkTag::ABILITYMGR, "getcolormode is %{public}s.", colormode.c_str());
        resConfig->SetColorMode(AppExecFwk::ConvertColorMode(colormode));
    } else {
        TAG_LOGW(AAFwkTag::ABILITYMGR, "getcolormode failed");
    }

    std::shared_ptr<Global::Resource::ResourceManager> resourceMgr(Global::Resource::CreateResourceManager());
    resourceMgr->UpdateResConfig(*resConfig);

    std::string loadPath;
    if (!abilityInfo_.hapPath.empty()) {
        loadPath = abilityInfo_.hapPath;
    } else {
        loadPath = abilityInfo_.resourcePath;
    }

    if (loadPath.empty()) {
        TAG_LOGW(AAFwkTag::ABILITYMGR, "invalid app resource");
        return nullptr;
    }

    if (!resourceMgr->AddResource(loadPath.c_str())) {
        TAG_LOGW(AAFwkTag::ABILITYMGR, "%{public}s, failed", __func__);
        return nullptr;
    }
    return resourceMgr;
}

std::shared_ptr<Media::PixelMap> AbilityRecord::GetPixelMap(const uint32_t windowIconId,
    std::shared_ptr<Global::Resource::ResourceManager> resourceMgr) const
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    if (resourceMgr == nullptr) {
        TAG_LOGW(AAFwkTag::ABILITYMGR, "%{public}s, null resourceMgr", __func__);
        return nullptr;
    }

    Media::SourceOptions opts;
    uint32_t errorCode = 0;
    std::unique_ptr<Media::ImageSource> imageSource;
    if (!abilityInfo_.hapPath.empty()) { // hap is not unzip
        std::unique_ptr<uint8_t[]> iconOut;
        size_t len;
        if (resourceMgr->GetMediaDataById(windowIconId, len, iconOut) != Global::Resource::RState::SUCCESS) {
            return nullptr;
        }
        imageSource = Media::ImageSource::CreateImageSource(iconOut.get(), len, opts, errorCode);
    } else { // already unzip hap
        std::string iconPath;
        if (resourceMgr->GetMediaById(windowIconId, iconPath) != Global::Resource::RState::SUCCESS) {
            return nullptr;
        }
        imageSource = Media::ImageSource::CreateImageSource(iconPath, opts, errorCode);
    }

    if (errorCode != 0 || imageSource == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "failed, id %{private}d err %{public}d", windowIconId, errorCode);
        return nullptr;
    }

    Media::DecodeOptions decodeOpts;
    auto pixelMapPtr = imageSource->CreatePixelMap(decodeOpts, errorCode);
    if (errorCode != 0) {
        TAG_LOGE(
            AAFwkTag::ABILITYMGR, "failed, id %{private}d err %{public}d", windowIconId, errorCode);
        return nullptr;
    }
    TAG_LOGD(AAFwkTag::ABILITYMGR, "OUT.");
    return std::shared_ptr<Media::PixelMap>(pixelMapPtr.release());
}

sptr<AbilityTransitionInfo> AbilityRecord::CreateAbilityTransitionInfo(
    const std::shared_ptr<StartOptions> &startOptions, const std::shared_ptr<Want> &want,
    const AbilityRequest &abilityRequest)
{
    sptr<AbilityTransitionInfo> info;
    if (startOptions) {
        info = CreateAbilityTransitionInfo(startOptions, want);
    } else {
        info = CreateAbilityTransitionInfo(abilityRequest);
    }

    SetAbilityTransitionInfo(info);
    SetStartingWindow(true);
    return info;
}

void AbilityRecord::StartingWindowHot(const std::shared_ptr<StartOptions> &startOptions,
    const std::shared_ptr<Want> &want, const AbilityRequest &abilityRequest)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    TAG_LOGD(AAFwkTag::ABILITYMGR, "call");
    auto windowHandler = GetWMSHandler();
    if (!windowHandler) {
        TAG_LOGW(AAFwkTag::ABILITYMGR, "get WMS failed");
        return;
    }

    auto missionListWrap = DelayedSingleton<AbilityManagerService>::GetInstance()->GetMissionListWrap();
    if (missionListWrap == nullptr) {
        TAG_LOGW(AAFwkTag::ABILITYMGR, "null missionListWrap");
        return;
    }

    auto pixelMap = missionListWrap->GetSnapshot(missionId_);
    if (!pixelMap) {
        TAG_LOGW(AAFwkTag::ABILITYMGR, "%{public}s, failed", __func__);
    }

    auto info = CreateAbilityTransitionInfo(startOptions, want, abilityRequest);
    windowHandler->StartingWindow(info, pixelMap);
}

void AbilityRecord::StartingWindowCold(const std::shared_ptr<StartOptions> &startOptions,
    const std::shared_ptr<Want> &want, const AbilityRequest &abilityRequest)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    TAG_LOGD(AAFwkTag::ABILITYMGR, "call");
    auto windowHandler = GetWMSHandler();
    if (!windowHandler) {
        TAG_LOGW(AAFwkTag::ABILITYMGR, "%{public}s, get WMS failed", __func__);
        return;
    }

    // get bg pixelmap and color.
    std::shared_ptr<Media::PixelMap> pixelMap = nullptr;
    uint32_t bgColor = 0;
    GetColdStartingWindowResource(pixelMap, bgColor);

    // start window
    auto info = CreateAbilityTransitionInfo(startOptions, want, abilityRequest);
    windowHandler->StartingWindow(info, pixelMap, bgColor);
    startingWindowBg_.reset();
}

void AbilityRecord::GetColdStartingWindowResource(std::shared_ptr<Media::PixelMap> &bg, uint32_t &bgColor)
{
    bg = startingWindowBg_;
    bgColor = bgColor_;
    if (bg) {
        return;
    }
    auto resourceMgr = CreateResourceManager();
    if (!resourceMgr) {
        TAG_LOGW(AAFwkTag::ABILITYMGR, "get resourceMgr failed");
        return;
    }

    auto windowIconId = static_cast<uint32_t>(abilityInfo_.startWindowIconId);
    bg = GetPixelMap(windowIconId, resourceMgr);

    auto colorId = static_cast<uint32_t>(abilityInfo_.startWindowBackgroundId);
    auto colorErrval = resourceMgr->GetColorById(colorId, bgColor);
    if (colorErrval != OHOS::Global::Resource::RState::SUCCESS) {
        TAG_LOGW(AAFwkTag::ABILITYMGR, "failed to GetColorById");
        bgColor = 0xdfffffff;
    }
    TAG_LOGD(AAFwkTag::ABILITYMGR, "colorId is %{public}u, bgColor is %{public}u.", colorId, bgColor);
}

void AbilityRecord::InitColdStartingWindowResource(
    const std::shared_ptr<Global::Resource::ResourceManager> &resourceMgr)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    if (!resourceMgr) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "invalid resourceManager");
        return;
    }

    startingWindowBg_ = GetPixelMap(static_cast<uint32_t>(abilityInfo_.startWindowIconId), resourceMgr);
    if (resourceMgr->GetColorById(static_cast<uint32_t>(abilityInfo_.startWindowBackgroundId), bgColor_) !=
        OHOS::Global::Resource::RState::SUCCESS) {
        TAG_LOGW(AAFwkTag::ABILITYMGR, "getColorById failed");
        bgColor_ = 0xdfffffff;
    }

    auto handler = DelayedSingleton<AbilityManagerService>::GetInstance()->GetTaskHandler();
    if (startingWindowBg_ && handler) {
        auto delayTask = [me = weak_from_this()] {
            auto self = me.lock();
            if (!self || !self->startingWindowBg_) {
                return;
            }
            self->startingWindowBg_.reset();
        };
        handler->SubmitTask(delayTask, "release_bg", RELEASE_STARTING_BG_TIMEOUT);
    }
}

bool AbilityRecord::ReportAtomicServiceDrawnCompleteEvent()
{
    if (abilityInfo_.applicationInfo.bundleType != AppExecFwk::BundleType::ATOMIC_SERVICE) {
        return false;
    }
    TAG_LOGD(AAFwkTag::ABILITYMGR, "Report atomic service first frame complete event.");
    AAFwk::EventInfo eventInfo;
    eventInfo.abilityName = abilityInfo_.name;
    eventInfo.moduleName = abilityInfo_.moduleName;
    eventInfo.bundleName = abilityInfo_.bundleName;
    auto eventName = AAFwk::EventName::ATOMIC_SERVICE_DRAWN_COMPLETE;
    AAFwk::EventReport::SendAtomicServiceEvent(eventName, HiSysEventType::BEHAVIOR, eventInfo);
    return true;
}

void AbilityRecord::SetCompleteFirstFrameDrawing(const bool flag)
{
    isCompleteFirstFrameDrawing_ = flag;
}

bool AbilityRecord::IsCompleteFirstFrameDrawing() const
{
    return isCompleteFirstFrameDrawing_;
}

bool AbilityRecord::GetColdStartFlag()
{
    return coldStart_;
}

void AbilityRecord::SetColdStartFlag(bool isColdStart)
{
    coldStart_ = isColdStart;
}
#endif

void AbilityRecord::BackgroundAbility(const Closure &task)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    TAG_LOGI(AAFwkTag::ABILITYMGR, "BackgroundLifecycle: ability:%{public}s", GetURI().c_str());
    if (lifecycleDeal_ == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "null lifecycleDeal_");
        return;
    }

    if (!IsDebug()) {
        auto handler = DelayedSingleton<AbilityManagerService>::GetInstance()->GetTaskHandler();
        if (handler && task) {
            int backgroundTimeout =
                AmsConfigurationParameter::GetInstance().GetAppStartTimeoutTime() * BACKGROUND_TIMEOUT_MULTIPLE;
            if (InsightIntentExecuteParam::IsInsightIntentExecute(GetWant())) {
                backgroundTimeout = AmsConfigurationParameter::GetInstance().GetAppStartTimeoutTime() *
                    INSIGHT_INTENT_TIMEOUT_MULTIPLE;
            }
            handler->SubmitTask(task, "background_" + std::to_string(recordId_), backgroundTimeout, false);

            if (abilityInfo_.type == AppExecFwk::AbilityType::PAGE) {
                std::string methodName = "BackgroundAbility";
                g_addLifecycleEventTask(token_, methodName);
            }
        }
    } else {
        TAG_LOGI(AAFwkTag::ABILITYMGR, "debug mode, no need to handle");
    }

    if (!IsTerminating() || IsRestarting()) {
        // schedule save ability state before moving to background.
        SaveAbilityState();
    }

    // schedule background after updating AbilityState and sending timeout message to avoid ability async callback
    // earlier than above actions.
#ifdef SUPPORT_SCREEN
    SetAbilityStateInner(AbilityState::BACKGROUNDING);
#endif // SUPPORT_SCREEN
    lifecycleDeal_->BackgroundNew(GetWant(), lifeCycleStateInfo_, GetSessionInfo());
    std::lock_guard guard(wantLock_);
    isLaunching_ = false;
}

bool AbilityRecord::PrepareTerminateAbility()
{
    TAG_LOGD(AAFwkTag::ABILITYMGR, "call");
    if (lifecycleDeal_ == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "null lifecycleDeal_");
        return false;
    }
    return lifecycleDeal_->PrepareTerminateAbility();
}

int AbilityRecord::TerminateAbility()
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    TAG_LOGI(AAFwkTag::ABILITYMGR, "ability:%{public}s", abilityInfo_.name.c_str());
#ifdef WITH_DLP
    HandleDlpClosed();
#endif // WITH_DLP
    AAFwk::EventInfo eventInfo;
    eventInfo.bundleName = GetAbilityInfo().bundleName;
    eventInfo.abilityName = GetAbilityInfo().name;
    if (clearMissionFlag_) {
        TAG_LOGD(AAFwkTag::ABILITYMGR, "deleteAbilityRecoverInfo before clearMission");
        (void)DelayedSingleton<AbilityRuntime::AppExitReasonDataManager>::GetInstance()->
            DeleteAbilityRecoverInfo(GetAbilityInfo().applicationInfo.accessTokenId, GetAbilityInfo().moduleName,
            GetAbilityInfo().name);
    }
    ResSchedUtil::GetInstance().ReportLoadingEventToRss(LoadingStage::DESTROY_END, GetPid(), GetUid(),
        0, GetRecordId());
    AAFwk::EventReport::SendAbilityEvent(AAFwk::EventName::TERMINATE_ABILITY, HiSysEventType::BEHAVIOR, eventInfo);
    eventInfo.errCode = DelayedSingleton<AppScheduler>::GetInstance()->TerminateAbility(token_, clearMissionFlag_);
    if (eventInfo.errCode != ERR_OK) {
        AAFwk::EventReport::SendAbilityEvent(
            AAFwk::EventName::TERMINATE_ABILITY_ERROR, HiSysEventType::FAULT, eventInfo);
    }
    return eventInfo.errCode;
}

const AppExecFwk::AbilityInfo &AbilityRecord::GetAbilityInfo() const
{
    return abilityInfo_;
}

const AppExecFwk::ApplicationInfo &AbilityRecord::GetApplicationInfo() const
{
    return abilityInfo_.applicationInfo;
}

AbilityState AbilityRecord::GetAbilityState() const
{
    return currentState_;
}

WindowConfig AbilityRecord::GetAbilityWindowConfig() const
{
    return windowConfig_;
}

bool AbilityRecord::IsForeground() const
{
    return currentState_ == AbilityState::FOREGROUND || currentState_ == AbilityState::FOREGROUNDING;
}

AbilityVisibilityState AbilityRecord::GetAbilityVisibilityState() const
{
    return abilityVisibilityState_.load();
}

void AbilityRecord::SetAbilityVisibilityState(AbilityVisibilityState state)
{
    abilityVisibilityState_.store(state);
}

void AbilityRecord::UpdateAbilityVisibilityState()
{
    if (GetAbilityVisibilityState() == AbilityVisibilityState::INITIAL) {
        auto state = AbilityVisibilityState::UNSPECIFIED;
        auto sessionInfo = GetSessionInfo();
        if (sessionInfo && sessionInfo->processOptions &&
            ProcessOptions::IsNewProcessMode(sessionInfo->processOptions->processMode)) {
            auto startupVisibility = sessionInfo->processOptions->startupVisibility;
            if (startupVisibility == StartupVisibility::STARTUP_SHOW) {
                state = AbilityVisibilityState::FOREGROUND_SHOW;
            } else if (startupVisibility == StartupVisibility::STARTUP_HIDE) {
                state = AbilityVisibilityState::FOREGROUND_HIDE;
            }
        }
        SetAbilityVisibilityState(state);
    }
}
#ifdef SUPPORT_SCREEN
void AbilityRecord::SetAbilityStateInner(AbilityState state)
{
    currentState_ = state;
    if (currentState_ == AbilityState::BACKGROUND) {
        isAbilityForegrounding_ = false;
    }

    auto collaborator = DelayedSingleton<AbilityManagerService>::GetInstance()->GetCollaborator(
        collaboratorType_);
    if (collaborator != nullptr) {
        TAG_LOGD(AAFwkTag::ABILITYMGR, "notify collaborator, missionId:%{public}d, state:%{public}d", missionId_,
            static_cast<int32_t>(state));
        int ret = ERR_OK;
        if (Rosen::SceneBoardJudgement::IsSceneBoardEnabled()) {
            auto sessionInfo = GetSessionInfo();
            if (sessionInfo == nullptr) {
                TAG_LOGE(AAFwkTag::ABILITYMGR, "null sessionInfo");
                return;
            }
            int32_t persistentId = sessionInfo->persistentId;
            switch (state) {
                case AbilityState::BACKGROUNDING: {
                    ret = collaborator->NotifyMoveMissionToBackground(persistentId);
                    break;
                }
                case AbilityState::TERMINATING: {
                    ret = collaborator->NotifyTerminateMission(persistentId);
                    break;
                }
                default:
                    break;
            }
            if (ret != ERR_OK) {
                TAG_LOGE(AAFwkTag::ABILITYMGR, "failed,err: %{public}d", ret);
            }
            return;
        }
        switch (state) {
            case AbilityState::FOREGROUNDING: {
                ret = collaborator->NotifyMoveMissionToForeground(missionId_);
                break;
            }
            case AbilityState::BACKGROUNDING: {
                ret = collaborator->NotifyMoveMissionToBackground(missionId_);
                break;
            }
            case AbilityState::TERMINATING: {
                ret = collaborator->NotifyTerminateMission(missionId_);
                break;
            }
            default:
                break;
        }
        if (ret != ERR_OK) {
            TAG_LOGE(AAFwkTag::ABILITYMGR, "failed, err: %{public}d", ret);
        }
    }

    auto missionListWrap = DelayedSingleton<AbilityManagerService>::GetInstance()->GetMissionListWrap();
    if (missionListWrap != nullptr) {
        missionListWrap->SetMissionAbilityState(missionId_, currentState_);
    }
}
#endif // SUPPORT_SCREEN
bool AbilityRecord::GetAbilityForegroundingFlag() const
{
    return isAbilityForegrounding_;
}

void AbilityRecord::SetAbilityForegroundingFlag()
{
    isAbilityForegrounding_ = true;
    DelayedSingleton<AppScheduler>::GetInstance()->SetAbilityForegroundingFlagToAppRecord(pid_);
}
#ifdef SUPPORT_SCREEN
void AbilityRecord::SetAbilityState(AbilityState state)
{
    SetAbilityStateInner(state);
    if (state == AbilityState::FOREGROUND || state == AbilityState::ACTIVE || state == AbilityState::BACKGROUND) {
        SetRestarting(false);
    }
    if (state == AbilityState::FOREGROUND) {
        ResSchedUtil::GetInstance().ReportLoadingEventToRss(LoadingStage::FOREGROUND_END, GetPid(),
            GetUid(), 0, GetAbilityRecordId());
    }
}
#endif // SUPPORT_SCREEN
void AbilityRecord::SetScheduler(const sptr<IAbilityScheduler> &scheduler)
{
    TAG_LOGD(AAFwkTag::ABILITYMGR, "bundle:%{public}s, ability: %{public}s",
        abilityInfo_.applicationInfo.bundleName.c_str(), abilityInfo_.name.c_str());
    CHECK_POINTER(lifecycleDeal_);
    if (scheduler != nullptr) {
        if (scheduler_ != nullptr && schedulerDeathRecipient_ != nullptr) {
            auto schedulerObject = scheduler_->AsObject();
            if (schedulerObject != nullptr) {
                schedulerObject->RemoveDeathRecipient(schedulerDeathRecipient_);
            }
        }
        if (schedulerDeathRecipient_ == nullptr) {
            schedulerDeathRecipient_ =
                new AbilitySchedulerRecipient([thisWeakPtr = weak_from_this()](const wptr<IRemoteObject> &remote) {
                    auto abilityRecord = thisWeakPtr.lock();
                    if (abilityRecord) {
                        abilityRecord->OnSchedulerDied(remote);
                    }
                });
        }
        isReady_ = true;
        scheduler_ = scheduler;
        lifecycleDeal_->SetScheduler(scheduler);
        auto schedulerObject = scheduler_->AsObject();
        if (schedulerObject == nullptr || !schedulerObject->AddDeathRecipient(schedulerDeathRecipient_)) {
            TAG_LOGE(AAFwkTag::ABILITYMGR, "AddDeathRecipient failed");
        }
        pid_ = static_cast<int32_t>(IPCSkeleton::GetCallingPid()); // set pid when ability attach to service.
        AfterLoaded();
        // add collaborator mission bind pid
        NotifyMissionBindPid();
#ifdef WITH_DLP
        HandleDlpAttached();
#endif // WITH_DLP
    } else {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "null scheduler");
        isReady_ = false;
        isWindowAttached_ = false;
        SetIsNewWant(false);
        if (scheduler_ != nullptr && schedulerDeathRecipient_ != nullptr) {
            auto schedulerObject = scheduler_->AsObject();
            if (schedulerObject != nullptr) {
                TAG_LOGI(AAFwkTag::ABILITYMGR, "RemoveDeathRecipient");
                schedulerObject->RemoveDeathRecipient(schedulerDeathRecipient_);
            }
        }
        scheduler_ = scheduler;
        pid_ = 0;
    }
}

void AbilityRecord::AfterLoaded()
{
    FreezeUtil::GetInstance().DeleteAppLifecycleEvent(GetPid());
    if (GetAbilityInfo().extensionAbilityType != AppExecFwk::ExtensionAbilityType::SERVICE) {
        ResSchedUtil::GetInstance().ReportLoadingEventToRss(LoadingStage::LOAD_END, GetPid(),
            GetUid(), 0, GetAbilityRecordId());
    }

    if (IsSceneBoard()) {
        TAG_LOGI(AAFwkTag::ABILITYMGR, "Sceneboard Added");
    }
}

sptr<Token> AbilityRecord::GetToken() const
{
    return token_;
}

void AbilityRecord::SetPreAbilityRecord(const std::shared_ptr<AbilityRecord> &abilityRecord)
{
    preAbilityRecord_ = abilityRecord;
}

std::shared_ptr<AbilityRecord> AbilityRecord::GetPreAbilityRecord() const
{
    return preAbilityRecord_.lock();
}

void AbilityRecord::SetNextAbilityRecord(const std::shared_ptr<AbilityRecord> &abilityRecord)
{
    nextAbilityRecord_ = abilityRecord;
}

std::shared_ptr<AbilityRecord> AbilityRecord::GetNextAbilityRecord() const
{
    return nextAbilityRecord_.lock();
}

bool AbilityRecord::IsReady() const
{
    return isReady_;
}

#ifdef SUPPORT_SCREEN
bool AbilityRecord::IsWindowAttached() const
{
    return isWindowAttached_;
}
#endif

bool AbilityRecord::IsLauncherAbility() const
{
    return isLauncherAbility_;
}

bool AbilityRecord::IsTerminating() const
{
    return isTerminating_;
}

void AbilityRecord::SetTerminatingState()
{
    isTerminating_ = true;
}

bool AbilityRecord::IsNewWant() const
{
    return lifeCycleStateInfo_.isNewWant;
}

void AbilityRecord::SetIsNewWant(bool isNewWant)
{
    lifeCycleStateInfo_.isNewWant = isNewWant;
}

bool AbilityRecord::IsCreateByConnect() const
{
    return isCreateByConnect_;
}

void AbilityRecord::SetCreateByConnectMode(bool isCreatedByConnect)
{
    isCreateByConnect_ = isCreatedByConnect;
}

void AbilityRecord::Activate()
{
    TAG_LOGI(AAFwkTag::ABILITYMGR, "activate");
    CHECK_POINTER(lifecycleDeal_);

    if (!IsDebug()) {
        int activeTimeout = AmsConfigurationParameter::GetInstance().GetAppStartTimeoutTime() * ACTIVE_TIMEOUT_MULTIPLE;
        SendEvent(AbilityManagerService::ACTIVE_TIMEOUT_MSG, activeTimeout);
    }

    // schedule active after updating AbilityState and sending timeout message to avoid ability async callback
    // earlier than above actions.
#ifdef SUPPORT_SCREEN
    SetAbilityStateInner(AbilityState::ACTIVATING);
#endif // SUPPORT_SCREEN
    lifecycleDeal_->Activate(GetWant(), lifeCycleStateInfo_);
}

void AbilityRecord::Inactivate()
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    TAG_LOGD(AAFwkTag::ABILITYMGR, "ability:%{public}s.", abilityInfo_.name.c_str());
    CHECK_POINTER(lifecycleDeal_);

    if (!IsDebug()) {
        int inactiveTimeout =
            AmsConfigurationParameter::GetInstance().GetAppStartTimeoutTime() * INACTIVE_TIMEOUT_MULTIPLE;
        SendEvent(AbilityManagerService::INACTIVE_TIMEOUT_MSG, inactiveTimeout);
    }

    // schedule inactive after updating AbilityState and sending timeout message to avoid ability async callback
    // earlier than above actions.
#ifdef SUPPORT_SCREEN
    SetAbilityStateInner(AbilityState::INACTIVATING);
#endif // SUPPORT_SCREEN
    Want want = GetWant();
    UpdateDmsCallerInfo(want);
    lifecycleDeal_->Inactivate(want, lifeCycleStateInfo_, GetSessionInfo());
}

void AbilityRecord::Terminate(const Closure &task)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    TAG_LOGD(AAFwkTag::ABILITYMGR, "ability: %{public}s.", GetURI().c_str());
    CHECK_POINTER(lifecycleDeal_);
    if (!IsDebug()) {
        auto handler = DelayedSingleton<AbilityManagerService>::GetInstance()->GetTaskHandler();
        if (handler && task) {
            int terminateTimeout =
                AmsConfigurationParameter::GetInstance().GetAppStartTimeoutTime() * TERMINATE_TIMEOUT_MULTIPLE;
            if (abilityInfo_.applicationInfo.asanEnabled) {
                terminateTimeout =
                    AmsConfigurationParameter::GetInstance().GetAppStartTimeoutTime() * TERMINATE_TIMEOUT_ASANENABLED;
            }
            handler->SubmitTask(task, "terminate_" + std::to_string(recordId_), terminateTimeout);
            ResSchedUtil::GetInstance().ReportLoadingEventToRss(LoadingStage::DESTROY_BEGIN, GetPid(), GetUid(),
                terminateTimeout, GetRecordId());
        }
    } else {
        TAG_LOGI(AAFwkTag::ABILITYMGR, "debug mode, no need to handle");
    }
#ifdef WITH_DLP
    HandleDlpClosed();
#endif // WITH_DLP
    // schedule background after updating AbilityState and sending timeout message to avoid ability async callback
    // earlier than above actions.
#ifdef SUPPORT_SCREEN
    SetAbilityStateInner(AbilityState::TERMINATING);
#endif // SUPPORT_SCREEN
    lifecycleDeal_->Terminate(GetWant(), lifeCycleStateInfo_, GetSessionInfo());
}

void AbilityRecord::ShareData(const int32_t &uniqueId)
{
    TAG_LOGI(AAFwkTag::ABILITYMGR, "ability:%{public}s", abilityInfo_.name.c_str());
    CHECK_POINTER(lifecycleDeal_);
    if (!IsDebug()) {
        int loadTimeout =
            AmsConfigurationParameter::GetInstance().GetAppStartTimeoutTime() * SHAREDATA_TIMEOUT_MULTIPLE;
        TAG_LOGD(AAFwkTag::ABILITYMGR, "loadTimeOut %{public}d.", loadTimeout);
        SendEvent(AbilityManagerService::SHAREDATA_TIMEOUT_MSG, loadTimeout, uniqueId);
    }
    lifecycleDeal_->ShareData(uniqueId);
}

void AbilityRecord::ConnectAbility()
{
    TAG_LOGI(AAFwkTag::ABILITYMGR, "%{public}s called.", __func__);
    Want want = GetWant();
    UpdateDmsCallerInfo(want);
    ConnectAbilityWithWant(want);
}

void AbilityRecord::ConnectAbilityWithWant(const Want &want)
{
    TAG_LOGD(AAFwkTag::ABILITYMGR, "Connect ability.");
    CHECK_POINTER(lifecycleDeal_);
    if (isConnected) {
        TAG_LOGW(AAFwkTag::ABILITYMGR, "state err");
    }
    lifecycleDeal_->ConnectAbility(want);
    isConnected = true;
}

void AbilityRecord::DisconnectAbility()
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    TAG_LOGI(AAFwkTag::ABILITYMGR, "DisconnectAbility, bundle:%{public}s, ability:%{public}s.",
        abilityInfo_.applicationInfo.bundleName.c_str(), abilityInfo_.name.c_str());
    CHECK_POINTER(lifecycleDeal_);
    lifecycleDeal_->DisconnectAbility(GetWant());
    if (GetAbilityInfo().extensionAbilityType == AppExecFwk::ExtensionAbilityType::UI_SERVICE) {
        if (GetInProgressRecordCount() == 0) {
            isConnected = false;
        }
    } else {
        isConnected = false;
    }
}

void AbilityRecord::DisconnectAbilityWithWant(const Want &want)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    TAG_LOGD(AAFwkTag::ABILITYMGR, "ability:%{public}s.", abilityInfo_.name.c_str());
    CHECK_POINTER(lifecycleDeal_);
    lifecycleDeal_->DisconnectAbility(want);
    if (GetInProgressRecordCount() == 0) {
        isConnected = false;
    }
}

void AbilityRecord::CommandAbility()
{
    TAG_LOGI(AAFwkTag::ABILITYMGR, "startId_:%{public}d.", startId_);
    Want want = GetWant();
    UpdateDmsCallerInfo(want);
    CHECK_POINTER(lifecycleDeal_);
    lifecycleDeal_->CommandAbility(want, false, startId_);
}

void AbilityRecord::CommandAbilityWindow(const sptr<SessionInfo> &sessionInfo, WindowCommand winCmd)
{
    CHECK_POINTER(lifecycleDeal_);
    lifecycleDeal_->CommandAbilityWindow(GetWant(), sessionInfo, winCmd);
}

void AbilityRecord::SaveAbilityState()
{
    TAG_LOGD(AAFwkTag::ABILITYMGR, "call");
    CHECK_POINTER(lifecycleDeal_);
    lifecycleDeal_->SaveAbilityState();
}

void AbilityRecord::SaveAbilityState(const PacMap &inState)
{
    TAG_LOGD(AAFwkTag::ABILITYMGR, "call");
    stateDatas_ = inState;
}

void AbilityRecord::SaveAbilityWindowConfig(const WindowConfig &windowConfig)
{
    TAG_LOGI(AAFwkTag::ABILITYMGR, "call");
    windowConfig_ = windowConfig;
}

void AbilityRecord::RestoreAbilityState()
{
    TAG_LOGI(AAFwkTag::ABILITYMGR, "call");
    CHECK_POINTER(lifecycleDeal_);
    lifecycleDeal_->RestoreAbilityState(stateDatas_);
    stateDatas_.Clear();
    isRestarting_ = false;
}

int AbilityRecord::GetRequestCode() const
{
    return requestCode_;
}

void AbilityRecord::SetResult(const std::shared_ptr<AbilityResult> &result)
{
    std::lock_guard guard(resultLock_);
    result_ = result;
}

std::shared_ptr<AbilityResult> AbilityRecord::GetResult() const
{
    std::lock_guard guard(resultLock_);
    return result_;
}

void AbilityRecord::SendResult(bool isSandboxApp, uint32_t tokeId)
{
    TAG_LOGI(AAFwkTag::ABILITYMGR, "ability:%{public}s", abilityInfo_.name.c_str());
    std::lock_guard<ffrt::mutex> guard(lock_);
    CHECK_POINTER(scheduler_);
    auto result = GetResult();
    CHECK_POINTER(result);
    GrantUriPermission(result->resultWant_, abilityInfo_.applicationInfo.bundleName, isSandboxApp, tokeId);
    scheduler_->SendResult(result->requestCode_, result->resultCode_, result->resultWant_);
    // reset result to avoid send result next time
    SetResult(nullptr);
}

void AbilityRecord::SendResultByBackToCaller(const std::shared_ptr<AbilityResult> &result)
{
    TAG_LOGI(AAFwkTag::ABILITYMGR, "ability:%{public}s", abilityInfo_.name.c_str());
    std::lock_guard<ffrt::mutex> guard(lock_);
    CHECK_POINTER(scheduler_);
    CHECK_POINTER(result);
    scheduler_->SendResult(result->requestCode_, result->resultCode_, result->resultWant_);
}

void AbilityRecord::SendSandboxSavefileResult(const Want &want, int resultCode, int requestCode)
{
    TAG_LOGI(AAFwkTag::ABILITYMGR, "ability:%{public}s", abilityInfo_.name.c_str());

    auto uriParam = want.GetParams().GetParam(PARAMS_FILE_SAVING_URL_KEY);
    auto uriArray = AAFwk::IArray::Query(uriParam);
    long arraySize = 0;
    if (uriArray && uriArray->GetLength(arraySize) == ERR_OK &&
        arraySize > 0 && AAFwk::Array::IsStringArray(uriArray)) {
        for (long i = 0; i < arraySize; i++) {
            sptr<AAFwk::IInterface> iface = nullptr;
            if (uriArray->Get(i, iface) != ERR_OK) {
                continue;
            }
            AAFwk::IString* iuri = AAFwk::IString::Query(iface);
            if (!iuri) {
                continue;
            }
            std::string uriStr;
            if (iuri->GetString(uriStr) != ERR_OK) {
                continue;
            }
            Uri uri(uriStr);
            uint32_t initiatorTokenId = IPCSkeleton::GetCallingTokenID();
            auto flag = Want::FLAG_AUTH_WRITE_URI_PERMISSION | Want::FLAG_AUTH_READ_URI_PERMISSION;
            auto ret = IN_PROCESS_CALL(UriPermissionManagerClient::GetInstance().GrantUriPermission(uri,
                flag, abilityInfo_.bundleName, appIndex_, initiatorTokenId));
            if (ret != ERR_OK) {
                TAG_LOGW(AAFwkTag::ABILITYMGR, "GrantUriPermission failed");
            }
        }
    } else {
        TAG_LOGW(AAFwkTag::ABILITYMGR, "uri illegal for request: %{public}d", requestCode);
    }

    auto scheduler = scheduler_;
    if (scheduler) {
        scheduler->SendResult(requestCode, resultCode, want);
    }
}

void AbilityRecord::SendResultToCallers(bool schedulerdied)
{
    for (auto caller : GetCallerRecordList()) {
        if (caller == nullptr) {
            TAG_LOGW(AAFwkTag::ABILITYMGR, "null caller");
            continue;
        }
        std::shared_ptr<AbilityRecord> callerAbilityRecord = caller->GetCaller();
        if (callerAbilityRecord != nullptr && callerAbilityRecord->GetResult() != nullptr) {
            bool isSandboxApp = appIndex_ > AbilityRuntime::GlobalConstant::MAX_APP_CLONE_INDEX ? true : false;
            callerAbilityRecord->SendResult(isSandboxApp, abilityInfo_.applicationInfo.accessTokenId);
        } else {
            std::shared_ptr<SystemAbilityCallerRecord> callerSystemAbilityRecord = caller->GetSaCaller();
            if (callerSystemAbilityRecord != nullptr) {
                TAG_LOGI(AAFwkTag::ABILITYMGR, "send result to system ability");
                callerSystemAbilityRecord->SendResultToSystemAbility(caller->GetRequestCode(),
                    callerSystemAbilityRecord, abilityInfo_.applicationInfo.uid,
                    abilityInfo_.applicationInfo.accessTokenId, schedulerdied);
            }
        }
    }
}

std::shared_ptr<AbilityRecord> AbilityRecord::GetCallerByRequestCode(int32_t requestCode, int32_t pid)
{
    for (auto caller : GetCallerRecordList()) {
        if (caller == nullptr) {
            TAG_LOGI(AAFwkTag::ABILITYMGR, "null caller");
            continue;
        }
        std::shared_ptr<AbilityRecord> callerAbilityRecord = caller->GetCaller();
        if (callerAbilityRecord == nullptr || callerAbilityRecord->GetPid() != pid) {
            TAG_LOGI(AAFwkTag::ABILITYMGR, "callerAbility not match");
            continue;
        }
        if (caller->IsHistoryRequestCode(requestCode)) {
            TAG_LOGI(AAFwkTag::ABILITYMGR, "found callerAbility");
            return callerAbilityRecord;
        }
    }
    TAG_LOGI(AAFwkTag::ABILITYMGR, "Can't found caller");
    return nullptr;
}

void AbilityRecord::SaveResultToCallers(const int resultCode, const Want *resultWant)
{
    auto callerRecordList = GetCallerRecordList();
    if (callerRecordList.empty()) {
        TAG_LOGW(AAFwkTag::ABILITYMGR, "callerRecordList empty");
        return;
    }
    auto latestCaller = callerRecordList.back();
    for (auto caller : callerRecordList) {
        if (caller == nullptr) {
            TAG_LOGW(AAFwkTag::ABILITYMGR, "null caller");
            continue;
        }
        if (caller == latestCaller) {
            TAG_LOGD(AAFwkTag::ABILITYMGR, "latestCaller");
            SaveResult(resultCode, resultWant, caller);
            continue;
        }
        SaveResult(SEND_RESULT_CANCELED, resultWant, caller);
    }
}

void AbilityRecord::SaveResult(int resultCode, const Want *resultWant, std::shared_ptr<CallerRecord> caller)
{
    std::lock_guard<ffrt::mutex> guard(lock_);
    std::shared_ptr<AbilityRecord> callerAbilityRecord = caller->GetCaller();
    if (callerAbilityRecord != nullptr) {
        Want* newWant = const_cast<Want*>(resultWant);
        if (callerAbilityRecord->GetApplicationInfo().name == AppUtils::GetInstance().GetBrokerDelegateBundleName()) {
            newWant->SetParam(std::string(PARAM_SEND_RESULT_CALLER_BUNDLENAME), abilityInfo_.applicationInfo.name);
            newWant->SetParam(std::string(PARAM_SEND_RESULT_CALLER_TOKENID), static_cast<int32_t>(
                abilityInfo_.applicationInfo.accessTokenId));
        }
        callerAbilityRecord->SetResult(
            std::make_shared<AbilityResult>(caller->GetRequestCode(), resultCode, *newWant));
    } else {
        std::shared_ptr<SystemAbilityCallerRecord> callerSystemAbilityRecord = caller->GetSaCaller();
        if (callerSystemAbilityRecord != nullptr) {
            TAG_LOGI(AAFwkTag::ABILITYMGR, "caller is system ability");
            Want* newWant = const_cast<Want*>(resultWant);
            callerSystemAbilityRecord->SetResultToSystemAbility(callerSystemAbilityRecord, *newWant,
                resultCode);
        }
    }
}

void SystemAbilityCallerRecord::SetResultToSystemAbility(
    std::shared_ptr<SystemAbilityCallerRecord> callerSystemAbilityRecord,
    Want &resultWant, int resultCode)
{
    std::vector<std::string> data;
    std::string srcAbilityId = callerSystemAbilityRecord->GetSrcAbilityId();
    SplitStr(srcAbilityId, "_", data);
    if (data.size() != VECTOR_SIZE) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "check size failed");
        return;
    }
    std::string srcDeviceId = data[0];
    TAG_LOGD(AAFwkTag::ABILITYMGR, "Get srcDeviceId = %{public}s", srcDeviceId.c_str());
    int missionId = atoi(data[1].c_str());
    TAG_LOGI(AAFwkTag::ABILITYMGR, "get missionId: %{public}d", missionId);
    resultWant.SetParam(DMS_SRC_NETWORK_ID, srcDeviceId);
    resultWant.SetParam(DMS_MISSION_ID, missionId);
    callerSystemAbilityRecord->SetResult(resultWant, resultCode);
}

void SystemAbilityCallerRecord::SendResultToSystemAbility(int requestCode,
    const std::shared_ptr<SystemAbilityCallerRecord> callerSystemAbilityRecord,
    int32_t callerUid, uint32_t accessToken, bool schedulerdied)
{
    TAG_LOGI(AAFwkTag::ABILITYMGR, "call");
    if (callerSystemAbilityRecord == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "null record");
        return;
    }
    int resultCode = callerSystemAbilityRecord->GetResultCode();
    Want resultWant = callerSystemAbilityRecord->GetResultWant();
    sptr<IRemoteObject> callerToken = callerSystemAbilityRecord->GetCallerToken();
    if (!schedulerdied) {
        callerUid = IPCSkeleton::GetCallingUid();
        accessToken = IPCSkeleton::GetCallingTokenID();
    }
    TAG_LOGI(AAFwkTag::ABILITYMGR, "Try to SendResult");
    if (callerToken == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "null callerToken");
        return;
    }
    MessageParcel data;
    if (!data.WriteInterfaceToken(SYSTEM_ABILITY_TOKEN_CALLBACK)) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "write interface token failed");
        return;
    }
    if (!data.WriteParcelable(&resultWant)) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "writeParcelable failed");
        return;
    }
    data.WriteInt32(callerUid);
    data.WriteInt32(requestCode);
    data.WriteUint32(accessToken);
    data.WriteInt32(resultCode);
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    int result = callerToken->SendRequest(ISystemAbilityTokenCallback::SEND_RESULT, data, reply, option);
    if (result != ERR_OK) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "error: %{public}d", result);
    }
}

bool AbilityRecord::NeedConnectAfterCommand()
{
    return !IsConnectListEmpty() && !isConnected;
}

void AbilityRecord::AddConnectRecordToList(const std::shared_ptr<ConnectionRecord> &connRecord)
{
    CHECK_POINTER(connRecord);
    std::lock_guard guard(connRecordListMutex_);
    auto it = std::find(connRecordList_.begin(), connRecordList_.end(), connRecord);
    // found it
    if (it != connRecordList_.end()) {
        TAG_LOGD(AAFwkTag::ABILITYMGR, "Found it in list, so no need to add same connection");
        return;
    }
    // no found then add new connection to list
    TAG_LOGD(AAFwkTag::ABILITYMGR, "No found in list, so add new connection to list");
    connRecordList_.push_back(connRecord);
}

std::list<std::shared_ptr<ConnectionRecord>> AbilityRecord::GetConnectRecordList() const
{
    std::lock_guard guard(connRecordListMutex_);
    return connRecordList_;
}

void AbilityRecord::RemoveConnectRecordFromList(const std::shared_ptr<ConnectionRecord> &connRecord)
{
    CHECK_POINTER(connRecord);
    std::lock_guard guard(connRecordListMutex_);
    connRecordList_.remove(connRecord);
    if (connRecordList_.empty()) {
        isConnected = false;
    }
}

void AbilityRecord::RemoveSpecifiedWantParam(const std::string &key)
{
    std::lock_guard guard(wantLock_);
    if (want_.HasParameter(key)) {
        want_.RemoveParam(key);
    }
}

void AbilityRecord::RemoveCallerRequestCode(std::shared_ptr<AbilityRecord> callerAbilityRecord, int32_t requestCode)
{
    if (callerAbilityRecord == nullptr) {
        TAG_LOGI(AAFwkTag::ABILITYMGR, "null record");
        return;
    }
    for (auto it = callerList_.begin(); it != callerList_.end(); it++) {
        if ((*it)->GetCaller() == callerAbilityRecord) {
            (*it)->RemoveHistoryRequestCode(requestCode);
            if ((*it)->GetRequestCodeSet().empty()) {
                callerList_.erase(it);
                TAG_LOGI(AAFwkTag::ABILITYMGR, "remove callerRecord");
            }
            return;
        }
    }
}

void AbilityRecord::AddCallerRecord(const sptr<IRemoteObject> &callerToken, int requestCode, const Want &want,
    std::string srcAbilityId, uint32_t callingTokenId)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    TAG_LOGD(AAFwkTag::ABILITYMGR, "call, callingTokenId:%{public}u", callingTokenId);
    auto abilityRecord = Token::GetAbilityRecordByToken(callerToken);
    if (abilityRecord == nullptr) {
        RecordSaCallerInfo(want);
    }
    if (!srcAbilityId.empty() && IsSystemAbilityCall(callerToken, callingTokenId)) {
        AddSystemAbilityCallerRecord(callerToken, requestCode, srcAbilityId);
        return;
    }
    CHECK_POINTER(abilityRecord);

    auto isExist = [&abilityRecord](const std::shared_ptr<CallerRecord> &callerRecord) {
        return (callerRecord->GetCaller() == abilityRecord);
    };

    auto record = std::find_if(callerList_.begin(), callerList_.end(), isExist);
    auto newCallerRecord = std::make_shared<CallerRecord>(requestCode, abilityRecord);
    if (record != callerList_.end()) {
        newCallerRecord->SetRequestCodeSet((*record)->GetRequestCodeSet());
        callerList_.erase(record);
    }
    newCallerRecord->AddHistoryRequestCode(requestCode);
    callerList_.emplace_back(newCallerRecord);

    lifeCycleStateInfo_.caller.requestCode = requestCode;
    lifeCycleStateInfo_.caller.deviceId = abilityRecord->GetAbilityInfo().deviceId;
    lifeCycleStateInfo_.caller.bundleName = abilityRecord->GetAbilityInfo().bundleName;
    lifeCycleStateInfo_.caller.abilityName = abilityRecord->GetAbilityInfo().name;
    TAG_LOGD(AAFwkTag::ABILITYMGR, "caller %{public}s, %{public}s, callerSize: %{public}zu",
        abilityRecord->GetAbilityInfo().bundleName.c_str(),
        abilityRecord->GetAbilityInfo().name.c_str(), callerList_.size());
}

bool AbilityRecord::IsSystemAbilityCall(const sptr<IRemoteObject> &callerToken, uint32_t callingTokenId)
{
    if (callerToken == nullptr) {
        return false;
    }
    auto abilityRecord = Token::GetAbilityRecordByToken(callerToken);
    if (abilityRecord != nullptr) {
        return false;
    }
    uint32_t tokenId = 0;
    if (Rosen::SceneBoardJudgement::IsSceneBoardEnabled()) {
        tokenId = callingTokenId;
    } else {
        tokenId = IPCSkeleton::GetCallingTokenID();
    }
    auto tokenType = Security::AccessToken::AccessTokenKit::GetTokenTypeFlag(tokenId);
    bool isNativeCall = tokenType == Security::AccessToken::ATokenTypeEnum::TOKEN_NATIVE;
    if (!isNativeCall) {
        TAG_LOGI(AAFwkTag::ABILITYMGR, "not native call");
        return false;
    }
    AccessToken::NativeTokenInfo nativeTokenInfo;
    int32_t result = AccessToken::AccessTokenKit::GetNativeTokenInfo(tokenId, nativeTokenInfo);
    if (result == ERR_OK && nativeTokenInfo.processName == DMS_PROCESS_NAME) {
        TAG_LOGI(AAFwkTag::ABILITYMGR, "system ability call");
        return true;
    }
    return false;
}

void AbilityRecord::AddSystemAbilityCallerRecord(const sptr<IRemoteObject> &callerToken, int requestCode,
    std::string srcAbilityId)
{
    TAG_LOGI(AAFwkTag::ABILITYMGR, "add system ability caller record");
    std::shared_ptr<SystemAbilityCallerRecord> systemAbilityRecord =
        std::make_shared<SystemAbilityCallerRecord>(srcAbilityId, callerToken);
    auto isExist = [&srcAbilityId](const std::shared_ptr<CallerRecord> &callerRecord) {
        std::shared_ptr<SystemAbilityCallerRecord> saCaller = callerRecord->GetSaCaller();
        return (saCaller != nullptr && saCaller->GetSrcAbilityId() == srcAbilityId);
    };
    auto record = std::find_if(callerList_.begin(), callerList_.end(), isExist);
    if (record != callerList_.end()) {
        TAG_LOGI(AAFwkTag::ABILITYMGR, "find same system ability caller record");
        callerList_.erase(record);
    }
    callerList_.emplace_back(std::make_shared<CallerRecord>(requestCode, systemAbilityRecord));
    TAG_LOGI(AAFwkTag::ABILITYMGR, "add system ability record end");
}

void AbilityRecord::RecordSaCallerInfo(const Want &want)
{
    saCallerInfo_ = std::make_shared<CallerAbilityInfo>();
    saCallerInfo_->callerTokenId = want.GetIntParam(Want::PARAM_RESV_CALLER_TOKEN, 0);
    saCallerInfo_->callerUid =  want.GetIntParam(Want::PARAM_RESV_CALLER_UID, 0);
    saCallerInfo_->callerPid =  want.GetIntParam(Want::PARAM_RESV_CALLER_PID, 0);
    saCallerInfo_->callerNativeName = want.GetStringParam(Want::PARAM_RESV_CALLER_NATIVE_NAME);
}

std::list<std::shared_ptr<CallerRecord>> AbilityRecord::GetCallerRecordList() const
{
    return callerList_;
}

std::shared_ptr<AbilityRecord> AbilityRecord::GetCallerRecord() const
{
    if (callerList_.empty()) {
        return nullptr;
    }
    if (callerList_.back() == nullptr) {
        return nullptr;
    }
    return callerList_.back()->GetCaller();
}

std::shared_ptr<CallerAbilityInfo> AbilityRecord::GetCallerInfo() const
{
    if (callerList_.empty() || callerList_.back() == nullptr) {
        return saCallerInfo_;
    }
    return callerList_.back()->GetCallerInfo();
}

bool AbilityRecord::IsConnectListEmpty()
{
    std::lock_guard guard(connRecordListMutex_);
    return connRecordList_.empty();
}

size_t AbilityRecord::GetConnectedListSize()
{
    std::lock_guard guard(connRecordListMutex_);
    return std::count_if(connRecordList_.begin(), connRecordList_.end(), [](std::shared_ptr<ConnectionRecord> record) {
        return record && record->GetConnectState() == ConnectionState::CONNECTED;
    });
}

size_t AbilityRecord::GetConnectingListSize()
{
    std::lock_guard guard(connRecordListMutex_);
    return std::count_if(connRecordList_.begin(), connRecordList_.end(), [](std::shared_ptr<ConnectionRecord> record) {
        return record && record->GetConnectState() == ConnectionState::CONNECTING;
    });
}

std::shared_ptr<ConnectionRecord> AbilityRecord::GetConnectingRecord() const
{
    std::lock_guard guard(connRecordListMutex_);
    auto connect =
        std::find_if(connRecordList_.begin(), connRecordList_.end(), [](std::shared_ptr<ConnectionRecord> record) {
            return record->GetConnectState() == ConnectionState::CONNECTING;
        });
    return (connect != connRecordList_.end()) ? *connect : nullptr;
}

std::list<std::shared_ptr<ConnectionRecord>> AbilityRecord::GetConnectingRecordList()
{
    std::lock_guard guard(connRecordListMutex_);
    std::list<std::shared_ptr<ConnectionRecord>> connectingList;
    for (auto record : connRecordList_) {
        if (record && record->GetConnectState() == ConnectionState::CONNECTING) {
            connectingList.push_back(record);
        }
    }
    return connectingList;
}

uint32_t AbilityRecord::GetInProgressRecordCount()
{
    std::lock_guard guard(connRecordListMutex_);
    uint32_t count = 0;
    for (auto record : connRecordList_) {
        if (record && (record->GetConnectState() == ConnectionState::CONNECTING ||
            record->GetConnectState() == ConnectionState::CONNECTED)) {
            count++;
        }
    }
    return count;
}

std::shared_ptr<ConnectionRecord> AbilityRecord::GetDisconnectingRecord() const
{
    std::lock_guard guard(connRecordListMutex_);
    auto connect =
        std::find_if(connRecordList_.begin(), connRecordList_.end(), [](std::shared_ptr<ConnectionRecord> record) {
            return record->GetConnectState() == ConnectionState::DISCONNECTING;
        });
    return (connect != connRecordList_.end()) ? *connect : nullptr;
}

void AbilityRecord::GetAbilityTypeString(std::string &typeStr)
{
    AppExecFwk::AbilityType type = GetAbilityInfo().type;
    switch (type) {
#ifdef SUPPORT_GRAPHICS
        case AppExecFwk::AbilityType::PAGE: {
            typeStr = "PAGE";
            break;
        }
#endif
        case AppExecFwk::AbilityType::SERVICE: {
            typeStr = UIExtensionUtils::IsUIExtension(GetAbilityInfo().extensionAbilityType) ?
                "UIEXTENSION" : "SERVICE";
            break;
        }
        // for config.json type
        case AppExecFwk::AbilityType::DATA: {
            typeStr = "DATA";
            break;
        }
        default: {
            typeStr = "UNKNOWN";
            break;
        }
    }
}

std::string AbilityRecord::ConvertAbilityState(const AbilityState &state)
{
    return  StateUtils::StateToStrMap(state);
}

std::string AbilityRecord::ConvertAppState(const AppState &state)
{
    return StateUtils::AppStateToStrMap(state);
}

int AbilityRecord::ConvertLifeCycleToAbilityState(const AbilityLifeCycleState &state)
{
    return StateUtils::ConvertStateMap(state);
}

void AbilityRecord::Dump(std::vector<std::string> &info)
{
    std::string dumpInfo = "      AbilityRecord ID #" + std::to_string(recordId_);
    info.push_back(dumpInfo);
    dumpInfo = "        app name [" + GetAbilityInfo().applicationName + "]";
    info.push_back(dumpInfo);
    dumpInfo = "        main name [" + GetAbilityInfo().name + "]";
    info.push_back(dumpInfo);
    dumpInfo = "        bundle name [" + GetAbilityInfo().bundleName + "]";
    info.push_back(dumpInfo);
    std::string isKeepAlive = GetKeepAlive() ? "true" : "false";
    dumpInfo = "        isKeepAlive: " + isKeepAlive;
    info.push_back(dumpInfo);
    // get ability type(unknown/page/service/provider)
    std::string typeStr;
    GetAbilityTypeString(typeStr);
    dumpInfo = "        ability type [" + typeStr + "]";
    info.push_back(dumpInfo);
    std::shared_ptr<AbilityRecord> preAbility = GetPreAbilityRecord();
    if (preAbility == nullptr) {
        dumpInfo = "        previous ability app name [NULL]";
        dumpInfo.append("\n");
        dumpInfo += "        previous ability file name [NULL]";
    } else {
        dumpInfo =
            "        previous ability app name [" + preAbility->GetAbilityInfo().applicationName + "]";
        dumpInfo.append("\n");
        dumpInfo += "        previous ability file name [" + preAbility->GetAbilityInfo().name + "]";
    }
    info.push_back(dumpInfo);
    std::shared_ptr<AbilityRecord> nextAbility = GetNextAbilityRecord();
    if (nextAbility == nullptr) {
        dumpInfo = "        next ability app name [NULL]";
        dumpInfo.append("\n");
        dumpInfo += "        next ability file name [NULL]";
    } else {
        dumpInfo =
            "        next ability app name [" + nextAbility->GetAbilityInfo().applicationName + "]";
        dumpInfo.append("\n");
        dumpInfo += "        next ability main name [" + nextAbility->GetAbilityInfo().name + "]";
    }
    info.push_back(dumpInfo);
    dumpInfo = "        state #" + AbilityRecord::ConvertAbilityState(GetAbilityState()) + "  start time [" +
               std::to_string(startTime_) + "]";
    info.push_back(dumpInfo);
    dumpInfo = "        app state #" + AbilityRecord::ConvertAppState(appState_);
    info.push_back(dumpInfo);
    dumpInfo = "        ready #" + std::to_string(isReady_) + "  window attached #" +
               std::to_string(isWindowAttached_) + "  launcher #" + std::to_string(isLauncherAbility_);
    info.push_back(dumpInfo);

    if (isLauncherRoot_) {
        dumpInfo = "        can restart num #" + std::to_string(restartCount_);
        info.push_back(dumpInfo);
    }
}

void AbilityRecord::DumpUIExtensionRootHostInfo(std::vector<std::string> &info) const
{
    if (!UIExtensionUtils::IsUIExtension(GetAbilityInfo().extensionAbilityType)) {
        // Dump host info only for uiextension.
        return;
    }

    sptr<IRemoteObject> token = GetToken();
    if (token == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "null token");
        return;
    }

    UIExtensionHostInfo hostInfo;
    auto ret = IN_PROCESS_CALL(AAFwk::AbilityManagerClient::GetInstance()->GetUIExtensionRootHostInfo(token, hostInfo));
    if (ret != ERR_OK) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "failed: %{public}d", ret);
        return;
    }

    std::string dumpInfo = "      root host bundle name [" + hostInfo.elementName_.GetBundleName() + "]";
    info.emplace_back(dumpInfo);
    dumpInfo = "      root host module name [" + hostInfo.elementName_.GetModuleName() + "]";
    info.emplace_back(dumpInfo);
    dumpInfo = "      root host ability name [" + hostInfo.elementName_.GetAbilityName() + "]";
    info.emplace_back(dumpInfo);
}

void AbilityRecord::DumpAbilityState(
    std::vector<std::string> &info, bool isClient, const std::vector<std::string> &params)
{
    std::string dumpInfo = "      AbilityRecord ID #" + std::to_string(recordId_);
    info.push_back(dumpInfo);
    dumpInfo = "        app name [" + GetAbilityInfo().applicationName + "]";
    info.push_back(dumpInfo);
    dumpInfo = "        main name [" + GetAbilityInfo().name + "]";
    info.push_back(dumpInfo);
    dumpInfo = "        bundle name [" + GetAbilityInfo().bundleName + "]";
    info.push_back(dumpInfo);
    std::string typeStr;
    GetAbilityTypeString(typeStr);
    dumpInfo = "        ability type [" + typeStr + "]";
    info.push_back(dumpInfo);

    dumpInfo = "        state #" + AbilityRecord::ConvertAbilityState(GetAbilityState()) + "  start time [" +
               std::to_string(startTime_) + "]";
    info.push_back(dumpInfo);
    dumpInfo = "        app state #" + AbilityRecord::ConvertAppState(appState_);
    info.push_back(dumpInfo);
    dumpInfo = "        ready #" + std::to_string(isReady_) + "  window attached #" +
               std::to_string(isWindowAttached_) + "  launcher #" + std::to_string(isLauncherAbility_);
    info.push_back(dumpInfo);
    dumpInfo = "        callee connections: ";
    info.push_back(dumpInfo);
    if (callContainer_) {
        callContainer_->Dump(info);
    }

    std::string isKeepAlive = GetKeepAlive() ? "true" : "false";
    dumpInfo = "        isKeepAlive: " + isKeepAlive;
    info.push_back(dumpInfo);
    if (isLauncherRoot_) {
        dumpInfo = "        can restart num #" + std::to_string(restartCount_);
        info.push_back(dumpInfo);
    }

    auto missionAffinity = GetMissionAffinity();
    if (!missionAffinity.empty()) {
        dumpInfo = "        missionAffinity: " + missionAffinity;
        info.push_back(dumpInfo);
    }

    // add dump client info
    DumpClientInfo(info, params, isClient, params.empty());
}

void AbilityRecord::SetStartTime()
{
    if (startTime_ == 0) {
        startTime_ = AbilityUtil::SystemTimeMillis();
    }
}

int64_t AbilityRecord::GetStartTime() const
{
    return startTime_;
}

void AbilityRecord::DumpService(std::vector<std::string> &info, bool isClient) const
{
    std::vector<std::string> params;
    DumpService(info, params, isClient);
}

void AbilityRecord::DumpService(std::vector<std::string> &info, std::vector<std::string> &params, bool isClient) const
{
    info.emplace_back("      AbilityRecord ID #" + std::to_string(GetRecordId()) + "   state #" +
                      AbilityRecord::ConvertAbilityState(GetAbilityState()) + "   start time [" +
                      std::to_string(GetStartTime()) + "]");
    info.emplace_back("      main name [" + GetAbilityInfo().name + "]");
    info.emplace_back("      bundle name [" + GetAbilityInfo().bundleName + "]");
    bool isUIExtension = UIExtensionUtils::IsUIExtension(GetAbilityInfo().extensionAbilityType);
    if (isUIExtension) {
        info.emplace_back("      ability type [UIEXTENSION]");
    } else {
        if (GetAbilityInfo().extensionAbilityType == AppExecFwk::ExtensionAbilityType::UI_SERVICE) {
            info.emplace_back("      ability type [UI_SERVICE]");
            info.emplace_back("      windowConfig windowType [" +
                std::to_string(GetAbilityWindowConfig().windowType) + "]");
            info.emplace_back("      windowConfig windowId [" +
                std::to_string(GetAbilityWindowConfig().windowId) + "]");
        } else {
            info.emplace_back("      ability type [SERVICE]");
        }
    }
    info.emplace_back("      app state #" + AbilityRecord::ConvertAppState(appState_));

    std::string isKeepAlive = GetKeepAlive() ? "true" : "false";
    info.emplace_back("        isKeepAlive: " + isKeepAlive);
    if (isLauncherRoot_) {
        info.emplace_back("      can restart num #" + std::to_string(restartCount_));
    }
    decltype(connRecordList_) connRecordListCpy;
    {
        std::lock_guard guard(connRecordListMutex_);
        connRecordListCpy = connRecordList_;
    }

    info.emplace_back("      Connections: " + std::to_string(connRecordListCpy.size()));
    for (auto &&conn : connRecordListCpy) {
        if (conn) {
            conn->Dump(info);
        }
    }
    // add dump client info
    DumpClientInfo(info, params, isClient);
    DumpUIExtensionRootHostInfo(info);
    DumpUIExtensionPid(info, isUIExtension);
}

void AbilityRecord::DumpUIExtensionPid(std::vector<std::string> &info, bool isUIExtension) const
{
    if (!isUIExtension) {
        TAG_LOGD(AAFwkTag::ABILITYMGR, "Not ui extension type.");
        return;
    }

    auto appScheduler = DelayedSingleton<AppScheduler>::GetInstance();
    if (appScheduler == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "null appScheduler");
        return;
    }
    AppExecFwk::RunningProcessInfo processInfo;
    appScheduler->GetRunningProcessInfoByToken(GetToken(), processInfo);
    info.emplace_back("      pid: " + std::to_string(processInfo.pid_));
}

void AbilityRecord::RemoveAbilityDeathRecipient() const
{
    if (scheduler_ == nullptr) {
        TAG_LOGW(AAFwkTag::ABILITYMGR, "null scheduler_");
        return;
    }

    if (schedulerDeathRecipient_ == nullptr) {
        TAG_LOGW(AAFwkTag::ABILITYMGR, "null schedulerDeathRecipient_");
        return;
    }

    auto schedulerObject = scheduler_->AsObject();
    if (schedulerObject != nullptr) {
        TAG_LOGD(AAFwkTag::ABILITYMGR, "RemoveDeathRecipient");
        schedulerObject->RemoveDeathRecipient(schedulerDeathRecipient_);
    }
}

void AbilityRecord::OnSchedulerDied(const wptr<IRemoteObject> &remote)
{
    TAG_LOGD(AAFwkTag::ABILITYMGR, "called");
    std::lock_guard<ffrt::mutex> guard(lock_);
    CHECK_POINTER(scheduler_);

    auto object = remote.promote();
    CHECK_POINTER(object);

    if (object != scheduler_->AsObject()) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "ability died: scheduler not matches remote");
        return;
    }

    if (scheduler_ != nullptr && schedulerDeathRecipient_ != nullptr) {
        auto schedulerObject = scheduler_->AsObject();
        if (schedulerObject != nullptr) {
            schedulerObject->RemoveDeathRecipient(schedulerDeathRecipient_);
        }
    }
    CHECK_POINTER(lifecycleDeal_);
    lifecycleDeal_->SetScheduler(nullptr);
    isWindowAttached_ = false;

    auto handler = DelayedSingleton<AbilityManagerService>::GetInstance()->GetTaskHandler();
    CHECK_POINTER(handler);

    TAG_LOGI(AAFwkTag::ABILITYMGR, "Ability on scheduler died: '%{public}s'", abilityInfo_.name.c_str());
    auto task = [ability = shared_from_this()]() {
        DelayedSingleton<AbilityManagerService>::GetInstance()->OnAbilityDied(ability);
    };
    handler->SubmitTask(task, AAFwk::TaskAttribute{
        .taskName_ = "OnSchedulerDied",
        .timeoutMillis_ = SCHEDULER_DIED_TIMEOUT
    });
    auto uriTask = [want = GetWant(), ability = shared_from_this()]() {
        ability->SaveResultToCallers(-1, &want);
        ability->SendResultToCallers(true);
    };
    handler->SubmitTask(uriTask);
#ifdef SUPPORT_GRAPHICS
    NotifyAnimationAbilityDied();
#endif
#ifdef WITH_DLP
    HandleDlpClosed();
#endif // WITH_DLP
    NotifyRemoveShellProcess(CollaboratorType::RESERVE_TYPE);
    NotifyRemoveShellProcess(CollaboratorType::OTHERS_TYPE);
}

void AbilityRecord::OnProcessDied()
{
    std::lock_guard<ffrt::mutex> guard(lock_);
    if (!IsSceneBoard() && scheduler_ != nullptr) {
        TAG_LOGD(AAFwkTag::ABILITYMGR, "OnProcessDied: '%{public}s', attached.", abilityInfo_.name.c_str());
        return;
    }
    isWindowAttached_ = false;

    auto handler = DelayedSingleton<AbilityManagerService>::GetInstance()->GetTaskHandler();
    CHECK_POINTER(handler);

    TAG_LOGI(AAFwkTag::ABILITYMGR, "OnProcessDied: '%{public}s'", abilityInfo_.name.c_str());
    auto task = [ability = shared_from_this()]() {
        DelayedSingleton<AbilityManagerService>::GetInstance()->OnAbilityDied(ability);
    };
    if (IsSceneBoard()) {
        handler->SubmitTask(task, RESTART_SCENEBOARD_DELAY);
    } else {
        handler->SubmitTask(task);
    }
    auto uriTask = [want = GetWant(), ability = shared_from_this()]() {
        ability->SaveResultToCallers(-1, &want);
        ability->SendResultToCallers(true);
    };
    handler->SubmitTask(uriTask);
#ifdef SUPPORT_GRAPHICS
    NotifyAnimationAbilityDied();
#endif
#ifdef WITH_DLP
    HandleDlpClosed();
#endif // WITH_DLP
    NotifyRemoveShellProcess(CollaboratorType::RESERVE_TYPE);
    NotifyRemoveShellProcess(CollaboratorType::OTHERS_TYPE);
}

void AbilityRecord::NotifyAnimationAbilityDied()
{
    if (Rosen::SceneBoardJudgement::IsSceneBoardEnabled()) {
        return;
    }
    // notify winddow manager service the ability died
    if (missionId_ != -1) {
#ifdef SUPPORT_SCREEN
        if (GetWMSHandler()) {
            sptr<AbilityTransitionInfo> info = new AbilityTransitionInfo();
            SetAbilityTransitionInfo(info);
            TAG_LOGI(AAFwkTag::ABILITYMGR, "UIAbiltiy abnormal death");
            GetWMSHandler()->NotifyAnimationAbilityDied(info);
        }
#endif // SUPPORT_SCREEN
    }
}

void AbilityRecord::SetConnRemoteObject(const sptr<IRemoteObject> &remoteObject)
{
    connRemoteObject_ = remoteObject;
}

sptr<IRemoteObject> AbilityRecord::GetConnRemoteObject() const
{
    return connRemoteObject_;
}

void AbilityRecord::AddStartId()
{
    startId_++;
}
int AbilityRecord::GetStartId() const
{
    return startId_;
}

void AbilityRecord::SetIsUninstallAbility()
{
    isUninstall_ = true;
}

bool AbilityRecord::IsUninstallAbility() const
{
    return isUninstall_;
}

void AbilityRecord::SetLauncherRoot()
{
    isLauncherRoot_ = true;
}

bool AbilityRecord::IsLauncherRoot() const
{
    return isLauncherRoot_;
}

bool AbilityRecord::IsAbilityState(const AbilityState &state) const
{
    return (currentState_ == state);
}

bool AbilityRecord::IsActiveState() const
{
    return (IsAbilityState(AbilityState::ACTIVE) || IsAbilityState(AbilityState::ACTIVATING) ||
            IsAbilityState(AbilityState::INITIAL) || IsAbilityState(AbilityState::FOREGROUND) ||
            IsAbilityState(AbilityState::FOREGROUNDING));
}

void AbilityRecord::SendEvent(uint32_t msg, uint32_t timeOut, int32_t param, bool isExtension)
{
    auto handler = DelayedSingleton<AbilityManagerService>::GetInstance()->GetEventHandler();
    CHECK_POINTER(handler);
    param = (param == -1) ? recordId_ : param;
    auto eventWrap = EventWrap(msg, param, isExtension);
    eventWrap.SetTimeout(timeOut);
    if (!handler->SendEvent(eventWrap, timeOut, false)) {
        TAG_LOGW(AAFwkTag::ABILITYMGR, "failed: %{public}u, %{public}d", msg, param);
    }
}

void AbilityRecord::SetWant(const Want &want)
{
    std::lock_guard guard(wantLock_);
    if (abilityInfo_.type == AppExecFwk::AbilityType::PAGE && isLaunching_) {
        TAG_LOGW(AAFwkTag::ABILITYMGR, "uIAbility launching");
        return;
    }
    auto multiThread = want_.GetBoolParam(MULTI_THREAD, false);
    auto errorInfoEnhance = want_.GetBoolParam(ERROR_INFO_ENHANCE, false);
    want_.CloseAllFd();

    want_ = want;
    if (launchDebugInfo_.isDebugAppSet) {
        want_.SetParam(DEBUG_APP, launchDebugInfo_.debugApp);
    } else {
        want_.RemoveParam(DEBUG_APP);
    }
    if (launchDebugInfo_.isNativeDebugSet) {
        want_.SetParam(NATIVE_DEBUG, launchDebugInfo_.nativeDebug);
    } else {
        want_.RemoveParam(NATIVE_DEBUG);
    }
    if (launchDebugInfo_.isPerfCmdSet) {
        want_.SetParam(PERF_CMD, launchDebugInfo_.perfCmd);
    } else {
        want_.RemoveParam(PERF_CMD);
    }
    if (multiThread) {
        want_.SetParam(MULTI_THREAD, true);
    }
    if (errorInfoEnhance) {
        want_.SetParam(ERROR_INFO_ENHANCE, true);
    }
    if (want_.HasParameter(UISERVICEHOSTPROXY_KEY)) {
        want_.RemoveParam(UISERVICEHOSTPROXY_KEY);
    }
}

Want AbilityRecord::GetWant() const
{
    std::lock_guard guard(wantLock_);
    return want_;
}

void AbilityRecord::RemoveSignatureInfo()
{
    std::lock_guard guard(wantLock_);
    want_.RemoveParam(Want::PARAM_RESV_CALLER_APP_ID);
    want_.RemoveParam(Want::PARAM_RESV_CALLER_APP_IDENTIFIER);
}

AppExecFwk::ElementName AbilityRecord::GetElementName() const
{
    std::lock_guard guard(wantLock_);
    return want_.GetElement();
}

bool AbilityRecord::IsDebugApp() const
{
    std::lock_guard guard(wantLock_);
    return launchDebugInfo_.debugApp;
}

bool AbilityRecord::IsDebug() const
{
    std::lock_guard guard(wantLock_);
    if (launchDebugInfo_.debugApp || launchDebugInfo_.nativeDebug ||
        !launchDebugInfo_.perfCmd.empty() || isAttachDebug_ || isAssertDebug_) {
        TAG_LOGI(AAFwkTag::ABILITYMGR, "debug mode, no need to handle");
        return true;
    }
    return false;
}

void AbilityRecord::SetWindowMode(int32_t windowMode)
{
    std::lock_guard guard(wantLock_);
    want_.SetParam(Want::PARAM_RESV_WINDOW_MODE, windowMode);
}

void AbilityRecord::RemoveWindowMode()
{
    std::lock_guard guard(wantLock_);
    want_.RemoveParam(Want::PARAM_RESV_WINDOW_MODE);
}

void AbilityRecord::UpdateRecoveryInfo(bool hasRecoverInfo)
{
    if (hasRecoverInfo) {
        std::lock_guard guard(wantLock_);
        want_.SetParam(Want::PARAM_ABILITY_RECOVERY_RESTART, true);
        SetLaunchReason(LaunchReason::LAUNCHREASON_APP_RECOVERY);
    }
}

bool AbilityRecord::GetRecoveryInfo()
{
    std::lock_guard guard(wantLock_);
    return want_.GetBoolParam(Want::PARAM_ABILITY_RECOVERY_RESTART, false);
}

void AbilityRecord::SetStartSetting(const std::shared_ptr<AbilityStartSetting> &setting)
{
    lifeCycleStateInfo_.setting = setting;
}

std::shared_ptr<AbilityStartSetting> AbilityRecord::GetStartSetting() const
{
    return lifeCycleStateInfo_.setting;
}

void AbilityRecord::SetRestarting(const bool isRestart)
{
    isRestarting_ = isRestart;
    TAG_LOGD(AAFwkTag::ABILITYMGR, "SetRestarting: %{public}d", isRestarting_);
    if ((isLauncherRoot_ && IsLauncherAbility()) || GetKeepAlive()) {
        restartCount_ = isRestart ? (--restartCount_) : restartMax_;
        TAG_LOGD(AAFwkTag::ABILITYMGR, "root launcher or resident process's restart count: %{public}d", restartCount_);
    }
}

void AbilityRecord::SetRestarting(const bool isRestart, int32_t canRestartCount)
{
    isRestarting_ = isRestart;
    TAG_LOGD(
        AAFwkTag::ABILITYMGR, "SetRestarting: %{public}d, restart count: %{public}d", isRestarting_, canRestartCount);

    if ((isLauncherRoot_ && IsLauncherAbility()) || GetKeepAlive()) {
        restartCount_ = isRestart ? canRestartCount : restartMax_;
        TAG_LOGI(AAFwkTag::ABILITYMGR, "root launcher or resident process's restart count: %{public}d", restartCount_);
    }
}

int32_t AbilityRecord::GetRestartCount() const
{
    return restartCount_;
}

void AbilityRecord::SetRestartCount(int32_t restartCount)
{
    restartCount_ = restartCount;
}

bool AbilityRecord::IsRestarting() const
{
    return isRestarting_;
}

bool AbilityRecord::GetKeepAlive() const
{
    // Special ability
    std::vector<std::pair<std::string, std::string>> trustAbilities{
        { AbilityConfig::SCENEBOARD_BUNDLE_NAME, AbilityConfig::SCENEBOARD_ABILITY_NAME },
        { AbilityConfig::SYSTEM_UI_BUNDLE_NAME, AbilityConfig::SYSTEM_UI_ABILITY_NAME },
        { AbilityConfig::LAUNCHER_BUNDLE_NAME, AbilityConfig::LAUNCHER_ABILITY_NAME }
    };
    for (const auto &pair : trustAbilities) {
        if (pair.first == abilityInfo_.bundleName && pair.second == abilityInfo_.name) {
            return true;
        }
    }
    bool keepAliveEnable = keepAliveBundle_;
    AmsResidentProcessRdb::GetInstance().GetResidentProcessEnable(
        abilityInfo_.applicationInfo.bundleName, keepAliveEnable);
    return keepAliveEnable;
}

void AbilityRecord::SetLoading(bool status)
{
    isLoading_ = status;
}

bool AbilityRecord::IsLoading() const
{
    return isLoading_;
}

int64_t AbilityRecord::GetRestartTime()
{
    return restartTime_;
}

void AbilityRecord::SetRestartTime(const int64_t restartTime)
{
    restartTime_ = restartTime;
}

void AbilityRecord::SetAppState(const AppState &state)
{
    appState_ = state;
}

AppState AbilityRecord::GetAppState() const
{
    return appState_;
}

void AbilityRecord::SetLaunchReason(const LaunchReason &reason)
{
    if (isAppAutoStartup_) {
        lifeCycleStateInfo_.launchParam.launchReason = LaunchReason::LAUNCHREASON_AUTO_STARTUP;
        return;
    }
    lifeCycleStateInfo_.launchParam.launchReason = reason;
}

void AbilityRecord::SetLastExitReason(const ExitReason &exitReason)
{
    lifeCycleStateInfo_.launchParam.lastExitReason = CovertAppExitReasonToLastReason(exitReason.reason);
    lifeCycleStateInfo_.launchParam.lastExitMessage = exitReason.exitMsg;
}

LastExitReason AbilityRecord::CovertAppExitReasonToLastReason(const Reason exitReason)
{
    switch (exitReason) {
        case REASON_NORMAL:
            return LASTEXITREASON_NORMAL;
        case REASON_CPP_CRASH:
            return LASTEXITREASON_CPP_CRASH;
        case REASON_JS_ERROR:
            return LASTEXITREASON_JS_ERROR;
        case REASON_APP_FREEZE:
            return LASTEXITREASON_APP_FREEZE;
        case REASON_PERFORMANCE_CONTROL:
            return LASTEXITREASON_PERFORMANCE_CONTROL;
        case REASON_RESOURCE_CONTROL:
            return LASTEXITREASON_RESOURCE_CONTROL;
        case REASON_UPGRADE:
            return LASTEXITREASON_UPGRADE;
        case REASON_UNKNOWN:
        default:
            return LASTEXITREASON_UNKNOWN;
    }
}

void AbilityRecord::NotifyContinuationResult(int32_t result)
{
    TAG_LOGI(AAFwkTag::ABILITYMGR, "NotifyContinuationResult");
    CHECK_POINTER(lifecycleDeal_);

    lifecycleDeal_->NotifyContinuationResult(result);
}

void AbilityRecord::SetMissionId(int32_t missionId)
{
    std::lock_guard guard(wantLock_);
    missionId_ = missionId;
    want_.RemoveParam(KEY_MISSION_ID);
    want_.SetParam(KEY_MISSION_ID, missionId_);
}

void AbilityRecord::SetSessionInfo(sptr<SessionInfo> sessionInfo)
{
    std::lock_guard guard(sessionLock_);
    sessionInfo_ = sessionInfo;
}

sptr<SessionInfo> AbilityRecord::GetSessionInfo() const
{
    std::lock_guard guard(sessionLock_);
    return sessionInfo_;
}

void AbilityRecord::UpdateSessionInfo(sptr<IRemoteObject> sessionToken)
{
    {
        std::lock_guard guard(sessionLock_);
        if (sessionInfo_ == nullptr) {
            TAG_LOGW(AAFwkTag::ABILITYMGR, "null sessionInfo_");
            return;
        }
        sessionInfo_->sessionToken = sessionToken;
    }
    CHECK_POINTER(lifecycleDeal_);
    lifecycleDeal_->UpdateSessionToken(sessionToken);
}

void AbilityRecord::SetMinimizeReason(bool fromUser)
{
    minimizeReason_ = fromUser;
}

void AbilityRecord::SetSceneFlag(uint32_t sceneFlag)
{
    lifeCycleStateInfo_.sceneFlag = sceneFlag;
}

void AbilityRecord::SetAppIndex(const int32_t appIndex)
{
    appIndex_ = appIndex;
}

int32_t AbilityRecord::GetAppIndex() const
{
    return appIndex_;
}

void AbilityRecord::SetWantAppIndex(const int32_t appIndex)
{
    std::lock_guard guard(wantLock_);
    want_.SetParam(Want::PARAM_APP_CLONE_INDEX_KEY, appIndex);
}

int32_t AbilityRecord::GetWantAppIndex() const
{
    std::lock_guard guard(wantLock_);
    return want_.GetIntParam(Want::PARAM_APP_CLONE_INDEX_KEY, 0);
}

bool AbilityRecord::IsMinimizeFromUser() const
{
    return minimizeReason_;
}

void AbilityRecord::SetClearMissionFlag(bool clearMissionFlag)
{
    clearMissionFlag_= clearMissionFlag;
}

bool AbilityRecord::IsClearMissionFlag()
{
    return clearMissionFlag_;
}

int32_t AbilityRecord::GetMissionId() const
{
    return missionId_;
}

void AbilityRecord::SetSpecifiedFlag(const std::string &flag)
{
    specifiedFlag_ = flag;
}

std::string AbilityRecord::GetSpecifiedFlag() const
{
    return specifiedFlag_;
}

// new version  --start
bool AbilityRecord::IsStartedByCall() const
{
    return isStartedByCall_;
}

void AbilityRecord::SetStartedByCall(const bool isFlag)
{
    isStartedByCall_ = isFlag;
}

bool AbilityRecord::IsStartToBackground() const
{
    return isStartToBackground_;
}

void AbilityRecord::SetStartToBackground(const bool flag)
{
    isStartToBackground_ = flag;
}

bool AbilityRecord::IsStartToForeground() const
{
    return isStartToForeground_;
}

void AbilityRecord::SetStartToForeground(const bool flag)
{
    isStartToForeground_ = flag;
}

bool AbilityRecord::IsCallerSetProcess() const
{
    return isCallerSetProcess_.load();
}

void AbilityRecord::SetCallerSetProcess(const bool flag)
{
    isCallerSetProcess_.store(flag);
}

void AbilityRecord::CallRequest()
{
    CHECK_POINTER(scheduler_);
    // Async call request
    scheduler_->CallRequest();
}

bool AbilityRecord::CallRequestDone(const sptr<IRemoteObject> &callStub) const
{
    CHECK_POINTER_RETURN_BOOL(callContainer_);
    if (!callContainer_->CallRequestDone(callStub)) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "call failed");
        return false;
    }
    return true;
}

ResolveResultType AbilityRecord::Resolve(const AbilityRequest &abilityRequest)
{
    auto callback = abilityRequest.connect;
    if (abilityRequest.callType != AbilityCallType::CALL_REQUEST_TYPE || !callback) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "only callType can create call record");
        return ResolveResultType::NG_INNER_ERROR;
    }
    if (!callContainer_) {
        callContainer_ = std::make_shared<CallContainer>();
        if (!callContainer_) {
            TAG_LOGE(AAFwkTag::ABILITYMGR, "mark_shared error");
            return ResolveResultType::NG_INNER_ERROR;
        }
    }

    TAG_LOGD(AAFwkTag::ABILITYMGR, "create call record for this resolve. callerUid:%{public}d ,targetname:%{public}s",
        abilityRequest.callerUid,
        abilityRequest.abilityInfo.name.c_str());

    std::shared_ptr<CallRecord> callRecord = callContainer_->GetCallRecord(callback);
    if (!callRecord) {
        callRecord = CallRecord::CreateCallRecord(
            abilityRequest.callerUid, shared_from_this(), callback, abilityRequest.callerToken);
        if (!callRecord) {
            TAG_LOGE(AAFwkTag::ABILITYMGR, "mark_shared error");
            return ResolveResultType::NG_INNER_ERROR;
        }
    }

    callContainer_->AddCallRecord(callback, callRecord);

    if (callRecord->IsCallState(CallState::REQUESTED) && callRecord->GetCallStub()) {
        TAG_LOGD(AAFwkTag::ABILITYMGR, "this record has requested.");
        if (!callRecord->SchedulerConnectDone()) {
            TAG_LOGD(AAFwkTag::ABILITYMGR, "this callrecord has requested, but callback failed.");
            return ResolveResultType::NG_INNER_ERROR;
        }
        return ResolveResultType::OK_HAS_REMOTE_OBJ;
    }

    callRecord->SetCallState(CallState::REQUESTING);
    return ResolveResultType::OK_NO_REMOTE_OBJ;
}

bool AbilityRecord::ReleaseCall(const sptr<IAbilityConnection>& connect)
{
    TAG_LOGD(AAFwkTag::ABILITYMGR, "ability release call record by callback.");
    CHECK_POINTER_RETURN_BOOL(callContainer_);

    return callContainer_->RemoveCallRecord(connect);
}

bool AbilityRecord::IsExistConnection(const sptr<IAbilityConnection> &connect)
{
    TAG_LOGD(AAFwkTag::ABILITYMGR, "ability find call record by callback.");
    CHECK_POINTER_RETURN_BOOL(callContainer_);

    return callContainer_->IsExistConnection(connect);
}

bool AbilityRecord::IsNeedToCallRequest() const
{
    TAG_LOGD(AAFwkTag::ABILITYMGR, "ability release call record by callback.");
    if (callContainer_ == nullptr) {
        return false;
    }

    return callContainer_->IsNeedToCallRequest();
}

void AbilityRecord::ContinueAbility(const std::string& deviceId, uint32_t versionCode)
{
    TAG_LOGI(AAFwkTag::ABILITYMGR, "ContinueAbility");
    CHECK_POINTER(lifecycleDeal_);

    lifecycleDeal_->ContinueAbility(deviceId, versionCode);
}

void AbilityRecord::SetSwitchingPause(bool state)
{
    isSwitchingPause_ = state;
}

bool AbilityRecord::IsSwitchingPause()
{
    return isSwitchingPause_;
}

void AbilityRecord::SetOwnerMissionUserId(int32_t userId)
{
    ownerMissionUserId_ = userId;
}

int32_t AbilityRecord::GetOwnerMissionUserId()
{
    return ownerMissionUserId_;
}

void AbilityRecord::DumpClientInfo(std::vector<std::string> &info, const std::vector<std::string> &params,
    bool isClient, bool dumpConfig) const
{
    if (!scheduler_ || !isReady_) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "something nullptr.");
        return;
    }
    if (!isClient) {
        return;
    }
    std::unique_lock<ffrt::mutex> lock(dumpLock_);
    scheduler_->DumpAbilityInfo(params, info);

    TAG_LOGI(AAFwkTag::ABILITYMGR, "dump begin wait");
    isDumpTimeout_ = false;
    std::chrono::milliseconds timeout { DUMP_TIMEOUT_MULTIPLE };
    if (dumpCondition_.wait_for(lock, timeout) == ffrt::cv_status::timeout) {
        isDumpTimeout_ = true;
    }
    TAG_LOGI(AAFwkTag::ABILITYMGR, "dump done and begin parse");
    if (!isDumpTimeout_) {
        std::lock_guard<ffrt::mutex> infoLock(dumpInfoLock_);
        for (auto one : dumpInfos_) {
            info.emplace_back(one);
        }
    }

    if (!dumpConfig) {
        TAG_LOGI(AAFwkTag::ABILITYMGR, "not dumpConfig");
        return;
    }
    AppExecFwk::Configuration config;
    if (DelayedSingleton<AppScheduler>::GetInstance()->GetConfiguration(config) == ERR_OK) {
        info.emplace_back("          configuration: " + config.GetName());
    }
}

void AbilityRecord::DumpAbilityInfoDone(std::vector<std::string> &infos)
{
    TAG_LOGI(AAFwkTag::ABILITYMGR, "call");
    if (isDumpTimeout_) {
        TAG_LOGW(AAFwkTag::ABILITYMGR, "%{public}s, time out", __func__);
        return;
    }
    {
        std::lock_guard<ffrt::mutex> infoLock(dumpInfoLock_);
        dumpInfos_.clear();
        for (auto info : infos) {
            dumpInfos_.emplace_back(info);
        }
    }
    dumpCondition_.notify_all();
}

void AbilityRecord::GrantUriPermission(Want &want, std::string targetBundleName, bool isSandboxApp, uint32_t tokenId)
{
    // only for UIAbility and send result
    if (specifyTokenId_ > 0) {
        TAG_LOGI(AAFwkTag::ABILITYMGR, "specifyTokenId: %{public}u, cleaned", specifyTokenId_);
        tokenId = specifyTokenId_;
        specifyTokenId_ = 0;
    }
    // reject sandbox to grant uri permission by start ability
    if (!callerList_.empty() && callerList_.back()) {
        auto caller = callerList_.back()->GetCaller();
        if (caller && caller->appIndex_ > AbilityRuntime::GlobalConstant::MAX_APP_CLONE_INDEX) {
            TAG_LOGE(AAFwkTag::ABILITYMGR, "sandbox can not grant UriPermission");
            return;
        }
    }
    auto callerTokenId = tokenId > 0 ? tokenId :
        static_cast<uint32_t>(want.GetIntParam(Want::PARAM_RESV_CALLER_TOKEN, 0));
    TAG_LOGD(AAFwkTag::ABILITYMGR, "callerTokenId:%{public}u, tokenId:%{public}u", callerTokenId, tokenId);

    UriUtils::GetInstance().GrantUriPermission(want, targetBundleName, appIndex_, isSandboxApp,
        callerTokenId, collaboratorType_);
}

#ifdef WITH_DLP
void AbilityRecord::HandleDlpAttached()
{
    if (abilityInfo_.bundleName == DLP_BUNDLE_NAME) {
        DelayedSingleton<ConnectionStateManager>::GetInstance()->AddDlpManager(shared_from_this());
    }

    if (appIndex_ > 0) {
        DelayedSingleton<ConnectionStateManager>::GetInstance()->AddDlpAbility(shared_from_this());
    }
}

void AbilityRecord::HandleDlpClosed()
{
    if (abilityInfo_.bundleName == DLP_BUNDLE_NAME) {
        DelayedSingleton<ConnectionStateManager>::GetInstance()->RemoveDlpManager(shared_from_this());
    }

    if (appIndex_ > 0) {
        DelayedSingleton<ConnectionStateManager>::GetInstance()->RemoveDlpAbility(shared_from_this());
    }
}
#endif // WITH_DLP

void AbilityRecord::NotifyRemoveShellProcess(int32_t type)
{
    TAG_LOGD(AAFwkTag::ABILITYMGR, "type is : %{public}d", type);
    if (abilityInfo_.bundleName == AppUtils::GetInstance().GetBrokerDelegateBundleName()) {
        auto collaborator = DelayedSingleton<AbilityManagerService>::GetInstance()->GetCollaborator(type);
        if (collaborator == nullptr) {
            TAG_LOGE(AAFwkTag::ABILITYMGR, "null collaborator");
            return;
        }
        int ret = collaborator->NotifyRemoveShellProcess(pid_, SHELL_ASSISTANT_DIETYPE, SHELL_ASSISTANT_DIEREASON);
        TAG_LOGI(AAFwkTag::ABILITYMGR, "notify broker params pid: %{public}d", pid_);
        if (ret != ERR_OK) {
            TAG_LOGE(AAFwkTag::ABILITYMGR, "failed, err: %{public}d", ret);
        }
    }
}

void AbilityRecord::NotifyMissionBindPid()
{
    if (!Rosen::SceneBoardJudgement::IsSceneBoardEnabled()) {
        return;
    }
    auto sessionInfo = GetSessionInfo();
    if (sessionInfo == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "null sessionInfo");
        return;
    }
    int32_t persistentId = sessionInfo->persistentId;
    if (abilityInfo_.bundleName == AppUtils::GetInstance().GetBrokerDelegateBundleName()) {
        auto collaborator = DelayedSingleton<AbilityManagerService>::GetInstance()->GetCollaborator(
            CollaboratorType::RESERVE_TYPE);
        if (collaborator == nullptr) {
            TAG_LOGE(AAFwkTag::ABILITYMGR, "null collaborator");
            return;
        }
        collaborator->NotifyMissionBindPid(persistentId, pid_);
    }
}

int32_t AbilityRecord::GetCurrentAccountId() const
{
    std::vector<int32_t> osActiveAccountIds;
    ErrCode ret = DelayedSingleton<AppExecFwk::OsAccountManagerWrapper>::GetInstance()->
            QueryActiveOsAccountIds(osActiveAccountIds);
    if (ret != ERR_OK) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "queryActiveOsAccountIds failed");
        return DEFAULT_USER_ID;
    }
    if (osActiveAccountIds.empty()) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "empty QueryActiveOsAccountIds");
        return DEFAULT_USER_ID;
    }

    return osActiveAccountIds.front();
}

void AbilityRecord::SetPendingState(AbilityState state)
{
    pendingState_.store(state);
}

AbilityState AbilityRecord::GetPendingState() const
{
    return pendingState_.load();
}

bool AbilityRecord::IsNeedBackToOtherMissionStack()
{
    return isNeedBackToOtherMissionStack_;
}

void AbilityRecord::SetNeedBackToOtherMissionStack(bool isNeedBackToOtherMissionStack)
{
    isNeedBackToOtherMissionStack_ = isNeedBackToOtherMissionStack;
}

std::shared_ptr<AbilityRecord> AbilityRecord::GetOtherMissionStackAbilityRecord() const
{
    return otherMissionStackAbilityRecord_.lock();
}

void AbilityRecord::SetOtherMissionStackAbilityRecord(const std::shared_ptr<AbilityRecord> &abilityRecord)
{
    otherMissionStackAbilityRecord_ = abilityRecord;
}

int32_t AbilityRecord::GetCollaboratorType() const
{
    return collaboratorType_;
}

std::string AbilityRecord::GetMissionAffinity() const
{
    return missionAffinity_;
}

void AbilityRecord::SetLockedState(bool lockedState)
{
    lockedState_ = lockedState;
}

bool AbilityRecord::GetLockedState()
{
    return lockedState_;
}

void AbilityRecord::SetAttachDebug(const bool isAttachDebug)
{
    isAttachDebug_ = isAttachDebug;
}

void AbilityRecord::SetAssertDebug(bool isAssertDebug)
{
    isAssertDebug_ = isAssertDebug;
}

void AbilityRecord::AddAbilityWindowStateMap(uint64_t uiExtensionComponentId,
    AbilityWindowState abilityWindowState)
{
    abilityWindowStateMap_[uiExtensionComponentId] = abilityWindowState;
}

void AbilityRecord::RemoveAbilityWindowStateMap(uint64_t uiExtensionComponentId)
{
    if (abilityWindowStateMap_.find(uiExtensionComponentId) != abilityWindowStateMap_.end()) {
        abilityWindowStateMap_.erase(uiExtensionComponentId);
    }
}

bool AbilityRecord::IsAbilityWindowReady()
{
    for (auto &item:abilityWindowStateMap_) {
        if (item.second == AbilityWindowState::BACKGROUNDING ||
            item.second == AbilityWindowState::TERMINATING) {
            return false;
        }
    }
    return true;
}

void AbilityRecord::SetAbilityWindowState(const sptr<SessionInfo> &sessionInfo, WindowCommand winCmd, bool isFinished)
{
    if (sessionInfo == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "null sessionInfo");
        return;
    }
    if (isFinished) {
        if (winCmd == WIN_CMD_FOREGROUND) {
            AddAbilityWindowStateMap(sessionInfo->uiExtensionComponentId, AbilityWindowState::FOREGROUND);
        } else if (winCmd == WIN_CMD_BACKGROUND) {
            AddAbilityWindowStateMap(sessionInfo->uiExtensionComponentId, AbilityWindowState::BACKGROUND);
        } else if (winCmd == WIN_CMD_DESTROY) {
            RemoveAbilityWindowStateMap(sessionInfo->uiExtensionComponentId);
        }
    } else {
        if (winCmd == WIN_CMD_FOREGROUND) {
            AddAbilityWindowStateMap(sessionInfo->uiExtensionComponentId, AbilityWindowState::FOREGROUNDING);
        } else if (winCmd == WIN_CMD_BACKGROUND) {
            AddAbilityWindowStateMap(sessionInfo->uiExtensionComponentId, AbilityWindowState::BACKGROUNDING);
        } else if (winCmd == WIN_CMD_DESTROY) {
            AddAbilityWindowStateMap(sessionInfo->uiExtensionComponentId, AbilityWindowState::TERMINATING);
        }
    }
}

int32_t AbilityRecord::CreateModalUIExtension(const Want &want)
{
    TAG_LOGD(AAFwkTag::ABILITYMGR, "call");
    CHECK_POINTER_AND_RETURN(scheduler_, INNER_ERR);
    return scheduler_->CreateModalUIExtension(want);
}

void AbilityRecord::SetURI(const std::string &uri)
{
    uri_ = uri;
}

std::string AbilityRecord::GetURI() const
{
    if (uri_.empty()) {
        auto bundleName = abilityInfo_.bundleName;
        if (MultiInstanceUtils::IsMultiInstanceApp(abilityInfo_.applicationInfo)) {
            bundleName = bundleName + '-' + GetInstanceKey();
        } else if (AbilityRuntime::StartupUtil::IsSupportAppClone(abilityInfo_.extensionAbilityType)) {
            if (appIndex_ > 0) {
                bundleName = std::to_string(appIndex_) + bundleName;
            }
        }
        return AppExecFwk::ElementName(abilityInfo_.deviceId, bundleName,
            abilityInfo_.name, abilityInfo_.moduleName).GetURI();
    }
    return uri_;
}

void AbilityRecord::SetProcessName(const std::string &process)
{
    abilityInfo_.process = process;
}

std::string AbilityRecord::GetProcessName() const
{
    return abilityInfo_.process;
}

void AbilityRecord::SetCustomProcessFlag(const std::string &process)
{
    customProcessFlag_ = process;
}

std::string AbilityRecord::GetCustomProcessFlag() const
{
    return customProcessFlag_;
}

void AbilityRecord::SetUIExtensionAbilityId(const int32_t uiExtensionAbilityId)
{
    uiExtensionAbilityId_ = uiExtensionAbilityId;
}

int32_t AbilityRecord::GetUIExtensionAbilityId() const
{
    return uiExtensionAbilityId_;
}

bool AbilityRecord::BackgroundAbilityWindowDelayed()
{
    return backgroundAbilityWindowDelayed_.load();
}

void AbilityRecord::DoBackgroundAbilityWindowDelayed(bool needBackground)
{
    backgroundAbilityWindowDelayed_.store(needBackground);
}

bool AbilityRecord::IsSceneBoard() const
{
    return AbilityUtil::IsSceneBoard(abilityInfo_.bundleName, abilityInfo_.name);
}

void AbilityRecord::SetRestartAppFlag(bool isRestartApp)
{
    isRestartApp_ = isRestartApp;
}

bool AbilityRecord::GetRestartAppFlag() const
{
    return isRestartApp_;
}

void AbilityRecord::UpdateUIExtensionInfo(const WantParams &wantParams)
{
    if (!UIExtensionUtils::IsUIExtension(GetAbilityInfo().extensionAbilityType)) {
        return;
    }

    std::lock_guard guard(wantLock_);
    if (want_.HasParameter(UIEXTENSION_ABILITY_ID)) {
        want_.RemoveParam(UIEXTENSION_ABILITY_ID);
    }
    want_.SetParam(UIEXTENSION_ABILITY_ID, wantParams.GetIntParam(UIEXTENSION_ABILITY_ID, -1));

    if (want_.HasParameter(UIEXTENSION_ROOT_HOST_PID)) {
        want_.RemoveParam(UIEXTENSION_ROOT_HOST_PID);
    }
    want_.SetParam(UIEXTENSION_ROOT_HOST_PID, wantParams.GetIntParam(UIEXTENSION_ROOT_HOST_PID, -1));
}

void AbilityRecord::SetSpecifyTokenId(uint32_t specifyTokenId)
{
    specifyTokenId_ = specifyTokenId;
}

void AbilityRecord::SetDebugAppByWaitingDebugFlag()
{
    if (!(abilityInfo_.applicationInfo.debug &&
        abilityInfo_.applicationInfo.appProvisionType == APP_PROVISION_TYPE_DEBUG) ||
        !system::GetBoolParameter(DEVELOPER_MODE_STATE, false)) {
        TAG_LOGD(AAFwkTag::ABILITYMGR, "Not meeting the set debugging conditions.");
        return;
    }

    if (IN_PROCESS_CALL(DelayedSingleton<AppExecFwk::AppMgrClient>::GetInstance()->IsWaitingDebugApp(
        abilityInfo_.applicationInfo.bundleName))) {
        want_.SetParam(DEBUG_APP, true);
        launchDebugInfo_.isDebugAppSet = true;
        launchDebugInfo_.debugApp = true;
        IN_PROCESS_CALL_WITHOUT_RET(
            DelayedSingleton<AppExecFwk::AppMgrClient>::GetInstance()->ClearNonPersistWaitingDebugFlag());
    }
}

void AbilityRecord::SaveConnectWant(const Want &want)
{
    std::lock_guard guard(connectWantLock_);
    if (connectWant_ == nullptr) {
        connectWant_ = std::make_shared<Want>(want);
    }
}

void AbilityRecord::UpdateConnectWant()
{
    std::lock_guard guard(connectWantLock_);
    if (connectWant_ != nullptr) {
        SetWant(*connectWant_);
    }
}

void AbilityRecord::RemoveConnectWant()
{
    std::lock_guard guard(connectWantLock_);
    connectWant_.reset();
}

void AbilityRecord::UpdateDmsCallerInfo(Want &want)
{
    if (want.GetIntParam(Want::PARAM_RESV_CALLER_UID, 0) != DMS_UID) {
        return;
    }
    want.SetParam(Want::PARAM_RESV_CALLER_TOKEN, -1);
    want.SetParam(Want::PARAM_RESV_CALLER_UID, -1);
    want.SetParam(Want::PARAM_RESV_CALLER_PID, -1);

    want.SetParam(Want::PARAM_RESV_CALLER_BUNDLE_NAME, want.GetStringParam(DMS_CALLER_BUNDLE_NAME));
    want.RemoveParam(DMS_CALLER_BUNDLE_NAME);
    want.SetParam(Want::PARAM_RESV_CALLER_ABILITY_NAME, want.GetStringParam(DMS_CALLER_ABILITY_NAME));
    want.RemoveParam(DMS_CALLER_ABILITY_NAME);
    want.SetParam(Want::PARAM_RESV_CALLER_NATIVE_NAME, want.GetStringParam(DMS_CALLER_NATIVE_NAME));
    want.RemoveParam(DMS_CALLER_NATIVE_NAME);
    want.SetParam(Want::PARAM_RESV_CALLER_APP_ID, want.GetStringParam(DMS_CALLER_APP_ID));
    want.RemoveParam(DMS_CALLER_APP_ID);
    want.SetParam(Want::PARAM_RESV_CALLER_APP_IDENTIFIER, want.GetStringParam(DMS_CALLER_APP_IDENTIFIER));
    want.RemoveParam(DMS_CALLER_APP_IDENTIFIER);
}

void AbilityRecord::SetDebugUIExtension()
{
    if (!UIExtensionUtils::IsUIExtension(GetAbilityInfo().extensionAbilityType)) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "Not UIExtension");
        return;
    }
    std::lock_guard guard(wantLock_);
    want_.SetParam(DEBUG_APP, true);
    launchDebugInfo_.isDebugAppSet = true;
    launchDebugInfo_.debugApp = true;
}
}  // namespace AAFwk
}  // namespace OHOS
