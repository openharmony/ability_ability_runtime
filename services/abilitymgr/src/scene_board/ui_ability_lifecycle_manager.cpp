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

#include "scene_board/ui_ability_lifecycle_manager.h"

#include "ability_manager_service.h"
#include "ability_permission_util.h"
#include "ability_record_death_manager.h"
#include "appfreeze_manager.h"
#include "app_exit_reason_data_manager.h"
#include "app_mgr_util.h"
#include "app_utils.h"
#include "ffrt.h"
#include "global_constant.h"
#include "hitrace_meter.h"
#include "permission_constants.h"
#include "process_options.h"
#include "server_constant.h"
#include "start_window_option.h"
#include "scene_board/status_bar_delegate_manager.h"
#include "session_manager_lite.h"
#include "session/host/include/zidl/session_interface.h"
#include "startup_util.h"
#include "ui_extension_utils.h"
#include "ability_stage_constant.h"
#ifdef SUPPORT_GRAPHICS
#include "ability_first_frame_state_observer_manager.h"
#endif
#include "hidden_start_observer_manager.h"

namespace OHOS {
using AbilityRuntime::FreezeUtil;
using namespace AbilityRuntime::ServerConstant;
namespace AAFwk {
namespace {
constexpr const char* SEPARATOR = ":";
constexpr const char* PARAM_MISSION_AFFINITY_KEY = "ohos.anco.param.missionAffinity";
constexpr const char* DMS_SRC_NETWORK_ID = "dmsSrcNetworkId";
constexpr const char* DMS_MISSION_ID = "dmsMissionId";
constexpr int DEFAULT_DMS_MISSION_ID = -1;
constexpr const char* PARAM_SPECIFIED_PROCESS_FLAG = "ohoSpecifiedProcessFlag";
constexpr const char* DMS_PROCESS_NAME = "distributedsched";
constexpr const char* DMS_PERSISTENT_ID = "ohos.dms.persistentId";
constexpr const char* IS_SHELL_CALL = "isShellCall";
#ifdef SUPPORT_ASAN
constexpr int KILL_TIMEOUT_MULTIPLE = 45;
#else
constexpr int KILL_TIMEOUT_MULTIPLE = 3;
#endif
constexpr int32_t DEFAULT_USER_ID = 0;
constexpr int32_t MAX_FIND_UIEXTENSION_CALLER_TIMES = 10;
constexpr int32_t START_UI_ABILITY_PER_SECOND_UPPER_LIMIT = 20;
constexpr int32_t API20 = 20;
constexpr int32_t API_VERSION_MOD = 100;
constexpr const char* IS_CALLING_FROM_DMS = "supportCollaborativeCallingFromDmsInAAFwk";
constexpr int REMOVE_STARTING_BUNDLE_TIMEOUT_MICRO_SECONDS = 5000000; // 5s

FreezeUtil::TimeoutState MsgId2State(uint32_t msgId)
{
    if (msgId == AbilityManagerService::LOAD_TIMEOUT_MSG) {
        return FreezeUtil::TimeoutState::LOAD;
    } else if (msgId == AbilityManagerService::FOREGROUND_TIMEOUT_MSG) {
        return FreezeUtil::TimeoutState::FOREGROUND;
    } else if (msgId == AbilityManagerService::BACKGROUND_TIMEOUT_MSG) {
        return FreezeUtil::TimeoutState::BACKGROUND;
    }
    return FreezeUtil::TimeoutState::UNKNOWN;
}

auto g_deleteLifecycleEventTask = [](const sptr<Token> &token) {
    CHECK_POINTER_LOG(token, "token is nullptr.");
    FreezeUtil::GetInstance().DeleteLifecycleEvent(token->AsObject());
};

bool CompareTwoRequest(const AbilityRequest &left, const AbilityRequest &right)
{
    int32_t leftIndex = 0;
    (void)AbilityRuntime::StartupUtil::GetAppIndex(left.want, leftIndex);
    int32_t rightIndex = 0;
    (void)AbilityRuntime::StartupUtil::GetAppIndex(right.want, rightIndex);

    auto LeftInstanceKey = left.want.GetStringParam(Want::APP_INSTANCE_KEY);
    auto RightInstanceKey = right.want.GetStringParam(Want::APP_INSTANCE_KEY);

    return leftIndex == rightIndex && LeftInstanceKey == RightInstanceKey &&
        left.abilityInfo.name == right.abilityInfo.name &&
        left.abilityInfo.bundleName == right.abilityInfo.bundleName &&
        left.abilityInfo.moduleName == right.abilityInfo.moduleName;
}
}

UIAbilityLifecycleManager::UIAbilityLifecycleManager(int32_t userId): userId_(userId) {}

bool UIAbilityLifecycleManager::ProcessColdStartBranch(AbilityRequest &abilityRequest, sptr<SessionInfo> sessionInfo,
    std::shared_ptr<AbilityRecord> uiAbilityRecord, bool isColdStart)
{
    if (isColdStart && uiAbilityRecord->IsHook()) {
        auto nextRequest = PopAndGetNextSpecified(sessionInfo->requestId);
        if (nextRequest) {
            TaskHandlerWrap::GetFfrtHandler()->SubmitTask([nextRequest, pThis = shared_from_this()]() {
                std::lock_guard lock(pThis->sessionLock_);
                pThis->StartSpecifiedRequest(*nextRequest);
                });
        }
        return false;
    }
    AddCallerRecord(abilityRequest, sessionInfo, uiAbilityRecord);
    uiAbilityRecord->SetPendingState(AbilityState::FOREGROUND);
    return true;
}

bool UIAbilityLifecycleManager::IsBundleStarting(pid_t pid)
{
    std::lock_guard<std::mutex> guard(startingPidsMutex_);
    for (auto iter = startingPids_.begin(); iter != startingPids_.end(); iter++) {
        if (*iter == pid) {
            return true;
        }
    }
    TAG_LOGW(AAFwkTag::ABILITYMGR, "not found");
    return false;
}

void UIAbilityLifecycleManager::AddStartingPid(pid_t pid)
{
    if (IsBundleStarting(pid)) {
        TAG_LOGI(AAFwkTag::ABILITYMGR, "%{public}d already exists", pid);
        return;
    }
    {
        std::lock_guard<std::mutex> guard(startingPidsMutex_);
        startingPids_.push_back(pid);
    }
    ffrt::task_attr attr;
    attr.delay(REMOVE_STARTING_BUNDLE_TIMEOUT_MICRO_SECONDS);
    std::weak_ptr<UIAbilityLifecycleManager> weakPtr = shared_from_this();
    ffrt::submit([weakPtr, pid]() {
        auto uiAbilityManager = weakPtr.lock();
        if (uiAbilityManager == nullptr) {
            TAG_LOGE(AAFwkTag::ABILITYMGR, "null uiAbilityManager");
            return;
        }
        uiAbilityManager->RemoveStartingPid(pid);
        }, attr);
}

void UIAbilityLifecycleManager::RemoveStartingPid(pid_t pid)
{
    std::lock_guard<std::mutex> guard(startingPidsMutex_);
    for (auto iter = startingPids_.begin(); iter != startingPids_.end(); iter++) {
        if (*iter == pid) {
            startingPids_.erase(iter);
            return;
        }
    }
    TAG_LOGW(AAFwkTag::ABILITYMGR, "%{public}d not found", pid);
}

void UIAbilityLifecycleManager::RecordPidKilling(pid_t pid, const std::string &reason)
{
    std::lock_guard<ffrt::mutex> guard(sessionLock_);
    for (const auto& [first, second] : sessionAbilityMap_) {
        if (second && pid == second->GetPid()) {
            second->SetKillReason(reason);
        }
    }
}

void UIAbilityLifecycleManager::MarkStartingFlag(const AbilityRequest &abilityRequest)
{
    for (auto iter = sessionAbilityMap_.begin(); iter != sessionAbilityMap_.end(); iter++) {
        if (iter->second == nullptr || iter->second->GetPid() <= 0 ||
            iter->second->GetAbilityInfo().bundleName != abilityRequest.abilityInfo.bundleName) {
            continue;
        }
        AddStartingPid(iter->second->GetPid());
    }
}

int UIAbilityLifecycleManager::StartUIAbility(AbilityRequest &abilityRequest, sptr<SessionInfo> sessionInfo,
    uint32_t sceneFlag, bool &isColdStart)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    std::lock_guard<ffrt::mutex> guard(sessionLock_);
    if (!CheckSessionInfo(sessionInfo)) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "sessionInfo invalid");
        return ERR_INVALID_VALUE;
    }
    auto isCallBySCB = sessionInfo->want.GetBoolParam(ServerConstant::IS_CALL_BY_SCB, true);
    sessionInfo->want.RemoveParam(ServerConstant::IS_CALL_BY_SCB);
    TAG_LOGI(AAFwkTag::ABILITYMGR, "StartUIAbility session:%{public}d. bundle:%{public}s, ability:%{public}s, "
        "instanceKey:%{public}s, requestId: %{public}d, isCallBySCB: %{public}d, reuseDelegator: %{public}d",
        sessionInfo->persistentId, abilityRequest.abilityInfo.bundleName.c_str(),
        abilityRequest.abilityInfo.name.c_str(), sessionInfo->instanceKey.c_str(),
        sessionInfo->requestId, isCallBySCB, sessionInfo->reuseDelegatorWindow);
    RemoveAbilityRequest(sessionInfo->requestId);
    abilityRequest.sessionInfo = sessionInfo;
    auto uiAbilityRecord = GenerateAbilityRecord(abilityRequest, sessionInfo, isColdStart);
    CHECK_POINTER_AND_RETURN(uiAbilityRecord, ERR_INVALID_VALUE);
    MarkStartingFlag(abilityRequest);
    if (sessionInfo->reuseDelegatorWindow) {
        uiAbilityRecord->lifeCycleStateInfo_.sceneFlagBak = sceneFlag;
        return ERR_OK;
    }
    auto want = uiAbilityRecord->GetWant();
    if (want.GetBoolParam(IS_CALLING_FROM_DMS, false) && !(sessionInfo->isNewWant)) {
        want.RemoveParam(IS_CALLING_FROM_DMS);
        uiAbilityRecord->SetWant(want);
    }
    TAG_LOGD(AAFwkTag::ABILITYMGR, "StartUIAbility");
    uiAbilityRecord->SetSpecifyTokenId(abilityRequest.specifyTokenId);
    UpdateAbilityRecordLaunchReason(abilityRequest, uiAbilityRecord);
    NotifyAbilityToken(uiAbilityRecord->GetToken(), abilityRequest);
    if (HandleStartSpecifiedCold(abilityRequest, sessionInfo, sceneFlag) &&
        ProcessColdStartBranch(abilityRequest, sessionInfo, uiAbilityRecord, isColdStart)) {
        return ERR_OK;
    }

    if (uiAbilityRecord->GetPendingState() != AbilityState::INITIAL) {
        TAG_LOGI(AAFwkTag::ABILITYMGR, "pending state: FOREGROUND/ BACKGROUND, dropped");
        uiAbilityRecord->SetPendingState(AbilityState::FOREGROUND);
        return ERR_OK;
    } else {
        TAG_LOGD(AAFwkTag::ABILITYMGR, "pending state is not FOREGROUND or BACKGROUND.");
        uiAbilityRecord->SetPendingState(AbilityState::FOREGROUND);
    }

    if (!uiAbilityRecord->IsReady() || sessionInfo->isNewWant) {
        AddCallerRecord(abilityRequest, sessionInfo, uiAbilityRecord);
    }
    auto isShellCall = abilityRequest.want.GetBoolParam(IS_SHELL_CALL, false);
    uint32_t callerTokenId = static_cast<uint32_t>(abilityRequest.want.GetIntParam(Want::PARAM_RESV_CALLER_TOKEN, 0));
    uiAbilityRecord->ProcessForegroundAbility(callerTokenId, sceneFlag, isShellCall);
    CheckSpecified(sessionInfo->requestId, uiAbilityRecord);
    SendKeyEvent(abilityRequest);
    return ERR_OK;
}

std::shared_ptr<AbilityRecord> UIAbilityLifecycleManager::GenerateAbilityRecord(AbilityRequest &abilityRequest,
    sptr<SessionInfo> sessionInfo, bool &isColdStart)
{
    std::shared_ptr<AbilityRecord> uiAbilityRecord = nullptr;
    auto iter = sessionAbilityMap_.find(sessionInfo->persistentId);
    bool isLowMemKill = (iter != sessionAbilityMap_.end()) &&
        (iter->second != nullptr) && (iter->second->GetKillReason() == GlobalConstant::LOW_MEMORY_KILL);
    if (iter == sessionAbilityMap_.end() || isLowMemKill) {
        uiAbilityRecord = FindRecordFromTmpMap(abilityRequest);
        auto abilityInfo = abilityRequest.abilityInfo;
        if (uiAbilityRecord == nullptr) {
            uiAbilityRecord = CreateAbilityRecord(abilityRequest, sessionInfo);
            bool isUIAbility = (abilityInfo.type == AppExecFwk::AbilityType::PAGE && abilityInfo.isStageBasedModel);
            abilityRequest.want.SetParam(Want::APP_INSTANCE_KEY, sessionInfo->instanceKey);
            auto abilityRecord = FindRecordFromSessionMap(abilityRequest);
            if (isUIAbility && IsHookModule(abilityRequest) && abilityRecord == nullptr &&
                (sessionInfo->processOptions == nullptr ||
                sessionInfo->processOptions->startupVisibility == StartupVisibility::STARTUP_SHOW)) {
                TAG_LOGI(AAFwkTag::ABILITYMGR, "only first need call SetIsHook");
                uiAbilityRecord->SetIsHook(true);
                uiAbilityRecord->SetLaunchWant(std::make_shared<Want>(abilityRequest.want));
            }
        } else {
            uiAbilityRecord->SetInstanceKey(sessionInfo->instanceKey);
            uiAbilityRecord->SetSessionInfo(sessionInfo);
        }
        isColdStart = true;
        UpdateProcessName(abilityRequest, uiAbilityRecord);
        if (isSCBRecovery_) {
            coldStartInSCBRecovery_.insert(sessionInfo->persistentId);
        }
        if (abilityInfo.applicationInfo.multiAppMode.multiAppModeType == AppExecFwk::MultiAppModeType::MULTI_INSTANCE &&
            abilityInfo.launchMode == AppExecFwk::LaunchMode::SPECIFIED) {
            auto appMgr = AppMgrUtil::GetAppMgr();
            if (appMgr == nullptr) {
                TAG_LOGW(AAFwkTag::ABILITYMGR, "AppMgrUtil::GetAppMgr failed");
                return uiAbilityRecord;
            }
            IN_PROCESS_CALL_WITHOUT_RET(
                appMgr->UpdateInstanceKeyBySpecifiedId(sessionInfo->requestId, sessionInfo->instanceKey));
        }
        MoreAbilityNumbersSendEventInfo(
            abilityRequest.userId, abilityInfo.bundleName, abilityInfo.name, abilityInfo.moduleName);
        if (isLowMemKill) {
            TAG_LOGI(AAFwkTag::ABILITYMGR, "killed by low-mem, created a new record, "
                "replacing old record id=%{public}s, new record id=%{public}s",
                std::to_string(sessionAbilityMap_[sessionInfo->persistentId]->GetAbilityRecordId()).c_str(),
                std::to_string(uiAbilityRecord->GetAbilityRecordId()).c_str());
            lowMemKillAbilityMap_.emplace(sessionInfo->persistentId, sessionAbilityMap_[sessionInfo->persistentId]);
            sessionAbilityMap_[sessionInfo->persistentId] = uiAbilityRecord;
        } else {
            sessionAbilityMap_.emplace(sessionInfo->persistentId, uiAbilityRecord);
        }
    } else {
        TAG_LOGI(AAFwkTag::ABILITYMGR, "NewWant:%{public}d", sessionInfo->isNewWant);
        uiAbilityRecord = iter->second;
        if (uiAbilityRecord == nullptr || uiAbilityRecord->GetSessionInfo() == nullptr) {
            TAG_LOGE(AAFwkTag::ABILITYMGR, "uiAbilityRecord invalid");
            return nullptr;
        }
        if (sessionInfo->sessionToken != uiAbilityRecord->GetSessionInfo()->sessionToken) {
            TAG_LOGE(AAFwkTag::ABILITYMGR, "sessionToken invalid");
            return nullptr;
        }
        abilityRequest.want.RemoveParam(Want::PARAMS_REAL_CALLER_KEY);
        auto appMgr = AppMgrUtil::GetAppMgr();
        if (appMgr != nullptr && sessionInfo->reuseDelegatorWindow) {
            auto ret = IN_PROCESS_CALL(appMgr->LaunchAbility(uiAbilityRecord->GetToken()));
            sessionInfo->want.CloseAllFd();
            if (ret == ERR_OK) {
                uiAbilityRecord->SetIsNewWant(false);
                return uiAbilityRecord;
            }
            return nullptr;
        }
        uiAbilityRecord->SetIsNewWant(sessionInfo->isNewWant);
        if (sessionInfo->isNewWant) {
            uiAbilityRecord->SetWant(abilityRequest.want);
            uiAbilityRecord->GetSessionInfo()->want.RemoveAllFd();
        } else {
            sessionInfo->want.CloseAllFd();
        }
    }
    return uiAbilityRecord;
}

std::shared_ptr<AbilityRecord> UIAbilityLifecycleManager::FindRecordFromTmpMap(
    const AbilityRequest &abilityRequest)
{
    int32_t appIndex = 0;
    (void)AbilityRuntime::StartupUtil::GetAppIndex(abilityRequest.want, appIndex);
    auto instanceKey = abilityRequest.want.GetStringParam(Want::APP_INSTANCE_KEY);
    for (const auto &[recordId, abilityRecord] : tmpAbilityMap_) {
        if (abilityRecord) {
            const auto &info = abilityRecord->GetAbilityInfo();
            if (info.name == abilityRequest.abilityInfo.name &&
                info.bundleName == abilityRequest.abilityInfo.bundleName &&
                info.moduleName == abilityRequest.abilityInfo.moduleName &&
                appIndex == abilityRecord->GetAppIndex() && instanceKey == abilityRecord->GetInstanceKey()) {
                return abilityRecord;
            }
        }
    }
    return nullptr;
}

bool UIAbilityLifecycleManager::CheckSessionInfo(sptr<SessionInfo> sessionInfo) const
{
    if (sessionInfo == nullptr || sessionInfo->sessionToken == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "sessionInfo invalid");
        return false;
    }
    auto sessionToken = iface_cast<Rosen::ISession>(sessionInfo->sessionToken);
    CHECK_POINTER_AND_RETURN(sessionToken, false);
    auto descriptor = Str16ToStr8(sessionToken->GetDescriptor());
    if (descriptor != "OHOS.ISession") {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "token's Descriptor: %{public}s", descriptor.c_str());
        return false;
    }
    std::string callerKey = sessionInfo->want.GetStringParam(Want::PARAMS_REAL_CALLER_KEY);
    bool isCallerKilling = IN_PROCESS_CALL(DelayedSingleton<AppScheduler>::GetInstance()->IsCallerKilling(callerKey));
    if (isCallerKilling) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "caller is killing");
        return false;
    }
    return true;
}

std::shared_ptr<AbilityRecord> UIAbilityLifecycleManager::CreateAbilityRecord(AbilityRequest &abilityRequest,
    sptr<SessionInfo> sessionInfo) const
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    TAG_LOGD(AAFwkTag::ABILITYMGR, "Create ability record.");
    if (sessionInfo->startSetting != nullptr) {
        TAG_LOGD(AAFwkTag::ABILITYMGR, "startSetting is valid.");
        abilityRequest.startSetting = sessionInfo->startSetting;
    }
    auto uiAbilityRecord = AbilityRecord::CreateAbilityRecord(abilityRequest);
    if (uiAbilityRecord == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "uiAbilityRecord invalid");
        return nullptr;
    }
    TAG_LOGD(AAFwkTag::ABILITYMGR, "user id: %{public}d.", userId_);
    uiAbilityRecord->SetOwnerMissionUserId(userId_);
    SetReceiverInfo(abilityRequest, uiAbilityRecord);
    return uiAbilityRecord;
}

void UIAbilityLifecycleManager::AddCallerRecord(AbilityRequest &abilityRequest, sptr<SessionInfo> sessionInfo,
    std::shared_ptr<AbilityRecord> uiAbilityRecord) const
{
    if (sessionInfo == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "sessionInfo invalid");
        return;
    }
    CHECK_POINTER(uiAbilityRecord);
    std::string srcAbilityId = "";
    if (abilityRequest.want.GetBoolParam(Want::PARAM_RESV_FOR_RESULT, false)) {
        std::string srcDeviceId = abilityRequest.want.GetStringParam(DMS_SRC_NETWORK_ID);
        int missionId = abilityRequest.want.GetIntParam(DMS_MISSION_ID, DEFAULT_DMS_MISSION_ID);
        TAG_LOGD(AAFwkTag::ABILITYMGR, "Get srcNetWorkId = %{public}s, missionId = %{public}d", srcDeviceId.c_str(),
            missionId);
        Want *newWant = const_cast<Want*>(&abilityRequest.want);
        newWant->RemoveParam(DMS_SRC_NETWORK_ID);
        newWant->RemoveParam(DMS_MISSION_ID);
        newWant->RemoveParam(Want::PARAM_RESV_FOR_RESULT);
        srcAbilityId = srcDeviceId + "_" + std::to_string(missionId);
    }
    uiAbilityRecord->AddCallerRecord(sessionInfo->callerToken,
        sessionInfo->requestCode, abilityRequest.want, srcAbilityId, sessionInfo->callingTokenId);
}

void UIAbilityLifecycleManager::CheckSpecified(int32_t requestId, std::shared_ptr<AbilityRecord> uiAbilityRecord)
{
    auto iter = specifiedFlagMap_.find(requestId);
    if (iter != specifiedFlagMap_.end()) {
        UpdateSpecifiedFlag(uiAbilityRecord, iter->second);
        uiAbilityRecord->SetSpecifiedFlag(iter->second);
        specifiedFlagMap_.erase(iter);
    }
}

void UIAbilityLifecycleManager::SendKeyEvent(const AbilityRequest &abilityRequest) const
{
    if (abilityRequest.abilityInfo.visible == false) {
        EventInfo eventInfo;
        eventInfo.abilityName = abilityRequest.abilityInfo.name;
        eventInfo.bundleName = abilityRequest.abilityInfo.bundleName;
        eventInfo.moduleName = abilityRequest.abilityInfo.moduleName;
        EventReport::SendKeyEvent(EventName::START_PRIVATE_ABILITY, HiSysEventType::BEHAVIOR, eventInfo);
    }
}

int UIAbilityLifecycleManager::AttachAbilityThread(const sptr<IAbilityScheduler> &scheduler,
    const sptr<IRemoteObject> &token)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    if (!IsContainsAbility(token)) {
        TAG_LOGW(AAFwkTag::ABILITYMGR, "Not in running list");
        return ERR_INVALID_VALUE;
    }
    auto&& abilityRecord = Token::GetAbilityRecordByToken(token);
    CHECK_POINTER_AND_RETURN(abilityRecord, ERR_INVALID_VALUE);
    abilityRecord->SetPid(IPCSkeleton::GetCallingPid());
    int32_t processAttachResult = DoProcessAttachment(abilityRecord);

    std::lock_guard<ffrt::mutex> guard(sessionLock_);
    TAG_LOGI(AAFwkTag::ABILITYMGR, "lifecycle name: %{public}s", abilityRecord->GetAbilityInfo().name.c_str());
    SetLastExitReason(abilityRecord);

    auto handler = DelayedSingleton<AbilityManagerService>::GetInstance()->GetEventHandler();
    CHECK_POINTER_AND_RETURN_LOG(handler, ERR_INVALID_VALUE, "Fail to get AbilityEventHandler.");
    abilityRecord->RemoveLoadTimeoutTask();
    abilityRecord->SetLoading(false);
    FreezeUtil::GetInstance().DeleteLifecycleEvent(token);

    abilityRecord->SetScheduler(scheduler);
    if (processAttachResult != ERR_OK) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "process attachment failed, close ability");
        TerminateSession(abilityRecord);
        return ERR_INVALID_VALUE;
    }
    if (abilityRecord->IsStartedByCall()) {
        if (abilityRecord->GetWant().GetBoolParam(Want::PARAM_RESV_CALL_TO_FOREGROUND, false)) {
            abilityRecord->SetStartToForeground(true);
            abilityRecord->PostForegroundTimeoutTask();
            abilityRecord->SetAbilityState(AbilityState::FOREGROUNDING);
            DelayedSingleton<AppScheduler>::GetInstance()->MoveToForeground(token);
        } else {
            abilityRecord->SetStartToBackground(true);
            MoveToBackground(abilityRecord);
        }
        return ERR_OK;
    }
    if (abilityRecord->IsNeedToCallRequest()) {
        abilityRecord->CallRequest();
    }
    abilityRecord->PostForegroundTimeoutTask();
    abilityRecord->SetAbilityState(AbilityState::FOREGROUNDING);
    DelayedSingleton<AppScheduler>::GetInstance()->MoveToForeground(token);
    return ERR_OK;
}

void UIAbilityLifecycleManager::OnAbilityRequestDone(const sptr<IRemoteObject> &token, int32_t state)
{
    TAG_LOGD(AAFwkTag::ABILITYMGR, "Ability request state %{public}d done.", state);
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    AppAbilityState abilityState = DelayedSingleton<AppScheduler>::GetInstance()->ConvertToAppAbilityState(state);
    if (abilityState == AppAbilityState::ABILITY_STATE_FOREGROUND) {
        std::lock_guard<ffrt::mutex> guard(sessionLock_);
        auto abilityRecord = GetAbilityRecordByToken(token);
        CHECK_POINTER(abilityRecord);
        if (abilityRecord->IsTerminating()) {
            TAG_LOGI(AAFwkTag::ABILITYMGR, "ability on terminating");
            auto handler = DelayedSingleton<AbilityManagerService>::GetInstance()->GetEventHandler();
            CHECK_POINTER(handler);
            abilityRecord->RemoveForegroundTimeoutTask();
            DelayedSingleton<AppScheduler>::GetInstance()->MoveToBackground(abilityRecord->GetToken());
            abilityRecord->SetPendingState(AbilityState::INITIAL);
            CompleteTerminateLocked(abilityRecord);
            return;
        }
        std::string element = abilityRecord->GetElementName().GetURI();
        TAG_LOGD(AAFwkTag::ABILITYMGR, "Ability is %{public}s, start to foreground.", element.c_str());
        abilityRecord->ForegroundAbility(abilityRecord->lifeCycleStateInfo_.sceneFlagBak);
    }
}

int UIAbilityLifecycleManager::AbilityTransactionDone(const sptr<IRemoteObject> &token, int state,
    const PacMap &saveData)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    int targetState = AbilityRecord::ConvertLifeCycleToAbilityState(static_cast<AbilityLifeCycleState>(state));
    std::string abilityState = AbilityRecord::ConvertAbilityState(static_cast<AbilityState>(targetState));
    TAG_LOGD(AAFwkTag::ABILITYMGR, "AbilityTransactionDone, state: %{public}s.", abilityState.c_str());

    std::lock_guard<ffrt::mutex> guard(sessionLock_);
    auto abilityRecord = GetAbilityRecordByToken(token);
    CHECK_POINTER_AND_RETURN(abilityRecord, ERR_INVALID_VALUE);
    abilityRecord->RemoveSignatureInfo();
    std::string element = abilityRecord->GetElementName().GetURI();
    TAG_LOGD(AAFwkTag::ABILITYMGR, "ability: %{public}s, state: %{public}s", element.c_str(), abilityState.c_str());

    if (targetState == AbilityState::BACKGROUND) {
        abilityRecord->SaveAbilityState(saveData);
    }

    return DispatchState(abilityRecord, targetState);
}

int UIAbilityLifecycleManager::AbilityWindowConfigTransactionDone(const sptr<IRemoteObject> &token,
    const WindowConfig &windowConfig)
{
    std::lock_guard<ffrt::mutex> guard(sessionLock_);
    auto abilityRecord = GetAbilityRecordByToken(token);
    CHECK_POINTER_AND_RETURN(abilityRecord, ERR_INVALID_VALUE);
    abilityRecord->SaveAbilityWindowConfig(windowConfig);
    return ERR_OK;
}

bool UIAbilityLifecycleManager::AddStartCallerTimestamp(int32_t callerUid)
{
    int64_t curTimeNs = AbilityUtil::GetSysTimeNs();
    int64_t aSecondEarlier = curTimeNs - AbilityUtil::NANOSECONDS;
    if (callerUid < 0) {
        callerUid = IPCSkeleton::GetCallingUid();
    }
    std::lock_guard<ffrt::mutex> guard(startUIAbilityCallerTimestampsLock_);
    if (startUIAbilityCallerTimestamps_.find(callerUid) == startUIAbilityCallerTimestamps_.end()) {
        startUIAbilityCallerTimestamps_[callerUid] = { curTimeNs };
        return true;
    }
    std::vector<int64_t> &callerTimestamps = startUIAbilityCallerTimestamps_[callerUid];
    auto it = callerTimestamps.begin();
    while (it != callerTimestamps.end() && *it < aSecondEarlier) {
        it = callerTimestamps.erase(it);
    }
    if (callerTimestamps.size() >= START_UI_ABILITY_PER_SECOND_UPPER_LIMIT) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "caller %{public}d exceeds limit", callerUid);
        return false;
    }
    callerTimestamps.emplace_back(curTimeNs);
    return true;
}

int UIAbilityLifecycleManager::NotifySCBToStartUIAbility(AbilityRequest &abilityRequest)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    if (!AddStartCallerTimestamp(abilityRequest.want.GetIntParam(Want::PARAM_RESV_CALLER_UID, -1))) {
        return ERR_INVALID_VALUE;
    }
    abilityRequest.want.SetParam(IS_SHELL_CALL, AAFwk::PermissionVerification::GetInstance()->IsShellCall());
    std::string callerKey = std::to_string(IPCSkeleton::GetCallingPid()) + ":" +
        std::to_string(IPCSkeleton::GetCallingUid());
    bool isCallerKilling = IN_PROCESS_CALL(DelayedSingleton<AppScheduler>::GetInstance()->IsCallerKilling(callerKey));
    if (isCallerKilling) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "caller is killing");
        return ERR_INVALID_VALUE;
    }
    abilityRequest.want.SetParam(Want::PARAMS_REAL_CALLER_KEY, callerKey);
    std::lock_guard<ffrt::mutex> guard(sessionLock_);
    // start ability with persistentId by dms
    int32_t persistentId = abilityRequest.want.GetIntParam(DMS_PERSISTENT_ID, 0);
    TAG_LOGD(AAFwkTag::ABILITYMGR, "NotifySCBToStartUIAbility, want with persistentId: %{public}d.", persistentId);
    if (persistentId != 0 &&
        AAFwk::PermissionVerification::GetInstance()->CheckSpecificSystemAbilityAccessPermission(DMS_PROCESS_NAME)) {
        return StartWithPersistentIdByDistributed(abilityRequest, persistentId);
    }
    if (StartSpecifiedProcessRequest(abilityRequest)) {
        return ERR_OK;
    }
    const auto &abilityInfo = abilityRequest.abilityInfo;
    auto requestId = GetRequestId();
    auto isPlugin = StartupUtil::IsStartPlugin(abilityRequest.want);
    auto isSpecified = (abilityInfo.launchMode == AppExecFwk::LaunchMode::SPECIFIED);
    if (isSpecified && !isPlugin) {
        auto specifiedRequest = std::make_shared<SpecifiedRequest>(requestId, abilityRequest);
        specifiedRequest->preCreateProcessName = true;
        AddSpecifiedRequest(specifiedRequest);
        return ERR_OK;
    }

    if (IsHookModule(abilityRequest)) {
        auto abilityRecord = FindRecordFromSessionMap(abilityRequest);
        if (abilityRecord != nullptr) {
            if (abilityRecord->IsHook() && !abilityRecord->GetHookOff()) {
                AbilityRequest request;
                request.callerToken = abilityRequest.callerToken;
                sptr<SessionInfo> hookSessionInfo = abilityRecord->GetSessionInfo();
                if (hookSessionInfo != nullptr) {
                    hookSessionInfo->want = abilityRequest.want;
                }
                int ret = NotifySCBPendingActivation(hookSessionInfo, request);
                if (hookSessionInfo != nullptr) {
                    hookSessionInfo->want.RemoveAllFd();
                }
                return ret;
            }
        }
    }
    auto sessionInfo = CreateSessionInfo(abilityRequest);
    sessionInfo->requestCode = abilityRequest.requestCode;
    sessionInfo->requestId = requestId;
    auto isCreating = abilityRequest.want.GetBoolParam(Want::CREATE_APP_INSTANCE_KEY, false);
    if (abilityInfo.applicationInfo.multiAppMode.multiAppModeType != AppExecFwk::MultiAppModeType::MULTI_INSTANCE ||
        !isCreating) {
        sessionInfo->persistentId = GetPersistentIdByAbilityRequest(abilityRequest, sessionInfo->reuse);
    }
    sessionInfo->userId = userId_;
    sessionInfo->isAtomicService = (abilityInfo.applicationInfo.bundleType == AppExecFwk::BundleType::ATOMIC_SERVICE);
    TAG_LOGI(AAFwkTag::ABILITYMGR, "Reused sessionId: %{public}d, userId: %{public}d, requestId: %{public}d",
        sessionInfo->persistentId, userId_, requestId);
    int ret = NotifySCBPendingActivation(sessionInfo, abilityRequest);
    sessionInfo->want.RemoveAllFd();
    return ret;
}

int32_t UIAbilityLifecycleManager::NotifySCBToRecoveryAfterInterception(const AbilityRequest &abilityRequest)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    std::lock_guard<ffrt::mutex> guard(sessionLock_);
    if (StartSpecifiedProcessRequest(abilityRequest)) {
        return ERR_OK;
    }
    const auto &abilityInfo = abilityRequest.abilityInfo;
    auto isPlugin = StartupUtil::IsStartPlugin(abilityRequest.want);
    auto isSpecified = (abilityInfo.launchMode == AppExecFwk::LaunchMode::SPECIFIED);
    if (isSpecified && !isPlugin) {
        auto specifiedRequest = std::make_shared<SpecifiedRequest>(GetRequestId(), abilityRequest);
        specifiedRequest->preCreateProcessName = true;
        AddSpecifiedRequest(specifiedRequest);
        return ERR_OK;
    }
    auto sessionInfo = CreateSessionInfo(abilityRequest);
    sessionInfo->requestCode = abilityRequest.requestCode;
    sessionInfo->persistentId = GetPersistentIdByAbilityRequest(abilityRequest, sessionInfo->reuse);
    sessionInfo->userId = userId_;
    sessionInfo->isAtomicService = (abilityInfo.applicationInfo.bundleType == AppExecFwk::BundleType::ATOMIC_SERVICE);
    sessionInfo->want.SetParam("ohos.ability.params.isSkipErmsFromSCB", true);
    TAG_LOGI(
        AAFwkTag::ABILITYMGR, "Reused sessionId: %{public}d, userId: %{public}d.", sessionInfo->persistentId, userId_);
    int ret = NotifySCBPendingActivation(sessionInfo, abilityRequest);
    sessionInfo->want.CloseAllFd();
    return ret;
}

int UIAbilityLifecycleManager::NotifySCBToPreStartUIAbility(const AbilityRequest &abilityRequest,
    sptr<SessionInfo> &sessionInfo)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);

    std::lock_guard<ffrt::mutex> guard(sessionLock_);
    sessionInfo = CreateSessionInfo(abilityRequest);
    sessionInfo->requestCode = abilityRequest.requestCode;
    sessionInfo->isAtomicService = true;
    return NotifySCBPendingActivation(sessionInfo, abilityRequest);
}

int UIAbilityLifecycleManager::DispatchState(const std::shared_ptr<AbilityRecord> &abilityRecord, int state)
{
    switch (state) {
        case AbilityState::INITIAL: {
            return DispatchTerminate(abilityRecord);
        }
        case AbilityState::BACKGROUND:
        case AbilityState::BACKGROUND_FAILED: {
            return DispatchBackground(abilityRecord);
        }
        case AbilityState::FOREGROUND: {
            return DispatchForeground(abilityRecord, true);
        }
        case AbilityState::FOREGROUND_FAILED:
        case AbilityState::FOREGROUND_INVALID_MODE:
        case AbilityState::FOREGROUND_WINDOW_FREEZED: {
            return DispatchForeground(abilityRecord, false, static_cast<AbilityState>(state));
        }
        default: {
            TAG_LOGW(AAFwkTag::ABILITYMGR, "no support transiting state: %{public}d", state);
            return ERR_INVALID_VALUE;
        }
    }
}

int UIAbilityLifecycleManager::DispatchForeground(const std::shared_ptr<AbilityRecord> &abilityRecord, bool success,
    AbilityState state)
{
    auto handler = DelayedSingleton<AbilityManagerService>::GetInstance()->GetEventHandler();
    CHECK_POINTER_AND_RETURN_LOG(handler, ERR_INVALID_VALUE, "Fail to get AbilityEventHandler.");
    auto taskHandler = DelayedSingleton<AbilityManagerService>::GetInstance()->GetTaskHandler();
    CHECK_POINTER_AND_RETURN_LOG(taskHandler, ERR_INVALID_VALUE, "Fail to get AbilityTaskHandler.");
    CHECK_POINTER_AND_RETURN(abilityRecord, ERR_INVALID_VALUE);

    RemoveStartingPid(abilityRecord->GetPid());

    if (!abilityRecord->IsAbilityState(AbilityState::FOREGROUNDING)) {
        TAG_LOGE(AAFwkTag::ABILITYMGR,
            "dispatchForeground ability transition error, expect %{public}d, actual %{public}d",
            AbilityState::FOREGROUNDING, abilityRecord->GetAbilityState());
        return ERR_INVALID_VALUE;
    }

    TAG_LOGD(AAFwkTag::ABILITYMGR, "ForegroundLifecycle: end.");
    abilityRecord->RemoveForegroundTimeoutTask();
    g_deleteLifecycleEventTask(abilityRecord->GetToken());
    FreezeUtil::GetInstance().DeleteAppLifecycleEvent(abilityRecord->GetPid());
    auto self(weak_from_this());
    if (success) {
        TAG_LOGD(AAFwkTag::ABILITYMGR, "foreground succeeded.");
        auto task = [self, abilityRecord]() {
            auto selfObj = self.lock();
            if (!selfObj) {
                TAG_LOGW(AAFwkTag::ABILITYMGR, "mgr invalid");
                return;
            }
            selfObj->CompleteForegroundSuccess(abilityRecord);
        };
        taskHandler->SubmitTask(task, TaskQoS::USER_INTERACTIVE);
    } else {
        auto task = [self, abilityRecord, state]() {
            auto selfObj = self.lock();
            if (!selfObj) {
                TAG_LOGW(AAFwkTag::ABILITYMGR, "mission list mgr invalid");
                return;
            }
            if (state == AbilityState::FOREGROUND_WINDOW_FREEZED) {
                TAG_LOGI(AAFwkTag::ABILITYMGR, "window freezed");
                if (abilityRecord != nullptr) {
                    abilityRecord->SetAbilityState(AbilityState::BACKGROUND);
                    DelayedSingleton<AppScheduler>::GetInstance()->MoveToBackground(abilityRecord->GetToken());
                }
                return;
            }
            selfObj->HandleForegroundFailed(abilityRecord, state);
        };
        taskHandler->SubmitTask(task, TaskQoS::USER_INTERACTIVE);
    }
    return ERR_OK;
}

int UIAbilityLifecycleManager::DispatchBackground(const std::shared_ptr<AbilityRecord> &abilityRecord)
{
    auto handler = DelayedSingleton<AbilityManagerService>::GetInstance()->GetTaskHandler();
    CHECK_POINTER_AND_RETURN_LOG(handler, ERR_INVALID_VALUE, "Fail to get AbilityTaskHandler.");
    CHECK_POINTER_AND_RETURN(abilityRecord, ERR_INVALID_VALUE);

    if (!abilityRecord->IsAbilityState(AbilityState::BACKGROUNDING)) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "ability transition error, actual %{public}d",
            abilityRecord->GetAbilityState());
        return ERR_INVALID_VALUE;
    }

    TAG_LOGD(AAFwkTag::ABILITYMGR, "end.");
    // remove background timeout task.
    handler->CancelTask("background_" + std::to_string(abilityRecord->GetAbilityRecordId()));
    g_deleteLifecycleEventTask(abilityRecord->GetToken());
    FreezeUtil::GetInstance().DeleteAppLifecycleEvent(abilityRecord->GetPid());
    auto self(shared_from_this());
    auto task = [self, abilityRecord]() { self->CompleteBackground(abilityRecord); };
    handler->SubmitTask(task, TaskQoS::USER_INTERACTIVE);

    return ERR_OK;
}

int UIAbilityLifecycleManager::DispatchTerminate(const std::shared_ptr<AbilityRecord> &abilityRecord)
{
    CHECK_POINTER_AND_RETURN(abilityRecord, ERR_INVALID_VALUE);
    if (abilityRecord->GetAbilityState() != AbilityState::TERMINATING) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "error, abilityState: %{public}d",
            abilityRecord->GetAbilityState());
        return INNER_ERR;
    }

    // remove terminate timeout task.
    auto handler = DelayedSingleton<AbilityManagerService>::GetInstance()->GetTaskHandler();
    CHECK_POINTER_AND_RETURN_LOG(handler, ERR_INVALID_VALUE, "Fail to get AbilityTaskHandler.");
    handler->CancelTask("terminate_" + std::to_string(abilityRecord->GetAbilityRecordId()));
    auto self(shared_from_this());
    auto task = [self, abilityRecord]() { self->CompleteTerminate(abilityRecord); };
    handler->SubmitTask(task, TaskQoS::USER_INTERACTIVE);

    return ERR_OK;
}

void UIAbilityLifecycleManager::CompleteForegroundSuccess(const std::shared_ptr<AbilityRecord> &abilityRecord)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    std::lock_guard<ffrt::mutex> guard(sessionLock_);

    CHECK_POINTER(abilityRecord);
    // ability do not save window mode
    abilityRecord->RemoveWindowMode();
    std::string element = abilityRecord->GetElementName().GetURI();
    TAG_LOGD(AAFwkTag::ABILITYMGR, "ability: %{public}s", element.c_str());
    abilityRecord->SetAbilityState(AbilityState::FOREGROUND);
    abilityRecord->UpdateAbilityVisibilityState();

    // new version. started by caller, scheduler call request
    if (abilityRecord->IsStartedByCall() && abilityRecord->IsStartToForeground() && abilityRecord->IsReady()) {
        TAG_LOGD(AAFwkTag::ABILITYMGR, "call request after completing foreground state");
        abilityRecord->CallRequest();
        abilityRecord->SetStartToForeground(false);
    }

    if (abilityRecord->IsNewWant()) {
        TAG_LOGD(AAFwkTag::ABILITYMGR, "has new want");
        abilityRecord->ForegroundAbility();
    } else if (abilityRecord->GetPendingState() == AbilityState::BACKGROUND) {
        abilityRecord->SetMinimizeReason(true);
        MoveToBackground(abilityRecord);
    } else if (abilityRecord->GetPendingState() == AbilityState::FOREGROUND) {
        TAG_LOGD(AAFwkTag::ABILITYMGR, "not continuous startup.");
        abilityRecord->SetPendingState(AbilityState::INITIAL);
    }
    if (handler_ != nullptr && abilityRecord->GetSessionInfo() != nullptr) {
        TAG_LOGD(AAFwkTag::ABILITYMGR, "OnSessionMovedToFront() called");
        handler_->OnSessionMovedToFront(abilityRecord->GetSessionInfo()->persistentId);
    }
}

void UIAbilityLifecycleManager::HandleForegroundFailed(const std::shared_ptr<AbilityRecord> &ability,
    AbilityState state)
{
    TAG_LOGD(AAFwkTag::ABILITYMGR, "state: %{public}d.", static_cast<int32_t>(state));
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    std::lock_guard<ffrt::mutex> guard(sessionLock_);
    if (ability == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "null ability record");
        return;
    }

    if (!ability->IsAbilityState(AbilityState::FOREGROUNDING)) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "not foregrounding");
        return;
    }

    NotifySCBToHandleException(ability,
        static_cast<int32_t>(ErrorLifecycleState::ABILITY_STATE_LOAD_TIMEOUT), "handleForegroundTimeout");
    PrepareCloseUIAbility(ability, 0, nullptr, false);
    CloseUIAbilityInner(ability);
}

std::shared_ptr<AbilityRecord> UIAbilityLifecycleManager::GetAbilityRecordByToken(const sptr<IRemoteObject> &token)
    const
{
    if (token == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "null");
        return nullptr;
    }

    for (auto ability : terminateAbilityList_) {
        if (ability && token == ability->GetToken()->AsObject()) {
            return ability;
        }
    }

    for (auto iter = sessionAbilityMap_.begin(); iter != sessionAbilityMap_.end(); iter++) {
        if (iter->second != nullptr && iter->second->GetToken()->AsObject() == token) {
            return iter->second;
        }
    }
    return nullptr;
}

#ifdef SUPPORT_SCREEN
void UIAbilityLifecycleManager::CompleteFirstFrameDrawing(const sptr<IRemoteObject> &token)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    if (token == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "null");
        return;
    }
    std::lock_guard<ffrt::mutex> guard(sessionLock_);
    if (!IsContainsAbilityInner(token)) {
        TAG_LOGW(AAFwkTag::ABILITYMGR, "Not in running list");
        return;
    }
    auto abilityRecord = GetAbilityRecordByToken(token);
    CHECK_POINTER(abilityRecord);
    if (abilityRecord->IsCompleteFirstFrameDrawing()) {
        TAG_LOGD(AAFwkTag::ABILITYMGR, "First frame drawing has completed.");
        return;
    }
    abilityRecord->ReportAtomicServiceDrawnCompleteEvent();
    abilityRecord->SetCompleteFirstFrameDrawing(true);
    AppExecFwk::AbilityFirstFrameStateObserverManager::GetInstance().
        HandleOnFirstFrameState(abilityRecord);
}
#endif

bool UIAbilityLifecycleManager::IsContainsAbility(const sptr<IRemoteObject> &token) const
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    std::lock_guard<ffrt::mutex> guard(sessionLock_);
    return IsContainsAbilityInner(token);
}

bool UIAbilityLifecycleManager::IsContainsAbilityInner(const sptr<IRemoteObject> &token) const
{
    for (auto iter = sessionAbilityMap_.begin(); iter != sessionAbilityMap_.end(); iter++) {
        if (iter->second != nullptr && iter->second->GetToken()->AsObject() == token) {
            return true;
        }
    }
    return false;
}

void UIAbilityLifecycleManager::EraseAbilityRecord(const std::shared_ptr<AbilityRecord> &abilityRecord)
{
    if (abilityRecord == nullptr) {
        return;
    }

    for (auto iter = sessionAbilityMap_.begin(); iter != sessionAbilityMap_.end(); iter++) {
        if (iter->second != nullptr && iter->second->GetToken()->AsObject() == abilityRecord->GetToken()->AsObject()) {
            sessionAbilityMap_.erase(iter);
            AbilityRecordDeathManager::GetInstance().AddRecordToDeadList(abilityRecord);
            break;
        }
    }
    for (auto iter = lowMemKillAbilityMap_.begin(); iter != lowMemKillAbilityMap_.end(); iter++) {
        if (iter->second != nullptr && iter->second->GetToken()->AsObject() == abilityRecord->GetToken()->AsObject()) {
            lowMemKillAbilityMap_.erase(iter);
            AbilityRecordDeathManager::GetInstance().AddRecordToDeadList(abilityRecord);
            break;
        }
    }
    callRequestCache_.erase(abilityRecord);
}

std::string UIAbilityLifecycleManager::GenerateProcessNameForNewProcessMode(const AppExecFwk::AbilityInfo& abilityInfo)
{
    static uint32_t index = 0;
    std::string processName = abilityInfo.bundleName + SEPARATOR + abilityInfo.moduleName + SEPARATOR +
        abilityInfo.name + SEPARATOR + std::to_string(index++);
    TAG_LOGI(AAFwkTag::ABILITYMGR, "processName: %{public}s", processName.c_str());
    return processName;
}

void UIAbilityLifecycleManager::PreCreateProcessName(AbilityRequest &abilityRequest)
{
    if (abilityRequest.processOptions == nullptr ||
        !ProcessOptions::IsNewProcessMode(abilityRequest.processOptions->processMode)) {
        TAG_LOGD(AAFwkTag::ABILITYMGR, "No need to pre create process name.");
        return;
    }
    TAG_LOGI(AAFwkTag::ABILITYMGR, "create process name in advance");
    std::string processName = GenerateProcessNameForNewProcessMode(abilityRequest.abilityInfo);
    abilityRequest.processOptions->processName = processName;
    abilityRequest.abilityInfo.process = processName;
}

void UIAbilityLifecycleManager::UpdateProcessName(const AbilityRequest &abilityRequest,
    std::shared_ptr<AbilityRecord> &abilityRecord)
{
    if (abilityRecord == nullptr || abilityRequest.sessionInfo == nullptr ||
        abilityRequest.sessionInfo->processOptions == nullptr ||
        !ProcessOptions::IsNewProcessMode(abilityRequest.sessionInfo->processOptions->processMode)) {
        TAG_LOGD(AAFwkTag::ABILITYMGR, "No need to update process name.");
        return;
    }
    std::string processName;
    if (!abilityRequest.sessionInfo->processOptions->processName.empty()) {
        TAG_LOGD(AAFwkTag::ABILITYMGR, "The process name has been generated in advance.");
        processName = abilityRequest.sessionInfo->processOptions->processName;
    } else {
        processName = GenerateProcessNameForNewProcessMode(abilityRequest.abilityInfo);
    }
    abilityRecord->SetProcessName(processName);
    abilityRecord->SetCallerSetProcess(true);
}

void UIAbilityLifecycleManager::UpdateAbilityRecordLaunchReason(
    const AbilityRequest &abilityRequest, std::shared_ptr<AbilityRecord> &abilityRecord) const
{
    if (abilityRecord == nullptr) {
        TAG_LOGW(AAFwkTag::ABILITYMGR, "null input record");
        return;
    }

    std::string value = abilityRequest.want.GetStringParam(Want::PARM_LAUNCH_REASON_MESSAGE);
    if (!value.empty()) {
        TAG_LOGD(AAFwkTag::ABILITYMGR, "set launchReasonMessage:%{public}s", value.c_str());
        abilityRecord->SetLaunchReasonMessage(value);
    }
    if (abilityRequest.IsAppRecovery() || abilityRecord->GetRecoveryInfo()) {
        abilityRecord->SetLaunchReason(LaunchReason::LAUNCHREASON_APP_RECOVERY);
        return;
    }

    auto res = abilityRequest.IsContinuation();
    if (res.first) {
        abilityRecord->SetLaunchReason(res.second);
        return;
    }

    if (abilityRequest.IsAcquireShareData()) {
        abilityRecord->SetLaunchReason(LaunchReason::LAUNCHREASON_SHARE);
        return;
    }

    abilityRecord->SetLaunchReason(LaunchReason::LAUNCHREASON_START_ABILITY);
    return;
}

std::shared_ptr<AbilityRecord> UIAbilityLifecycleManager::GetUIAbilityRecordBySessionInfo(
    const sptr<SessionInfo> &sessionInfo)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    std::lock_guard<ffrt::mutex> guard(sessionLock_);
    CHECK_POINTER_AND_RETURN(sessionInfo, nullptr);
    CHECK_POINTER_AND_RETURN(sessionInfo->sessionToken, nullptr);
    auto sessionToken = iface_cast<Rosen::ISession>(sessionInfo->sessionToken);
    CHECK_POINTER_AND_RETURN(sessionToken, nullptr);
    std::string descriptor = Str16ToStr8(sessionToken->GetDescriptor());
    if (descriptor != "OHOS.ISession") {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "failed, descriptor: %{public}s",
            descriptor.c_str());
        return nullptr;
    }

    auto iter = sessionAbilityMap_.find(sessionInfo->persistentId);
    if (iter != sessionAbilityMap_.end()) {
        return iter->second;
    }
    return nullptr;
}

int32_t UIAbilityLifecycleManager::NotifySCBToMinimizeUIAbility(const sptr<IRemoteObject> token)
{
    TAG_LOGI(AAFwkTag::ABILITYMGR, "notifySCBToMinimizeUIAbility");
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    auto sceneSessionManager = Rosen::SessionManagerLite::GetInstance().GetSceneSessionManagerLiteProxy();
    CHECK_POINTER_AND_RETURN(sceneSessionManager, ERR_NULL_OBJECT);
    Rosen::WSError ret = sceneSessionManager->PendingSessionToBackgroundForDelegator(token);
    if (ret != Rosen::WSError::WS_OK) {
        TAG_LOGE(AAFwkTag::ABILITYMGR,
            "call error:%{public}d", ret);
    }
    return static_cast<int32_t>(ret);
}

int UIAbilityLifecycleManager::MinimizeUIAbility(const std::shared_ptr<AbilityRecord> &abilityRecord, bool fromUser,
    uint32_t sceneFlag)
{
    TAG_LOGD(AAFwkTag::ABILITYMGR, "call");
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    std::lock_guard<ffrt::mutex> guard(sessionLock_);
    if (abilityRecord == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "null ability record");
        return ERR_INVALID_VALUE;
    }
    TAG_LOGI(AAFwkTag::ABILITYMGR, "infoName:%{public}s", abilityRecord->GetAbilityInfo().name.c_str());
    abilityRecord->SetMinimizeReason(fromUser);
    abilityRecord->SetSceneFlag(sceneFlag);
    if (abilityRecord->GetPendingState() != AbilityState::INITIAL) {
        TAG_LOGI(AAFwkTag::ABILITYMGR, "pending state: FOREGROUND/ BACKGROUND, dropped");
        abilityRecord->SetPendingState(AbilityState::BACKGROUND);
        return ERR_OK;
    }
    if (!abilityRecord->IsAbilityState(AbilityState::FOREGROUND)) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "not foreground: %{public}d",
            abilityRecord->GetAbilityState());
        return ERR_OK;
    }
    abilityRecord->SetPendingState(AbilityState::BACKGROUND);
    MoveToBackground(abilityRecord);
    abilityRecord->SetSceneFlag(0);
    return ERR_OK;
}

void UIAbilityLifecycleManager::MoveToBackground(const std::shared_ptr<AbilityRecord> &abilityRecord)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    if (abilityRecord == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "null ability record");
        return;
    }
    abilityRecord->SetIsNewWant(false);
    auto self(weak_from_this());
    auto task = [abilityRecord, self]() {
        auto selfObj = self.lock();
        if (selfObj == nullptr) {
            TAG_LOGW(AAFwkTag::ABILITYMGR, "UIAbilityLifecycleManager invalid");
            return;
        }
        TAG_LOGE(AAFwkTag::ABILITYMGR, "move to background timeout");
        selfObj->PrintTimeOutLog(abilityRecord, AbilityManagerService::BACKGROUND_TIMEOUT_MSG);
        selfObj->CompleteBackground(abilityRecord);
    };
    abilityRecord->BackgroundAbility(task);
}

int UIAbilityLifecycleManager::ResolveLocked(const AbilityRequest &abilityRequest)
{
    TAG_LOGI(AAFwkTag::ABILITYMGR, "ByCall, ability:%{public}s", abilityRequest.want.GetElement().GetURI().c_str());

    if (!abilityRequest.IsCallType(AbilityCallType::CALL_REQUEST_TYPE)) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "%{public}s, resolve ability_name:", __func__);
        return RESOLVE_CALL_ABILITY_INNER_ERR;
    }

    return CallAbilityLocked(abilityRequest);
}

bool UIAbilityLifecycleManager::IsAbilityStarted(AbilityRequest &abilityRequest,
    std::shared_ptr<AbilityRecord> &targetRecord)
{
    TAG_LOGD(AAFwkTag::ABILITYMGR, "Call.");
    std::lock_guard<ffrt::mutex> guard(sessionLock_);
    bool reuse = false;
    auto persistentId = GetPersistentIdByAbilityRequest(abilityRequest, reuse);
    if (persistentId == 0) {
        return false;
    }
    targetRecord = sessionAbilityMap_.at(persistentId);
    if (targetRecord && targetRecord->GetScheduler() != nullptr) {
        targetRecord->AddCallerRecord(abilityRequest.callerToken, abilityRequest.requestCode, abilityRequest.want);
        targetRecord->SetLaunchReason(LaunchReason::LAUNCHREASON_CALL);
        return true;
    }

    return false;
}

int UIAbilityLifecycleManager::CallAbilityLocked(const AbilityRequest &abilityRequest)
{
    TAG_LOGD(AAFwkTag::ABILITYMGR, "CallAbilityLocked");
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    std::lock_guard<ffrt::mutex> guard(sessionLock_);

    // Get target uiAbility record.
    std::shared_ptr<AbilityRecord> uiAbilityRecord;
    bool reuse = false;
    auto persistentId = GetPersistentIdByAbilityRequest(abilityRequest, reuse);
    if (persistentId == 0) {
        uiAbilityRecord = FindRecordFromTmpMap(abilityRequest);
        if (uiAbilityRecord != nullptr) {
            TAG_LOGI(AAFwkTag::ABILITYMGR, "cache call request");
            callRequestCache_[uiAbilityRecord].push_back(abilityRequest);
            return ERR_OK;
        }
        uiAbilityRecord = AbilityRecord::CreateAbilityRecord(abilityRequest);
        uiAbilityRecord->SetOwnerMissionUserId(userId_);
        SetReceiverInfo(abilityRequest, uiAbilityRecord);
    } else {
        uiAbilityRecord = sessionAbilityMap_.at(persistentId);
    }
    uiAbilityRecord->AddCallerRecord(abilityRequest.callerToken, abilityRequest.requestCode, abilityRequest.want);
    uiAbilityRecord->SetLaunchReason(LaunchReason::LAUNCHREASON_CALL);

#ifdef SUPPORT_UPMS
    if (InsightIntentExecuteParam::IsInsightIntentExecute(abilityRequest.want)) {
        uiAbilityRecord->GrantUriPermission();
    }
#endif // SUPPORT_UPMS

    std::string value = abilityRequest.want.GetStringParam(Want::PARM_LAUNCH_REASON_MESSAGE);
    if (!value.empty()) {
        TAG_LOGD(AAFwkTag::ABILITYMGR, "set launchReasonMessage:%{public}s", value.c_str());
        uiAbilityRecord->SetLaunchReasonMessage(value);
    }
    NotifyAbilityToken(uiAbilityRecord->GetToken(), abilityRequest);

    // new version started by call type
    const auto& abilityInfo = abilityRequest.abilityInfo;
    auto ret = ResolveAbility(uiAbilityRecord, abilityRequest);
    if (ret == ResolveResultType::OK_HAS_REMOTE_OBJ || (ret == ResolveResultType::OK_NO_REMOTE_OBJ &&
        persistentId != 0)) {
        TAG_LOGD(AAFwkTag::ABILITYMGR, "target ability has been resolved: %{public}d", ret);
        if (abilityRequest.want.GetBoolParam(Want::PARAM_RESV_CALL_TO_FOREGROUND, false)) {
            TAG_LOGI(AAFwkTag::ABILITYMGR, "target ability needs to be switched to foreground.");
            auto sessionInfo = CreateSessionInfo(abilityRequest);
            if ((persistentId != 0) && abilityRequest.want.GetBoolParam(IS_CALLING_FROM_DMS, false)) {
                HandleForegroundCollaborate(abilityRequest, uiAbilityRecord);
            }
            sessionInfo->persistentId = persistentId;
            sessionInfo->state = CallToState::FOREGROUND;
            sessionInfo->reuse = reuse;
            sessionInfo->uiAbilityId = uiAbilityRecord->GetAbilityRecordId();
            sessionInfo->isAtomicService =
                (abilityInfo.applicationInfo.bundleType == AppExecFwk::BundleType::ATOMIC_SERVICE);
            if (uiAbilityRecord->GetPendingState() != AbilityState::INITIAL) {
                TAG_LOGI(AAFwkTag::ABILITYMGR, "pending state: FOREGROUND/ BACKGROUND, dropped");
                uiAbilityRecord->SetPendingState(AbilityState::FOREGROUND);
                return NotifySCBPendingActivation(sessionInfo, abilityRequest);
            }
            uiAbilityRecord->SetPendingState(AbilityState::FOREGROUND);
            uiAbilityRecord->ProcessForegroundAbility(sessionInfo->callingTokenId);
            return NotifySCBPendingActivation(sessionInfo, abilityRequest);
        } else {
            if ((persistentId != 0) && abilityRequest.want.GetBoolParam(IS_CALLING_FROM_DMS, false)) {
                uiAbilityRecord->ScheduleCollaborate(abilityRequest.want);
            }
        }
        return ERR_OK;
    } else if (ret == ResolveResultType::NG_INNER_ERROR) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "resolve failed, error: %{public}d", RESOLVE_CALL_ABILITY_INNER_ERR);
        return RESOLVE_CALL_ABILITY_INNER_ERR;
    }

    auto sessionInfo = CreateSessionInfo(abilityRequest);
    sessionInfo->persistentId = persistentId;
    sessionInfo->reuse = reuse;
    sessionInfo->uiAbilityId = uiAbilityRecord->GetAbilityRecordId();
    sessionInfo->isAtomicService = (abilityInfo.applicationInfo.bundleType == AppExecFwk::BundleType::ATOMIC_SERVICE);
    sessionInfo->requestId = GetRequestId();
    if (abilityRequest.want.GetBoolParam(Want::PARAM_RESV_CALL_TO_FOREGROUND, false)) {
        sessionInfo->state = CallToState::FOREGROUND;
    } else {
        sessionInfo->state = CallToState::BACKGROUND;
        sessionInfo->needClearInNotShowRecent = true;
    }
    TAG_LOGD(AAFwkTag::ABILITYMGR, "Notify scb's abilityId is %{public}" PRIu64 ".", sessionInfo->uiAbilityId);
    tmpAbilityMap_.emplace(sessionInfo->requestId, uiAbilityRecord);
    PostCallTimeoutTask(uiAbilityRecord);
    return NotifySCBPendingActivation(sessionInfo, abilityRequest);
}

void UIAbilityLifecycleManager::PostCallTimeoutTask(std::shared_ptr<AbilityRecord> abilityRecord)
{
    CHECK_POINTER(abilityRecord);
    auto handler = DelayedSingleton<AbilityManagerService>::GetInstance()->GetTaskHandler();
    CHECK_POINTER(handler);

    std::weak_ptr<AbilityRecord> weakRecord(abilityRecord);
    auto timeoutTask = [self = shared_from_this(), weakRecord]() {
        auto abilityRecord = weakRecord.lock();
        if (!abilityRecord) {
            return;
        }

        std::lock_guard guard(self->sessionLock_);
        for (auto it = self->tmpAbilityMap_.begin(); it != self->tmpAbilityMap_.end(); ++it) {
            if (abilityRecord == it->second) {
                TAG_LOGW(AAFwkTag::ABILITYMGR, "CallUIAbilityBySCB timeout: %{public}s",
                    abilityRecord->GetURI().c_str());
                self->tmpAbilityMap_.erase(it);
                self->callRequestCache_.erase(abilityRecord);
                return;
            }
        }
    };

    int timeout = AmsConfigurationParameter::GetInstance().GetAppStartTimeoutTime() *
        GlobalConstant::COLDSTART_TIMEOUT_MULTIPLE;
    handler->SubmitTaskJust(timeoutTask, "CallTimeout", timeout);
}

void UIAbilityLifecycleManager::CallUIAbilityBySCB(const sptr<SessionInfo> &sessionInfo, bool &isColdStart)
{
    TAG_LOGI(AAFwkTag::ABILITYMGR, "scb call, CallUIAbilityBySCB");
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    std::lock_guard<ffrt::mutex> guard(sessionLock_);
    CHECK_POINTER_LOG(sessionInfo, "sessionInfo is invalid.");
    CHECK_POINTER_LOG(sessionInfo->sessionToken, "sessionToken is nullptr.");
    auto sessionToken = iface_cast<Rosen::ISession>(sessionInfo->sessionToken);
    CHECK_POINTER_LOG(sessionToken, "sessionToken is nullptr.");
    auto descriptor = Str16ToStr8(sessionToken->GetDescriptor());
    if (descriptor != "OHOS.ISession") {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "token's Descriptor: %{public}s", descriptor.c_str());
        return;
    }

    TAG_LOGD(AAFwkTag::ABILITYMGR, "SCB output abilityId is %{public}" PRIu64 ".", sessionInfo->uiAbilityId);
    auto search = tmpAbilityMap_.find(sessionInfo->requestId);
    if (search == tmpAbilityMap_.end()) {
        if (sessionInfo->uiAbilityId == 0 && tmpAbilityMap_.size() == 1) {
            search = tmpAbilityMap_.begin();
        } else {
            TAG_LOGW(AAFwkTag::ABILITYMGR, "not find UIAbility");
            return;
        }
    }
    auto uiAbilityRecord = search->second;
    tmpAbilityMap_.erase(search);
    CHECK_POINTER_LOG(uiAbilityRecord, "UIAbility not exist.");
    auto sessionSearch = sessionAbilityMap_.find(sessionInfo->persistentId);
    if (sessionSearch != sessionAbilityMap_.end()) {
        // ability could be in loading state, waiting for callback
        TAG_LOGI(AAFwkTag::ABILITYMGR, "session exist");
        return;
    }
    isColdStart = true;
    uiAbilityRecord->SetInstanceKey(sessionInfo->instanceKey);

    MoreAbilityNumbersSendEventInfo(sessionInfo->userId, sessionInfo->want.GetElement().GetBundleName(),
        sessionInfo->want.GetElement().GetAbilityName(), sessionInfo->want.GetElement().GetModuleName());

    sessionAbilityMap_.emplace(sessionInfo->persistentId, uiAbilityRecord);
    uiAbilityRecord->SetSessionInfo(sessionInfo);
    if (sessionInfo->state == CallToState::BACKGROUND) {
        TAG_LOGI(AAFwkTag::ABILITYMGR, "set pending BACKGROUND");
        uiAbilityRecord->SetPendingState(AbilityState::BACKGROUND);
    } else {
        uiAbilityRecord->SetPendingState(AbilityState::FOREGROUND);
    }
    uiAbilityRecord->LoadAbility();
}

sptr<SessionInfo> UIAbilityLifecycleManager::CreateSessionInfo(const AbilityRequest &abilityRequest) const
{
    TAG_LOGD(AAFwkTag::ABILITYMGR, "Create session.");
    sptr<SessionInfo> sessionInfo = new SessionInfo();
    sessionInfo->callerToken = abilityRequest.callerToken;
    sessionInfo->want = abilityRequest.want;
    sessionInfo->processOptions = abilityRequest.processOptions;
    sessionInfo->startWindowOption = abilityRequest.startWindowOption;
    sessionInfo->supportWindowModes = abilityRequest.supportWindowModes;
    if (abilityRequest.startSetting != nullptr) {
        TAG_LOGD(AAFwkTag::ABILITYMGR, "Assign start setting to session.");
        sessionInfo->startSetting = abilityRequest.startSetting;
    }
    sessionInfo->callingTokenId = static_cast<uint32_t>(abilityRequest.want.GetIntParam(Want::PARAM_RESV_CALLER_TOKEN,
        IPCSkeleton::GetCallingTokenID()));
    sessionInfo->instanceKey = abilityRequest.want.GetStringParam(Want::APP_INSTANCE_KEY);
    return sessionInfo;
}

int UIAbilityLifecycleManager::NotifySCBPendingActivation(sptr<SessionInfo> &sessionInfo,
    const AbilityRequest &abilityRequest)
{
    CHECK_POINTER_AND_RETURN(sessionInfo, ERR_INVALID_VALUE);
    TAG_LOGD(AAFwkTag::ABILITYMGR, "windowLeft=%{public}d,windowTop=%{public}d,windowHeight=%{public}d,"
        "windowWidth=%{public}d,windowMode=%{public}d,supportWindowModes.size=%{public}zu,minWindowWidth=%{public}d,"
        "minWindowHeight=%{public}d,maxWindowWidth=%{public}d,maxWindowHeight=%{public}d,specifiedFlag=%{public}s",
        (sessionInfo->want).GetIntParam(Want::PARAM_RESV_WINDOW_LEFT, 0),
        (sessionInfo->want).GetIntParam(Want::PARAM_RESV_WINDOW_TOP, 0),
        (sessionInfo->want).GetIntParam(Want::PARAM_RESV_WINDOW_HEIGHT, 0),
        (sessionInfo->want).GetIntParam(Want::PARAM_RESV_WINDOW_WIDTH, 0),
        (sessionInfo->want).GetIntParam(Want::PARAM_RESV_WINDOW_MODE, 0),
        (sessionInfo->supportWindowModes).size(),
        (sessionInfo->want).GetIntParam(Want::PARAM_RESV_MIN_WINDOW_WIDTH, 0),
        (sessionInfo->want).GetIntParam(Want::PARAM_RESV_MIN_WINDOW_HEIGHT, 0),
        (sessionInfo->want).GetIntParam(Want::PARAM_RESV_MAX_WINDOW_WIDTH, 0),
        (sessionInfo->want).GetIntParam(Want::PARAM_RESV_MAX_WINDOW_HEIGHT, 0), sessionInfo->specifiedFlag.c_str());
    bool hasStartWindowOption = (sessionInfo->startWindowOption != nullptr);
    bool hasStartWindow = hasStartWindowOption ? sessionInfo->startWindowOption->hasStartWindow : false;
    std::string backgroundColor =
        hasStartWindowOption ? sessionInfo->startWindowOption->startWindowBackgroundColor : "";
    TAG_LOGI(AAFwkTag::ABILITYMGR, "appCloneIndex:%{public}d, instanceKey:%{public}s, "
        "hasStartWindow:%{public}d, backgroundColor:%{public}s",
        (sessionInfo->want).GetIntParam(Want::PARAM_APP_CLONE_INDEX_KEY, 0), sessionInfo->instanceKey.c_str(),
        hasStartWindow, backgroundColor.c_str());
    auto abilityRecord = GetAbilityRecordByToken(abilityRequest.callerToken);
    if (abilityRecord != nullptr && !abilityRecord->GetRestartAppFlag()) {
        auto callerSessionInfo = abilityRecord->GetSessionInfo();
        CHECK_POINTER_AND_RETURN(callerSessionInfo, ERR_INVALID_VALUE);
        CHECK_POINTER_AND_RETURN(callerSessionInfo->sessionToken, ERR_INVALID_VALUE);
        auto callerSession = iface_cast<Rosen::ISession>(callerSessionInfo->sessionToken);
        CHECK_POINTER_AND_RETURN(callerSession, ERR_INVALID_VALUE);
        CheckCallerFromBackground(abilityRecord, sessionInfo);
        auto requestId = abilityRequest.want.GetStringParam(KEY_REQUEST_ID);
        if (!requestId.empty()) {
            TAG_LOGI(AAFwkTag::ABILITYMGR, "notify request success, requestId:%{public}s", requestId.c_str());
            abilityRecord->NotifyAbilityRequestSuccess(requestId, abilityRequest.want.GetElement(), "success");
        }
        const_cast<AbilityRequest &>(abilityRequest).want.RemoveParam(KEY_REQUEST_ID);
        TAG_LOGI(AAFwkTag::ABILITYMGR, "scb call, NotifySCBPendingActivation for callerSession, target: %{public}s",
            sessionInfo->want.GetElement().GetAbilityName().c_str());
        return static_cast<int>(callerSession->PendingSessionActivation(sessionInfo));
    }
    auto tmpSceneSession = iface_cast<Rosen::ISession>(rootSceneSession_);
    CHECK_POINTER_AND_RETURN(tmpSceneSession, ERR_INVALID_VALUE);
    sessionInfo->canStartAbilityFromBackground = true;
    TAG_LOGI(AAFwkTag::ABILITYMGR, "scb call, NotifySCBPendingActivation for rootSceneSession, target: %{public}s",
        sessionInfo->want.GetElement().GetAbilityName().c_str());
    return static_cast<int>(tmpSceneSession->PendingSessionActivation(sessionInfo));
}

bool UIAbilityLifecycleManager::IsHookModule(const AbilityRequest &abilityRequest) const
{
    AppExecFwk::HapModuleInfo hapModuleInfo;
    if (DelayedSingleton<AppExecFwk::BundleMgrHelper>::GetInstance()->GetHapModuleInfo(
        abilityRequest.abilityInfo, hapModuleInfo)) {
        TAG_LOGD(AAFwkTag::ABILITYMGR, "module:%{public}s, ability:%{public}s",
            hapModuleInfo.abilityStageSrcEntryDelegator.c_str(), hapModuleInfo.abilitySrcEntryDelegator.c_str());
        if (hapModuleInfo.abilitySrcEntryDelegator.empty() || hapModuleInfo.abilityStageSrcEntryDelegator.empty()) {
            return false;
        }
        if (hapModuleInfo.abilityStageSrcEntryDelegator == hapModuleInfo.moduleName) {
            TAG_LOGW(AAFwkTag::ABILITYMGR, "not support");
            return false;
        }
        Want want;
        want.SetElementName("", hapModuleInfo.bundleName, hapModuleInfo.abilitySrcEntryDelegator,
            hapModuleInfo.abilityStageSrcEntryDelegator);
        AppExecFwk::AbilityInfo abilityInfo;
        if (!IN_PROCESS_CALL(DelayedSingleton<AppExecFwk::BundleMgrHelper>::GetInstance()->QueryAbilityInfo(
            want, AppExecFwk::AbilityInfoFlag::GET_ABILITY_INFO_WITH_APPLICATION, userId_, abilityInfo))) {
            TAG_LOGW(AAFwkTag::ABILITYMGR, "Query hookAbilityInfo fail");
            return false;
        }
        return true;
    }
    return false;
}

int UIAbilityLifecycleManager::ResolveAbility(
    const std::shared_ptr<AbilityRecord> &targetAbility, const AbilityRequest &abilityRequest) const
{
    TAG_LOGD(AAFwkTag::ABILITYMGR, "targetAbilityRecord resolve call record.");
    CHECK_POINTER_AND_RETURN(targetAbility, ResolveResultType::NG_INNER_ERROR);

    ResolveResultType result = targetAbility->Resolve(abilityRequest);
    switch (result) {
        case ResolveResultType::NG_INNER_ERROR:
        case ResolveResultType::OK_HAS_REMOTE_OBJ:
            return result;
        default:
            break;
    }

    if (targetAbility->IsReady()) {
        TAG_LOGD(AAFwkTag::ABILITYMGR, "targetAbility is ready, directly scheduler call request.");
        targetAbility->CallRequest();
        return ResolveResultType::OK_HAS_REMOTE_OBJ;
    }

    TAG_LOGD(AAFwkTag::ABILITYMGR, "targetAbility need to call request after lifecycle.");
    return result;
}

void UIAbilityLifecycleManager::NotifyAbilityToken(const sptr<IRemoteObject> &token,
    const AbilityRequest &abilityRequest) const
{
    auto abilityInfoCallback = iface_cast<AppExecFwk::IAbilityInfoCallback>(abilityRequest.abilityInfoCallback);
    if (abilityInfoCallback != nullptr) {
        abilityInfoCallback->NotifyAbilityToken(token, abilityRequest.want);
    }
}

void UIAbilityLifecycleManager::PrintTimeOutLog(std::shared_ptr<AbilityRecord> ability, uint32_t msgId, bool isHalf)
{
    CHECK_POINTER_LOG(ability, "null ability");
    AppExecFwk::RunningProcessInfo processInfo = {};
    DelayedSingleton<AppScheduler>::GetInstance()->GetRunningProcessInfoByToken(ability->GetToken(), processInfo);
    if (processInfo.pid_ == 0) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "ability:%{public}s, app fork fail/ not run",
            ability->GetAbilityInfo().name.data());
        return;
    }
    int typeId = AppExecFwk::AppfreezeManager::TypeAttribute::NORMAL_TIMEOUT;
    std::string msgContent = "ability:" + ability->GetAbilityInfo().name + " ";
    if (!GetContentAndTypeId(msgId, msgContent, typeId)) {
        TAG_LOGW(AAFwkTag::ABILITYMGR, "msgId invalid");
        return;
    }

    std::string eventName = isHalf ?
        AppExecFwk::AppFreezeType::LIFECYCLE_HALF_TIMEOUT : AppExecFwk::AppFreezeType::LIFECYCLE_TIMEOUT;
    TAG_LOGW(AAFwkTag::ABILITYMGR, "%{public}s: uid: %{public}d, pid: %{public}d, bundleName: %{public}s, "
        "abilityName: %{public}s, msg: %{public}s",
        eventName.c_str(), processInfo.uid_, processInfo.pid_, ability->GetAbilityInfo().bundleName.c_str(),
        ability->GetAbilityInfo().name.c_str(), msgContent.c_str());

    AppExecFwk::AppfreezeManager::ParamInfo info = {
        .typeId = typeId,
        .pid = processInfo.pid_,
        .eventName = eventName,
        .bundleName = ability->GetAbilityInfo().bundleName,
    };
    FreezeUtil::TimeoutState state = MsgId2State(msgId);
    FreezeUtil::LifecycleFlow flow;
    if (state != FreezeUtil::TimeoutState::UNKNOWN) {
        if (ability->GetToken() != nullptr) {
            flow.token = ability->GetToken()->AsObject();
            flow.state = state;
        }
        info.msg = msgContent + "\nserver actions for ability:\n" +
            FreezeUtil::GetInstance().GetLifecycleEvent(flow.token)
            + "\nserver actions for app:\n" + FreezeUtil::GetInstance().GetAppLifecycleEvent(processInfo.pid_);
        if (!isHalf) {
            FreezeUtil::GetInstance().DeleteLifecycleEvent(flow.token);
            FreezeUtil::GetInstance().DeleteAppLifecycleEvent(processInfo.pid_);
        }
    } else {
        info.msg = msgContent;
    }
    AppExecFwk::AppfreezeManager::GetInstance()->LifecycleTimeoutHandle(info, flow);
}

bool UIAbilityLifecycleManager::GetContentAndTypeId(uint32_t msgId, std::string &msgContent, int &typeId) const
{
    switch (msgId) {
        case AbilityManagerService::LOAD_TIMEOUT_MSG:
            msgContent += "load timeout.";
            typeId = AppExecFwk::AppfreezeManager::TypeAttribute::CRITICAL_TIMEOUT;
            break;
        case AbilityManagerService::FOREGROUND_TIMEOUT_MSG:
            msgContent += "foreground timeout.";
            typeId = AppExecFwk::AppfreezeManager::TypeAttribute::CRITICAL_TIMEOUT;
            break;
        case AbilityManagerService::BACKGROUND_TIMEOUT_MSG:
            msgContent += "background timeout.";
            break;
        case AbilityManagerService::TERMINATE_TIMEOUT_MSG:
            msgContent += "terminate timeout.";
            break;
        default:
            return false;
    }
    return true;
}

void UIAbilityLifecycleManager::CompleteBackground(const std::shared_ptr<AbilityRecord> &abilityRecord)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    std::lock_guard<ffrt::mutex> guard(sessionLock_);
    CHECK_POINTER(abilityRecord);
    if (abilityRecord->GetAbilityState() != AbilityState::BACKGROUNDING) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "failed, state: %{public}d, not complete background",
            abilityRecord->GetAbilityState());
        return;
    }
    abilityRecord->SetAbilityState(AbilityState::BACKGROUND);
    // notify AppMS to update application state.
    DelayedSingleton<AppScheduler>::GetInstance()->MoveToBackground(abilityRecord->GetToken());

    if (abilityRecord->GetPendingState() == AbilityState::FOREGROUND) {
        abilityRecord->PostForegroundTimeoutTask();
        abilityRecord->SetAbilityState(AbilityState::FOREGROUNDING);
        DelayedSingleton<AppScheduler>::GetInstance()->MoveToForeground(abilityRecord->GetToken());
    } else if (abilityRecord->GetPendingState() == AbilityState::BACKGROUND) {
        TAG_LOGD(AAFwkTag::ABILITYMGR, "not continuous startup.");
        abilityRecord->SetPendingState(AbilityState::INITIAL);
    }

    // new version. started by caller, scheduler call request
    if (abilityRecord->IsStartedByCall() && abilityRecord->IsStartToBackground() && abilityRecord->IsReady()) {
        TAG_LOGD(AAFwkTag::ABILITYMGR, "call request after completing background state");
        abilityRecord->CallRequest();
        abilityRecord->SetStartToBackground(false);
    }

    // Abilities ahead of the one started were put in terminate list, we need to terminate them.
    auto self(shared_from_this());
    for (auto terminateAbility : terminateAbilityList_) {
        if (terminateAbility->GetAbilityState() == AbilityState::BACKGROUND) {
            auto timeoutTask = [terminateAbility, self]() {
                TAG_LOGW(AAFwkTag::ABILITYMGR, "terminate ability timeout");
                self->DelayCompleteTerminate(terminateAbility);
            };
            terminateAbility->Terminate(timeoutTask);
        }
    }
}

int32_t UIAbilityLifecycleManager::BackToCallerAbilityWithResult(std::shared_ptr<AbilityRecord> abilityRecord,
    int resultCode, const Want *resultWant, int64_t callerRequestCode)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    std::lock_guard<ffrt::mutex> guard(sessionLock_);
    if (abilityRecord == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "null abilityRecord");
        return ERR_INVALID_VALUE;
    }
    auto requestInfo = StartupUtil::ParseFullRequestCode(callerRequestCode);
    TAG_LOGI(AAFwkTag::ABILITYMGR, "pid:%{public}d, backFlag:%{public}d, requestCode:%{public}d",
        requestInfo.pid, requestInfo.backFlag, requestInfo.requestCode);
    if (requestInfo.requestCode <= 0 || requestInfo.pid <= 0) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "no find caller by requestCode");
        return ERR_CALLER_NOT_EXISTS;
    }
    auto callerAbilityRecord = abilityRecord->GetCallerByRequestCode(requestInfo.requestCode, requestInfo.pid);
    if (callerAbilityRecord == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "caller not exist");
        return ERR_CALLER_NOT_EXISTS;
    }
    auto abilityResult = std::make_shared<AbilityResult>(requestInfo.requestCode, resultCode, *resultWant);
    callerAbilityRecord->SendResultByBackToCaller(abilityResult);
    abilityRecord->RemoveCallerRequestCode(callerAbilityRecord, requestInfo.requestCode);
    if (!requestInfo.backFlag) {
        TAG_LOGW(AAFwkTag::ABILITYMGR, "not back to caller");
        return ERR_NOT_SUPPORT_BACK_TO_CALLER;
    }
    if (callerAbilityRecord == abilityRecord) {
        TAG_LOGI(AAFwkTag::ABILITYMGR, "caller is self");
        return ERR_OK;
    }
    auto tokenId = abilityRecord->GetAbilityInfo().applicationInfo.accessTokenId;
    TAG_LOGD(AAFwkTag::ABILITYMGR, "tokenId: %{public}d.", tokenId);
    if (!abilityRecord->IsForeground() && !abilityRecord->GetAbilityForegroundingFlag() &&
        !PermissionVerification::GetInstance()->VerifyPermissionByTokenId(tokenId,
        PermissionConstants::PERMISSION_START_ABILITIES_FROM_BACKGROUND)) {
        TAG_LOGW(AAFwkTag::ABILITYMGR, "no call ability");
        return CHECK_PERMISSION_FAILED;
    }
    // find host of UI Extension
    auto foundCount = 0;
    while (((++foundCount) <= MAX_FIND_UIEXTENSION_CALLER_TIMES) && callerAbilityRecord &&
        UIExtensionUtils::IsUIExtension(callerAbilityRecord->GetAbilityInfo().extensionAbilityType)) {
        TAG_LOGI(AAFwkTag::ABILITYMGR, "caller uiExtension");
        callerAbilityRecord = callerAbilityRecord->GetCallerRecord();
    }
    return BackToCallerAbilityWithResultLocked(abilityRecord->GetSessionInfo(), callerAbilityRecord);
}

int32_t UIAbilityLifecycleManager::BackToCallerAbilityWithResultLocked(sptr<SessionInfo> currentSessionInfo,
    std::shared_ptr<AbilityRecord> callerAbilityRecord)
{
    TAG_LOGI(AAFwkTag::ABILITYMGR, "call");
    if (currentSessionInfo == nullptr || currentSessionInfo->sessionToken == nullptr) {
        TAG_LOGI(AAFwkTag::ABILITYMGR, "currentSessionInfo invalid");
        return ERR_INVALID_VALUE;
    }

    if (callerAbilityRecord == nullptr) {
        TAG_LOGI(AAFwkTag::ABILITYMGR, "callerAbility invalid");
        return ERR_INVALID_VALUE;
    }

    auto callerSessionInfo = callerAbilityRecord->GetSessionInfo();
    if (callerSessionInfo == nullptr || callerSessionInfo->sessionToken == nullptr) {
        TAG_LOGI(AAFwkTag::ABILITYMGR, "callerSessionInfo invalid");
        return ERR_INVALID_VALUE;
    }

    auto currentSession = iface_cast<Rosen::ISession>(currentSessionInfo->sessionToken);
    callerSessionInfo->isBackTransition = true;
    auto ret = static_cast<int>(currentSession->PendingSessionActivation(callerSessionInfo));
    callerSessionInfo->isBackTransition = false;
    return ret;
}

int UIAbilityLifecycleManager::CloseUIAbility(const std::shared_ptr<AbilityRecord> &abilityRecord,
    int resultCode, const Want *resultWant, bool isClearSession)
{
    TAG_LOGD(AAFwkTag::ABILITYMGR, "call");
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    std::lock_guard<ffrt::mutex> guard(sessionLock_);
    CHECK_POINTER_AND_RETURN(abilityRecord, ERR_INVALID_VALUE);
    std::string element = abilityRecord->GetElementName().GetURI();
    TAG_LOGI(AAFwkTag::ABILITYMGR, "CloseUIAbility call: %{public}s", element.c_str());
    if (abilityRecord->IsTerminating() && !abilityRecord->IsForeground()) {
        TAG_LOGI(AAFwkTag::ABILITYMGR, "ability on terminating");
        return ERR_OK;
    }
    PrepareCloseUIAbility(abilityRecord, resultCode, resultWant, isClearSession);
    if (abilityRecord->GetAbilityState() == AbilityState::INITIAL) {
        if (abilityRecord->GetScheduler() == nullptr) {
            auto handler = DelayedSingleton<AbilityManagerService>::GetInstance()->GetEventHandler();
            CHECK_POINTER_AND_RETURN_LOG(handler, ERR_INVALID_VALUE, "Fail to get AbilityEventHandler.");
            abilityRecord->RemoveLoadTimeoutTask();
        }
        terminateAbilityList_.remove(abilityRecord);
        return abilityRecord->TerminateAbility();
    }
    if (abilityRecord->IsDebug() && isClearSession) {
        TAG_LOGD(AAFwkTag::ABILITYMGR, "notify AppMS terminate");
        terminateAbilityList_.remove(abilityRecord);
        return abilityRecord->TerminateAbility();
    }
    if (abilityRecord->GetPendingState() != AbilityState::INITIAL) {
        TAG_LOGI(AAFwkTag::ABILITYMGR, "pending state: FOREGROUND/ BACKGROUND, dropped");
        abilityRecord->SetPendingState(AbilityState::BACKGROUND);
        return ERR_OK;
    }
    return CloseUIAbilityInner(abilityRecord);
}

void UIAbilityLifecycleManager::PrepareCloseUIAbility(std::shared_ptr<AbilityRecord> abilityRecord,
    int resultCode, const Want *resultWant, bool isClearSession)
{
    if (!abilityRecord) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "ability record null");
        return;
    }
    DelayedSingleton<AppScheduler>::GetInstance()->PrepareTerminate(abilityRecord->GetToken(), isClearSession);
    abilityRecord->SetTerminatingState();
    abilityRecord->SetClearMissionFlag(isClearSession);
    // save result to caller AbilityRecord
    if (resultWant != nullptr) {
        Want* newWant = const_cast<Want*>(resultWant);
        newWant->RemoveParam(Want::PARAM_RESV_CALLER_TOKEN);
        abilityRecord->SaveResultToCallers(resultCode, newWant);
    } else {
        Want want;
        abilityRecord->SaveResultToCallers(-1, &want);
    }
    EraseAbilityRecord(abilityRecord);
    abilityRecord->SendResultToCallers();
    terminateAbilityList_.push_back(abilityRecord);
}

int UIAbilityLifecycleManager::CloseUIAbilityInner(std::shared_ptr<AbilityRecord> abilityRecord)
{
    CHECK_POINTER_AND_RETURN(abilityRecord, ERR_INVALID_VALUE);
    if (abilityRecord->IsAbilityState(FOREGROUND) || abilityRecord->IsAbilityState(FOREGROUNDING)) {
        abilityRecord->SetPendingState(AbilityState::BACKGROUND);
        MoveToBackground(abilityRecord);
        return ERR_OK;
    }
    // ability on background, schedule to terminate.
    if (abilityRecord->GetAbilityState() == AbilityState::BACKGROUND) {
        auto self(shared_from_this());
        auto task = [abilityRecord, self]() {
            TAG_LOGW(AAFwkTag::ABILITYMGR, "close ability by scb timeout");
            self->DelayCompleteTerminate(abilityRecord);
        };
        abilityRecord->Terminate(task);
    }
    return ERR_OK;
}

void UIAbilityLifecycleManager::DelayCompleteTerminate(const std::shared_ptr<AbilityRecord> &abilityRecord)
{
    auto handler = DelayedSingleton<AbilityManagerService>::GetInstance()->GetTaskHandler();
    CHECK_POINTER(handler);

    PrintTimeOutLog(abilityRecord, AbilityManagerService::TERMINATE_TIMEOUT_MSG);

    auto timeoutTask = [self = shared_from_this(), abilityRecord]() {
        TAG_LOGI(AAFwkTag::ABILITYMGR, "delay complete terminate task");
        self->CompleteTerminate(abilityRecord);
    };
    int killTimeout = AmsConfigurationParameter::GetInstance().GetAppStartTimeoutTime() * KILL_TIMEOUT_MULTIPLE;
    handler->SubmitTaskJust(timeoutTask, "DELAY_KILL_PROCESS", killTimeout);
}

void UIAbilityLifecycleManager::CompleteTerminate(const std::shared_ptr<AbilityRecord> &abilityRecord)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    std::lock_guard<ffrt::mutex> guard(sessionLock_);

    CompleteTerminateLocked(abilityRecord);
}

void UIAbilityLifecycleManager::CompleteTerminateLocked(const std::shared_ptr<AbilityRecord> &abilityRecord)
{
    CHECK_POINTER(abilityRecord);
    if (abilityRecord->GetAbilityState() != AbilityState::TERMINATING) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "failed, %{public}s, ability not terminating", __func__);
        return;
    }
    abilityRecord->RemoveAbilityDeathRecipient();

    // notify AppMS terminate
    if (abilityRecord->TerminateAbility() != ERR_OK) {
        // Don't return here
        TAG_LOGE(AAFwkTag::ABILITYMGR, "appMS fail to terminate ability");
    }
    terminateAbilityList_.remove(abilityRecord);
}

int32_t UIAbilityLifecycleManager::GetPersistentIdByAbilityRequest(const AbilityRequest &abilityRequest,
    bool &reuse) const
{
    if (abilityRequest.collaboratorType != CollaboratorType::DEFAULT_TYPE) {
        return GetReusedCollaboratorPersistentId(abilityRequest, reuse);
    }

    if (abilityRequest.abilityInfo.launchMode == AppExecFwk::LaunchMode::SPECIFIED) {
        return GetReusedSpecifiedPersistentId(abilityRequest, reuse);
    }

    if (abilityRequest.abilityInfo.launchMode == AppExecFwk::LaunchMode::STANDARD) {
        return GetReusedStandardPersistentId(abilityRequest, reuse);
    }

    if (abilityRequest.abilityInfo.launchMode != AppExecFwk::LaunchMode::SINGLETON) {
        TAG_LOGW(AAFwkTag::ABILITYMGR, "launch not singleton");
        return 0;
    }

    reuse = true;
    for (const auto& [first, second] : sessionAbilityMap_) {
        if (CheckProperties(second, abilityRequest, AppExecFwk::LaunchMode::SINGLETON)) {
            TAG_LOGD(AAFwkTag::ABILITYMGR, "SINGLETON: find.");
            return first;
        }
    }

    TAG_LOGD(AAFwkTag::ABILITYMGR, "Not find existed ui ability.");
    return 0;
}

int32_t UIAbilityLifecycleManager::GetReusedSpecifiedPersistentId(const AbilityRequest &abilityRequest,
    bool &reuse) const
{
    TAG_LOGD(AAFwkTag::ABILITYMGR, "Call.");
    if (abilityRequest.abilityInfo.launchMode != AppExecFwk::LaunchMode::SPECIFIED) {
        TAG_LOGW(AAFwkTag::ABILITYMGR, "not SPECIFIED");
        return 0;
    }

    reuse = true;
    // specified ability name and bundle name and module name and appIndex format is same as singleton.
    for (const auto& [first, second] : sessionAbilityMap_) {
        if (second->GetSpecifiedFlag() == abilityRequest.specifiedFlag &&
            CheckProperties(second, abilityRequest, AppExecFwk::LaunchMode::SPECIFIED)) {
            TAG_LOGD(AAFwkTag::ABILITYMGR, "SPECIFIED: find.");
            return first;
        }
    }
    return 0;
}

int32_t UIAbilityLifecycleManager::GetReusedStandardPersistentId(const AbilityRequest &abilityRequest,
    bool &reuse) const
{
    TAG_LOGD(AAFwkTag::ABILITYMGR, "Call.");
    if (abilityRequest.abilityInfo.launchMode != AppExecFwk::LaunchMode::STANDARD) {
        TAG_LOGW(AAFwkTag::ABILITYMGR, "not STANDARD");
        return 0;
    }

    if (!abilityRequest.startRecent) {
        TAG_LOGW(AAFwkTag::ABILITYMGR, "startRecent false");
        return 0;
    }

    reuse = true;
    int64_t sessionTime = 0;
    int32_t persistentId = 0;
    for (const auto& [first, second] : sessionAbilityMap_) {
        if (CheckProperties(second, abilityRequest, AppExecFwk::LaunchMode::STANDARD) &&
            second->GetRestartTime() >= sessionTime) {
            persistentId = first;
            sessionTime = second->GetRestartTime();
        }
    }
    return persistentId;
}

int32_t UIAbilityLifecycleManager::GetReusedCollaboratorPersistentId(const AbilityRequest &abilityRequest,
    bool &reuse) const
{
    TAG_LOGD(AAFwkTag::ABILITYMGR, "Call.");

    reuse = false;
    int64_t sessionTime = 0;
    int32_t persistentId = 0;
    for (const auto& [first, second] : sessionAbilityMap_) {
        if (second->GetCollaboratorType() != CollaboratorType::DEFAULT_TYPE &&
            abilityRequest.want.GetStringParam(PARAM_MISSION_AFFINITY_KEY) == second->GetMissionAffinity() &&
            second->GetRestartTime() >= sessionTime) {
            reuse = true;
            persistentId = first;
            sessionTime = second->GetRestartTime();
        }
    }
    return persistentId;
}

bool UIAbilityLifecycleManager::CheckProperties(const std::shared_ptr<AbilityRecord> &abilityRecord,
    const AbilityRequest &abilityRequest, AppExecFwk::LaunchMode launchMode) const
{
    CHECK_POINTER_RETURN_BOOL(abilityRecord);
    const auto& abilityInfo = abilityRecord->GetAbilityInfo();
    int32_t appIndex = 0;
    (void)AbilityRuntime::StartupUtil::GetAppIndex(abilityRequest.want, appIndex);
    auto instanceKey = abilityRequest.want.GetStringParam(Want::APP_INSTANCE_KEY);
    return abilityInfo.launchMode == launchMode && abilityRequest.abilityInfo.name == abilityInfo.name &&
        abilityRequest.abilityInfo.bundleName == abilityInfo.bundleName &&
        abilityRequest.abilityInfo.moduleName == abilityInfo.moduleName &&
        appIndex == abilityRecord->GetAppIndex() && instanceKey == abilityRecord->GetInstanceKey();
}

void UIAbilityLifecycleManager::OnTimeOut(uint32_t msgId, int64_t abilityRecordId, bool isHalf)
{
    TAG_LOGD(AAFwkTag::ABILITYMGR, "call, msgId is %{public}d", msgId);
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    std::lock_guard<ffrt::mutex> guard(sessionLock_);
    std::shared_ptr<AbilityRecord> abilityRecord;
    for (auto iter = sessionAbilityMap_.begin(); iter != sessionAbilityMap_.end(); iter++) {
        if (iter->second != nullptr && iter->second->GetAbilityRecordId() == abilityRecordId) {
            abilityRecord = iter->second;
            break;
        }
    }
    if (abilityRecord == nullptr) {
        for (auto abilityIter : terminateAbilityList_) {
            if (abilityIter && abilityIter->GetAbilityRecordId() == abilityRecordId) {
                abilityRecord = abilityIter;
                break;
            }
        }
        if (abilityRecord == nullptr) {
            TAG_LOGE(AAFwkTag::ABILITYMGR, "null ability record");
            return;
        }
    }
    TAG_LOGD(AAFwkTag::ABILITYMGR, "call, msgId:%{public}d, name:%{public}s", msgId,
        abilityRecord->GetAbilityInfo().name.c_str());
    PrintTimeOutLog(abilityRecord, msgId, isHalf);
    if (isHalf) {
        return;
    }
    switch (msgId) {
        case AbilityManagerService::LOAD_TIMEOUT_MSG:
            abilityRecord->SetLoading(false);
            HandleLoadTimeout(abilityRecord);
            break;
        case AbilityManagerService::FOREGROUND_TIMEOUT_MSG:
            HandleForegroundTimeout(abilityRecord);
            break;
        default:
            break;
    }
}

void UIAbilityLifecycleManager::SetRootSceneSession(const sptr<IRemoteObject> &rootSceneSession)
{
    TAG_LOGD(AAFwkTag::ABILITYMGR, "call");
    auto tmpSceneSession = iface_cast<Rosen::ISession>(rootSceneSession);
    if (tmpSceneSession == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "rootSceneSession invalid");
        return;
    }
    rootSceneSession_ = rootSceneSession;
}

void UIAbilityLifecycleManager::NotifySCBToHandleException(const std::shared_ptr<AbilityRecord> &abilityRecord,
    int32_t errorCode, const std::string& errorReason, bool needClearCallerLink)
{
    TAG_LOGD(AAFwkTag::ABILITYMGR, "call");
    if (abilityRecord == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "null ability record");
        return;
    }
    auto sessionInfo = abilityRecord->GetSessionInfo();
    CHECK_POINTER(sessionInfo);
    CHECK_POINTER(sessionInfo->sessionToken);
    auto session = iface_cast<Rosen::ISession>(sessionInfo->sessionToken);
    CHECK_POINTER(session);
    TAG_LOGI(AAFwkTag::ABILITYMGR, "scb call, NotifySCBToHandleException reason: %{public}s", errorReason.c_str());
    sptr<SessionInfo> info = abilityRecord->GetSessionInfo();
    info->errorCode = errorCode;
    info->errorReason = errorReason;
    Rosen::ExceptionInfo exceptionInfo;
    exceptionInfo.needClearCallerLink = needClearCallerLink;
    session->NotifySessionException(info, exceptionInfo);
    EraseAbilityRecord(abilityRecord);
}

void UIAbilityLifecycleManager::NotifySCBToHandleAtomicServiceException(sptr<SessionInfo> sessionInfo,
    int32_t errorCode, const std::string& errorReason)
{
    TAG_LOGD(AAFwkTag::ABILITYMGR, "call");
    CHECK_POINTER(sessionInfo);
    CHECK_POINTER(sessionInfo->sessionToken);
    auto session = iface_cast<Rosen::ISession>(sessionInfo->sessionToken);
    CHECK_POINTER(session);
    TAG_LOGI(AAFwkTag::ABILITYMGR,
        "call notifySessionException, errorReason: %{public}s", errorReason.c_str());
    sessionInfo->errorCode = errorCode;
    sessionInfo->errorReason = errorReason;
    Rosen::ExceptionInfo exceptionInfo;
    session->NotifySessionException(sessionInfo, exceptionInfo);
}

void UIAbilityLifecycleManager::HandleLoadTimeout(const std::shared_ptr<AbilityRecord> &abilityRecord)
{
    TAG_LOGD(AAFwkTag::ABILITYMGR, "call");
    if (abilityRecord == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "null ability record");
        return;
    }
    NotifySCBToHandleException(abilityRecord,
        static_cast<int32_t>(ErrorLifecycleState::ABILITY_STATE_LOAD_TIMEOUT), "handleLoadTimeout");
    DelayedSingleton<AppScheduler>::GetInstance()->AttachTimeOut(abilityRecord->GetToken());
}

void UIAbilityLifecycleManager::HandleForegroundTimeout(const std::shared_ptr<AbilityRecord> &abilityRecord)
{
    TAG_LOGD(AAFwkTag::ABILITYMGR, "call");
    if (abilityRecord == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "null ability record");
        return;
    }
    if (!abilityRecord->IsAbilityState(AbilityState::FOREGROUNDING)) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "ability not foregrounding");
        return;
    }
    NotifySCBToHandleException(abilityRecord,
        static_cast<int32_t>(ErrorLifecycleState::ABILITY_STATE_FOREGROUND_TIMEOUT), "handleForegroundTimeout");
    DelayedSingleton<AppScheduler>::GetInstance()->AttachTimeOut(abilityRecord->GetToken());
}

void UIAbilityLifecycleManager::OnAbilityDied(std::shared_ptr<AbilityRecord> abilityRecord)
{
    TAG_LOGD(AAFwkTag::ABILITYMGR, "call OnAbilityDied");
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    CancelPrepareTerminate(abilityRecord);
    std::lock_guard<ffrt::mutex> guard(sessionLock_);
    if (abilityRecord == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "null ability record");
        return;
    }
    auto handler = DelayedSingleton<AbilityManagerService>::GetInstance()->GetEventHandler();
    CHECK_POINTER_LOG(handler, "Fail to get AbilityEventHandler.");
    if (abilityRecord->GetAbilityState() == AbilityState::INITIAL) {
        abilityRecord->RemoveLoadTimeoutTask();
        abilityRecord->SetLoading(false);
    }
    if (abilityRecord->GetAbilityState() == AbilityState::FOREGROUNDING) {
        abilityRecord->RemoveForegroundTimeoutTask();
    }
    auto taskHandler = DelayedSingleton<AbilityManagerService>::GetInstance()->GetTaskHandler();
    CHECK_POINTER_LOG(taskHandler, "Get AbilityTaskHandler failed.");
    if (abilityRecord->GetAbilityState() == AbilityState::BACKGROUNDING) {
        taskHandler->CancelTask("background_" + std::to_string(abilityRecord->GetAbilityRecordId()));
    }

    terminateAbilityList_.push_back(abilityRecord);
    abilityRecord->SetAbilityState(AbilityState::TERMINATING);
    if (abilityRecord->GetKillForPermissionUpdateFlag()) {
        bool needClearCallerLink = false;
        NotifySCBToHandleException(abilityRecord,
            static_cast<int32_t>(ErrorLifecycleState::ABILITY_STATE_PERMISSION_UPDATE),
            "kill process for permission update", needClearCallerLink);
    } else if (abilityRecord->GetKillReason() == GlobalConstant::LOW_MEMORY_KILL) {
        TAG_LOGI(AAFwkTag::ABILITYMGR, "kill by low memory");
        NotifySCBToHandleException(abilityRecord,
            static_cast<int32_t>(ErrorLifecycleState::ABILITY_STATE_LOW_MEMORY_KILL),
            abilityRecord->GetKillReason());
    } else if (!abilityRecord->GetRestartAppFlag()) {
        NotifySCBToHandleException(abilityRecord, static_cast<int32_t>(ErrorLifecycleState::ABILITY_STATE_DIED),
            "onAbilityDied");
    }
    DelayedSingleton<AppScheduler>::GetInstance()->AttachTimeOut(abilityRecord->GetToken());
    DispatchTerminate(abilityRecord);
}

void UIAbilityLifecycleManager::OnAcceptWantResponse(const AAFwk::Want &want, const std::string &flag,
    int32_t requestId)
{
    TAG_LOGI(AAFwkTag::ABILITYMGR, "OnAcceptWantResponse, %{public}d", requestId);
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    std::lock_guard guard(sessionLock_);
    auto iter = hookSpecifiedMap_.find(requestId);
    if (iter != hookSpecifiedMap_.end() && iter->second != nullptr) {
        auto abilityRecord = iter->second;
        abilityRecord->SetSpecifiedFlag(flag);
        auto sessionInfo = abilityRecord->GetSessionInfo();
        CHECK_POINTER(sessionInfo);
        sessionInfo->reuseDelegatorWindow = true;
        AbilityRequest request;
        request.callerToken = abilityRecord->GetToken();
        int ret = NotifySCBPendingActivation(sessionInfo, request);
        if (ret == ERR_OK) {
            abilityRecord->SetHookOff(true);
            abilityRecord->SetIsHook(false);
        }
        sessionInfo->reuseDelegatorWindow = false;
        hookSpecifiedMap_.erase(iter);
        return;
    }
    auto request = GetSpecifiedRequest(requestId);
    if (request == nullptr) {
        TAG_LOGW(AAFwkTag::ABILITYMGR, "no request");
        return;
    }
    auto nextRequest = PopAndGetNextSpecified(requestId);
    if (nextRequest) {
        TaskHandlerWrap::GetFfrtHandler()->SubmitTask([nextRequest, pThis = shared_from_this()]() {
            std::lock_guard lock(pThis->sessionLock_);
            pThis->StartSpecifiedRequest(*nextRequest);
            });
    }
    if (request->isCold) {
        if (request->persistentId == 0) {
            TAG_LOGW(AAFwkTag::ABILITYMGR, "persistentId error for: %{public}d", requestId);
            PutSpecifiedFlag(requestId, flag);
            return;
        }
        if (HandleColdAcceptWantDone(want, flag, *request)) {
            return;
        }
    }

    HandleLegacyAcceptWantDone(request->abilityRequest, requestId, flag, want);
}

void UIAbilityLifecycleManager::HandleLegacyAcceptWantDone(AbilityRequest &abilityRequest, int32_t requestId,
    const std::string &flag, const AAFwk::Want &want)
{
    TAG_LOGI(AAFwkTag::ABILITYMGR, "%{public}s", want.GetElement().GetURI().c_str());
    auto callerAbility = GetAbilityRecordByToken(abilityRequest.callerToken);
    if (!flag.empty()) {
        abilityRequest.specifiedFlag = flag;
        bool reuse = false;
        auto persistentId = GetReusedSpecifiedPersistentId(abilityRequest, reuse);
        if (persistentId != 0) {
            std::shared_ptr<AbilityRecord> abilityRecord = nullptr;
            auto iter = sessionAbilityMap_.find(persistentId);
            if (iter == sessionAbilityMap_.end()) {
                TAG_LOGE(AAFwkTag::ABILITYMGR, "OnAcceptWantResponse Unexpected Error");
                return;
            }
            TAG_LOGI(AAFwkTag::ABILITYMGR, "find specified ability, session:%{public}d", persistentId);
            abilityRecord = iter->second;
            CHECK_POINTER_LOG(abilityRecord, "OnAcceptWantResponse abilityRecord null");
            abilityRecord->SetWant(abilityRequest.want);
            abilityRecord->SetIsNewWant(true);
            UpdateAbilityRecordLaunchReason(abilityRequest, abilityRecord);
            MoveAbilityToFront(abilityRequest, abilityRecord, callerAbility);
            NotifyRestartSpecifiedAbility(abilityRequest, abilityRecord->GetToken());
            return;
        }
    }
    NotifyStartSpecifiedAbility(abilityRequest, want);
    StartAbilityBySpecifed(abilityRequest, callerAbility, requestId, flag);
}

void UIAbilityLifecycleManager::OnStartSpecifiedAbilityTimeoutResponse(int32_t requestId)
{
    TAG_LOGI(AAFwkTag::ABILITYMGR, "SpecifiedAbilityTimeout %{public}d", requestId);
    OnStartSpecifiedFailed(requestId);
}

void UIAbilityLifecycleManager::OnStartSpecifiedFailed(int32_t requestId)
{
    std::lock_guard lock(sessionLock_);
    auto iter = hookSpecifiedMap_.find(requestId);
    if (iter != hookSpecifiedMap_.end() && iter->second != nullptr) {
        std::shared_ptr<AbilityRecord> abilityRecord = iter->second;
        NotifySCBToHandleException(abilityRecord,
            static_cast<int32_t>(ErrorLifecycleState::ABILITY_STATE_LOAD_TIMEOUT), "handleLoadTimeout");
        hookSpecifiedMap_.erase(iter);
        return;
    }
    auto curRequest = GetSpecifiedRequest(requestId);
    if (curRequest == nullptr) {
        return;
    }
    TAG_LOGI(AAFwkTag::ABILITYMGR, "OnStartSpecifiedFailed %{public}d", requestId);
    if (curRequest->persistentId != 0) {
        auto iter = sessionAbilityMap_.find(curRequest->persistentId);
        if (iter != sessionAbilityMap_.end() && iter->second != nullptr) {
            auto abilityRecord = iter->second;
            NotifySCBToHandleException(abilityRecord,
                static_cast<int32_t>(ErrorLifecycleState::ABILITY_STATE_LOAD_TIMEOUT), "handleLoadTimeout");
        }
    }

    auto nextRequest = PopAndGetNextSpecified(requestId);
    if (nextRequest) {
        StartSpecifiedRequest(*nextRequest);
    }
}

void UIAbilityLifecycleManager::OnStartSpecifiedProcessResponse(const std::string &flag, int32_t requestId)
{
    TAG_LOGI(AAFwkTag::ABILITYMGR, "OnStartSpecifiedProcessResponse, %{public}d", requestId);
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    std::lock_guard guard(sessionLock_);
    auto request = GetSpecifiedRequest(requestId);
    if (request == nullptr) {
        TAG_LOGW(AAFwkTag::ABILITYMGR, "no request");
        return;
    }

    auto &abilityRequest = request->abilityRequest;
    abilityRequest.want.SetParam(PARAM_SPECIFIED_PROCESS_FLAG, flag);
    if (abilityRequest.abilityInfo.launchMode == AppExecFwk::LaunchMode::SPECIFIED) {
        request->specifiedProcessState = SpecifiedProcessState::STATE_ABILITY;
        StartSpecifiedRequest(*request);
        return;
    }
    auto nextRequest = PopAndGetNextSpecified(requestId);
    if (nextRequest) {
        TaskHandlerWrap::GetFfrtHandler()->SubmitTask([nextRequest, pThis = shared_from_this()]() {
            std::lock_guard lock(pThis->sessionLock_);
            pThis->StartSpecifiedRequest(*nextRequest);
            });
    }
    auto sessionInfo = CreateSessionInfo(abilityRequest);
    sessionInfo->requestCode = abilityRequest.requestCode;
    sessionInfo->persistentId = GetPersistentIdByAbilityRequest(abilityRequest, sessionInfo->reuse);
    sessionInfo->userId = abilityRequest.userId;
    sessionInfo->isAtomicService =
        (abilityRequest.abilityInfo.applicationInfo.bundleType == AppExecFwk::BundleType::ATOMIC_SERVICE);
    TAG_LOGI(AAFwkTag::ABILITYMGR, "reused sessionId: %{public}d, userId: %{public}d", sessionInfo->persistentId,
        abilityRequest.userId);
    NotifySCBPendingActivation(sessionInfo, abilityRequest);
}

void UIAbilityLifecycleManager::OnStartSpecifiedProcessTimeoutResponse(int32_t requestId)
{
    TAG_LOGI(AAFwkTag::ABILITYMGR, "OnStartSpecifiedProcessTimeoutResponse %{public}d", requestId);
    std::lock_guard guard(sessionLock_);
    auto nextRequest = PopAndGetNextSpecified(requestId);
    if (nextRequest) {
        StartSpecifiedRequest(*nextRequest);
    }
}

bool UIAbilityLifecycleManager::StartSpecifiedProcessRequest(const AbilityRequest &abilityRequest)
{
    const auto &abilityInfo = abilityRequest.abilityInfo;
    if (!abilityInfo.isolationProcess) {
        return false;
    }
    if (!AppUtils::GetInstance().IsStartSpecifiedProcess()) {
        return false;
    }
    bool isUIAbility = (abilityInfo.type == AppExecFwk::AbilityType::PAGE && abilityInfo.isStageBasedModel);
    if (!isUIAbility) {
        return false;
    }
    // When 'processMode' is set to new process mode, the priority is higher than 'isolationProcess'.
    bool isNewProcessMode = abilityRequest.processOptions &&
        ProcessOptions::IsNewProcessMode(abilityRequest.processOptions->processMode);
    if (isNewProcessMode) {
        return false;
    }
    bool isPlugin = StartupUtil::IsStartPlugin(abilityRequest.want);
    if (isPlugin) {
        return false;
    }
    auto requestId = GetRequestId();
    TAG_LOGI(AAFwkTag::ABILITYMGR, "StartSpecifiedProcess, requestId:%{public}d", requestId);
    auto specifiedRequest = std::make_shared<SpecifiedRequest>(requestId, abilityRequest);
    specifiedRequest->specifiedProcessState = SpecifiedProcessState::STATE_PROCESS;
    AddSpecifiedRequest(specifiedRequest);
    return true;
}

void UIAbilityLifecycleManager::StartSpecifiedAbilityBySCB(const Want &want)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    TAG_LOGD(AAFwkTag::ABILITYMGR, "call");
    AbilityRequest abilityRequest;
    int result = DelayedSingleton<AbilityManagerService>::GetInstance()->GenerateAbilityRequest(
        want, DEFAULT_INVAL_VALUE, abilityRequest, nullptr, userId_);
    if (result != ERR_OK) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "no find request");
        return;
    }
    abilityRequest.isFromIcon = true;
    std::lock_guard guard(sessionLock_);
    // support specified process mode
    if (StartSpecifiedProcessRequest(abilityRequest)) {
        return;
    }
    AddSpecifiedRequest(std::make_shared<SpecifiedRequest>(GetRequestId(), abilityRequest));
}

void UIAbilityLifecycleManager::NotifyRestartSpecifiedAbility(const AbilityRequest &request,
    const sptr<IRemoteObject> &token)
{
    if (request.abilityInfoCallback == nullptr) {
        return;
    }
    sptr<AppExecFwk::IAbilityInfoCallback> abilityInfoCallback
        = iface_cast<AppExecFwk::IAbilityInfoCallback> (request.abilityInfoCallback);
    if (abilityInfoCallback != nullptr) {
        TAG_LOGD(AAFwkTag::ABILITYMGR, "called");
        abilityInfoCallback->NotifyRestartSpecifiedAbility(token);
    }
}

void UIAbilityLifecycleManager::NotifyStartSpecifiedAbility(AbilityRequest &abilityRequest, const AAFwk::Want &want)
{
    if (abilityRequest.abilityInfoCallback == nullptr) {
        return;
    }

    sptr<AppExecFwk::IAbilityInfoCallback> abilityInfoCallback
        = iface_cast<AppExecFwk::IAbilityInfoCallback> (abilityRequest.abilityInfoCallback);
    if (abilityInfoCallback != nullptr) {
        Want newWant = want;
        int32_t type = static_cast<int32_t>(abilityRequest.abilityInfo.type);
        newWant.SetParam("abilityType", type);
        sptr<Want> extraParam = new (std::nothrow) Want();
        CHECK_POINTER(extraParam);
        abilityInfoCallback->NotifyStartSpecifiedAbility(abilityRequest.callerToken, newWant,
            abilityRequest.requestCode, extraParam);
        int32_t procCode = extraParam->GetIntParam(Want::PARAM_RESV_REQUEST_PROC_CODE, 0);
        if (procCode != 0) {
            abilityRequest.want.SetParam(Want::PARAM_RESV_REQUEST_PROC_CODE, procCode);
        }
        int32_t tokenCode = extraParam->GetIntParam(Want::PARAM_RESV_REQUEST_TOKEN_CODE, 0);
        if (tokenCode != 0) {
            abilityRequest.want.SetParam(Want::PARAM_RESV_REQUEST_TOKEN_CODE, tokenCode);
        }
    }
}

int UIAbilityLifecycleManager::MoveAbilityToFront(const AbilityRequest &abilityRequest,
    const std::shared_ptr<AbilityRecord> &abilityRecord, std::shared_ptr<AbilityRecord> callerAbility,
    std::shared_ptr<StartOptions> startOptions)
{
    TAG_LOGD(AAFwkTag::ABILITYMGR, "call");
    if (!abilityRecord) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "ability record failed");
        return ERR_INVALID_VALUE;
    }
    sptr<SessionInfo> sessionInfo = abilityRecord->GetSessionInfo();
    CHECK_POINTER_AND_RETURN(sessionInfo, ERR_INVALID_VALUE);
    sessionInfo->want = abilityRequest.want;
    sessionInfo->callerToken = abilityRequest.callerToken;
    sessionInfo->requestCode = abilityRequest.requestCode;
    sessionInfo->processOptions = nullptr;
    if (AppUtils::GetInstance().IsStartOptionsWithProcessOptions() &&
        abilityRequest.abilityInfo.launchMode == AppExecFwk::LaunchMode::SPECIFIED) {
        sessionInfo->processOptions = abilityRequest.processOptions;
    }
    sessionInfo->startWindowOption = nullptr;
    sessionInfo->isFromIcon = abilityRequest.isFromIcon;
    SendSessionInfoToSCB(callerAbility, sessionInfo);
    abilityRecord->RemoveWindowMode();
    if (startOptions != nullptr) {
        abilityRecord->SetWindowMode(startOptions->GetWindowMode());
    }
    return ERR_OK;
}

int UIAbilityLifecycleManager::SendSessionInfoToSCB(std::shared_ptr<AbilityRecord> &callerAbility,
    sptr<SessionInfo> &sessionInfo)
{
    CHECK_POINTER_AND_RETURN(sessionInfo, ERR_INVALID_VALUE);
    TAG_LOGD(AAFwkTag::ABILITYMGR, "call"
        "windowLeft=%{public}d,windowTop=%{public}d,"
        "windowHeight=%{public}d,windowWidth=%{public}d,"
        "minWindowWidth=%{public}d,minWindowHeight=%{public}d,"
        "maxWindowWidth=%{public}d,mixWindowHeight=%{public}d,"
        "specifiedFlag=%{public}s",
        (sessionInfo->want).GetIntParam(Want::PARAM_RESV_WINDOW_LEFT, 0),
        (sessionInfo->want).GetIntParam(Want::PARAM_RESV_WINDOW_TOP, 0),
        (sessionInfo->want).GetIntParam(Want::PARAM_RESV_WINDOW_HEIGHT, 0),
        (sessionInfo->want).GetIntParam(Want::PARAM_RESV_WINDOW_WIDTH, 0),
        (sessionInfo->want).GetIntParam(Want::PARAM_RESV_MIN_WINDOW_WIDTH, 0),
        (sessionInfo->want).GetIntParam(Want::PARAM_RESV_MIN_WINDOW_HEIGHT, 0),
        (sessionInfo->want).GetIntParam(Want::PARAM_RESV_MAX_WINDOW_WIDTH, 0),
        (sessionInfo->want).GetIntParam(Want::PARAM_RESV_MAX_WINDOW_HEIGHT, 0),
        sessionInfo->specifiedFlag.c_str());
    auto tmpSceneSession = iface_cast<Rosen::ISession>(rootSceneSession_);
    if (callerAbility != nullptr) {
        auto callerSessionInfo = callerAbility->GetSessionInfo();
        if (callerSessionInfo != nullptr && callerSessionInfo->sessionToken != nullptr) {
            auto callerSession = iface_cast<Rosen::ISession>(callerSessionInfo->sessionToken);
            CHECK_POINTER_AND_RETURN(callerSession, ERR_INVALID_VALUE);
            CheckCallerFromBackground(callerAbility, sessionInfo);
            TAG_LOGI(AAFwkTag::ABILITYMGR, "scb call, NotifySCBPendingActivation for callerSession, target: %{public}s",
                sessionInfo->want.GetElement().GetAbilityName().c_str());
            callerSession->PendingSessionActivation(sessionInfo);
        } else {
            CHECK_POINTER_AND_RETURN(tmpSceneSession, ERR_INVALID_VALUE);
            sessionInfo->canStartAbilityFromBackground = true;
            TAG_LOGI(AAFwkTag::ABILITYMGR, "NotifySCBPendingActivation for rootSceneSession, target:%{public}s",
                sessionInfo->want.GetElement().GetAbilityName().c_str());
            tmpSceneSession->PendingSessionActivation(sessionInfo);
        }
    } else {
        CHECK_POINTER_AND_RETURN(tmpSceneSession, ERR_INVALID_VALUE);
        sessionInfo->canStartAbilityFromBackground = true;
        TAG_LOGI(AAFwkTag::ABILITYMGR, "scb call, NotifySCBPendingActivation for rootSceneSession, target: %{public}s",
            sessionInfo->want.GetElement().GetAbilityName().c_str());
        tmpSceneSession->PendingSessionActivation(sessionInfo);
    }
    return ERR_OK;
}

int UIAbilityLifecycleManager::StartAbilityBySpecifed(const AbilityRequest &abilityRequest,
    std::shared_ptr<AbilityRecord> &callerAbility, int32_t requestId, const std::string &flag)
{
    TAG_LOGD(AAFwkTag::ABILITYMGR, "call");
    sptr<SessionInfo> sessionInfo = new SessionInfo();
    sessionInfo->callerToken = abilityRequest.callerToken;
    sessionInfo->want = abilityRequest.want;
    sessionInfo->requestCode = abilityRequest.requestCode;
    sessionInfo->processOptions = abilityRequest.processOptions;
    sessionInfo->startWindowOption = abilityRequest.startWindowOption;
    sessionInfo->instanceKey = abilityRequest.want.GetStringParam(Want::APP_INSTANCE_KEY);
    sessionInfo->isFromIcon = abilityRequest.isFromIcon;
    sessionInfo->requestId = requestId;
    sessionInfo->specifiedFlag = flag;
    TAG_LOGI(AAFwkTag::ABILITYMGR, "specified flag:%{public}s", flag.c_str());
    PutSpecifiedFlag(requestId, abilityRequest.specifiedFlag);
    SendSessionInfoToSCB(callerAbility, sessionInfo);
    return ERR_OK;
}

void UIAbilityLifecycleManager::CallRequestDone(const std::shared_ptr<AbilityRecord> &abilityRecord,
    const sptr<IRemoteObject> &callStub)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    std::lock_guard<ffrt::mutex> guard(sessionLock_);
    if (abilityRecord == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "null ability record");
        return;
    }
    if (callStub == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "null call stub");
        return;
    }
    abilityRecord->CallRequestDone(callStub);

    auto iter = callRequestCache_.find(abilityRecord);
    if (iter == callRequestCache_.end()) {
        return;
    }
    auto requestList = std::move(iter->second);
    callRequestCache_.erase(iter);
    auto taskHandler = DelayedSingleton<AbilityManagerService>::GetInstance()->GetTaskHandler();
    if (taskHandler == nullptr) {
        return;
    }
    auto wThis = weak_from_this();
    for (const auto &request : requestList) {
        auto task = [request, wThis]() {
            auto pThis = wThis.lock();
            if (pThis) {
                pThis->CallAbilityLocked(request);
            }
        };
        taskHandler->SubmitTask(task);
    }
}

int UIAbilityLifecycleManager::ReleaseCallLocked(
    const sptr<IAbilityConnection> &connect, const AppExecFwk::ElementName &element)
{
    TAG_LOGD(AAFwkTag::ABILITYMGR, "release call ability.");
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    CHECK_POINTER_AND_RETURN(connect, ERR_INVALID_VALUE);
    CHECK_POINTER_AND_RETURN(connect->AsObject(), ERR_INVALID_VALUE);

    std::lock_guard<ffrt::mutex> guard(sessionLock_);

    auto abilityRecords = GetAbilityRecordsByNameInner(element);
    auto isExist = [connect] (const std::shared_ptr<AbilityRecord> &abilityRecord) {
        if (abilityRecord == nullptr) {
            return false;
        }
        return abilityRecord->IsExistConnection(connect);
    };
    auto findRecord = std::find_if(abilityRecords.begin(), abilityRecords.end(), isExist);
    if (findRecord == abilityRecords.end()) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "not find record");
        return RELEASE_CALL_ABILITY_INNER_ERR;
    }
    auto abilityRecord = *findRecord;
    CHECK_POINTER_AND_RETURN(abilityRecord, RELEASE_CALL_ABILITY_INNER_ERR);

    if (!abilityRecord->ReleaseCall(connect)) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "ability release call failed");
        return RELEASE_CALL_ABILITY_INNER_ERR;
    }
    return ERR_OK;
}

void UIAbilityLifecycleManager::OnCallConnectDied(const std::shared_ptr<CallRecord> &callRecord)
{
    TAG_LOGI(AAFwkTag::ABILITYMGR, "on callConnect died");
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    CHECK_POINTER(callRecord);
    std::lock_guard<ffrt::mutex> guard(sessionLock_);

    AppExecFwk::ElementName element = callRecord->GetTargetServiceName();
    auto abilityRecords = GetAbilityRecordsByNameInner(element);
    auto isExist = [callRecord] (const std::shared_ptr<AbilityRecord> &abilityRecord) {
        if (abilityRecord == nullptr) {
            return false;
        }
        return abilityRecord->IsExistConnection(callRecord->GetConCallBack());
    };
    auto findRecord = std::find_if(abilityRecords.begin(), abilityRecords.end(), isExist);
    if (findRecord == abilityRecords.end()) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "not find record");
        return;
    }
    auto abilityRecord = *findRecord;
    CHECK_POINTER(abilityRecord);
    abilityRecord->ReleaseCall(callRecord->GetConCallBack());
}

std::vector<std::shared_ptr<AbilityRecord>> UIAbilityLifecycleManager::GetAbilityRecordsByName(
    const AppExecFwk::ElementName &element)
{
    std::lock_guard<ffrt::mutex> guard(sessionLock_);
    return GetAbilityRecordsByNameInner(element);
}

std::vector<std::shared_ptr<AbilityRecord>> UIAbilityLifecycleManager::GetAbilityRecordsByNameInner(
    const AppExecFwk::ElementName &element)
{
    std::vector<std::shared_ptr<AbilityRecord>> records;
    for (const auto& [first, second] : sessionAbilityMap_) {
        auto &abilityInfo = second->GetAbilityInfo();
        AppExecFwk::ElementName localElement(abilityInfo.deviceId, abilityInfo.bundleName,
            abilityInfo.name, abilityInfo.moduleName);
        AppExecFwk::ElementName localElementNoModuleName(abilityInfo.deviceId,
            abilityInfo.bundleName, abilityInfo.name);
        if (localElement == element || localElementNoModuleName == element) {
            TAG_LOGD(AAFwkTag::ABILITYMGR, "find element %{public}s", localElement.GetURI().c_str());
            records.push_back(second);
        }
    }
    return records;
}

int32_t UIAbilityLifecycleManager::GetSessionIdByAbilityToken(const sptr<IRemoteObject> &token)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    std::lock_guard<ffrt::mutex> guard(sessionLock_);
    for (const auto& [first, second] : sessionAbilityMap_) {
        if (second && second->GetToken()->AsObject() == token) {
            return first;
        }
    }
    TAG_LOGE(AAFwkTag::ABILITYMGR, "not find");
    return 0;
}

void UIAbilityLifecycleManager::SetReceiverInfo(const AbilityRequest &abilityRequest,
    std::shared_ptr<AbilityRecord> &abilityRecord) const
{
    CHECK_POINTER(abilityRecord);
    const auto &abilityInfo = abilityRequest.abilityInfo;
    std::string abilityName = abilityInfo.name;
    auto isStandard = abilityInfo.launchMode == AppExecFwk::LaunchMode::STANDARD && !abilityRequest.startRecent;
    if (isStandard && abilityRequest.sessionInfo != nullptr) {
        // Support standard launch type.
        auto persistentId = abilityRequest.sessionInfo->persistentId;
        abilityName += std::to_string(abilityRequest.sessionInfo->persistentId);
    }

    bool hasRecoverInfo = false;
    (void)DelayedSingleton<AbilityRuntime::AppExitReasonDataManager>::GetInstance()->
        GetAbilityRecoverInfo(abilityInfo.applicationInfo.accessTokenId, abilityInfo.moduleName, abilityName,
        hasRecoverInfo);
    abilityRecord->UpdateRecoveryInfo(hasRecoverInfo);
    (void)DelayedSingleton<AbilityRuntime::AppExitReasonDataManager>::GetInstance()->
        DeleteAbilityRecoverInfo(abilityInfo.applicationInfo.accessTokenId, abilityInfo.moduleName, abilityName);
}

void UIAbilityLifecycleManager::SetLastExitReason(std::shared_ptr<AbilityRecord> &abilityRecord) const
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    if (abilityRecord == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "null abilityRecord");
        return;
    }

    if (abilityRecord->GetAbilityInfo().bundleName.empty()) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "bundleName empty");
        return;
    }

    auto sessionInfo = abilityRecord->GetSessionInfo();
    if (sessionInfo == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "sessionInfo invalid");
        return;
    }

    std::string abilityName = abilityRecord->GetAbilityInfo().name;
    if (abilityRecord->GetAbilityInfo().launchMode == AppExecFwk::LaunchMode::STANDARD) {
        abilityName += std::to_string(sessionInfo->persistentId);
    }

    ExitReason exitReason;
    bool isSetReason;
    auto accessTokenId = abilityRecord->GetAbilityInfo().applicationInfo.accessTokenId;
    AppExecFwk::RunningProcessInfo processInfo;
    int64_t time_stamp = 0;
    bool withKillMsg = false;
    DelayedSingleton<AbilityRuntime::AppExitReasonDataManager>::GetInstance()->GetAppExitReason(
        abilityRecord->GetAbilityInfo().bundleName, accessTokenId, abilityName, isSetReason, exitReason,
        processInfo, time_stamp, withKillMsg);

    if (isSetReason) {
        TAG_LOGD(AAFwkTag::ABILITYMGR, "Set last exit reason, ability: %{public}s, reason: %{public}d.",
            abilityName.c_str(), exitReason.reason);
        abilityRecord->SetLastExitReason(exitReason, processInfo, time_stamp, withKillMsg);
    }
}

bool UIAbilityLifecycleManager::PrepareTerminateAbility(const std::shared_ptr<AbilityRecord> &abilityRecord,
    bool isSCBCall)
{
    TAG_LOGD(AAFwkTag::ABILITYMGR, "call PrepareTerminateAbility");
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    if (AbilityPermissionUtil::GetInstance().CheckPrepareTerminateEnable(abilityRecord) != ERR_OK) {
        TAG_LOGD(AAFwkTag::ABILITYMGR, "Not support prepare terminate.");
        return false;
    }
    TAG_LOGI(AAFwkTag::ABILITYMGR, "abilityInfoName:%{public}s", abilityRecord->GetAbilityInfo().name.c_str());
    return abilityRecord->PrepareTerminateAbility(isSCBCall);
}

void UIAbilityLifecycleManager::PrepareTerminateAbilityDone(std::shared_ptr<AbilityRecord> abilityRecord,
    bool isTerminate)
{
    TAG_LOGD(AAFwkTag::ABILITYMGR, "call PrepareTerminateAbilityDone");
    CHECK_POINTER(abilityRecord);
    abilityRecord->PrepareTerminateAbilityDone(isTerminate);
}

void UIAbilityLifecycleManager::SetSessionHandler(const sptr<ISessionHandler> &handler)
{
    handler_ = handler;
}

std::shared_ptr<AbilityRecord> UIAbilityLifecycleManager::GetAbilityRecordsById(int32_t sessionId) const
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    std::lock_guard<ffrt::mutex> guard(sessionLock_);
    auto search = sessionAbilityMap_.find(sessionId);
    if (search == sessionAbilityMap_.end()) {
        TAG_LOGI(AAFwkTag::ABILITYMGR, "sessionId invalid");
        return nullptr;
    }
    return search->second;
}

void UIAbilityLifecycleManager::GetActiveAbilityList(int32_t uid, std::vector<std::string> &abilityList, int32_t pid)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    std::lock_guard<ffrt::mutex> guard(sessionLock_);
    TAG_LOGD(AAFwkTag::ABILITYMGR, "Call");
    for (const auto& [sessionId, abilityRecord] : sessionAbilityMap_) {
        if (abilityRecord == nullptr) {
            TAG_LOGW(AAFwkTag::ABILITYMGR, "null second");
            continue;
        }
        if (!CheckPid(abilityRecord, pid)) {
            continue;
        }
        const auto &abilityInfo = abilityRecord->GetAbilityInfo();
        if (abilityInfo.applicationInfo.uid == uid && !abilityInfo.name.empty()) {
            std::string abilityName = abilityInfo.name;
            if (abilityInfo.launchMode == AppExecFwk::LaunchMode::STANDARD &&
                abilityRecord->GetSessionInfo() != nullptr) {
                abilityName += std::to_string(abilityRecord->GetSessionInfo()->persistentId);
            }
            TAG_LOGD(AAFwkTag::ABILITYMGR, "find ability name is %{public}s.", abilityName.c_str());
            abilityList.push_back(abilityName);
        }
    }
    if (!abilityList.empty()) {
        sort(abilityList.begin(), abilityList.end());
        abilityList.erase(unique(abilityList.begin(), abilityList.end()), abilityList.end());
    }
}

bool UIAbilityLifecycleManager::CheckPid(const std::shared_ptr<AbilityRecord> abilityRecord, const int32_t pid) const
{
    CHECK_POINTER_RETURN_BOOL(abilityRecord);
    return pid == NO_PID || abilityRecord->GetPid() == pid;
}

int32_t UIAbilityLifecycleManager::CheckAbilityNumber(
    const std::string &bundleName, const std::string &abilityName, const std::string &moduleName) const
{
    int32_t checkAbilityNumber = 0;

    for (auto [persistentId, record] : sessionAbilityMap_) {
        auto recordAbilityInfo = record->GetAbilityInfo();
        if (bundleName == recordAbilityInfo.bundleName && abilityName == recordAbilityInfo.name &&
            moduleName == recordAbilityInfo.moduleName) {
            // check ability number created previously and add new one.
            checkAbilityNumber += 1;
        }
    }

    return checkAbilityNumber;
}

void UIAbilityLifecycleManager::MoreAbilityNumbersSendEventInfo(
    int32_t userId, const std::string &bundleName, const std::string &abilityName, const std::string &moduleName)
{
    int32_t checkAbilityNumber = 0;
    checkAbilityNumber = CheckAbilityNumber(bundleName, abilityName, moduleName);
    TAG_LOGD(AAFwkTag::ABILITYMGR, "Check ability number:%{public}d", checkAbilityNumber);

    if (checkAbilityNumber >= 1) {
        EventInfo eventInfo;
        eventInfo.userId = userId;
        eventInfo.abilityName = abilityName;
        eventInfo.bundleName = bundleName;
        eventInfo.moduleName = moduleName;
        // get ability number created previously and add new one.
        eventInfo.abilityNumber = checkAbilityNumber + 1;
        EventReport::SendAbilityEvent(EventName::START_STANDARD_ABILITIES, HiSysEventType::BEHAVIOR, eventInfo);
    }
}

void UIAbilityLifecycleManager::OnAppStateChanged(const AppInfo &info)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    std::lock_guard<ffrt::mutex> guard(sessionLock_);
    TAG_LOGD(AAFwkTag::ABILITYMGR, "Call.");
    if (info.state == AppState::TERMINATED || info.state == AppState::END) {
        for (const auto& abilityRecord : terminateAbilityList_) {
            if (abilityRecord == nullptr) {
                TAG_LOGW(AAFwkTag::ABILITYMGR, "null abilityRecord");
                continue;
            }
            if (info.bundleName == abilityRecord->GetApplicationInfo().bundleName &&
                info.appIndex == abilityRecord->GetAppIndex() && info.instanceKey == abilityRecord->GetInstanceKey()) {
                abilityRecord->SetAppState(info.state);
            }
        }
        return;
    }
    if (info.state == AppState::COLD_START) {
        for (const auto& [sessionId, abilityRecord] : sessionAbilityMap_) {
            if (abilityRecord == nullptr) {
                TAG_LOGW(AAFwkTag::ABILITYMGR, "null abilityRecord");
                continue;
            }
            if (info.bundleName == abilityRecord->GetApplicationInfo().bundleName &&
                info.appIndex == abilityRecord->GetAppIndex() && info.instanceKey == abilityRecord->GetInstanceKey()) {
#ifdef SUPPORT_SCREEN
                abilityRecord->SetColdStartFlag(true);
#endif // SUPPORT_SCREEN
                break;
            }
        }
        return;
    }
    for (const auto& [sessionId, abilityRecord] : sessionAbilityMap_) {
        if (abilityRecord == nullptr) {
            TAG_LOGW(AAFwkTag::ABILITYMGR, "null abilityRecord");
            continue;
        }
        if (info.bundleName == abilityRecord->GetApplicationInfo().bundleName &&
            info.appIndex == abilityRecord->GetAppIndex() && info.instanceKey == abilityRecord->GetInstanceKey()) {
            abilityRecord->SetAppState(info.state);
        }
    }
}

void UIAbilityLifecycleManager::UninstallApp(const std::string &bundleName, int32_t uid)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    std::lock_guard<ffrt::mutex> guard(sessionLock_);
    TAG_LOGD(AAFwkTag::ABILITYMGR, "Call");
    for (auto it = sessionAbilityMap_.begin(); it != sessionAbilityMap_.end();) {
        if (it->second == nullptr) {
            it++;
            continue;
        }
        auto &abilityInfo = it->second->GetAbilityInfo();
        if (abilityInfo.bundleName == bundleName && it->second->GetUid() == uid) {
            std::string abilityName = abilityInfo.name;
            auto sessionInfo = it->second->GetSessionInfo();
            if (abilityInfo.launchMode == AppExecFwk::LaunchMode::STANDARD && sessionInfo != nullptr) {
                abilityName += std::to_string(sessionInfo->persistentId);
            }
            (void)DelayedSingleton<AbilityRuntime::AppExitReasonDataManager>::GetInstance()->
                DeleteAbilityRecoverInfo(abilityInfo.applicationInfo.accessTokenId, abilityInfo.moduleName,
                abilityName);
        }
        it++;
    }

    for (auto it = startAbilityCheckMap_.begin(); it != startAbilityCheckMap_.end();) {
        const auto &request = it->second;
        if (request && request->appInfo.uid == uid) {
            it = startAbilityCheckMap_.erase(it);
        } else {
            ++it;
        }
    }
}

void UIAbilityLifecycleManager::GetAbilityRunningInfos(std::vector<AbilityRunningInfo> &info, bool isPerm) const
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    std::lock_guard<ffrt::mutex> guard(sessionLock_);
    TAG_LOGD(AAFwkTag::ABILITYMGR, "Call.");
    for (auto [sessionId, abilityRecord] : sessionAbilityMap_) {
        if (abilityRecord == nullptr) {
            TAG_LOGW(AAFwkTag::ABILITYMGR, "null abilityRecord");
            continue;
        }
        if (isPerm) {
            DelayedSingleton<AbilityManagerService>::GetInstance()->GetAbilityRunningInfo(info, abilityRecord);
        } else {
            auto callingTokenId = IPCSkeleton::GetCallingTokenID();
            auto tokenID = abilityRecord->GetApplicationInfo().accessTokenId;
            if (callingTokenId == tokenID) {
                DelayedSingleton<AbilityManagerService>::GetInstance()->GetAbilityRunningInfo(info, abilityRecord);
            }
        }
    }
}

void UIAbilityLifecycleManager::Dump(std::vector<std::string> &info)
{
    TAG_LOGI(AAFwkTag::ABILITYMGR, "call");
    std::unordered_map<int32_t, std::shared_ptr<AbilityRecord>> sessionAbilityMapLocked;
    {
        HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
        std::lock_guard<ffrt::mutex> guard(sessionLock_);
        for (const auto& [sessionId, abilityRecord] : sessionAbilityMap_) {
            sessionAbilityMapLocked[sessionId] = abilityRecord;
        }
    }

    std::string dumpInfo = "User ID #" + std::to_string(userId_);
    info.push_back(dumpInfo);
    dumpInfo = "  current mission lists:{";
    info.push_back(dumpInfo);

    for (const auto& [sessionId, abilityRecord] : sessionAbilityMapLocked) {
        if (abilityRecord == nullptr) {
            TAG_LOGW(AAFwkTag::ABILITYMGR, "null abilityRecord");
            continue;
        }

        sptr<SessionInfo> sessionInfo = abilityRecord->GetSessionInfo();
        dumpInfo = "    Mission ID #" + std::to_string(sessionId);
        if (sessionInfo) {
            dumpInfo += "  mission name #[" + sessionInfo->sessionName + "]";
        }
        dumpInfo += "  lockedState #" + std::to_string(abilityRecord->GetLockedState());
        dumpInfo += "  mission affinity #[" + abilityRecord->GetMissionAffinity() + "]";
        info.push_back(dumpInfo);

        abilityRecord->Dump(info);
    }
    dumpInfo = " }";
    info.push_back(dumpInfo);
}

void UIAbilityLifecycleManager::DumpMissionList(
    std::vector<std::string> &info, bool isClient, const std::string &args)
{
    TAG_LOGI(AAFwkTag::ABILITYMGR, "call");
    std::unordered_map<int32_t, std::shared_ptr<AbilityRecord>> sessionAbilityMapLocked;
    {
        HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
        std::lock_guard<ffrt::mutex> guard(sessionLock_);
        for (const auto& [sessionId, abilityRecord] : sessionAbilityMap_) {
            sessionAbilityMapLocked[sessionId] = abilityRecord;
        }
    }
    std::string dumpInfo = "User ID #" + std::to_string(userId_);
    info.push_back(dumpInfo);
    dumpInfo = "  current mission lists:{";
    info.push_back(dumpInfo);

    for (const auto& [sessionId, abilityRecord] : sessionAbilityMapLocked) {
        if (abilityRecord == nullptr) {
            TAG_LOGW(AAFwkTag::ABILITYMGR, "null abilityRecord");
            continue;
        }
        sptr<SessionInfo> sessionInfo = abilityRecord->GetSessionInfo();
        dumpInfo = "    Mission ID #" + std::to_string(sessionId);
        if (sessionInfo) {
            dumpInfo += "  mission name #[" + sessionInfo->sessionName + "]";
        }
        dumpInfo += "  lockedState #" + std::to_string(abilityRecord->GetLockedState());
        dumpInfo += "  mission affinity #[" + abilityRecord->GetMissionAffinity() + "]";
        info.push_back(dumpInfo);

        std::vector<std::string> params;
        abilityRecord->DumpAbilityState(info, isClient, params);
    }
    dumpInfo = " }";
    info.push_back(dumpInfo);
}

void UIAbilityLifecycleManager::DumpMissionListByRecordId(std::vector<std::string> &info, bool isClient,
    int32_t abilityRecordId, const std::vector<std::string> &params)
{
    TAG_LOGI(AAFwkTag::ABILITYMGR, "call");
    std::unordered_map<int32_t, std::shared_ptr<AbilityRecord>> sessionAbilityMapLocked;
    {
        HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
        std::lock_guard<ffrt::mutex> guard(sessionLock_);
        for (const auto& [sessionId, abilityRecord] : sessionAbilityMap_) {
            sessionAbilityMapLocked[sessionId] = abilityRecord;
        }
    }
    std::string dumpInfo = "User ID #" + std::to_string(userId_);
    info.push_back(dumpInfo);
    dumpInfo = "  current mission lists:{";
    info.push_back(dumpInfo);

    for (const auto& [sessionId, abilityRecord] : sessionAbilityMapLocked) {
        if (abilityRecord == nullptr) {
            TAG_LOGW(AAFwkTag::ABILITYMGR, "null abilityRecord");
            continue;
        }
        if (abilityRecord->GetAbilityRecordId() != abilityRecordId) {
            continue;
        }
        sptr<SessionInfo> sessionInfo = abilityRecord->GetSessionInfo();
        dumpInfo = "    Mission ID #" + std::to_string(sessionId);
        if (sessionInfo) {
            dumpInfo += "  mission name #[" + sessionInfo->sessionName + "]";
        }
        dumpInfo += "  lockedState #" + std::to_string(abilityRecord->GetLockedState());
        dumpInfo += "  mission affinity #[" + abilityRecord->GetMissionAffinity() + "]";
        info.push_back(dumpInfo);

        abilityRecord->DumpAbilityState(info, isClient, params);
    }
    dumpInfo = " }";
    info.push_back(dumpInfo);
}

int UIAbilityLifecycleManager::MoveMissionToFront(int32_t sessionId, std::shared_ptr<StartOptions> startOptions)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    auto tmpSceneSession = iface_cast<Rosen::ISession>(rootSceneSession_);
    CHECK_POINTER_AND_RETURN(tmpSceneSession, ERR_INVALID_VALUE);
    std::shared_ptr<AbilityRecord> abilityRecord = GetAbilityRecordsById(sessionId);
    CHECK_POINTER_AND_RETURN(abilityRecord, ERR_INVALID_VALUE);
    sptr<SessionInfo> sessionInfo = abilityRecord->GetSessionInfo();
    CHECK_POINTER_AND_RETURN(sessionInfo, ERR_INVALID_VALUE);
    if (startOptions != nullptr) {
        abilityRecord->SetWindowMode(startOptions->GetWindowMode());
        TAG_LOGI(AAFwkTag::ABILITYMGR, "MoveMissionToFront, setting displayId=%{public}d",
            startOptions->GetDisplayID());
        (sessionInfo->want).SetParam(Want::PARAM_RESV_DISPLAY_ID, startOptions->GetDisplayID());
    }
    sessionInfo->processOptions = nullptr;
    sessionInfo->startWindowOption = nullptr;
    TAG_LOGI(AAFwkTag::ABILITYMGR, "call PendingSessionActivation by rootSceneSession"
        "windowLeft=%{public}d,windowTop=%{public}d,"
        "windowHeight=%{public}d,windowWidth=%{public}d",
        (sessionInfo->want).GetIntParam(Want::PARAM_RESV_WINDOW_LEFT, 0),
        (sessionInfo->want).GetIntParam(Want::PARAM_RESV_WINDOW_TOP, 0),
        (sessionInfo->want).GetIntParam(Want::PARAM_RESV_WINDOW_HEIGHT, 0),
        (sessionInfo->want).GetIntParam(Want::PARAM_RESV_WINDOW_WIDTH, 0));
    sessionInfo->canStartAbilityFromBackground = true;
    return static_cast<int>(tmpSceneSession->PendingSessionActivation(sessionInfo));
}

std::shared_ptr<StatusBarDelegateManager> UIAbilityLifecycleManager::GetStatusBarDelegateManager()
{
    std::lock_guard<ffrt::mutex> lock(statusBarDelegateManagerLock_);
    if (statusBarDelegateManager_ == nullptr) {
        statusBarDelegateManager_ = std::make_shared<StatusBarDelegateManager>();
    }
    return statusBarDelegateManager_;
}

int32_t UIAbilityLifecycleManager::RegisterStatusBarDelegate(sptr<AbilityRuntime::IStatusBarDelegate> delegate)
{
    auto statusBarDelegateManager = GetStatusBarDelegateManager();
    CHECK_POINTER_AND_RETURN(statusBarDelegateManager, ERR_INVALID_VALUE);
    return statusBarDelegateManager->RegisterStatusBarDelegate(delegate);
}

bool UIAbilityLifecycleManager::IsCallerInStatusBar(const std::string &instanceKey)
{
    auto statusBarDelegateManager = GetStatusBarDelegateManager();
    CHECK_POINTER_AND_RETURN(statusBarDelegateManager, false);
    return statusBarDelegateManager->IsCallerInStatusBar(instanceKey);
}

bool UIAbilityLifecycleManager::IsInStatusBar(uint32_t accessTokenId, bool isMultiInstance)
{
    auto statusBarDelegateManager = GetStatusBarDelegateManager();
    CHECK_POINTER_AND_RETURN(statusBarDelegateManager, false);
    return statusBarDelegateManager->IsInStatusBar(accessTokenId, isMultiInstance);
}

bool UIAbilityLifecycleManager::IsSupportStatusBar()
{
    auto statusBarDelegateManager = GetStatusBarDelegateManager();
    CHECK_POINTER_AND_RETURN(statusBarDelegateManager, false);
    return statusBarDelegateManager->IsSupportStatusBar();
}

int32_t UIAbilityLifecycleManager::DoProcessAttachment(std::shared_ptr<AbilityRecord> abilityRecord)
{
    auto statusBarDelegateManager = GetStatusBarDelegateManager();
    CHECK_POINTER_AND_RETURN(statusBarDelegateManager, ERR_INVALID_VALUE);
    return statusBarDelegateManager->DoProcessAttachment(abilityRecord);
}

int32_t UIAbilityLifecycleManager::DoCallerProcessAttachment(std::shared_ptr<AbilityRecord> abilityRecord)
{
    auto statusBarDelegateManager = GetStatusBarDelegateManager();
    CHECK_POINTER_AND_RETURN(statusBarDelegateManager, ERR_INVALID_VALUE);
    return statusBarDelegateManager->DoCallerProcessAttachment(abilityRecord);
}

int32_t UIAbilityLifecycleManager::DoCallerProcessDetachment(std::shared_ptr<AbilityRecord> abilityRecord)
{
    auto statusBarDelegateManager = GetStatusBarDelegateManager();
    CHECK_POINTER_AND_RETURN(statusBarDelegateManager, ERR_INVALID_VALUE);
    return statusBarDelegateManager->DoCallerProcessDetachment(abilityRecord);
}

bool UIAbilityLifecycleManager::CheckPrepareTerminateTokens(const std::vector<sptr<IRemoteObject>> &tokens,
    uint32_t &tokenId, std::map<std::string, std::vector<sptr<IRemoteObject>>> &tokensPerModuleName)
{
    if (!AppUtils::GetInstance().IsStartOptionsWithAnimation()) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "Not supported device");
        return false;
    }
    if (tokens.empty()) {
        TAG_LOGW(AAFwkTag::ABILITYMGR, "empty tokens");
        return false;
    }
    for (auto token: tokens) {
        auto abilityRecord = Token::GetAbilityRecordByToken(token);
        if (abilityRecord == nullptr) {
            continue;
        }
        tokenId = abilityRecord->GetApplicationInfo().accessTokenId;
        auto moduleName = abilityRecord->GetAbilityInfo().moduleName;
        if (tokensPerModuleName.find(moduleName) == tokensPerModuleName.end()) {
            tokensPerModuleName[moduleName] = {};
        }
        tokensPerModuleName[moduleName].push_back(token);
    }
    if (tokenId == 0 || !AAFwk::PermissionVerification::GetInstance()->VerifyPrepareTerminatePermission(tokenId)) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "invalid tokenId or no permission ohos.permission.PREPARE_APP_TERMINATE");
        return false;
    }
    return true;
}

void UIAbilityLifecycleManager::HandleAbilityStageOnPrepareTerminationTimeout(
    int32_t pid, const std::string &moduleName, const std::vector<sptr<IRemoteObject>> &tokens)
{
    TAG_LOGE(AAFwkTag::ABILITYMGR, "handle abilityStage.onPrepareTermination timeout, token size=%{public}zu",
        tokens.size());
    for (auto token: tokens) {
        TerminateSession(Token::GetAbilityRecordByToken(token));
    }
    auto iter = std::find_if(prepareTerminateByPidRecords_.begin(), prepareTerminateByPidRecords_.end(),
        [pid, _moduleName = moduleName](const std::shared_ptr<PrepareTerminateByPidRecord> &record) {
        return record->pid_ == pid && record->moduleName_ == _moduleName;
    });
    if (iter != prepareTerminateByPidRecords_.end()) {
        prepareTerminateByPidRecords_.erase(iter);
    }
}

std::vector<sptr<IRemoteObject>> UIAbilityLifecycleManager::PrepareTerminateAppAndGetRemainingInner(
    int32_t pid, const std::string &moduleName, const std::vector<sptr<IRemoteObject>> &tokens)
{
    std::vector<sptr<IRemoteObject>> remainingTokens;
    // execute onPrepareTerminate until timeout
    std::unique_lock<std::mutex> lock(isTryPrepareTerminateByPidsDoneMutex_);
    auto iter = std::find_if(prepareTerminateByPidRecords_.begin(), prepareTerminateByPidRecords_.end(),
        [pid, _moduleName = moduleName](const std::shared_ptr<PrepareTerminateByPidRecord> &record) {
        return record->pid_ == pid && record->moduleName_ == _moduleName;
    });
    if (iter != prepareTerminateByPidRecords_.end()) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "record with (pid=%{public}d,moduleName=%{public}s) already exists",
            pid, moduleName.c_str());
        return remainingTokens;
    }
    std::shared_ptr<PrepareTerminateByPidRecord> record = std::make_shared<PrepareTerminateByPidRecord>(
        pid, moduleName, false, 0, false);
    prepareTerminateByPidRecords_.push_back(record);
    auto condition = [record] {
        if (record == nullptr) {
            TAG_LOGE(AAFwkTag::ABILITYMGR, "null record");
            return false;
        }
        return record->isTryPrepareTerminateByPidsDone_.load();
    };
    auto task = [pid, _moduleName = moduleName]() {
        DelayedSingleton<AppScheduler>::GetInstance()->PrepareTerminateApp(pid, _moduleName);
    };
    ffrt::submit(task);
    if (!isTryPrepareTerminateByPidsCv_.wait_for(lock,
        std::chrono::milliseconds(GlobalConstant::PREPARE_TERMINATE_TIMEOUT_TIME), condition)) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "wait timeout, kill immediately");
        HandleAbilityStageOnPrepareTerminationTimeout(pid, moduleName, tokens);
    } else if (!record->isExist_) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "onPrepareTermination/onPrepareTerminationAsync not exist");
        remainingTokens.insert(remainingTokens.end(), tokens.begin(), tokens.end());
    } else if (static_cast<AppExecFwk::PrepareTermination>(record->prepareTermination_) ==
        AppExecFwk::PrepareTermination::CANCEL) {
        TAG_LOGI(AAFwkTag::ABILITYMGR, "PrepareTerminate cancel");
    } else {
        // Terminate immediately by default
        TAG_LOGI(AAFwkTag::ABILITYMGR, "PrepareTerminate immediately");
        for (auto token: tokens) {
            TerminateSession(Token::GetAbilityRecordByToken(token));
        }
    }
    return remainingTokens;
}

std::vector<sptr<IRemoteObject>> UIAbilityLifecycleManager::PrepareTerminateAppAndGetRemaining(
    int32_t pid, const std::vector<sptr<IRemoteObject>> &tokens)
{
    uint32_t tokenId = 0;
    std::map<std::string, std::vector<sptr<IRemoteObject>>> tokensPerModuleName;
    if (!CheckPrepareTerminateTokens(tokens, tokenId, tokensPerModuleName)) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "CheckPrepareTerminateTokens failed");
        return tokens;
    }
    std::vector<sptr<IRemoteObject>> remainingTokens;
    for (const auto& [moduleName, _tokens] : tokensPerModuleName) {
        auto _remainingTokens = PrepareTerminateAppAndGetRemainingInner(pid, moduleName, _tokens);
        if (!_remainingTokens.empty()) {
            remainingTokens.insert(remainingTokens.end(), _remainingTokens.begin(), _remainingTokens.end());
        }
    }
    return remainingTokens;
}

int32_t UIAbilityLifecycleManager::TryPrepareTerminateByPids(const std::vector<int32_t>& pids)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    TAG_LOGI(AAFwkTag::ABILITYMGR, "prepare terminate app");
    IN_PROCESS_CALL_WITHOUT_RET(DelayedSingleton<AppScheduler>::GetInstance()->BlockProcessCacheByPids(pids));
    for (const auto &pid : pids) {
        std::unordered_set<std::shared_ptr<AbilityRecord>> abilitysToTerminate;
        std::vector<sptr<IRemoteObject>> tokens;
        IN_PROCESS_CALL_WITHOUT_RET(
            DelayedSingleton<AppScheduler>::GetInstance()->GetAbilityRecordsByProcessID(pid, tokens));
        for (const auto &token : PrepareTerminateAppAndGetRemaining(pid, tokens)) {
            auto abilityRecord = Token::GetAbilityRecordByToken(token);
            if (PrepareTerminateAbility(abilityRecord, true)) {
                TAG_LOGI(AAFwkTag::ABILITYMGR, "terminate blocked");
                continue;
            }
            abilitysToTerminate.emplace(abilityRecord);
        }
        for (const auto &abilityRecord : abilitysToTerminate) {
            TerminateSession(abilityRecord);
        }
    }
    TAG_LOGI(AAFwkTag::ABILITYMGR, "end.");
    return ERR_OK;
}

void UIAbilityLifecycleManager::TryPrepareTerminateByPidsDone(const std::string &moduleName,
    int32_t prepareTermination, bool isExist)
{
    auto pid = IPCSkeleton::GetCallingPid();
    TAG_LOGD(AAFwkTag::ABILITYMGR, "call TryPrepareTerminateByPidsDone, pid=%{public}d", pid);
    std::unique_lock<std::mutex> lock(isTryPrepareTerminateByPidsDoneMutex_);
    auto iter = std::find_if(prepareTerminateByPidRecords_.begin(), prepareTerminateByPidRecords_.end(),
        [pid, _moduleName = moduleName](const std::shared_ptr<PrepareTerminateByPidRecord> &record) {
        return record->pid_ == pid && record->moduleName_ == _moduleName;
    });
    if (iter == prepareTerminateByPidRecords_.end()) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "record with (pid=%{public}d,moduleName=%{public}s) not exist",
            pid, moduleName.c_str());
        return;
    }
    if ((*iter) == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "record is nullptr");
        prepareTerminateByPidRecords_.erase(iter);
        return;
    }
    (*iter)->prepareTermination_ = prepareTermination;
    (*iter)->isExist_ = isExist;
    (*iter)->isTryPrepareTerminateByPidsDone_.store(true);
    isTryPrepareTerminateByPidsCv_.notify_one();
    prepareTerminateByPidRecords_.erase(iter);
}

void UIAbilityLifecycleManager::CancelPrepareTerminate(std::shared_ptr<AbilityRecord> abilityRecord)
{
    CHECK_POINTER(abilityRecord);
    auto abilityInfo = abilityRecord->GetAbilityInfo();
    TAG_LOGI(AAFwkTag::ABILITYMGR,
        "canceling PrepareTerminate,bundle=%{public}s,module=%{public}s,ability=%{public}s",
        abilityInfo.bundleName.c_str(), abilityInfo.moduleName.c_str(), abilityInfo.name.c_str());
    std::unique_lock<std::mutex> lock(isTryPrepareTerminateByPidsDoneMutex_);
    auto iter = std::find_if(prepareTerminateByPidRecords_.begin(), prepareTerminateByPidRecords_.end(),
        [pid = abilityRecord->GetPid(), moduleName = abilityInfo.moduleName](
            const std::shared_ptr<PrepareTerminateByPidRecord> &record) {
        return record->pid_ == pid && record->moduleName_ == moduleName;
    });
    if (iter == prepareTerminateByPidRecords_.end()) {
        TAG_LOGI(AAFwkTag::ABILITYMGR, "record with (pid=%{public}d,moduleName=%{public}s) not exist",
            abilityRecord->GetPid(), abilityInfo.moduleName.c_str());
        return;
    }
    if ((*iter) == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "record is nullptr");
        prepareTerminateByPidRecords_.erase(iter);
        return;
    }
    // no need to terminate again, return cancel by default
    (*iter)->prepareTermination_ = static_cast<int32_t>(AppExecFwk::PrepareTermination::CANCEL);
    (*iter)->isExist_ = true;
    (*iter)->isTryPrepareTerminateByPidsDone_.store(true);
    isTryPrepareTerminateByPidsCv_.notify_one();
    prepareTerminateByPidRecords_.erase(iter);
}

void UIAbilityLifecycleManager::BatchCloseUIAbility(
    const std::unordered_set<std::shared_ptr<AbilityRecord>>& abilitySet)
{
    auto closeTask = [ self = shared_from_this(), abilitySet]() {
        TAG_LOGI(AAFwkTag::ABILITYMGR, "abilities must close");
        if (self == nullptr) {
            TAG_LOGE(AAFwkTag::ABILITYMGR, "null manager");
            return;
        }
        for (const auto& ability : abilitySet) {
            self->CloseUIAbility(ability, -1, nullptr, false);
        }
    };
    auto taskHandler = DelayedSingleton<AbilityManagerService>::GetInstance()->GetTaskHandler();
    if (taskHandler != nullptr) {
        taskHandler->SubmitTask(closeTask, TaskQoS::USER_INTERACTIVE);
    }
}

void UIAbilityLifecycleManager::TerminateSession(std::shared_ptr<AbilityRecord> abilityRecord)
{
    CHECK_POINTER(abilityRecord);
    auto sessionInfo = abilityRecord->GetSessionInfo();
    CHECK_POINTER(sessionInfo);
    CHECK_POINTER(sessionInfo->sessionToken);
    auto session = iface_cast<Rosen::ISession>(sessionInfo->sessionToken);
    CHECK_POINTER(session);
    TAG_LOGI(AAFwkTag::ABILITYMGR, "call TerminateSession, session id: %{public}d", sessionInfo->persistentId);
    session->TerminateSession(sessionInfo);
}

int UIAbilityLifecycleManager::ChangeAbilityVisibility(sptr<IRemoteObject> token, bool isShow)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    std::shared_ptr<AbilityRecord> abilityRecord;
    {
        std::lock_guard<ffrt::mutex> guard(sessionLock_);
        abilityRecord = GetAbilityRecordByToken(token);
    }
    CHECK_POINTER_AND_RETURN(abilityRecord, ERR_INVALID_VALUE);
    if (IPCSkeleton::GetCallingTokenID() != abilityRecord->GetApplicationInfo().accessTokenId) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "not self");
        return ERR_NATIVE_NOT_SELF_APPLICATION;
    }
    auto sessionInfo = abilityRecord->GetSessionInfo();
    CHECK_POINTER_AND_RETURN(sessionInfo, ERR_INVALID_VALUE);

    do {
        if (HiddenStartObserverManager::GetInstance().IsHiddenStart(abilityRecord->GetPid())) {
            if (!IsCallerInStatusBar(abilityRecord->GetInstanceKey())) {
                TAG_LOGI(AAFwkTag::ABILITYMGR, "no status bar while detaching.");
                break;
            }
            auto ret = DoCallerProcessDetachment(abilityRecord);
            if (ret != ERR_OK) {
                TAG_LOGE(AAFwkTag::ABILITYMGR, "caller detach to status bar failed, ret: %{public}d", ret);
                return ERR_START_OPTIONS_CHECK_FAILED;
            }
            TAG_LOGI(AAFwkTag::ABILITYMGR, "Hidden start allowed by observer.");
            break;
        }
        if (!IsCallerInStatusBar(abilityRecord->GetInstanceKey()) && sessionInfo->processOptions != nullptr &&
            !ProcessOptions::IsNoAttachmentMode(sessionInfo->processOptions->processMode) &&
            !sessionInfo->processOptions->isRestartKeepAlive) {
            TAG_LOGE(AAFwkTag::ABILITYMGR, "caller not add to status bar");
            return ERR_START_OPTIONS_CHECK_FAILED;
        }
        if (sessionInfo->processOptions == nullptr ||
            (!ProcessOptions::IsAttachToStatusBarMode(sessionInfo->processOptions->processMode) &&
            !ProcessOptions::IsNoAttachmentMode(sessionInfo->processOptions->processMode) &&
            !sessionInfo->processOptions->isRestartKeepAlive)) {
            auto ret = DoCallerProcessAttachment(abilityRecord);
            if (ret != ERR_OK) {
                TAG_LOGE(AAFwkTag::ABILITYMGR, "caller attach to status bar failed, ret: %{public}d", ret);
                return ERR_START_OPTIONS_CHECK_FAILED;
            }
        }
    } while (false);

    auto callerSessionInfo = abilityRecord->GetSessionInfo();
    CHECK_POINTER_AND_RETURN(callerSessionInfo, ERR_INVALID_VALUE);
    CHECK_POINTER_AND_RETURN(callerSessionInfo->sessionToken, ERR_INVALID_VALUE);
    auto callerSession = iface_cast<Rosen::ISession>(callerSessionInfo->sessionToken);
    TAG_LOGI(AAFwkTag::ABILITYMGR, "got callerSession, call ChangeSessionVisibilityWithStatusBar()");
    CHECK_POINTER_AND_RETURN(callerSession, ERR_INVALID_VALUE);
    return static_cast<int>(callerSession->ChangeSessionVisibilityWithStatusBar(callerSessionInfo, isShow));
}

int UIAbilityLifecycleManager::ChangeUIAbilityVisibilityBySCB(sptr<SessionInfo> sessionInfo, bool isShow)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    std::lock_guard<ffrt::mutex> guard(sessionLock_);
    CHECK_POINTER_AND_RETURN(sessionInfo, ERR_INVALID_VALUE);
    auto iter = sessionAbilityMap_.find(sessionInfo->persistentId);
    if (iter == sessionAbilityMap_.end()) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "ability not found");
        return ERR_NATIVE_ABILITY_NOT_FOUND;
    }
    std::shared_ptr<AbilityRecord> uiAbilityRecord = iter->second;
    CHECK_POINTER_AND_RETURN(uiAbilityRecord, ERR_INVALID_VALUE);
    uiAbilityRecord->SetIsNewWant(sessionInfo->isNewWant);
    TAG_LOGI(AAFwkTag::ABILITYMGR, "change ability visibility: %{public}d, isNewWant: %{public}d",
        isShow, sessionInfo->isNewWant);
    if (isShow) {
        uiAbilityRecord->SetAbilityVisibilityState(AbilityVisibilityState::FOREGROUND_SHOW);
#ifdef SUPPORT_SCREEN
        if (uiAbilityRecord->GetPendingState() != AbilityState::INITIAL) {
            TAG_LOGI(AAFwkTag::ABILITYMGR, "pending state: FOREGROUND/ BACKGROUND, dropped");
            uiAbilityRecord->SetPendingState(AbilityState::FOREGROUND);
            return ERR_OK;
        } else {
            TAG_LOGD(AAFwkTag::ABILITYMGR, "pending state is not FOREGROUND or BACKGROUND.");
            uiAbilityRecord->SetPendingState(AbilityState::FOREGROUND);
        }
        uiAbilityRecord->ProcessForegroundAbility(sessionInfo->callingTokenId);
#endif // SUPPORT_SCREEN
    } else {
        uiAbilityRecord->SetAbilityVisibilityState(AbilityVisibilityState::FOREGROUND_HIDE);
    }
    return ERR_OK;
}

int32_t UIAbilityLifecycleManager::UpdateSessionInfoBySCB(std::list<SessionInfo> &sessionInfos,
    std::vector<int32_t> &sessionIds)
{
    std::unordered_set<std::shared_ptr<AbilityRecord>> abilitySet;
    {
        std::lock_guard<ffrt::mutex> guard(sessionLock_);
        isSCBRecovery_ = false;
        for (auto [sessionId, abilityRecord] : sessionAbilityMap_) {
            bool isFind = false;
            for (auto iter = sessionInfos.begin(); iter != sessionInfos.end(); iter++) {
                if (iter->persistentId == sessionId) {
                    abilityRecord->UpdateSessionInfo(iter->sessionToken);
                    sessionInfos.erase(iter);
                    isFind = true;
                    break;
                }
            }
            if (!isFind && coldStartInSCBRecovery_.count(sessionId) == 0) {
                abilitySet.emplace(abilityRecord);
            }
        }
        coldStartInSCBRecovery_.clear();
    }
    for (const auto &info : sessionInfos) {
        sessionIds.emplace_back(info.persistentId);
    }

    BatchCloseUIAbility(abilitySet);
    TAG_LOGI(AAFwkTag::ABILITYMGR, "end of updating sessionInfo");
    return ERR_OK;
}

void UIAbilityLifecycleManager::SignRestartAppFlag(int32_t uid, const std::string &instanceKey, bool isAppRecovery)
{
    std::lock_guard<ffrt::mutex> guard(sessionLock_);
    auto tempSessionAbilityMap = sessionAbilityMap_;
    for (auto &[sessionId, abilityRecord] : tempSessionAbilityMap) {
        if (abilityRecord == nullptr || abilityRecord->GetUid() != uid ||
            abilityRecord->GetInstanceKey() != instanceKey) {
            continue;
        }
        abilityRecord->SetRestartAppFlag(true);
        std::string reason = "onAbilityDied";
        if (isAppRecovery) {
            reason = "appRecovery";
        }
        NotifySCBToHandleException(abilityRecord, static_cast<int32_t>(ErrorLifecycleState::ABILITY_STATE_DIED),
            reason);
    }
}

void UIAbilityLifecycleManager::CompleteFirstFrameDrawing(int32_t sessionId) const
{
    TAG_LOGD(AAFwkTag::ABILITYMGR, "called");
    auto abilityRecord = GetAbilityRecordsById(sessionId);
    if (abilityRecord == nullptr) {
        TAG_LOGW(AAFwkTag::ABILITYMGR, "completeFirstFrameDrawing, get AbilityRecord by sessionId failed");
        return;
    }
    abilityRecord->ReportAtomicServiceDrawnCompleteEvent();
#ifdef SUPPORT_SCREEN
    abilityRecord->SetCompleteFirstFrameDrawing(true);
    AppExecFwk::AbilityFirstFrameStateObserverManager::GetInstance().
        HandleOnFirstFrameState(abilityRecord);
#endif // SUPPORT_SCREEN
}

int UIAbilityLifecycleManager::StartWithPersistentIdByDistributed(const AbilityRequest &abilityRequest,
    int32_t persistentId)
{
    TAG_LOGI(AAFwkTag::ABILITYMGR, "StartWithPersistentIdByDistributed, called");
    auto sessionInfo = CreateSessionInfo(abilityRequest);
    sessionInfo->requestCode = abilityRequest.requestCode;
    sessionInfo->persistentId = persistentId;
    sessionInfo->userId = userId_;
    sessionInfo->isAtomicService =
        (abilityRequest.abilityInfo.applicationInfo.bundleType == AppExecFwk::BundleType::ATOMIC_SERVICE);
    return NotifySCBPendingActivation(sessionInfo, abilityRequest);
}

int32_t UIAbilityLifecycleManager::GetAbilityStateByPersistentId(int32_t persistentId, bool &state)
{
    TAG_LOGD(AAFwkTag::ABILITYMGR, "called");
    std::lock_guard<ffrt::mutex> guard(sessionLock_);
    auto iter = sessionAbilityMap_.find(persistentId);
    if (iter != sessionAbilityMap_.end()) {
        std::shared_ptr<AbilityRecord> uiAbilityRecord = iter->second;
        if (uiAbilityRecord && uiAbilityRecord->GetPendingState() == AbilityState::INITIAL) {
            state = true;
            return ERR_OK;
        }
    }
    state = false;
    return ERR_INVALID_VALUE;
}

int32_t UIAbilityLifecycleManager::CleanUIAbility(
    const std::shared_ptr<AbilityRecord> &abilityRecord)
{
    TAG_LOGD(AAFwkTag::ABILITYMGR, "call");
    CHECK_POINTER_AND_RETURN(abilityRecord, ERR_INVALID_VALUE);
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    std::string element = abilityRecord->GetElementName().GetURI();
    if (DelayedSingleton<AppScheduler>::GetInstance()->CleanAbilityByUserRequest(abilityRecord->GetToken())) {
        TAG_LOGI(AAFwkTag::ABILITYMGR, "user clean ability: %{public}s success", element.c_str());
        return ERR_OK;
    }
    TAG_LOGI(AAFwkTag::ABILITYMGR,
        "can not force kill when user request clean ability, schedule lifecycle:%{public}s", element.c_str());
    return CloseUIAbility(abilityRecord, -1, nullptr, true);
}

void UIAbilityLifecycleManager::CheckCallerFromBackground(
    std::shared_ptr<AbilityRecord> callerAbility, sptr<SessionInfo> &sessionInfo)
{
    CHECK_POINTER(callerAbility);
    CHECK_POINTER(sessionInfo);
    TAG_LOGD(AAFwkTag::ABILITYMGR, "called");
    auto permission = AAFwk::PermissionVerification::GetInstance();
    bool hasPermission =
        permission->VerifyCallingPermission(PermissionConstants::PERMISSION_START_ABILITIES_FROM_BACKGROUND) ||
        permission->VerifyCallingPermission(PermissionConstants::PERMISSION_START_ABILIIES_FROM_BACKGROUND);

    sessionInfo->canStartAbilityFromBackground = hasPermission;
    TAG_LOGD(AAFwkTag::ABILITYMGR, "CheckCallerFromBackground: %{public}d", sessionInfo->canStartAbilityFromBackground);
}

void UIAbilityLifecycleManager::EnableListForSCBRecovery()
{
    std::lock_guard<ffrt::mutex> guard(sessionLock_);
    isSCBRecovery_ = true;
    coldStartInSCBRecovery_.clear();
}

std::shared_ptr<AbilityRecord> UIAbilityLifecycleManager::FindRecordFromSessionMap(const AbilityRequest &abilityRequest)
{
    int32_t appIndex = 0;
    (void)AbilityRuntime::StartupUtil::GetAppIndex(abilityRequest.want, appIndex);
    auto instanceKey = abilityRequest.want.GetStringParam(Want::APP_INSTANCE_KEY);
    for (const auto &[sessionId, abilityRecord] : sessionAbilityMap_) {
        if (abilityRecord) {
            const auto &info = abilityRecord->GetAbilityInfo();
            if (info.bundleName == abilityRequest.abilityInfo.bundleName &&
                info.moduleName == abilityRequest.abilityInfo.moduleName &&
                appIndex == abilityRecord->GetAppIndex() && instanceKey == abilityRecord->GetInstanceKey()) {
                return abilityRecord;
            }
        }
    }
    return nullptr;
}

bool UIAbilityLifecycleManager::HasAbilityRequest(const AbilityRequest &abilityRequest)
{
    for (const auto &[requestId, item] : startAbilityCheckMap_) {
        if (item && CompareTwoRequest(*item, abilityRequest)) {
            return true;
        }
    }
    return false;
}

void UIAbilityLifecycleManager::AddAbilityRequest(const AbilityRequest &abilityRequest, int32_t requestId)
{
    auto newRequest = std::make_shared<AbilityRequest>(abilityRequest);
    startAbilityCheckMap_.emplace(requestId, newRequest);
    TaskHandlerWrap::GetFfrtHandler()->SubmitTask([wThis = weak_from_this(), requestId]() {
        auto pThis = wThis.lock();
        if (pThis) {
            std::lock_guard guard(pThis->sessionLock_);
            if (pThis->startAbilityCheckMap_.erase(requestId)) {
                TAG_LOGI(AAFwkTag::ABILITYMGR, "scb call timeout: %{public}d", requestId);
            }
        }
        }, GlobalConstant::CONCURRENT_START_TIMEOUT * GlobalConstant::TIMEOUT_UNIT_TIME);
}

void UIAbilityLifecycleManager::RemoveAbilityRequest(int32_t requestId)
{
    if (requestId != 0 && startAbilityCheckMap_.erase(requestId)) {
        TAG_LOGD(AAFwkTag::ABILITYMGR, "RemoveAbilityRequest: %{public}d", requestId);
    }
}

void UIAbilityLifecycleManager::AddSpecifiedRequest(std::shared_ptr<SpecifiedRequest> request)
{
    if (!request) {
        return;
    }

    auto &abilityRequest = request->abilityRequest;
    TAG_LOGI(AAFwkTag::ABILITYMGR, "AddSpecifiedRequest: %{public}d, %{public}s", request->requestId,
        abilityRequest.want.GetElement().GetURI().c_str());
    auto instanceKey = abilityRequest.want.GetStringParam(Want::APP_INSTANCE_KEY);
    auto accessTokenIdStr = std::to_string(abilityRequest.abilityInfo.applicationInfo.accessTokenId);
    auto &list = specifiedRequestList_[accessTokenIdStr + instanceKey];
    list.push_back(request);
    if (list.size() == 1) {
        StartSpecifiedRequest(*request);
    }
}

bool UIAbilityLifecycleManager::TryProcessHookModule(SpecifiedRequest &specifiedRequest, bool isHookModule)
{
    if (!isHookModule) {
        return false;
    }
    auto abilityRecord = FindRecordFromSessionMap(specifiedRequest.abilityRequest);
    if (abilityRecord == nullptr || !abilityRecord->IsHook() || abilityRecord->GetHookOff()) {
        return false;
    }
    sptr<SessionInfo> hookSessionInfo = abilityRecord->GetSessionInfo();
    NotifySCBPendingActivation(hookSessionInfo, specifiedRequest.abilityRequest);
    auto nextRequest = PopAndGetNextSpecified(specifiedRequest.requestId);
    if (nextRequest) {
        TaskHandlerWrap::GetFfrtHandler()->SubmitTask([nextRequest, pThis = shared_from_this()]() {
            std::lock_guard lock(pThis->sessionLock_);
            pThis->StartSpecifiedRequest(*nextRequest);
            });
    }
    return true;
}

void UIAbilityLifecycleManager::StartSpecifiedRequest(SpecifiedRequest &specifiedRequest)
{
    TAG_LOGI(AAFwkTag::ABILITYMGR, "StartSpecifiedRequest: %{public}d", specifiedRequest.requestId);
    auto &request = specifiedRequest.abilityRequest;

    if (specifiedRequest.specifiedProcessState == SpecifiedProcessState::STATE_PROCESS) {
        DelayedSingleton<AppScheduler>::GetInstance()->StartSpecifiedProcess(request.want,
            request.abilityInfo, specifiedRequest.requestId);
    } else {
        if (specifiedRequest.preCreateProcessName) {
            PreCreateProcessName(request);
        }
        auto isHookModule = IsHookModule(request);
        if (TryProcessHookModule(specifiedRequest, isHookModule)) {
            return;
        }
        if (specifiedRequest.specifiedProcessState == SpecifiedProcessState::STATE_NONE &&
            !IsSpecifiedModuleLoaded(request)) {
            specifiedRequest.isCold = true;
            auto sessionInfo = CreateSessionInfo(request);
            sessionInfo->requestCode = request.requestCode;
            sessionInfo->userId = userId_;
            sessionInfo->requestId = specifiedRequest.requestId;
            sessionInfo->isFromIcon = request.isFromIcon;
            TAG_LOGI(AAFwkTag::ABILITYMGR, "StartSpecifiedRequest cold");
            NotifySCBPendingActivation(sessionInfo, request);
            sessionInfo->want.RemoveAllFd();
        }
        if (specifiedRequest.isCold && isHookModule) {
            return;
        }
        DelayedSingleton<AppScheduler>::GetInstance()->StartSpecifiedAbility(request.want,
            request.abilityInfo, specifiedRequest.requestId);
    }

    auto timeoutTask = [requestId = specifiedRequest.requestId, wThis = weak_from_this()]() {
        auto pThis = wThis.lock();
        if (pThis) {
            pThis->OnStartSpecifiedFailed(requestId);
        }
    };
    TaskHandlerWrap::GetFfrtHandler()->SubmitTaskJust(timeoutTask, "SpecifiedFinalTimeout",
        GlobalConstant::TIMEOUT_UNIT_TIME * GlobalConstant::COLDSTART_TIMEOUT_MULTIPLE);
}

std::shared_ptr<SpecifiedRequest> UIAbilityLifecycleManager::PopAndGetNextSpecified(int32_t requestId)
{
    for (auto iter = specifiedRequestList_.begin(); iter != specifiedRequestList_.end(); ++iter) {
        auto &list = iter->second;
        if (!list.empty() && list.front()->requestId == requestId) {
            list.pop_front();
            if (list.empty()) {
                TAG_LOGI(AAFwkTag::ABILITYMGR, "empty list");
                specifiedRequestList_.erase(iter);
                return nullptr;
            } else {
                return list.front();
            }
        }
    }
    TAG_LOGI(AAFwkTag::ABILITYMGR, "unknown request: %{public}d", requestId);
    return nullptr;
}

bool UIAbilityLifecycleManager::IsSpecifiedModuleLoaded(const AbilityRequest &abilityRequest)
{
    auto appMgr = AppMgrUtil::GetAppMgr();
    if (appMgr == nullptr) {
        TAG_LOGW(AAFwkTag::ABILITYMGR, "AppMgrUtil::GetAppMgr failed");
        return false;
    }
    bool appExist = false;
    auto ret = IN_PROCESS_CALL(appMgr->IsSpecifiedModuleLoaded(abilityRequest.want,
        abilityRequest.abilityInfo, appExist));
    return ret == ERR_OK && appExist;
}

bool UIAbilityLifecycleManager::HandleStartSpecifiedCold(AbilityRequest &abilityRequest, sptr<SessionInfo> sessionInfo,
    uint32_t sceneFlag)
{
    if (!sessionInfo) {
        return false;
    }
    const auto &abilityInfo = abilityRequest.abilityInfo;
    if (abilityInfo.launchMode != AppExecFwk::LaunchMode::SPECIFIED) {
        return false;
    }

    auto request = GetSpecifiedRequest(sessionInfo->requestId);
    if (request == nullptr || !request->isCold) {
        return false;
    }

    TAG_LOGI(AAFwkTag::ABILITYMGR, "HandleStartSpecifiedCold: %{public}d, persitentId: %{public}d",
        request->requestId, sessionInfo->persistentId);
    request->persistentId = sessionInfo->persistentId;
    request->sceneFlag = sceneFlag;
    request->callingTokenId = sessionInfo->callingTokenId;
    return true;
}

bool UIAbilityLifecycleManager::HandleColdAcceptWantDone(const AAFwk::Want &want, const std::string &flag,
    const SpecifiedRequest &specifiedRequest)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    auto iter = sessionAbilityMap_.find(specifiedRequest.persistentId);
    if (iter == sessionAbilityMap_.end() || !(iter->second) ||
        !(iter->second->GetSpecifiedFlag().empty())) {
        return false;
    }

    TAG_LOGI(AAFwkTag::ABILITYMGR, "HandleColdAcceptWantDone: %{public}d, session:%{public}d",
        specifiedRequest.requestId, specifiedRequest.persistentId);
    auto uiAbilityRecord = iter->second;
    CHECK_POINTER_AND_RETURN(uiAbilityRecord, false);
    UpdateSpecifiedFlag(uiAbilityRecord, flag);
    uiAbilityRecord->SetSpecifiedFlag(flag);
    auto isShellCall = specifiedRequest.abilityRequest.want.GetBoolParam(IS_SHELL_CALL, false);
    uiAbilityRecord->SetPendingState(AbilityState::FOREGROUND);
    uiAbilityRecord->ProcessForegroundAbility(specifiedRequest.callingTokenId,
        specifiedRequest.sceneFlag, isShellCall);
    SendKeyEvent(specifiedRequest.abilityRequest);
    return true;
}

std::shared_ptr<SpecifiedRequest> UIAbilityLifecycleManager::GetSpecifiedRequest(int32_t requestId)
{
    for (const auto &[key, list] : specifiedRequestList_) {
        if (!list.empty() && list.front()->requestId == requestId) {
            return list.front();
        }
    }
    return nullptr;
}

void UIAbilityLifecycleManager::PutSpecifiedFlag(int32_t requestId, const std::string &flag)
{
    specifiedFlagMap_[requestId] = flag;
    auto timeoutTask = [requestId, pThis = shared_from_this()]() {
        std::lock_guard lock(pThis->sessionLock_);
        pThis->specifiedFlagMap_.erase(requestId);
    };
    TaskHandlerWrap::GetFfrtHandler()->SubmitTaskJust(timeoutTask, "PutSpecifiedFlagTimeout",
        AmsConfigurationParameter::GetInstance().GetAppStartTimeoutTime() * GlobalConstant::COLDSTART_TIMEOUT_MULTIPLE);
}

void UIAbilityLifecycleManager::SetKillForPermissionUpdateFlag(uint32_t accessTokenId)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    std::lock_guard<ffrt::mutex> guard(sessionLock_);
    for (auto it = sessionAbilityMap_.begin(); it != sessionAbilityMap_.end(); it++) {
        if (it->second == nullptr) {
            continue;
        }
        auto &abilityInfo = it->second->GetAbilityInfo();
        auto &applicationInfo = it->second->GetApplicationInfo();
        if (applicationInfo.accessTokenId == accessTokenId &&
            applicationInfo.bundleType == AppExecFwk::BundleType::ATOMIC_SERVICE &&
            abilityInfo.type == AppExecFwk::AbilityType::PAGE) {
                it->second->SetKillForPermissionUpdateFlag(true);
        }
    }
}

void UIAbilityLifecycleManager::HandleForegroundCollaborate(
    const AbilityRequest &abilityRequest, std::shared_ptr<AbilityRecord> abilityRecord)
{
    abilityRecord->SetWant(abilityRequest.want);
    if (abilityRecord->GetAbilityState() == AbilityState::FOREGROUND) {
        abilityRecord->ScheduleCollaborate(abilityRequest.want);
    }
}

bool UIAbilityLifecycleManager::UpdateSpecifiedFlag(std::shared_ptr<AbilityRecord> uiAbilityRecord,
    const std::string &flag)
{
    if (uiAbilityRecord == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "uiAbilityRecord is nullptr");
        return false;
    }
    auto sessionInfo = uiAbilityRecord->GetSessionInfo();
    if (sessionInfo == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "sessionInfo is nullptr");
        return false;
    }
    auto session = iface_cast<Rosen::ISession>(sessionInfo->sessionToken);
    if (session == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "session is nullptr");
        return false;
    }
    session->UpdateFlag(flag);
    TAG_LOGD(AAFwkTag::ABILITYMGR, "call session UpdateFlag, specifiedFlag: %{public}s", flag.c_str());
    return true;
}

int32_t UIAbilityLifecycleManager::RevokeDelegator(sptr<IRemoteObject> token)
{
    if (token == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "null token");
        return ERR_INVALID_CONTEXT;
    }
    std::lock_guard<ffrt::mutex> guard(sessionLock_);
    auto abilityRecord = Token::GetAbilityRecordByToken(token);
    CHECK_POINTER_AND_RETURN(abilityRecord, ERR_INVALID_CONTEXT);
    auto callingTokenId = IPCSkeleton::GetCallingTokenID();
    if (callingTokenId != abilityRecord->GetApplicationInfo().accessTokenId) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "not self");
        return ERR_INVALID_CONTEXT;
    }
    if (!abilityRecord->IsForeground() && !abilityRecord->GetAbilityForegroundingFlag()) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "ability not foreground");
        return ERR_ABILITY_NOT_FOREGROUND;
    }
    if (!abilityRecord->IsHook()) {
        return ERR_NOT_HOOK;
    }
    auto abilityInfo = abilityRecord->GetAbilityInfo();
    auto isSpecified = (abilityInfo.launchMode == AppExecFwk::LaunchMode::SPECIFIED);
    if (isSpecified) {
        auto requestId = GetRequestId();
        hookSpecifiedMap_.emplace(requestId, abilityRecord);
        DelayedSingleton<AppScheduler>::GetInstance()->StartSpecifiedAbility(abilityRecord->GetWant(),
            abilityInfo, requestId);
        return ERR_OK;
    }
    auto sessionInfo = abilityRecord->GetSessionInfo();
    CHECK_POINTER_AND_RETURN(sessionInfo, ERR_INVALID_VALUE);
    sessionInfo->reuseDelegatorWindow = true;
    auto launchWant = abilityRecord->GetLaunchWant();
    if (launchWant == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "launchWant is nullptr");
        return ERR_INVALID_VALUE;
    }
    sessionInfo->want = *launchWant;
    abilityRecord->SetWant(sessionInfo->want);
    AbilityRequest request;
    request.callerToken = token;
    int ret = NotifySCBPendingActivation(sessionInfo, request);
    TAG_LOGI(
        AAFwkTag::ABILITYMGR, "Reused sessionId: %{public}d, ret: %{public}d.", sessionInfo->persistentId, ret);
    sessionInfo->reuseDelegatorWindow = false;
    sessionInfo->want.RemoveAllFd();
    if (ret == ERR_OK) {
        abilityRecord->SetHookOff(true);
        abilityRecord->SetIsHook(false);
        abilityRecord->SetLaunchWant(nullptr);
        return ERR_OK;
    } else {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "scb error");
        return ERR_FROM_WINDOW;
    }
}
}  // namespace AAFwk
}  // namespace OHOS