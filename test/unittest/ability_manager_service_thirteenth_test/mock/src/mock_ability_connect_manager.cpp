/*
 * Copyright (c) 2021-2025 Huawei Device Co., Ltd.
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

#include "ability_connect_manager.h"
#include "mock_my_status.h"

namespace OHOS {
namespace AAFwk {
AbilityConnectManager::AbilityConnectManager(int userId) : userId_(userId)
{
    uiExtensionAbilityRecordMgr_ = std::make_unique<AbilityRuntime::ExtensionRecordManager>(userId);
}

AbilityConnectManager::~AbilityConnectManager()
{}

bool AbilityConnectManager::HasRequestIdInLoadAbilityQueue(int32_t requestId)
{
    return false;
}

void AbilityConnectManager::OnStartSpecifiedProcessResponse(const std::string &flag, int32_t requestId)
{}

void AbilityConnectManager::OnStartSpecifiedProcessTimeoutResponse(int32_t requestId)
{}

void AbilityConnectManager::StartSpecifiedProcess(
    const LoadAbilityContext &context, const std::shared_ptr<BaseExtensionRecord> &abilityRecord)
{}


int AbilityConnectManager::StartAbility(const AbilityRequest &abilityRequest)
{
    return 0;
}

int AbilityConnectManager::TerminateAbility(const sptr<IRemoteObject> &token)
{
    return 0;
}

int AbilityConnectManager::TerminateAbilityInner(const sptr<IRemoteObject> &token)
{
    return 0;
}

int AbilityConnectManager::StopServiceAbility(const AbilityRequest &abilityRequest)
{
    return 0;
}

int AbilityConnectManager::StartAbilityLocked(const AbilityRequest &abilityRequest)
{
    return ERR_OK;
}

void AbilityConnectManager::SetLastExitReason(
    const AbilityRequest &abilityRequest, std::shared_ptr<BaseExtensionRecord> &targetRecord)
{
}

void AbilityConnectManager::DoForegroundUIExtension(std::shared_ptr<BaseExtensionRecord> abilityRecord,
    const AbilityRequest &abilityRequest)
{
}

void AbilityConnectManager::EnqueueStartServiceReq(const AbilityRequest &abilityRequest, const std::string &serviceUri)
{
}

int AbilityConnectManager::TerminateAbilityLocked(const sptr<IRemoteObject> &token)
{
    return ERR_OK;
}

int AbilityConnectManager::StopServiceAbilityLocked(const AbilityRequest &abilityRequest)
{
    return ERR_OK;
}

int32_t AbilityConnectManager::GetOrCreateExtensionRecord(const AbilityRequest &abilityRequest, bool isCreatedByConnect,
    const std::string &hostBundleName, std::shared_ptr<BaseExtensionRecord> &extensionRecord, bool &isLoaded)
{
    return ERR_OK;
}

void AbilityConnectManager::GetOrCreateServiceRecord(const AbilityRequest &abilityRequest,
    const bool isCreatedByConnect, std::shared_ptr<BaseExtensionRecord> &targetService, bool &isLoadedAbility)
{
}

void AbilityConnectManager::RemoveServiceFromMapSafe(const std::string &serviceKey)
{
}


void AbilityConnectManager::GetConnectRecordListFromMap(
    const sptr<IAbilityConnection> &connect, std::list<std::shared_ptr<ConnectionRecord>> &connectRecordList)
{
}

int32_t AbilityConnectManager::GetOrCreateTargetServiceRecord(
    const AbilityRequest &abilityRequest, const sptr<UIExtensionAbilityConnectInfo> &connectInfo,
    std::shared_ptr<BaseExtensionRecord> &targetService, bool &isLoadedAbility)
{
    return ERR_OK;
}

int AbilityConnectManager::PreloadUIExtensionAbilityLocked(const AbilityRequest &abilityRequest,
    std::string &hostBundleName, int32_t hostPid)
{
    return ERR_OK;
}

int AbilityConnectManager::PreloadUIExtensionAbilityInner(const AbilityRequest &abilityRequest,
    std::string &hostBundleName, int32_t hostPid)
{
    return ERR_OK;
}

int AbilityConnectManager::UnloadUIExtensionAbility(const std::shared_ptr<AAFwk::BaseExtensionRecord> &abilityRecord,
    int32_t &hostPid)
{
    return ERR_OK;
}

void AbilityConnectManager::ReportEventToRSS(const AppExecFwk::AbilityInfo &abilityInfo,
    const std::shared_ptr<BaseExtensionRecord> abilityRecord, sptr<IRemoteObject> callerToken)
{
}

int AbilityConnectManager::ConnectAbilityLocked(const AbilityRequest &abilityRequest,
    const sptr<IAbilityConnection> &connect, const sptr<IRemoteObject> &callerToken, sptr<SessionInfo> sessionInfo,
    sptr<UIExtensionAbilityConnectInfo> connectInfo)
{
    return ERR_OK;
}

void AbilityConnectManager::HandleActiveAbility(std::shared_ptr<BaseExtensionRecord> &targetService,
    std::shared_ptr<ConnectionRecord> &connectRecord)
{
}

std::shared_ptr<ConnectionRecord> AbilityConnectManager::GetAbilityConnectedRecordFromRecordList(
    const std::shared_ptr<BaseExtensionRecord> &targetService,
    std::list<std::shared_ptr<ConnectionRecord>> &connectRecordList)
{
    return nullptr;
}

int AbilityConnectManager::DisconnectAbilityLocked(const sptr<IAbilityConnection> &connect)
{
    return ERR_OK;
}

int AbilityConnectManager::DisconnectAbilityLocked(const sptr<IAbilityConnection> &connect, bool callerDied)
{
    return ERR_OK;
}

int32_t AbilityConnectManager::SuspendExtensionAbilityLocked(const sptr<IAbilityConnection> &connect)
{
    return ERR_OK;
}

int32_t AbilityConnectManager::ResumeExtensionAbilityLocked(const sptr<IAbilityConnection> &connect)
{
    return ERR_OK;
}

void AbilityConnectManager::TerminateRecord(std::shared_ptr<BaseExtensionRecord> abilityRecord)
{
}

int AbilityConnectManager::DisconnectRecordNormal(ConnectListType &list,
    std::shared_ptr<ConnectionRecord> connectRecord, bool callerDied) const
{
    return ERR_OK;
}

void AbilityConnectManager::DisconnectRecordForce(ConnectListType &list,
    std::shared_ptr<ConnectionRecord> connectRecord)
{
}

int AbilityConnectManager::AttachAbilityThreadLocked(
    const sptr<IAbilityScheduler> &scheduler, const sptr<IRemoteObject> &token)
{
    return ERR_OK;
}

void AbilityConnectManager::OnAbilityRequestDone(const sptr<IRemoteObject> &token, const int32_t state)
{
}

void AbilityConnectManager::OnAppStateChanged(const AppInfo &info)
{
}

int AbilityConnectManager::AbilityTransitionDone(const sptr<IRemoteObject> &token, int state)
{
    return ERR_OK;
}

int AbilityConnectManager::AbilityWindowConfigTransactionDone(const sptr<IRemoteObject> &token,
    const WindowConfig &windowConfig)
{
    return ERR_OK;
}

void AbilityConnectManager::ProcessPreload(const std::shared_ptr<BaseExtensionRecord> &record) const
{
}

int AbilityConnectManager::ScheduleConnectAbilityDoneLocked(
    const sptr<IRemoteObject> &token, const sptr<IRemoteObject> &remoteObject)
{
    return ERR_OK;
}

void AbilityConnectManager::ProcessEliminateAbilityRecord(std::shared_ptr<BaseExtensionRecord> eliminateRecord)
{
}

void AbilityConnectManager::TerminateOrCacheAbility(std::shared_ptr<BaseExtensionRecord> abilityRecord)
{
}

int AbilityConnectManager::ScheduleDisconnectAbilityDoneLocked(const sptr<IRemoteObject> &token)
{
    return ERR_OK;
}

int AbilityConnectManager::ScheduleCommandAbilityDoneLocked(const sptr<IRemoteObject> &token)
{
    return ERR_OK;
}

int AbilityConnectManager::ScheduleCommandAbilityWindowDone(
    const sptr<IRemoteObject> &token,
    const sptr<SessionInfo> &sessionInfo,
    WindowCommand winCmd,
    AbilityCommand abilityCmd)
{
    return ERR_OK;
}

void AbilityConnectManager::HandleCommandDestroy(const sptr<SessionInfo> &sessionInfo)
{
}

void AbilityConnectManager::CompleteCommandAbility(std::shared_ptr<BaseExtensionRecord> abilityRecord)
{
}

void AbilityConnectManager::CompleteStartServiceReq(const std::string &serviceUri)
{
}

std::shared_ptr<BaseExtensionRecord> AbilityConnectManager::GetServiceRecordByAbilityRequest(
    const AbilityRequest &abilityRequest)
{
    return nullptr;
}

std::shared_ptr<BaseExtensionRecord> AbilityConnectManager::GetServiceRecordByElementName(const std::string &element)
{
    return nullptr;
}

std::shared_ptr<BaseExtensionRecord> AbilityConnectManager::GetExtensionByTokenFromServiceMap(
    const sptr<IRemoteObject> &token)
{
    return nullptr;
}

std::shared_ptr<BaseExtensionRecord> AbilityConnectManager::GetExtensionByIdFromServiceMap(
    const int64_t &abilityRecordId)
{
    return nullptr;
}

std::shared_ptr<BaseExtensionRecord> AbilityConnectManager::GetExtensionByIdFromTerminatingMap(
    const int64_t &abilityRecordId)
{
    return nullptr;
}

std::shared_ptr<BaseExtensionRecord> AbilityConnectManager::GetUIExtensionBySessionInfo(
    const sptr<SessionInfo> &sessionInfo)
{
    return MyStatus::GetInstance().acmGetUIExtensionBySessionInfo_;
}

std::shared_ptr<BaseExtensionRecord> AbilityConnectManager::GetExtensionByTokenFromTerminatingMap(
    const sptr<IRemoteObject> &token)
{
    return nullptr;
}

void AbilityConnectManager::LoadAbility(const std::shared_ptr<BaseExtensionRecord> &abilityRecord,
    std::function<void(const std::shared_ptr<BaseExtensionRecord>&)> updateRecordCallback)
{
}

void AbilityConnectManager::SetExtensionLoadParam(AbilityRuntime::LoadParam &loadParam,
    std::shared_ptr<BaseExtensionRecord> abilityRecord)
{
}

bool AbilityConnectManager::IsStrictMode(std::shared_ptr<BaseExtensionRecord> abilityRecord)
{
    return true;
}

bool AbilityConnectManager::NeedExtensionControl(std::shared_ptr<BaseExtensionRecord> abilityRecord)
{
    return true;
}

void AbilityConnectManager::PostRestartResidentTask(const AbilityRequest &abilityRequest)
{
}

void AbilityConnectManager::HandleRestartResidentTask(const AbilityRequest &abilityRequest)
{
}

void AbilityConnectManager::PostTimeOutTask(const std::shared_ptr<BaseExtensionRecord> &abilityRecord,
    uint32_t messageId)
{
}

void AbilityConnectManager::PostTimeOutTask(const std::shared_ptr<BaseExtensionRecord> &abilityRecord,
    int connectRecordId, uint32_t messageId)
{
}

void AbilityConnectManager::HandleStartTimeoutTask(const std::shared_ptr<BaseExtensionRecord> &abilityRecord)
{
}

void AbilityConnectManager::HandleCommandTimeoutTask(const std::shared_ptr<BaseExtensionRecord> &abilityRecord)
{
}

void AbilityConnectManager::HandleConnectTimeoutTask(std::shared_ptr<BaseExtensionRecord> abilityRecord)
{
}

void AbilityConnectManager::HandleCommandWindowTimeoutTask(const std::shared_ptr<BaseExtensionRecord> &abilityRecord,
    const sptr<SessionInfo> &sessionInfo, WindowCommand winCmd)
{
}

void AbilityConnectManager::HandleStopTimeoutTask(const std::shared_ptr<BaseExtensionRecord> &abilityRecord)
{
}

void AbilityConnectManager::HandleTerminateDisconnectTask(const ConnectListType& connectlist)
{
}

int AbilityConnectManager::DispatchInactive(const std::shared_ptr<BaseExtensionRecord> &abilityRecord, int state)
{
    return ERR_OK;
}

int AbilityConnectManager::DispatchForeground(const std::shared_ptr<BaseExtensionRecord> &abilityRecord)
{
    return ERR_OK;
}

int AbilityConnectManager::DispatchBackground(const std::shared_ptr<BaseExtensionRecord> &abilityRecord)
{
    return ERR_OK;
}

int AbilityConnectManager::DispatchTerminate(const std::shared_ptr<BaseExtensionRecord> &abilityRecord)
{
    return ERR_OK;
}

void AbilityConnectManager::ConnectAbility(const std::shared_ptr<BaseExtensionRecord> &abilityRecord)
{
}

void AbilityConnectManager::ConnectUIServiceExtAbility(const std::shared_ptr<BaseExtensionRecord> &abilityRecord,
    int connectRecordId, const Want &want)
{
}

void AbilityConnectManager::ResumeConnectAbility(const std::shared_ptr<BaseExtensionRecord> &abilityRecord)
{
}

void AbilityConnectManager::CommandAbility(const std::shared_ptr<BaseExtensionRecord> &abilityRecord)
{
}

void AbilityConnectManager::CommandAbilityWindow(const std::shared_ptr<BaseExtensionRecord> &abilityRecord,
    const sptr<SessionInfo> &sessionInfo, WindowCommand winCmd)
{
}

void AbilityConnectManager::BackgroundAbilityWindowLocked(const std::shared_ptr<BaseExtensionRecord> &abilityRecord,
    const sptr<SessionInfo> &sessionInfo)
{
}

void AbilityConnectManager::DoBackgroundAbilityWindow(const std::shared_ptr<BaseExtensionRecord> &abilityRecord,
    const sptr<SessionInfo> &sessionInfo)
{
}

void AbilityConnectManager::TerminateAbilityWindowLocked(const std::shared_ptr<BaseExtensionRecord> &abilityRecord,
    const sptr<SessionInfo> &sessionInfo)
{
}

void AbilityConnectManager::TerminateDone(const std::shared_ptr<BaseExtensionRecord> &abilityRecord)
{
}

void AbilityConnectManager::RemoveConnectionRecordFromMap(std::shared_ptr<ConnectionRecord> connection)
{
}

void AbilityConnectManager::RemoveServiceAbility(const std::shared_ptr<BaseExtensionRecord> &abilityRecord)
{
}

void AbilityConnectManager::AddConnectDeathRecipient(sptr<IRemoteObject> connectObject)
{
}

void AbilityConnectManager::RemoveConnectDeathRecipient(sptr<IRemoteObject> connectObject)
{
}

void AbilityConnectManager::OnCallBackDied(const wptr<IRemoteObject> &remote)
{
}

void AbilityConnectManager::HandleCallBackDiedTask(const sptr<IRemoteObject> &connect)
{
}

int32_t AbilityConnectManager::GetActiveUIExtensionList(
    const int32_t pid, std::vector<std::string> &extensionList)
{
    return 0;
}

int32_t AbilityConnectManager::GetActiveUIExtensionList(
    const std::string &bundleName, std::vector<std::string> &extensionList)
{
    return 0;
}

void AbilityConnectManager::OnLoadAbilityFailed(std::shared_ptr<BaseExtensionRecord> abilityRecord)
{
}

void AbilityConnectManager::OnAbilityDied(const std::shared_ptr<BaseExtensionRecord> abilityRecord)
{
}

void AbilityConnectManager::OnTimeOut(uint32_t msgId, int64_t abilityRecordId, bool isHalf)
{
}

void AbilityConnectManager::HandleInactiveTimeout(const std::shared_ptr<BaseExtensionRecord> &ability)
{
}

void AbilityConnectManager::CleanActivatingTimeoutAbility(std::shared_ptr<BaseExtensionRecord> abilityRecord)
{
}

bool AbilityConnectManager::IsAbilityNeedKeepAlive(const std::shared_ptr<BaseExtensionRecord> &abilityRecord)
{
    return true;
}

void AbilityConnectManager::ClearPreloadUIExtensionRecord(const std::shared_ptr<BaseExtensionRecord> &abilityRecord)
{
}

void AbilityConnectManager::KeepAbilityAlive(const std::shared_ptr<BaseExtensionRecord> &abilityRecord)
{
}

bool AbilityConnectManager::IsNeedToRestart(const std::shared_ptr<BaseExtensionRecord> &abilityRecord,
    const std::string &bundleName, const std::string &abilityName)
{
    return true;
}

void AbilityConnectManager::DisconnectBeforeCleanup()
{
}

void AbilityConnectManager::HandleAbilityDiedTask(
    const std::shared_ptr<BaseExtensionRecord> &abilityRecord)
{
}

static bool CheckIsNumString(const std::string &numStr)
{
    return true;
}

void AbilityConnectManager::HandleNotifyAssertFaultDialogDied(const std::shared_ptr<BaseExtensionRecord> &abilityRecord)
{
}

void AbilityConnectManager::CloseAssertDialog(const std::string &assertSessionId)
{
}

void AbilityConnectManager::HandleUIExtensionDied(const std::shared_ptr<BaseExtensionRecord> &abilityRecord)
{
}

void AbilityConnectManager::RestartAbility(const std::shared_ptr<BaseExtensionRecord> &abilityRecord,
    int32_t currentUserId)
{
}

std::string AbilityConnectManager::GetServiceKey(const std::shared_ptr<BaseExtensionRecord> &service)
{
    return "";
}

void AbilityConnectManager::DumpState(std::vector<std::string> &info, bool isClient, const std::string &args)
{
}

void AbilityConnectManager::DumpStateByUri(std::vector<std::string> &info, bool isClient, const std::string &args,
    std::vector<std::string> &params)
{
}

void AbilityConnectManager::GetExtensionRunningInfos(int upperLimit, std::vector<ExtensionRunningInfo> &info,
    const int32_t userId, bool isPerm)
{
}

void AbilityConnectManager::GetAbilityRunningInfos(std::vector<AbilityRunningInfo> &info, bool isPerm)
{
}

void AbilityConnectManager::GetExtensionRunningInfo(std::shared_ptr<BaseExtensionRecord> &abilityRecord,
    const int32_t userId, std::vector<ExtensionRunningInfo> &info)
{
}

void AbilityConnectManager::PauseExtensions()
{
}

void AbilityConnectManager::RemoveLauncherDeathRecipient()
{
}

bool AbilityConnectManager::IsLauncher(std::shared_ptr<BaseExtensionRecord> serviceExtension) const
{
    return true;
}

void AbilityConnectManager::KillProcessesByUserId() const
{
}

void AbilityConnectManager::MoveToBackground(const std::shared_ptr<BaseExtensionRecord> &abilityRecord)
{
}

void AbilityConnectManager::CompleteForeground(const std::shared_ptr<BaseExtensionRecord> &abilityRecord)
{
}

void AbilityConnectManager::HandleForegroundTimeoutTask(const std::shared_ptr<BaseExtensionRecord> &abilityRecord)
{
}

void AbilityConnectManager::CompleteBackground(const std::shared_ptr<BaseExtensionRecord> &abilityRecord)
{
}

void AbilityConnectManager::PrintTimeOutLog(const std::shared_ptr<BaseExtensionRecord> &ability,
    uint32_t msgId, bool isHalf)
{
}

bool AbilityConnectManager::GetTimeoutMsgContent(uint32_t msgId, std::string &msgContent, int &typeId)
{
    return true;
}

void AbilityConnectManager::MoveToTerminatingMap(const std::shared_ptr<BaseExtensionRecord>& abilityRecord)
{
}

void AbilityConnectManager::AddUIExtWindowDeathRecipient(const sptr<IRemoteObject> &session)
{
}

void AbilityConnectManager::RemoveUIExtWindowDeathRecipient(const sptr<IRemoteObject> &session)
{
}

void AbilityConnectManager::OnUIExtWindowDied(const wptr<IRemoteObject> &remote)
{
}

void AbilityConnectManager::HandleUIExtWindowDiedTask(const sptr<IRemoteObject> &remote)
{
}

bool AbilityConnectManager::IsUIExtensionFocused(uint32_t uiExtensionTokenId, const sptr<IRemoteObject>& focusToken)
{
    return true;
}

sptr<IRemoteObject> AbilityConnectManager::GetUIExtensionSourceToken(const sptr<IRemoteObject> &token)
{
    return nullptr;
}

void AbilityConnectManager::GetUIExtensionCallerTokenList(const std::shared_ptr<AbilityRecord> &abilityRecord,
    std::list<sptr<IRemoteObject>> &callerList)
{
}

bool AbilityConnectManager::IsWindowExtensionFocused(uint32_t extensionTokenId, const sptr<IRemoteObject>& focusToken)
{
    return true;
}

void AbilityConnectManager::HandleProcessFrozen(const std::vector<int32_t> &pidList, int32_t uid)
{
}

void AbilityConnectManager::PostExtensionDelayDisconnectTask(const std::shared_ptr<ConnectionRecord> &connectRecord)
{
}

void AbilityConnectManager::RemoveExtensionDelayDisconnectTask(const std::shared_ptr<ConnectionRecord> &connectRecord)
{
}

void AbilityConnectManager::HandleExtensionDisconnectTask(const std::shared_ptr<ConnectionRecord> &connectRecord)
{
}

bool AbilityConnectManager::IsUIExtensionAbility(const std::shared_ptr<BaseExtensionRecord> &abilityRecord)
{
    return true;
}

bool AbilityConnectManager::IsCacheExtensionAbilityByInfo(const AppExecFwk::AbilityInfo &abilityInfo)
{
    return true;
}

bool AbilityConnectManager::IsCacheExtensionAbility(const std::shared_ptr<BaseExtensionRecord> &abilityRecord)
{
    return true;
}

bool AbilityConnectManager::CheckUIExtensionAbilitySessionExist(
    const std::shared_ptr<BaseExtensionRecord> &abilityRecord)
{
    return true;
}

void AbilityConnectManager::RemoveUIExtensionAbilityRecord(const std::shared_ptr<BaseExtensionRecord> &abilityRecord)
{
}

void AbilityConnectManager::AddUIExtensionAbilityRecordToTerminatedList(
    const std::shared_ptr<BaseExtensionRecord> &abilityRecord)
{
}

bool AbilityConnectManager::IsCallerValid(const std::shared_ptr<BaseExtensionRecord> &abilityRecord)
{
    return true;
}

std::shared_ptr<AAFwk::AbilityRecord> AbilityConnectManager::GetUIExtensionRootHostInfo(const sptr<IRemoteObject> token)
{
    return nullptr;
}

int32_t AbilityConnectManager::GetUIExtensionSessionInfo(const sptr<IRemoteObject> token,
    UIExtensionSessionInfo &uiExtensionSessionInfo)
{
    return ERR_OK;
}

void AbilityConnectManager::SignRestartAppFlag(int32_t uid, const std::string &instanceKey)
{
}

bool AbilityConnectManager::AddToServiceMap(const std::string &key, std::shared_ptr<BaseExtensionRecord> abilityRecord)
{
    return true;
}

AbilityConnectManager::ServiceMapType AbilityConnectManager::GetServiceMap()
{
    std::lock_guard lock(serviceMapMutex_);
    return serviceMap_;
}

void AbilityConnectManager::AddConnectObjectToMap(sptr<IRemoteObject> connectObject,
    const ConnectListType &connectRecordList, bool updateOnly)
{
}

EventInfo AbilityConnectManager::BuildEventInfo(const std::shared_ptr<BaseExtensionRecord> &abilityRecord)
{
    EventInfo eventInfo;
    return eventInfo;
}

void AbilityConnectManager::UpdateUIExtensionInfo(const std::shared_ptr<BaseExtensionRecord> &abilityRecord,
    int32_t hostPid)
{
}

std::string AbilityConnectManager::GenerateBundleName(const AbilityRequest &abilityRequest) const
{
    return "";
}

int32_t AbilityConnectManager::ReportXiaoYiToRSSIfNeeded(const AppExecFwk::AbilityInfo &abilityInfo)
{
    return ERR_OK;
}

int32_t AbilityConnectManager::ReportAbilityStartInfoToRSS(const AppExecFwk::AbilityInfo &abilityInfo)
{
    return ERR_OK;
}

void AbilityConnectManager::UninstallApp(const std::string &bundleName, int32_t uid)
{
}

int32_t AbilityConnectManager::UpdateKeepAliveEnableState(const std::string &bundleName,
    const std::string &moduleName, const std::string &mainElement, bool updateEnable)
{
    return ERR_OK;
}

int32_t AbilityConnectManager::QueryPreLoadUIExtensionRecordInner(const AppExecFwk::ElementName &element,
                                                                  const std::string &moduleName,
                                                                  const int32_t hostPid,
                                                                  int32_t &recordNum)
{
    return ERR_OK;
}

std::shared_ptr<BaseExtensionRecord> AbilityConnectManager::GetUIExtensionBySessionFromServiceMap(
    const sptr<SessionInfo> &sessionInfo)
{
    return MyStatus::GetInstance().acmGetUIExtensionBySessionFromServiceMap_;
}

void AbilityConnectManager::UpdateUIExtensionBindInfo(
    const std::shared_ptr<BaseExtensionRecord> &abilityRecord, std::string callerBundleName, int32_t notifyProcessBind)
{
}

int AbilityConnectManager::UnPreloadUIExtensionAbilityLocked(int32_t extensionAbilityId)
{
    return 0;
}

int AbilityConnectManager::ClearAllPreloadUIExtensionAbilityLocked()
{
    return 0;
}

int32_t AbilityConnectManager::RegisterPreloadUIExtensionHostClient(const sptr<IRemoteObject> &callerToken)
{
    return 0;
}

int32_t AbilityConnectManager::UnRegisterPreloadUIExtensionHostClient(int32_t key)
{
    return 0;
}

class PreloadUIExtensionHostClientDeathRecipient : public IRemoteObject::DeathRecipient {
public:
    using PreloadUIExtensionHostClientDiedHandler = std::function<void(const wptr<IRemoteObject> &)>;
    explicit PreloadUIExtensionHostClientDeathRecipient(PreloadUIExtensionHostClientDiedHandler handler)
        : diedHandler_(handler)
    {}
    ~PreloadUIExtensionHostClientDeathRecipient() = default;
    void OnRemoteDied(const wptr<IRemoteObject> &remote) final
    {
        if (diedHandler_) {
            diedHandler_(remote);
        }
    }
private:
    PreloadUIExtensionHostClientDiedHandler diedHandler_;
};
}  // namespace AAFwk
}  // namespace OHOS
