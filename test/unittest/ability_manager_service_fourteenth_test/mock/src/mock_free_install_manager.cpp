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

#include "mock_free_install_manager.h"
#include "mock_my_status.h"

namespace OHOS {
namespace AAFwk {
FreeInstallManager::FreeInstallManager(const std::weak_ptr<AbilityManagerService> &server)
    : server_(server)
{
}

bool FreeInstallManager::IsTopAbility(const sptr<IRemoteObject> &callerToken)
{
    return true;
}

int FreeInstallManager::StartFreeInstall(const Want &want, int32_t userId, int requestCode,
    const sptr<IRemoteObject> &callerToken, std::shared_ptr<FreeInstallParams> param)
{
    return MyStatus::GetInstance().fimStartFreeInstall_;
}

int FreeInstallManager::RemoteFreeInstall(const Want &want, int32_t userId, int requestCode,
    const sptr<IRemoteObject> &callerToken)
{
    return NOT_TOP_ABILITY;
}

FreeInstallInfo FreeInstallManager::BuildFreeInstallInfo(const Want &want, int32_t userId, int requestCode,
    const sptr<IRemoteObject> &callerToken, std::shared_ptr<FreeInstallParams> param)
{
    FreeInstallInfo info = {};
    return info;
}

int FreeInstallManager::StartRemoteFreeInstall(const Want &want, int requestCode, int32_t validUserId,
    const sptr<IRemoteObject> &callerToken)
{
    return 0;
}

int FreeInstallManager::NotifyDmsCallback(const Want &want, int resultCode)
{
    return ERR_OK;
}

void FreeInstallManager::NotifyFreeInstallResult(int32_t recordId, const Want &want, int resultCode, bool isAsync)
{
}

void FreeInstallManager::HandleOnFreeInstallSuccess(int32_t recordId, FreeInstallInfo &freeInstallInfo, bool isAsync)
{
}

void FreeInstallManager::HandleOnFreeInstallFail(int32_t recordId, FreeInstallInfo &freeInstallInfo, int resultCode,
    bool isAsync)
{
}

void FreeInstallManager::HandleFreeInstallResult(int32_t recordId, FreeInstallInfo &freeInstallInfo, int resultCode,
    bool isAsync)
{
}

void FreeInstallManager::StartAbilityByFreeInstall(FreeInstallInfo &info, std::string &bundleName,
    std::string &abilityName, std::string &startTime)
{
}

void FreeInstallManager::StartAbilityByPreInstall(int32_t recordId, FreeInstallInfo &info, std::string &bundleName,
    std::string &abilityName, std::string &startTime)
{
}

void FreeInstallManager::StartAbilityByConvertedWant(FreeInstallInfo &info, const std::string &startTime)
{
}

void FreeInstallManager::StartAbilityByOriginalWant(FreeInstallInfo &info, const std::string &startTime)
{
}

int32_t FreeInstallManager::UpdateElementName(Want &want, int32_t userId) const
{
    return ERR_OK;
}

int FreeInstallManager::FreeInstallAbilityFromRemote(const Want &want, const sptr<IRemoteObject> &callback,
    int32_t userId, int requestCode)
{
    return ERR_OK;
}

int FreeInstallManager::ConnectFreeInstall(const Want &want, int32_t userId,
    const sptr<IRemoteObject> &callerToken, const std::string& localDeviceId)
{
    return ERR_OK;
}

std::time_t FreeInstallManager::GetTimeStamp()
{
    std::chrono::time_point<std::chrono::system_clock, std::chrono::milliseconds> tp =
        std::chrono::time_point_cast<std::chrono::milliseconds>(std::chrono::system_clock::now());
    std::time_t timestamp = tp.time_since_epoch().count();
    return timestamp;
}

void FreeInstallManager::OnInstallFinished(int32_t recordId, int resultCode, const Want &want,
    int32_t userId, bool isAsync)
{
}

void FreeInstallManager::PostUpgradeAtomicServiceTask(int resultCode, const Want &want, int32_t userId)
{
}

void FreeInstallManager::OnRemoteInstallFinished(int32_t recordId, int resultCode, const Want &want, int32_t userId)
{
}

int FreeInstallManager::AddFreeInstallObserver(const sptr<IRemoteObject> &callerToken,
    const sptr<AbilityRuntime::IFreeInstallObserver> &observer)
{
    return CHECK_PERMISSION_FAILED;
}

void FreeInstallManager::RemoveFreeInstallInfo(const std::string &bundleName, const std::string &abilityName,
    const std::string &startTime)
{
}

bool FreeInstallManager::VerifyStartFreeInstallPermission(const sptr<IRemoteObject> &callerToken)
{
    return true;
}

int32_t FreeInstallManager::GetRecordIdByToken(const sptr<IRemoteObject> &callerToken)
{
    return 0;
}

int FreeInstallManager::SetAppRunningState(Want &want)
{
    return ERR_OK;
}

bool FreeInstallManager::GetFreeInstallTaskInfo(const std::string& bundleName, const std::string& abilityName,
    const std::string& startTime, FreeInstallInfo& taskInfo)
{
    return false;
}

bool FreeInstallManager::GetFreeInstallTaskInfo(const std::string& sessionId, FreeInstallInfo& taskInfo)
{
    return false;
}

void FreeInstallManager::SetSCBCallStatus(const std::string& bundleName, const std::string& abilityName,
    const std::string& startTime, bool scbCallStatus)
{
}

void FreeInstallManager::SetPreStartMissionCallStatus(const std::string& bundleName, const std::string& abilityName,
    const std::string& startTime, bool preStartMissionCallStatus)
{
}

void FreeInstallManager::SetFreeInstallTaskSessionId(const std::string& bundleName, const std::string& abilityName,
    const std::string& startTime, const std::string& sessionId)
{
}

void FreeInstallManager::NotifyInsightIntentFreeInstallResult(const Want &want, int resultCode)
{
}

void FreeInstallManager::NotifyInsightIntentExecuteDone(const Want &want, int resultCode)
{
}
}  // namespace AAFwk
}  // namespace OHOS
