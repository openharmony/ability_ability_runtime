/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "missionlistmanagerfirst_fuzzer.h"

#include <cstddef>
#include <cstdint>

#define private public
#define protected public
#include "ability_record.h"
#include "mission_info_mgr.h"
#include "mission_list_manager.h"
#undef protected
#undef private

using namespace OHOS::AAFwk;
using namespace OHOS::AppExecFwk;

namespace OHOS {
namespace {
constexpr uint8_t ENABLE = 2;
constexpr int INPUT_ZERO = 0;
constexpr int INPUT_ONE = 1;
constexpr int INPUT_TWO = 2;
constexpr int INPUT_THREE = 3;
constexpr size_t U32_AT_SIZE = 4;
constexpr uint8_t OFFSET_32_VAL = 32;
constexpr size_t OFFSET_ZERO = 24;
constexpr size_t OFFSET_ONE = 16;
constexpr size_t OFFSET_TWO = 8;
constexpr uint8_t ABILITY_STATE_MOD = 20;
const std::string PARAM_APP_CLONE_INDEX_KEY("ohos.extra.param.key.appCloneIndex");
class MyAbilityConnection : public IAbilityConnection {
public:
    MyAbilityConnection() = default;
    virtual ~MyAbilityConnection() = default;
    void OnAbilityConnectDone(
        const AppExecFwk::ElementName& element, const sptr<IRemoteObject>& remoteObject, int resultCode) override
    {}
    void OnAbilityDisconnectDone(const AppExecFwk::ElementName& element, int resultCode) override
    {}
    sptr<IRemoteObject> AsObject() override
    {
        return {};
    }
};
}

uint32_t GetU32Data(const char* ptr)
{
    // convert fuzz input data to an integer
    return (ptr[INPUT_ZERO] << OFFSET_ZERO) | (ptr[INPUT_ONE] << OFFSET_ONE) | (ptr[INPUT_TWO] << OFFSET_TWO) |
        ptr[INPUT_THREE];
}

std::shared_ptr<AbilityRecord> GetFuzzAbilityRecord()
{
    sptr<Token> token = nullptr;
    AbilityRequest abilityRequest;
    abilityRequest.appInfo.bundleName = "com.example.fuzzTest";
    abilityRequest.abilityInfo.name = "MainAbility";
    abilityRequest.abilityInfo.type = AbilityType::DATA;
    std::shared_ptr<AbilityRecord> abilityRecord = AbilityRecord::CreateAbilityRecord(abilityRequest);
    if (!abilityRecord) {
        return nullptr;
    }
    return abilityRecord;
}

sptr<Token> GetFuzzAbilityToken()
{
    sptr<Token> token = nullptr;
    std::shared_ptr<AbilityRecord> abilityRecord = GetFuzzAbilityRecord();
    if (abilityRecord) {
        token = abilityRecord->GetToken();
    }
    return token;
}

AbilityRequest InitAbilityRequest(const char* data)
{
    AbilityRequest abilityRequest;
    uint32_t mod = static_cast<uint32_t>(LaunchMode::SPECIFIED) + 1;
    abilityRequest.abilityInfo.launchMode = static_cast<LaunchMode>(GetU32Data(data) % mod);
    mod = static_cast<uint32_t>(AbilityCallType::START_EXTENSION_TYPE) + 1;
    abilityRequest.callType = static_cast<AbilityCallType>(GetU32Data(data) % mod);
    return abilityRequest;
}

std::shared_ptr<MissionListManager> InitMissionListManager(int32_t intParam)
{
    static std::once_flag flag;
    auto missionListMgr = std::make_shared<MissionListManager>(intParam);
    missionListMgr->Init();
    return missionListMgr;
}

void DoSomethingTestWithMyAPI0(std::shared_ptr<MissionListManager> missionListMgr, const char* data)
{
    int32_t int32Param = static_cast<int32_t>(GetU32Data(data));
    missionListMgr->RegisterMissionListener(nullptr);
    missionListMgr->GetMissionCount();
    missionListMgr->FindEarliestMission();
    AbilityRequest abilityRequest;
    missionListMgr->EnqueueWaitingAbility(abilityRequest);
    missionListMgr->EnqueueWaitingAbilityToFront(abilityRequest);
    missionListMgr->StartWaitingAbility();
    missionListMgr->UnRegisterMissionListener(nullptr);
    std::shared_ptr<AbilityRecord> targetAbilityRecord = GetFuzzAbilityRecord();
    missionListMgr->AddRecord(abilityRequest, targetAbilityRecord);
    std::shared_ptr<Mission> targetMission = std::make_shared<Mission>(int32Param, targetAbilityRecord);
    missionListMgr->GetTargetMission(abilityRequest, targetMission, targetAbilityRecord);
    missionListMgr->StartAbilityLocked(nullptr, nullptr, abilityRequest);
    abilityRequest.want.SetParam(PARAM_APP_CLONE_INDEX_KEY, int32Param);
    missionListMgr->GetMissionName(abilityRequest);
    bool boolParam = *data % ENABLE;
    missionListMgr->GetTargetMissionAndAbility(abilityRequest, targetMission, targetAbilityRecord, boolParam);
    missionListMgr->EnableRecoverAbility(int32Param);
    missionListMgr->GetTargetMissionList(nullptr, abilityRequest);
    targetAbilityRecord->isLauncherAbility_ = boolParam;
    std::shared_ptr<Mission> mission = std::make_shared<Mission>(int32Param, targetAbilityRecord);
    missionListMgr->launcherList_->AddMissionToTop(mission);
    missionListMgr->GetTargetMissionList(targetAbilityRecord, abilityRequest);
    uint32_t uint32Param = static_cast<uint32_t>(GetU32Data(data));
    abilityRequest.abilityInfo.launchMode = static_cast<LaunchMode>(uint32Param % 3);  // 3 means luanch mode max enum
    missionListMgr->GetReusedMission(abilityRequest);
    missionListMgr->MoveNoneTopMissionToDefaultList(targetMission);
    missionListMgr->MoveMissionListToTop(nullptr);
    missionListMgr->MoveMissionListToTop(missionListMgr->launcherList_);
    auto token = targetAbilityRecord->GetToken();
    missionListMgr->GetAbilityRecordByToken(nullptr);
    missionListMgr->GetAbilityRecordByToken(token);
    targetAbilityRecord->currentState_ = static_cast<AAFwk::AbilityState>(uint32Param % ABILITY_STATE_MOD);
    missionListMgr->DispatchState(targetAbilityRecord, uint32Param % ABILITY_STATE_MOD);
    missionListMgr->CompleteForegroundSuccess(targetAbilityRecord);
    std::shared_ptr<AbilityRecord> prevAbilityRecord = GetFuzzAbilityRecord();
    prevAbilityRecord->isTerminating_ = boolParam;
    prevAbilityRecord->currentState_ = static_cast<AAFwk::AbilityState>(uint32Param % ABILITY_STATE_MOD);
    targetAbilityRecord->SetPreAbilityRecord(prevAbilityRecord);
    missionListMgr->TerminatePreviousAbility(targetAbilityRecord);
    missionListMgr->CompleteBackground(targetAbilityRecord);
}

void DoSomethingTestWithMyAPI1(std::shared_ptr<MissionListManager> missionListMgr, const char* data, size_t size)
{
    bool boolParam = *data % ENABLE;
    int32_t int32Param = static_cast<int32_t>(GetU32Data(data));
    uint32_t uint32Param = static_cast<uint32_t>(GetU32Data(data));
    MissionInfo missionInfo;
    missionListMgr->GetMissionInfo(int32Param, missionInfo);
    std::shared_ptr<StartOptions> startOptions = nullptr;
    missionListMgr->MoveMissionToFront(int32Param, startOptions);
    std::shared_ptr<AbilityRecord> callerAbility = GetFuzzAbilityRecord();
    auto abilityRecord = GetFuzzAbilityRecord();
    std::shared_ptr<Mission> mission = std::make_shared<Mission>(int32Param, abilityRecord);
    missionListMgr->defaultStandardList_->AddMissionToTop(mission);
    missionListMgr->MoveMissionToFront(int32Param, boolParam, boolParam, callerAbility, startOptions);
}

void DoSomethingTestWithMyAPI2(std::shared_ptr<MissionListManager> missionListMgr, const char* data, size_t size)
{
    bool boolParam = *data % ENABLE;
    int32_t int32Param = static_cast<int32_t>(GetU32Data(data));
    uint32_t uint32Param = static_cast<uint32_t>(GetU32Data(data));
    InnerMissionInfo info;
    AbilityRequest abilityRequest = InitAbilityRequest(data);
    missionListMgr->CreateOrReusedMissionInfo(abilityRequest, info);
    auto abilityRecord = GetFuzzAbilityRecord();
    abilityRecord->SetPendingState(static_cast<AAFwk::AbilityState>(GetU32Data(data) % ABILITY_STATE_MOD));
    abilityRecord->currentState_ = static_cast<AAFwk::AbilityState>(GetU32Data(data) % ABILITY_STATE_MOD);
    auto token = abilityRecord->GetToken();
    std::shared_ptr<Mission> mission = std::make_shared<Mission>(int32Param, abilityRecord);
    missionListMgr->defaultStandardList_->AddMissionToTop(mission);
    missionListMgr->MinimizeAbility(token, boolParam);
    missionListMgr->MoveAbilityToBackground(abilityRecord);
    Want *resultWant = new Want();
    int64_t int64Param = (static_cast<int64_t>(GetU32Data(data)) << OFFSET_32_VAL) + GetU32Data(data);
    missionListMgr->BackToCallerAbilityWithResult(abilityRecord, int32Param, resultWant, int64Param);
}

void DoSomethingTestWithMyAPI3(std::shared_ptr<MissionListManager> missionListMgr, const char* data, size_t size)
{
    bool boolParam = *data % ENABLE;
    int32_t int32Param = static_cast<int32_t>(GetU32Data(data));
    uint32_t uint32Param = static_cast<uint32_t>(GetU32Data(data));
    auto abilityRecord = GetFuzzAbilityRecord();
    std::shared_ptr<Mission> mission = std::make_shared<Mission>(int32Param, abilityRecord);
    abilityRecord->SetMissionId(int32Param);
    missionListMgr->defaultStandardList_->AddMissionToTop(mission);
    missionListMgr->SetMissionLockedState(int32Param, boolParam);
    const AppExecFwk::ElementName element;
    missionListMgr->GetAbilityNumber(element);
    missionListMgr->MoveToBackgroundTask(abilityRecord, boolParam);
    missionListMgr->PrintTimeOutLog(abilityRecord, uint32Param, boolParam);
    uint32_t msgId = uint32Param % ABILITY_STATE_MOD;
    std::string stringParam(data, size);
    missionListMgr->GetContentAndTypeId(msgId, stringParam, int32Param);
    abilityRecord->recordId_ = int32Param;
    missionListMgr->OnTimeOut(msgId, int32Param, boolParam);
    missionListMgr->HandleLoadTimeout(abilityRecord);
    auto state = static_cast<AAFwk::AbilityState>(GetU32Data(data) % ABILITY_STATE_MOD);
    abilityRecord->currentState_ = static_cast<AAFwk::AbilityState>(GetU32Data(data) % ABILITY_STATE_MOD);
    missionListMgr->HandleForegroundTimeout(abilityRecord, state);
    missionListMgr->CompleteForegroundFailed(abilityRecord, state);
    missionListMgr->HandleTimeoutAndResumeAbility(abilityRecord, state);
    missionListMgr->DelayedResumeTimeout(abilityRecord);
    missionListMgr->MoveToTerminateList(abilityRecord);
}

void DoSomethingTestWithMyAPI4(std::shared_ptr<MissionListManager> missionListMgr, const char* data, size_t size)
{
    bool boolParam = *data % ENABLE;
    int32_t int32Param = static_cast<int32_t>(GetU32Data(data));
    uint32_t uint32Param = static_cast<uint32_t>(GetU32Data(data));
    auto abilityRecord = GetFuzzAbilityRecord();
    std::shared_ptr<Mission> mission = std::make_shared<Mission>(int32Param, abilityRecord);
    abilityRecord->SetMissionId(int32Param);
    abilityRecord->recordId_ = int32Param;
    missionListMgr->defaultStandardList_->AddMissionToTop(mission);
    missionListMgr->launcherList_->AddMissionToTop(mission);
    missionListMgr->GetAbilityRecordByCaller(abilityRecord, int32Param);
    missionListMgr->OnAbilityDied(abilityRecord, int32Param);
    int64_t abilityRecordId = static_cast<int64_t>(int32Param);
    missionListMgr->GetAbilityRecordById(abilityRecordId);
    missionListMgr->PostStartWaitingAbility();
    auto type = static_cast<AbilityType>(GetU32Data(data) % ABILITY_STATE_MOD);
    const_cast<AppExecFwk::AbilityInfo&>(abilityRecord->GetAbilityInfo()).type = type;
    auto state = static_cast<AAFwk::AbilityState>(GetU32Data(data) % ABILITY_STATE_MOD);
    abilityRecord->currentState_ = state;
    abilityRecord->isTerminating_ = boolParam;
    missionListMgr->HandleAbilityDied(abilityRecord);
    missionListMgr->DelayedStartLauncher();
    missionListMgr->BackToLauncher();
    auto continueState = static_cast<ContinueState>(GetU32Data(data) % ABILITY_STATE_MOD);
    missionListMgr->SetMissionContinueState(nullptr, int32Param, continueState);
    missionListMgr->SetMissionContinueState(abilityRecord->GetToken(), int32Param, continueState);
    std::vector<std::string> info;
    std::vector<std::string> params;
    std::string stringParam(data, size);
    missionListMgr->Dump(info);
    missionListMgr->DumpMissionListByRecordId(info, boolParam, int32Param, params);
    missionListMgr->DumpMissionList(info, boolParam, stringParam);
    missionListMgr->DumpMissionInfos(info);
    missionListMgr->DumpMission(int32Param, info);
    auto abilityRequest = InitAbilityRequest(data);
    abilityRequest.callType = static_cast<AbilityCallType>(GetU32Data(data) % ABILITY_STATE_MOD);
    missionListMgr->CallAbilityLocked(abilityRequest);
    ElementName element;
    missionListMgr->GetAbilityRecordByName(element);
    missionListMgr->GetAbilityRecordsByName(element);
    auto callRecord = std::make_shared<CallRecord>(int32Param, abilityRecord, nullptr, abilityRecord->GetToken());
    missionListMgr->OnCallConnectDied(callRecord);
    Want want;
    missionListMgr->OnAcceptWantResponse(want, stringParam);
    missionListMgr->EnqueueWaitingAbility(abilityRequest);
    missionListMgr->EnqueueWaitingAbility(abilityRequest); // add twice
    missionListMgr->OnStartSpecifiedAbilityTimeoutResponse(want);
    missionListMgr->GetMissionBySpecifiedFlag(want, stringParam);
}

bool DoSomethingInterestingWithMyAPI(const char* data, size_t size)
{
    // fuzz for MissionListManager
    int32_t int32Param = static_cast<int32_t>(GetU32Data(data));
    auto missionListMgr = InitMissionListManager(int32Param);
    DoSomethingTestWithMyAPI0(missionListMgr, data);
    DoSomethingTestWithMyAPI1(missionListMgr, data, size);
    DoSomethingTestWithMyAPI2(missionListMgr, data, size);
    DoSomethingTestWithMyAPI3(missionListMgr, data, size);
    DoSomethingTestWithMyAPI4(missionListMgr, data, size);
    return true;
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    if (data == nullptr) {
        return 0;
    }

    /* Validate the length of size */
    if (size < OHOS::U32_AT_SIZE) {
        return 0;
    }

    char* ch = (char*)malloc(size + 1);
    if (ch == nullptr) {
        std::cout << "malloc failed." << std::endl;
        return 0;
    }

    (void)memset_s(ch, size + 1, 0x00, size + 1);
    if (memcpy_s(ch, size, data, size) != EOK) {
        std::cout << "copy failed." << std::endl;
        free(ch);
        ch = nullptr;
        return 0;
    }

    OHOS::DoSomethingInterestingWithMyAPI(ch, size);
    free(ch);
    ch = nullptr;
    return 0;
}