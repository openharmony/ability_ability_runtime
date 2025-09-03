/*
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
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

#include "dataabilitymanager_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <cstring>
#include <string>
#include <vector>
#include <fuzzer/FuzzedDataProvider.h>

#define private public
#include "data_ability_manager.h"
#undef private

#include "ability_record.h"

using namespace OHOS::AAFwk;
using namespace OHOS::AppExecFwk;

namespace OHOS {
namespace {
constexpr size_t STRING_MAX_LENGTH = 128;
}

uint32_t GetU32Data(const char* ptr)
{
    // convert fuzz input data to an integer
    return (ptr[0] << 24) | (ptr[1] << 16) | (ptr[2] << 8) | ptr[3];
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

bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
{
    auto dataAbilityManager = std::make_shared<DataAbilityManager>();
    bool boolParam;
    bool isClient;
    int intParam;
    int32_t int32Param;
    int64_t int64Param;
    std::string stringParam;
    std::shared_ptr<AbilityRecord> abilityRecord = GetFuzzAbilityRecord();
    sptr<IRemoteObject> token = GetFuzzAbilityToken();
    std::vector<std::string> info;
    AbilityRequest abilityRequest;
    FuzzedDataProvider fdp(data, size);
    boolParam = fdp.ConsumeBool();
    isClient = fdp.ConsumeBool();
    intParam = fdp.ConsumeIntegral<int>();
    int32Param = fdp.ConsumeIntegral<int32_t>();
    int64Param = fdp.ConsumeIntegral<int64_t>();
    stringParam = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    sptr<IRemoteObject> client;
    dataAbilityManager->Acquire(abilityRequest, boolParam, client, boolParam);
    abilityRequest.abilityInfo.type = AppExecFwk::AbilityType::DATA;
    dataAbilityManager->Acquire(abilityRequest, boolParam, client, boolParam);
    abilityRequest.abilityInfo.type = AppExecFwk::AbilityType::UNKNOWN;
    dataAbilityManager->Acquire(abilityRequest, boolParam, client, boolParam);
    abilityRequest.abilityInfo.bundleName = "";
    abilityRequest.abilityInfo.name = "";
    dataAbilityManager->Acquire(abilityRequest, boolParam, client, boolParam);
    boolParam = true;
    dataAbilityManager->Acquire(abilityRequest, boolParam, client, boolParam);
    boolParam = false;
    dataAbilityManager->Acquire(abilityRequest, boolParam, client, boolParam);
    sptr<IAbilityScheduler> scheduler;
    dataAbilityManager->Release(scheduler, client, boolParam);
    dataAbilityManager->ContainsDataAbility(scheduler);
    dataAbilityManager->AttachAbilityThread(scheduler, token);
    dataAbilityManager->AbilityTransitionDone(token, intParam);
    dataAbilityManager->OnAbilityRequestDone(token, int32Param);
    dataAbilityManager->OnAbilityDied(abilityRecord);
    AppInfo appInfo;
    dataAbilityManager->OnAppStateChanged(appInfo);
    appInfo.bundleName = abilityRecord->GetApplicationInfo().bundleName;
    appInfo.appIndex = abilityRecord->GetAppIndex();
    appInfo.instanceKey = abilityRecord->GetInstanceKey();
    dataAbilityManager->OnAppStateChanged(appInfo);
    dataAbilityManager->GetAbilityRecordById(int64Param);
    dataAbilityManager->GetAbilityRecordByToken(token);
    dataAbilityManager->GetAbilityRecordByScheduler(scheduler);
    auto func = std::make_unique<char[]>(stringParam.length() + 1);
    if (memcpy_s(func.get(), stringParam.length() + 1, stringParam.data(), stringParam.length()) != EOK) {
        return false;
    }
    func[stringParam.length()] = '\0';
    dataAbilityManager->Dump(static_cast<const char*>(func.get()), intParam);
    dataAbilityManager->LoadLocked(stringParam, abilityRequest);
    dataAbilityManager->DumpLocked(static_cast<const char*>(func.get()), intParam);
    dataAbilityManager->DumpState(info, stringParam);
    std::shared_ptr<DataAbilityRecord> record;
    dataAbilityManager->DumpClientInfo(info, isClient, record);
    dataAbilityManager->DumpSysState(info, boolParam, stringParam);
    std::vector<AbilityRunningInfo> AbilityRunningInfoVector;
    dataAbilityManager->GetAbilityRunningInfos(AbilityRunningInfoVector, boolParam);
    dataAbilityManager->RestartDataAbility(abilityRecord);
    dataAbilityManager->ReportDataAbilityAcquired(client, boolParam, record);
    dataAbilityManager->ReportDataAbilityReleased(client, boolParam, record);

    return true;
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    // Run your code on data.
    OHOS::DoSomethingInterestingWithMyAPI(data, size);
    return 0;
}