/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "abilityautostartupservicefirst_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <fuzzer/FuzzedDataProvider.h>

#define private public
#define protected public
#include "ability_auto_startup_service.h"
#undef protected
#undef private

#include "ability_auto_startup_data_manager.h"
#include "ability_record.h"

using namespace OHOS::AAFwk;
using namespace OHOS::AppExecFwk;
using namespace OHOS::AbilityRuntime;

namespace OHOS {
namespace {
constexpr size_t STRING_MAX_LENGTH = 128;
}
sptr<Token> GetFuzzAbilityToken()
{
    sptr<Token> token = nullptr;
    AbilityRequest abilityRequest;
    abilityRequest.appInfo.bundleName = "com.example.fuzzTest";
    abilityRequest.abilityInfo.name = "MainAbility";
    abilityRequest.abilityInfo.type = AbilityType::DATA;
    std::shared_ptr<AbilityRecord> abilityRecord = AbilityRecord::CreateAbilityRecord(abilityRequest);
    if (abilityRecord) {
        token = abilityRecord->GetToken();
    }
    return token;
}

bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
{
    std::string abilityTypeName;
    std::string accessTokenId;
    int32_t int32Param;
    int32_t userId;
    bool isSet;
    bool flag;
    bool isVisible;
    FuzzedDataProvider fdp(data, size);
    abilityTypeName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    accessTokenId = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    int32Param = fdp.ConsumeIntegral<int32_t>();
    userId = fdp.ConsumeIntegral<int32_t>();
    isSet = fdp.ConsumeBool();
    flag = fdp.ConsumeBool();
    isVisible = fdp.ConsumeBool();
    std::shared_ptr<AbilityAutoStartupService> service = std::make_shared<AbilityAutoStartupService>();
    sptr<IRemoteObject> token1 = GetFuzzAbilityToken();
    service->RegisterAutoStartupSystemCallback(token1); // branch
    service->RegisterAutoStartupSystemCallback(token1); // branch duplicate regist
    service->UnregisterAutoStartupSystemCallback(token1); // branch
    sptr<IRemoteObject> token2 = GetFuzzAbilityToken();
    service->UnregisterAutoStartupSystemCallback(token2); // branch unregister not exist.

    AutoStartupInfo info;
    info.bundleName = "com.example.fuzztest";
    info.moduleName = "stringParam";
    info.abilityName = "MainAbility";
    info.appCloneIndex = int32Param;
    info.accessTokenId = "accessTokenId";
    info.setterUserId = int32Param;
    info.userId = int32Param;

    AutoStartupAbilityData abilityData;
    abilityData.isVisible = isVisible;
    abilityData.abilityTypeName = abilityTypeName;
    abilityData.accessTokenId = accessTokenId;
    abilityData.setterUserId = int32Param;
    bool isFlag = service->GetAbilityData(info, abilityData);
    service->SetApplicationAutoStartup(info);
    if (isFlag) {
        AutoStartupInfo fullInfo(info);
        fullInfo.abilityTypeName = abilityData.abilityTypeName;
        fullInfo.setterUserId = abilityData.setterUserId;
        fullInfo.accessTokenId = abilityData.accessTokenId;
        fullInfo.userId = abilityData.userId;
        fullInfo.canUserModify = true;
        fullInfo.setterType = AutoStartupSetterType::USER;
    }
    service->SetApplicationAutoStartup(info);
    service->CancelApplicationAutoStartup(info);
    service->InnerCancelApplicationAutoStartup(info);
    service->SetApplicationAutoStartupByEDM(info, flag);
    service->CancelApplicationAutoStartupByEDM(info, flag);

    AutoStartupStatus status =
        DelayedSingleton<AbilityAutoStartupDataManager>::GetInstance()->QueryAutoStartupData(info);
    status.code = int32Param;
    service->InnerApplicationAutoStartupByEDM(info, isSet, flag);
    status.code = ERR_NAME_NOT_FOUND;
    service->InnerApplicationAutoStartupByEDM(info, isSet, flag);
    isSet = true;
    service->InnerApplicationAutoStartupByEDM(info, isSet, flag);
    isSet = false;
    service->InnerApplicationAutoStartupByEDM(info, isSet, flag);
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