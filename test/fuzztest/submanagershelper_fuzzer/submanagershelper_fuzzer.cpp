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

#include "submanagershelper_fuzzer.h"
#include "sub_managers_helper.h"

#include <dlfcn.h>
#include <fuzzer/FuzzedDataProvider.h>

using namespace OHOS::AAFwk;

namespace OHOS {
namespace AAFwk {
constexpr int32_t USER0_ID = 0;
constexpr size_t STRING_MAX_LENGTH = 128;
constexpr size_t U32_AT_SIZE = 4;
}

sptr<Token> GetFuzzAbilityToken()
{
    sptr<Token> token = nullptr;
    AbilityRequest abilityRequest;
    abilityRequest.appInfo.bundleName = "com.example.fuzzTest";
    abilityRequest.abilityInfo.name = "MainAbility";
    abilityRequest.abilityInfo.type = AbilityType::DATA;
    std::shared_ptr<AbilityRecord> abilityRecord =
        AbilityRecord::CreateAbilityRecord(abilityRequest);
    if (abilityRecord) {
        token = abilityRecord->GetToken();
    }
    return token;
}

void SubManagersHelperFuzztest(bool switchUser, int64_t abilityRecordId,
    int32_t uid, const std::string &bundleName)
{
    std::shared_ptr<SubManagersHelper> helper =
        std::make_shared<SubManagersHelper>(nullptr, nullptr);
    sptr<IAbilityScheduler> scheduler;
    sptr<IRemoteObject> token = GetFuzzAbilityToken();

    helper->InitSubManagers(USER0_ID, switchUser);
    helper->InitPendWantManager(USER0_ID, switchUser);
    helper->InitUIAbilityManager(USER0_ID, switchUser);
    helper->ClearSubManagers(USER0_ID);
    helper->GetDataAbilityManager(scheduler);
    helper->GetDataAbilityManagerByUserId(USER0_ID);
    helper->GetDataAbilityManagerByToken(token);
}

bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    bool switchUser = fdp.ConsumeBool();
    int64_t abilityRecordId = fdp.ConsumeIntegral<int64_t>();
    int32_t uid = fdp.ConsumeIntegral<int32_t>();
    std::string bundleName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    SubManagersHelperFuzztest(switchUser, abilityRecordId, uid, bundleName);

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