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

#include "abilitydebugdealfirst_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <fuzzer/FuzzedDataProvider.h>

#define private public
#include "ability_debug_deal.h"
#undef private
#include "ability_record.h"
#include "ability_debug_response_stub.h"
#include "securec.h"

using namespace OHOS::AAFwk;
using namespace OHOS::AppExecFwk;

namespace OHOS {
namespace {
constexpr size_t STRING_MAX_LENGTH = 128;
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
    bool boolParam;
    sptr<IRemoteObject> token = GetFuzzAbilityToken();
    std::vector<sptr<IRemoteObject>> tokens;
    std::weak_ptr<AbilityDebugDeal> deal;
    FuzzedDataProvider fdp(data, size);
    boolParam = fdp.ConsumeBool();
    auto abilityDebugDeal = std::make_shared<AbilityDebugDeal>();
    abilityDebugDeal->RegisterAbilityDebugResponse();
    abilityDebugDeal->OnAbilitysDebugStarted(tokens);
    abilityDebugDeal->OnAbilitysDebugStoped(tokens);
    abilityDebugDeal->OnAbilitysAssertDebugChange(tokens, boolParam);
    Token::GetAbilityRecordByToken(token) = nullptr;
    abilityDebugDeal->OnAbilitysDebugStarted(tokens);
    abilityDebugDeal->OnAbilitysDebugStoped(tokens);
    abilityDebugDeal->OnAbilitysAssertDebugChange(tokens, boolParam);

    auto abilityDebugResponse = std::make_shared<AbilityDebugResponse>(deal);
    abilityDebugResponse->OnAbilitysDebugStarted(tokens);
    abilityDebugResponse->OnAbilitysDebugStoped(tokens);
    abilityDebugResponse->OnAbilitysAssertDebugChange(tokens, boolParam);
    abilityDebugResponse->abilityDebugDeal_.lock() = nullptr;
    abilityDebugResponse->OnAbilitysDebugStarted(tokens);
    abilityDebugResponse->OnAbilitysDebugStoped(tokens);
    abilityDebugResponse->OnAbilitysAssertDebugChange(tokens, boolParam);
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