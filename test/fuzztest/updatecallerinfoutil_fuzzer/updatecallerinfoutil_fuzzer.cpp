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

#include "updatecallerinfoutil_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <fuzzer/FuzzedDataProvider.h>

#include "ability_fuzz_util.h"
#define private public
#include "update_caller_info_util.h"
#undef private
using namespace OHOS::AAFwk;
using namespace OHOS::AppExecFwk;

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
    FuzzedDataProvider fdp(data, size);
    ElementName elementName;
    AbilityFuzzUtil::GenerateElementName(fdp, elementName);
    Want want;
    want.SetElement(elementName);
    sptr<IRemoteObject> callerToken = GetFuzzAbilityToken();
    sptr<IRemoteObject> asCallerSourceToken = GetFuzzAbilityToken();
    int32_t requestCode = fdp.ConsumeIntegral<int32_t>();
    int32_t appIndex = fdp.ConsumeIntegral<int32_t>();
    bool backFlag = fdp.ConsumeBool();
    bool isRemote = fdp.ConsumeBool();
    std::string bundleName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    std::string abilityName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);

    UpdateCallerInfoUtil::GetInstance().UpdateAsCallerSourceInfo(want, asCallerSourceToken, callerToken);
    UpdateCallerInfoUtil::GetInstance().UpdateCallerInfo(want, callerToken);
    UpdateCallerInfoUtil::GetInstance().UpdateBackToCallerFlag(callerToken, want, requestCode, backFlag);
    UpdateCallerInfoUtil::GetInstance().UpdateCallerInfoFromToken(want, callerToken);
    UpdateCallerInfoUtil::GetInstance().UpdateDmsCallerInfo(want, callerToken);
    UpdateCallerInfoUtil::GetInstance().UpdateSignatureInfo(bundleName, want, isRemote);
    UpdateCallerInfoUtil::GetInstance().UpdateAsCallerInfoFromToken(want, asCallerSourceToken);
    UpdateCallerInfoUtil::GetInstance().UpdateAsCallerInfoFromCallerRecord(want, callerToken);
    UpdateCallerInfoUtil::GetInstance().UpdateAsCallerInfoFromDialog(want);
    UpdateCallerInfoUtil::GetInstance().UpdateCallerBundleName(want, bundleName);
    UpdateCallerInfoUtil::GetInstance().UpdateCallerAbilityName(want, abilityName);
    UpdateCallerInfoUtil::GetInstance().UpdateCallerAppCloneIndex(want, appIndex);
    UpdateCallerInfoUtil::GetInstance().ClearProtectedWantParam(want);

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