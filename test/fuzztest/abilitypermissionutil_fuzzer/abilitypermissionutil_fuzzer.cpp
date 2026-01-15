/*
 * Copyright (c) 2025-2026 Huawei Device Co., Ltd.
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
#include "abilitypermissionutil_fuzzer.h"

#define private public
#define protected public
#include "ability_permission_util.h"
#undef protected
#undef private

#include <fuzzer/FuzzedDataProvider.h>
#include <iostream>
#include "securec.h"
#include "ability_fuzz_util.h"
#include "ability_record.h"

using namespace OHOS::AAFwk;
using namespace OHOS::AppExecFwk;

namespace OHOS {
namespace {
constexpr size_t STRING_MAX_LENGTH = 128;
}

bool DoSomethingInterestingWithMyAPI(const uint8_t *data, size_t size)
{
    AAFwk::AbilityPermissionUtil &util = AAFwk::AbilityPermissionUtil::GetInstance();
    FuzzedDataProvider fdp(data, size);
    ElementName elementName;
    AbilityFuzzUtil::GenerateElementName(fdp, elementName);
    Want want;
    want.SetElement(elementName);
    sptr<OHOS::IRemoteObject> callerToken = nullptr;
    bool isPendingWantCaller = fdp.ConsumeBool();
    int32_t userId = fdp.ConsumeIntegral<int32_t>();
    int32_t appIndex = fdp.ConsumeIntegral<int32_t>();
    bool isScbCall = fdp.ConsumeBool();
    bool isCreating = fdp.ConsumeBool();
    std::string instanceKey = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    int32_t maxCount = fdp.ConsumeIntegral<int32_t>();
    std::vector<std::string> info = AbilityFuzzUtil::GenerateStringArray(fdp);
    AbilityRequest abilityRequest;
    AbilityFuzzUtil::GenerateAbilityRequestInfo(fdp, abilityRequest);

    std::shared_ptr<AbilityRecord> abilityRecord = nullptr;
    pid_t pid = fdp.ConsumeIntegral<pid_t>();
    int32_t tokenId = fdp.ConsumeIntegral<int32_t>();
    StartSelfUIAbilityRecordGuard startSelfUIAbilityRecordGuard(pid, tokenId);
    util.IsDominateScreen(want, isPendingWantCaller);
    util.CheckMultiInstanceAndAppClone(want, userId, appIndex, callerToken, isScbCall);
    util.CheckMultiInstance(want, callerToken, maxCount, isCreating);
    util.UpdateInstanceKey(want, instanceKey, info, instanceKey);
    util.CheckMultiInstanceKeyForExtension(abilityRequest);
    util.CheckStartRecentAbility(want, abilityRequest);
    util.CheckStartCallHasFloatingWindow(callerToken);
    util.AddStartSelfUIAbilityRecord(pid, tokenId);
    util.RemoveStartSelfUIAbilityRecord(pid);
    util.GetTokenIdByPid(pid);
    util.IsStartSelfUIAbility();
    util.CheckPrepareTerminateEnable(abilityRecord);
    util.NeedCheckStatusBar(abilityRecord, abilityRequest);
    abilityRequest.Dump(info);
    int srcRequestCode = fdp.ConsumeIntegral<int>();
    std::shared_ptr<AbilityStartSetting> srcStartSetting = std::make_shared<AbilityStartSetting>();
    int srcCallerUid = fdp.ConsumeIntegral<int>();
    abilityRequest.Voluation(want, srcRequestCode, callerToken, srcStartSetting, srcCallerUid);
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