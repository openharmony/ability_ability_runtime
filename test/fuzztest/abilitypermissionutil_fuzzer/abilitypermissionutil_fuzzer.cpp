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
#include "abilitypermissionutil_fuzzer.h"

#define private public
#include "ability_permission_util.h"
#undef private

#include <fuzzer/FuzzedDataProvider.h>
#include <iostream>
#include "securec.h"
#include "ability_record.h"

namespace OHOS {
namespace {
constexpr uint8_t ENABLE = 2;
constexpr size_t U32_AT_SIZE = 4;
constexpr size_t STRING_MAX_LENGTH = 128;
}

bool DoSomethingInterestingWithMyAPI(const uint8_t *data, size_t size)
{
    AAFwk::AbilityPermissionUtil &util = AAFwk::AbilityPermissionUtil::GetInstance();
    FuzzedDataProvider fdp(data, size);
    OHOS::AAFwk::Want want;
    sptr<OHOS::IRemoteObject> callerToken = nullptr;
    bool isCreating = (size > 0) ? (*data % ENABLE) : false;
    std::string instanceKey = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    int32_t maxCount = fdp.ConsumeIntegralInRange<int32_t>(0, U32_AT_SIZE);
    std::vector<std::string> info;
    AAFwk::AbilityRequest abilityRequest;
    std::shared_ptr<AAFwk::AbilityRecord> abilityRecord = nullptr;
    pid_t pid = 0;
    util.CheckMultiInstance(want, callerToken, maxCount, isCreating);
    util.UpdateInstanceKey(want, instanceKey, info, instanceKey);
    util.CheckMultiInstanceKeyForExtension(abilityRequest);
    util.CheckStartRecentAbility(want, abilityRequest);
    util.CheckStartCallHasFloatingWindow(callerToken);
    util.AddStartSelfUIAbilityRecord(pid, maxCount);
    util.RemoveStartSelfUIAbilityRecord(pid);
    util.GetTokenIdByPid(pid);
    util.CheckPrepareTerminateEnable(abilityRecord);
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