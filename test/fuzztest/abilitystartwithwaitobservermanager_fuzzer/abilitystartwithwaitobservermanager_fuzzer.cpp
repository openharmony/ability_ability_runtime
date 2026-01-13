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

#include "abilitystartwithwaitobservermanager_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <fuzzer/FuzzedDataProvider.h>

#define private public
#define protected public
#include "ability_start_with_wait_observer_manager.h"
#undef protected
#undef private
#include "securec.h"
#include "ability_fuzz_util.h"
#include "ability_record.h"

using namespace OHOS::AAFwk;
using namespace OHOS::AppExecFwk;

namespace OHOS {
namespace {
constexpr size_t U32_AT_SIZE = 4;
class IAbilityStartWithWaitObserverFUZZ : public IAbilityStartWithWaitObserver {
public:
    explicit IAbilityStartWithWaitObserverFUZZ() {};
    virtual ~ IAbilityStartWithWaitObserverFUZZ() {};
    int32_t NotifyAATerminateWait(const AbilityStartWithWaitObserverData &abilityStartWithWaitData) override
    {
        return 0;
    };
    sptr<IRemoteObject> AsObject() override
    {
    return nullptr;
    }
};
}

bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
{
    Want want;
    AbilityRequest info;
    sptr<IAbilityStartWithWaitObserver> observer = nullptr;
    FuzzedDataProvider fdp(data, size);
    AbilityFuzzUtil::GetRandomAbilityRequestInfo(fdp, info);
    std::shared_ptr<AbilityRecord> abilityRecord = AbilityRecord::CreateAbilityRecord(info);
    std::shared_ptr<AbilityStartWithWaitObserverManager> infos =
        std::make_shared<AbilityStartWithWaitObserverManager>();
    infos->RegisterObserver(want, observer);
    infos->UnregisterObserver(observer);
    infos->NotifyAATerminateWait(want);
    infos->NotifyAATerminateWait(abilityRecord);
    infos->SetColdStartForShellCall(abilityRecord);
    infos->GenerateDeathRecipient(observer);
    sptr<IAbilityStartWithWaitObserver> observer1 = new IAbilityStartWithWaitObserverFUZZ();
    infos->RegisterObserver(want, observer1);
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