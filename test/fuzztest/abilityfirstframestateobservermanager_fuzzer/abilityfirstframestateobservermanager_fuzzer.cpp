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

#include "abilityfirstframestateobservermanager_fuzzer.h"

#include <cstddef>
#include <cstdint>

#define protected public
#include "ability_first_frame_state_observer_manager.h"
#undef protected
#include "permission_verification.h"
#include "securec.h"

using namespace OHOS::AAFwk;
using namespace OHOS::AppExecFwk;

namespace OHOS {
namespace {
constexpr int INPUT_ZERO = 0;
constexpr int INPUT_ONE = 1;
constexpr int INPUT_THREE = 3;
constexpr uint8_t ENABLE = 2;
constexpr size_t U32_AT_SIZE = 4;
constexpr size_t OFFSET_ZERO = 24;
constexpr size_t OFFSET_ONE = 16;
constexpr size_t OFFSET_TWO = 8;
}  // namespace
uint32_t GetU32Data(const char* ptr)
{
    // convert fuzz input data to an integer
    return (ptr[INPUT_ZERO] << OFFSET_ZERO) | (ptr[INPUT_ONE] << OFFSET_ONE) |
           (ptr[ENABLE] << OFFSET_TWO) | ptr[INPUT_THREE];
}

bool DoSomethingInterestingWithMyAPI(const char* data, size_t size)
{
    bool boolParam = *data % ENABLE;
    std::string strParam(data, size);
    std::shared_ptr<AbilityRecord> abilityRecord;
    sptr<IRemoteBroker> observers;
    sptr<IAbilityFirstFrameStateObserver> observer;
    auto abilityFirstFrameStateObserverSet =
        std::make_shared<AbilityFirstFrameStateObserverSet>(boolParam);
    abilityFirstFrameStateObserverSet->AddAbilityFirstFrameStateObserver(
        observer, strParam);
    abilityFirstFrameStateObserverSet->RemoveAbilityFirstFrameStateObserver(observer);
    abilityFirstFrameStateObserverSet->OnAbilityFirstFrameState(abilityRecord);
    abilityFirstFrameStateObserverSet->AddObserverDeathRecipient(observers);
    abilityFirstFrameStateObserverSet->RemoveObserverDeathRecipient(observers);
    AbilityFirstFrameStateObserverManager& instance =
        AbilityFirstFrameStateObserverManager::GetInstance();
    instance.Init();
    instance.RegisterAbilityFirstFrameStateObserver(observer, strParam);
    instance.UnregisterAbilityFirstFrameStateObserver(observer);
    instance.HandleOnFirstFrameState(abilityRecord);
    return true;
}
}  // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    if (data == nullptr) {
        std::cout << "invalid data" << std::endl;
        return 0;
    }
    /* Validate the length of size */
    if (size < OHOS::U32_AT_SIZE) {
        return 0;
    }
    char* ch = static_cast<char*>(malloc(size + 1));
    if (ch == nullptr) {
        std::cout << "malloc failed." << std::endl;
        return 0;
    }
    (void)memset_s(ch, size + 1, 0x00, size + 1);
    if (memcpy_s(ch, size + 1, data, size) != EOK) {
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
