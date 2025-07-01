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

#include "wantagenthelperstring_fuzzer.h"

#include <cstddef>
#include <cstdint>

#include "parcel.h"
#include "pending_want.h"
#include "want_agent.h"
#include "want_agent_helper.h"

using namespace OHOS::AbilityRuntime::WantAgent;

namespace OHOS {
bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
{
    Parcel wantAgentParcel;
    bool isMultithreadingSupported;
    WantAgent* wantAgent = nullptr;
    if (wantAgentParcel.WriteBuffer(data, size)) {
        std::shared_ptr<PendingWant> pendingWant = nullptr;
        std::shared_ptr<WantAgent> wantAgent1 = std::make_shared<WantAgent>(pendingWant);
        Parcel parcel;
        wantAgent1->Marshalling(parcel);
        wantAgent = WantAgent::Unmarshalling(wantAgentParcel);
        if (wantAgent) {
            std::shared_ptr<PendingWant> pendingWant1 = wantAgent->GetPendingWant();
            wantAgent->GetLocalPendingWant();
            wantAgent->SetPendingWant(pendingWant1);
            wantAgent->GetIsMultithreadingSupported();
            isMultithreadingSupported = true;
            wantAgent->SetIsMultithreadingSupported(isMultithreadingSupported);
            isMultithreadingSupported = false;
            wantAgent->SetIsMultithreadingSupported(isMultithreadingSupported);
            wantAgent->IsLocal();
            std::shared_ptr<WantAgent> sptrAgent = std::make_shared<WantAgent>(pendingWant1);
            std::string str = WantAgentHelper::ToString(sptrAgent);
            auto newWantAgent = WantAgentHelper::FromString(str);
            (void)newWantAgent;
        }
    }

    if (wantAgent) {
        delete wantAgent;
        wantAgent = nullptr;
    }

    return true;
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::DoSomethingInterestingWithMyAPI(data, size);
    return 0;
}