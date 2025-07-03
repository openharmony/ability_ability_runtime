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
#include "abilitymissioninfo_fuzzer.h"

#include "mission_info.h"

#include <fuzzer/FuzzedDataProvider.h>
#include <iostream>
#include "securec.h"

namespace OHOS {
using namespace OHOS::AAFwk;

bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    std::shared_ptr<MissionInfo> missionInfo = std::make_shared<MissionInfo>();
    std::shared_ptr<MissionValidResult> missionValidResult = std::make_shared<MissionValidResult>();
    if (missionInfo == nullptr || missionValidResult == nullptr) {
        return false;
    }
    Parcel parcel;
    parcel.WriteString(fdp.ConsumeRandomLengthString());
    missionInfo->ReadFromParcel(parcel);
    missionInfo->Marshalling(parcel);
    MissionInfo::Unmarshalling(parcel);
    missionValidResult->ReadFromParcel(parcel);
    missionValidResult->Marshalling(parcel);
    MissionValidResult::Unmarshalling(parcel);
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