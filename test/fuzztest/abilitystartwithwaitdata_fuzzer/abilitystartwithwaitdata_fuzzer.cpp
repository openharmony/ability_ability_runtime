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

#include "abilitystartwithwaitdata_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <fuzzer/FuzzedDataProvider.h>

#define private public
#define protected public
#include "ability_start_with_wait_observer_data.h"
#undef protected
#undef private
#include "securec.h"
#include "ability_record.h"
#include "parcel.h"
#include <iostream>
#include "configuration.h"

using namespace OHOS::AAFwk;
using namespace OHOS::AppExecFwk;

namespace OHOS {
bool DoSomethingInterestingWithMyAPI(FuzzedDataProvider *fdp)
{
    std::shared_ptr<AbilityStartWithWaitObserverData> infos = std::make_shared<AbilityStartWithWaitObserverData>();
    if (infos == nullptr) {
        return false;
    }
    Parcel parcel;
    parcel.WriteString(fdp->ConsumeRandomLengthString());
    infos->Marshalling(parcel);
    infos->ReadFromParcel(parcel);
    AbilityStartWithWaitObserverData::Unmarshalling(parcel);
    return true;
}
}
/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    OHOS::DoSomethingInterestingWithMyAPI(&fdp);
    return 0;
}
