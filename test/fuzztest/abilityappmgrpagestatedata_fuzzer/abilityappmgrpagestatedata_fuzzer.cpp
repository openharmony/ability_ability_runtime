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

#include "abilityappmgrpagestatedata_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <fuzzer/FuzzedDataProvider.h>

#define private public
#include "page_state_data.h"
#include "app_cjheap_mem_info.h"
#include "start_params_by_SCB.h"
#undef private

#include "securec.h"
#include "ability_record.h"

using namespace OHOS::AAFwk;
using namespace OHOS::AbilityRuntime;
using namespace OHOS::AppExecFwk;

namespace OHOS {
bool DoSomethingInterestingWithMyAPI(FuzzedDataProvider *fdp)
{
    PageStateData info;
    Parcel parcel;
    parcel.WriteString(fdp->ConsumeRandomLengthString());
    info.ReadFromParcel(parcel);
    info.Marshalling(parcel);

    CjHeapDumpInfo cj;
    cj.needGc = fdp->ConsumeBool();
    cj.needSnapshot = fdp->ConsumeBool();
    cj.pid = fdp->ConsumeIntegral<int32_t>();
    Parcel parcel1;
    cj.Marshalling(parcel1);
    cj.Unmarshalling(parcel1);

    StartParamsBySCB bySCB;
    Parcel parcel2;
    parcel2.WriteString(fdp->ConsumeRandomLengthString());
    bySCB.Marshalling(parcel2);
    return true;
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    FuzzedDataProvider fdp(data, size);
    OHOS::DoSomethingInterestingWithMyAPI(&fdp);
    return 0;
}

