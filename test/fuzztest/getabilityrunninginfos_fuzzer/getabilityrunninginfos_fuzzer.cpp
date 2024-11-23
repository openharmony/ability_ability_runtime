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

#include "getabilityrunninginfos_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <fuzzer/FuzzedDataProvider.h>

#include "ability_manager_client.h"
#include "ability_running_info.h"
#include "parcel.h"

using namespace OHOS::AAFwk;
using namespace OHOS::AppExecFwk;

namespace OHOS {
bool DoSomethingInterestingWithMyAPI(FuzzedDataProvider *fdp)
{
    std::vector<AAFwk::AbilityRunningInfo> infos;
    auto abilityMgr = AbilityManagerClient::GetInstance();
    if (!abilityMgr) {
        return false;
    }
    
    Parcel parcel;
    parcel.WriteString(fdp->ConsumeRandomLengthString());
    sptr<AAFwk::AbilityRunningInfo> info = AAFwk::AbilityRunningInfo::Unmarshalling(parcel);
    AAFwk::AbilityRunningInfo runingInfo(*info);
    infos.emplace_back(runingInfo);
    // fuzz for abilityRunningInfo
    abilityMgr->GetAbilityRunningInfos(infos);

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

