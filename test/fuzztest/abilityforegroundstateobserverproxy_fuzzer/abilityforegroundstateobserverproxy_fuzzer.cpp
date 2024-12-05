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

#include "abilityforegroundstateobserverproxy_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <fuzzer/FuzzedDataProvider.h>

#define private public
#include "ability_foreground_state_observer_proxy.h"
#undef private

#include "ability_record.h"
#include "parcel.h"
#include "securec.h"
#include "want.h"

using namespace OHOS::AAFwk;
using namespace OHOS::AppExecFwk;

namespace OHOS {
const std::u16string APPMGR_INTERFACE_TOKEN = u"ohos.aafwk.AppManager";

bool DoSomethingInterestingWithMyAPI(FuzzedDataProvider *fdp)
{
    sptr<IRemoteObject> impl;
    auto abilityForegroundStateObserverProxy = std::make_shared<AbilityForegroundStateObserverProxy>(impl);
    Parcel parcel;
    parcel.WriteString(fdp->ConsumeRandomLengthString());
    sptr<AppExecFwk::AbilityStateData> abilityStateData(AppExecFwk::AbilityStateData::Unmarshalling(parcel));
    abilityForegroundStateObserverProxy->OnAbilityStateChanged(*abilityStateData);
    MessageParcel dataParcel;
    abilityForegroundStateObserverProxy->WriteInterfaceToken(dataParcel);

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
