/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "abilitychildprocessinfo_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <fuzzer/FuzzedDataProvider.h>

#define private public
#define protected public
#include "child_process_info.h"
#include "child_process_args.h"
#include "child_process_options.h"
#include "configuration_policy.h"
#include "application_state_filter.h"
#undef protected
#undef private
#include "parcel.h"
#include <iostream>
#include "securec.h"
#include "configuration.h"
using namespace OHOS::AppExecFwk;
namespace OHOS {
bool DoSomethingInterestingWithMyAPI(FuzzedDataProvider *fdp)
{
    std::shared_ptr<ChildProcessInfo>childProcessInfo = std::make_shared<ChildProcessInfo>();
    if (childProcessInfo == nullptr) {
        return false;
    }
    Parcel parcel;
    parcel.WriteString(fdp->ConsumeRandomLengthString());
    childProcessInfo->ReadFromParcel(parcel);
    childProcessInfo->Marshalling(parcel);
    ChildProcessInfo::Unmarshalling(parcel);

    std::shared_ptr<ChildProcessArgs>childProcessArgs = std::make_shared<ChildProcessArgs>();
    if (childProcessArgs == nullptr) {
        return false;
    }
    Parcel parcel1;
    parcel1.WriteString(fdp->ConsumeRandomLengthString());
    childProcessArgs->Marshalling(parcel1);
    childProcessArgs->CheckFdsSize();
    childProcessArgs->CheckFdsKeyLength();
    std::string key = fdp->ConsumeRandomLengthString();
    childProcessArgs->CheckFdKeyLength(key);

    std::shared_ptr<ChildProcessOptions>childProcessOptions = std::make_shared<ChildProcessOptions>();
    if (childProcessOptions == nullptr) {
        return false;
    }
    Parcel parcel2;
    parcel2.WriteString(fdp->ConsumeRandomLengthString());
    childProcessOptions->Marshalling(parcel2);

    std::shared_ptr<ConfigurationPolicy>configurationPolicy = std::make_shared<ConfigurationPolicy>();
    if (configurationPolicy == nullptr) {
        return false;
    }
    Parcel parcel3;
    parcel2.WriteString(fdp->ConsumeRandomLengthString());
    configurationPolicy->Marshalling(parcel3);

    FilterCallback callbacks = static_cast<FilterCallback>(fdp->ConsumeIntegral<uint32_t>());
    FilterBundleType bundleTypes = static_cast<FilterBundleType>(fdp->ConsumeIntegral<uint32_t>());
    FilterAppStateType appStateTypes = static_cast<FilterAppStateType>(fdp->ConsumeIntegral<uint32_t>());
    FilterProcessStateType processStateTypes = static_cast<FilterProcessStateType>(fdp->ConsumeIntegral<uint32_t>());
    FilterAbilityStateType abilityStateTypes = static_cast<FilterAbilityStateType>(fdp->ConsumeIntegral<uint32_t>());
    AppStateFilter appStateFilter(callbacks, bundleTypes, appStateTypes, processStateTypes, abilityStateTypes);

    MessageParcel parcel4;
    parcel4.WriteUint32(static_cast<uint32_t>(callbacks));
    parcel4.WriteUint32(static_cast<uint32_t>(bundleTypes));
    parcel4.WriteUint32(static_cast<uint32_t>(appStateTypes));
    parcel4.WriteUint32(static_cast<uint32_t>(processStateTypes));
    parcel4.WriteUint32(static_cast<uint32_t>(abilityStateTypes));
    AppStateFilter fromParcel;
    fromParcel.ReadFromParcel(parcel4);

    MessageParcel parcel5;
    parcel5.WriteUint32(static_cast<uint32_t>(callbacks));
    parcel5.WriteUint32(static_cast<uint32_t>(bundleTypes));
    parcel5.WriteUint32(static_cast<uint32_t>(appStateTypes));
    parcel5.WriteUint32(static_cast<uint32_t>(processStateTypes));
    parcel5.WriteUint32(static_cast<uint32_t>(abilityStateTypes));

    AppStateFilter* unmarshalled = AppStateFilter::Unmarshalling(parcel5);
    if (unmarshalled != nullptr) {
        delete unmarshalled;
    }

    MessageParcel parcel6;
    appStateFilter.Marshalling(parcel6);

    appStateFilter.Match(appStateFilter);

    ApplicationState applicationState = static_cast<ApplicationState>(fdp->ConsumeIntegral<uint32_t>());
    FilterAppStateType filterAppState = GetFilterTypeFromApplicationState(applicationState);

    AppProcessState appProcessState = static_cast<AppProcessState>(fdp->ConsumeIntegral<uint32_t>());
    FilterProcessStateType filterProcessStateType = GetFilterTypeFromAppProcessState(appProcessState);

    AbilityState abilityState = static_cast<AbilityState>(fdp->ConsumeIntegral<uint32_t>());
    FilterAbilityStateType filterAbilityStateType = GetFilterTypeFromAbilityState(abilityState);

    ExtensionState extensionState = static_cast<ExtensionState>(fdp->ConsumeIntegral<uint32_t>());
    FilterAbilityStateType filterAbilityStateType1 = GetFilterTypeFromExtensionState(extensionState);

    BundleType bundleType = static_cast<BundleType>(fdp->ConsumeIntegral<uint32_t>());
    FilterBundleType filterBundleType = GetFilterTypeFromBundleType(bundleType);
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

