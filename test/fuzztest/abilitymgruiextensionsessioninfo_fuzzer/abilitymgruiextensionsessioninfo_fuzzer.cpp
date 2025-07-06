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

#include "abilitymgruiextensionsessioninfo_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <iostream>
#include <fuzzer/FuzzedDataProvider.h>

#include "securec.h"
#define private public
#include "ui_extension/ui_extension_session_info.h"
#undef private

using namespace OHOS::AAFwk;
using namespace OHOS::AbilityRuntime;

namespace OHOS {
bool DoSomethingInterestingWithMyAPI(const uint8_t *data, size_t size)
{
    std::shared_ptr<UIExtensionSessionInfo> uiExtensionSessionInfo = std::make_shared<UIExtensionSessionInfo>();
    Parcel parcel;
    FuzzedDataProvider fdp(data, size);
    parcel.WriteInt32(fdp.ConsumeIntegral<int32_t>());
    parcel.WriteInt32(uiExtensionSessionInfo->persistentId);
    uiExtensionSessionInfo->Marshalling(parcel);
    parcel.WriteUint32(fdp.ConsumeIntegral<uint32_t>());
    parcel.WriteUint32(uiExtensionSessionInfo->hostWindowId);
    uiExtensionSessionInfo->Marshalling(parcel);
    parcel.WriteUint32(static_cast<uint32_t>(uiExtensionSessionInfo->uiExtensionUsage));
    uiExtensionSessionInfo->Marshalling(parcel);
    parcel.WriteInt32(static_cast<int32_t>(uiExtensionSessionInfo->extensionAbilityType));
    uiExtensionSessionInfo->Marshalling(parcel);
    uiExtensionSessionInfo->Unmarshalling(parcel);
    return true;
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    OHOS::DoSomethingInterestingWithMyAPI(data, size);
    return 0;
}