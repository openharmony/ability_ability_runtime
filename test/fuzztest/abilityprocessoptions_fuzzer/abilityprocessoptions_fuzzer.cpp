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
#include "abilityprocessoptions_fuzzer.h"

#include "process_options.h"

#include <fuzzer/FuzzedDataProvider.h>
#include <iostream>
#include "securec.h"

namespace OHOS {
namespace {
constexpr size_t U32_AT_SIZE = 4;
constexpr size_t STRING_MAX_LENGTH = 128;
}

bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
{
    std::shared_ptr<AAFwk::ProcessOptions> processOption = std::make_shared<AAFwk::ProcessOptions>();
    if (processOption == nullptr) {
        return false;
    }
    AAFwk::ProcessMode processMode = AAFwk::ProcessMode::UNSPECIFIED;
    int32_t value;
    FuzzedDataProvider fdp(data, size);
    value = fdp.ConsumeIntegralInRange<int32_t>(0, U32_AT_SIZE);
    Parcel parcel;
    parcel.WriteString(fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH));
    processOption->ReadFromParcel(parcel);
    processOption->Marshalling(parcel);
    processOption.reset(AAFwk::ProcessOptions::Unmarshalling(parcel));
    AAFwk::ProcessOptions::ConvertInt32ToProcessMode(value);
    AAFwk::ProcessOptions::ConvertInt32ToStartupVisibility(value);
    processOption->IsNewProcessMode(processMode);
    processOption->IsAttachToStatusBarMode(processMode);
    processOption->IsValidProcessMode(processMode);
    processOption->IsNoAttachmentMode(processMode);
    processOption->IsAttachToStatusBarItemMode(processMode);
    processOption->IsNewHiddenProcessMode(processMode);
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