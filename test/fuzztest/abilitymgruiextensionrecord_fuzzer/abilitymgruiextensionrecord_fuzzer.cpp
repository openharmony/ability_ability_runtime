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

#include "abilitymgruiextensionrecord_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <fuzzer/FuzzedDataProvider.h>

#define private public
#include "ui_extension_record.h"
#undef private

#include "securec.h"
#include "ability_record.h"

using namespace OHOS::AAFwk;
using namespace OHOS::AppExecFwk;

namespace OHOS {
bool DoSomethingInterestingWithMyAPI(FuzzedDataProvider *fdp)
{
    std::shared_ptr<AAFwk::AbilityRecord> abilityRecord;
    AbilityRuntime::UIExtensionRecord infos(abilityRecord);
    infos.ContinueToGetCallerToken();
    AAFwk::AbilityRequest abilityRequest;
    infos.Update(abilityRequest);
    infos.LoadTimeout();
    infos.ForegroundTimeout();
    infos.BackgroundTimeout();
    infos.TerminateTimeout();
    auto code = static_cast<AbilityRuntime::UIExtensionRecord::ErrorCode>(fdp->ConsumeIntegral<int32_t>());
    infos.HandleNotifyUIExtensionTimeout(code);
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

