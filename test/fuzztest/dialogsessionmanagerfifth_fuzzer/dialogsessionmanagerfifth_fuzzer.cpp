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

#include "dialogsessionmanagerfifth_fuzzer.h"
#include <cstddef>
#include <cstdint>
#include <fuzzer/FuzzedDataProvider.h>
#define private public
#include "dialog_session_manager.h"
#undef private
#include "ability_record.h"
#include "dialog_session_manager.h"

using namespace OHOS::AAFwk;
using namespace OHOS::AppExecFwk;

namespace OHOS {
namespace {} // namespace

bool DoSomethingInterestingWithMyAPI(const uint8_t *data, size_t size)
{
    sptr<DialogSessionInfo> dilogSessionInfo;
    std::shared_ptr<DialogCallerInfo> dialogCallerInfo;
    std::string dialogSessionId;
    FuzzedDataProvider fdp(data, size);
    dialogSessionId = fdp.ConsumeRandomLengthString();
    std::shared_ptr<DialogSessionManager> dialogSessionManager = std::make_shared<DialogSessionManager>();
    if (dialogSessionManager == nullptr) {
        return false;
    }
    dialogSessionManager->SetDialogSessionInfo(dialogSessionId, dilogSessionInfo, dialogCallerInfo);
    return true;
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */

    OHOS::DoSomethingInterestingWithMyAPI(data, size);
    return 0;
}