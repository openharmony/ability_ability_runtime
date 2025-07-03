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

#include "multiuserconfigmgr_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <fuzzer/FuzzedDataProvider.h>

#define private public
#include "multi_user_config_mgr.h"
#undef private

using namespace OHOS::AppExecFwk;

namespace OHOS {

bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);

    auto multiUserConfigurationMgr = std::make_shared<AppExecFwk::MultiUserConfigurationMgr>();
    if (multiUserConfigurationMgr == nullptr) {
        return false;
    }

    std::shared_ptr<AppExecFwk::Configuration> configurationPtr= std::make_shared<AppExecFwk::Configuration>();
    if (configurationPtr == nullptr) {
        return false;
    }
    configurationPtr->AddItem(fdp.ConsumeRandomLengthString(), fdp.ConsumeRandomLengthString());
    configurationPtr->AddItem(fdp.ConsumeRandomLengthString(), fdp.ConsumeRandomLengthString());
    configurationPtr->AddItem(fdp.ConsumeRandomLengthString(), fdp.ConsumeRandomLengthString());

    int32_t userId = fdp.ConsumeIntegral<int32_t>();

    std::vector<std::string> changeKeyV;
    bool isNotifyUser0;

    multiUserConfigurationMgr->GetConfigurationByUserId(userId);
    multiUserConfigurationMgr->InitConfiguration(configurationPtr);
    multiUserConfigurationMgr->HandleConfiguration(userId, *configurationPtr, changeKeyV, isNotifyUser0);
    multiUserConfigurationMgr->UpdateMultiUserConfiguration(*configurationPtr);
    multiUserConfigurationMgr->UpdateMultiUserConfigurationForGlobal(*configurationPtr);
    multiUserConfigurationMgr->SetOrUpdateConfigByUserId(userId, *configurationPtr, changeKeyV);

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