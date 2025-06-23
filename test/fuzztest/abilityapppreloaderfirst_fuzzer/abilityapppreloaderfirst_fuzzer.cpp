/*
 * Copyright (c) 2022-2025 Huawei Device Co., Ltd.
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

#include "abilityapppreloaderfirst_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <fuzzer/FuzzedDataProvider.h>

#define private public
#define protected public
#include "app_preloader.h"
#include "bundle_mgr_helper.h"
#undef protected
#undef private
#include "parcel.h"
#include <iostream>
#include "securec.h"
#include "configuration.h"

using namespace OHOS::AppExecFwk;

namespace OHOS {
namespace {
constexpr size_t STRING_MAX_LENGTH = 128;
}

bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
{
    std::shared_ptr<RemoteClientManager> remoteClientManager = std::make_shared<RemoteClientManager>();
    auto bundleMgrHelper = std::make_shared<AppExecFwk::BundleMgrHelper>();
    remoteClientManager->SetBundleManagerHelper(bundleMgrHelper);
    auto appPreloader = std::make_shared<AppPreloader>(remoteClientManager);
    std::string bundleName;
    int32_t userId;
    int32_t appIndex;
    PreloadRequest request;
    FuzzedDataProvider fdp(data, size);
    bundleName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    userId = fdp.ConsumeIntegral<int32_t>();
    appIndex = fdp.ConsumeIntegral<int32_t>();
    appPreloader->GeneratePreloadRequest(bundleName, userId, appIndex, request);
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