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

#include "bundlemgrhelperfirst_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <fuzzer/FuzzedDataProvider.h>
#define private public
#define protected public
#include "bundle_mgr_helper.h"
#include "ability_keep_alive_service.h"
#include "bundle_info.h"
#include "main_thread.h"
#include "connection_observer.h"
#undef protected
#undef private
#include "ability_fuzz_util.h"
#include "ability_record.h"
#include "app_mgr_client.h"
#include "continuous_task_callback_info.h"
#include "keep_alive_process_manager.h"
#include "parameters.h"
#include "permission_verification.h"


using namespace OHOS::AAFwk;
using namespace OHOS::AppExecFwk;
using namespace OHOS::AbilityRuntime;

namespace OHOS {
namespace {
constexpr int INPUT_ZERO = 0;
constexpr int INPUT_ONE = 1;
constexpr int INPUT_THREE = 3;
constexpr size_t U32_AT_SIZE = 4;
constexpr uint8_t ENABLE = 2;
constexpr size_t OFFSET_ZERO = 24;
constexpr size_t OFFSET_ONE = 16;
constexpr size_t OFFSET_TWO = 8;
constexpr size_t STRING_MAX_LENGTH = 128;
}

uint32_t GetU32Data(const char* ptr)
{
    // convert fuzz input data to an integer
    return (ptr[INPUT_ZERO] << OFFSET_ZERO) | (ptr[INPUT_ONE] << OFFSET_ONE) | (ptr[ENABLE] << OFFSET_TWO) |
        ptr[INPUT_THREE];
}

bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
{
    std::shared_ptr<BundleMgrHelper> bmHelper = std::make_shared<BundleMgrHelper>();
    std::string bundleName;
    int32_t userId;
    bool bmsReady;
    std::string hostBundleName;
    std::string pluginBundleName;
    std::string pluginModuleName;
    BundleInfo bundleInfo;
    int32_t flags;
    std::vector<int32_t> appIndexes;
    SignatureInfo signatureInfo;
    HapModuleInfo hapModuleInfo;
    std::string moduleName;
    int32_t resId;
    int32_t appIndex;
    FuzzedDataProvider fdp(data, size);
    bundleName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    hostBundleName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    pluginBundleName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    moduleName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    pluginModuleName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    userId = fdp.ConsumeIntegral<int32_t>();
    flags = fdp.ConsumeIntegral<int32_t>();
    resId = fdp.ConsumeIntegral<int32_t>();
    appIndex = fdp.ConsumeIntegral<int32_t>();
    bmsReady = fdp.ConsumeBool();
    AbilityFuzzUtil::GetRandomBundleInfo(fdp, bundleInfo);
    AbilityFuzzUtil::GenerateSignatureInfo(fdp, signatureInfo);
    bmHelper->PreConnect();
    bmHelper->GetAppIdByBundleName(bundleName, userId);
    return true;
}
}
/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    OHOS::DoSomethingInterestingWithMyAPI(data, size);
    return 0;
}

