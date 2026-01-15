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
#include "abilityappmgreventsecond_fuzzer.h"

#define private public
#include "app_mgr_event.h"
#undef private

#include <cstddef>
#include <cstdint>
#include <iostream>
#include "securec.h"
#include "configuration.h"
#include "application_info.h"
using namespace OHOS::AppExecFwk;
using namespace OHOS::AAFwk;

namespace OHOS {
namespace {
constexpr size_t U32_AT_SIZE = 4;
constexpr size_t U32_LEFT1 = 24;
constexpr size_t U32_LEFT2 = 16;
constexpr size_t U32_LEFT3 = 8;
}

uint32_t GetU32Data(const char* ptr)
{
    return (ptr[0] << U32_LEFT1) | (ptr[1] << U32_LEFT2) | (ptr[2] << U32_LEFT3) | ptr[3];
}

bool DoSomethingInterestingWithMyAPI(const char* data, size_t size)
{
    std::shared_ptr<ApplicationInfo> appInfo = std::make_shared<ApplicationInfo>();
    int32_t recordId = static_cast<int32_t>(GetU32Data(data));
    std::string processName(data, size);
    
    std::shared_ptr<AppRunningRecord> callerAppRecord = std::make_shared<AppRunningRecord>(
        appInfo, recordId, processName);
    std::shared_ptr<AppRunningRecord> appRecord = std::make_shared<AppRunningRecord>(
        appInfo, recordId + 1, processName + "_test");
    std::string moduleName(data, size);
    std::string abilityName(data, size);
    int32_t intParam = static_cast<int32_t>(GetU32Data(data));
    int64_t longParam = static_cast<int64_t>(GetU32Data(data));

    AppMgrEventUtil::SendCreateAtomicServiceProcessEvent(nullptr, nullptr, moduleName, abilityName);
    AppMgrEventUtil::SendCreateAtomicServiceProcessEvent(callerAppRecord, nullptr, moduleName, abilityName);
    AppMgrEventUtil::SendCreateAtomicServiceProcessEvent(nullptr, appRecord, moduleName, abilityName);
    AppMgrEventUtil::SendCreateAtomicServiceProcessEvent(callerAppRecord, appRecord, moduleName, abilityName);
    return true;
}
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (data == nullptr) {
        std::cout << "invalid data" << std::endl;
        return 0;
    }

    if (size < OHOS::U32_AT_SIZE) {
        return 0;
    }

    char* ch = (char*)malloc(size + 1);
    if (ch == nullptr) {
        std::cout << "malloc failed." << std::endl;
        return 0;
    }

    (void)memset_s(ch, size + 1, 0x00, size + 1);
    if (memcpy_s(ch, size + 1, data, size) != EOK) {
        std::cout << "copy failed." << std::endl;
        free(ch);
        ch = nullptr;
        return 0;
    }

    OHOS::DoSomethingInterestingWithMyAPI(ch, size);
    free(ch);
    ch = nullptr;
    return 0;
}