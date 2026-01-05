/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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
#include "appfreezeutil_fuzzer.h"

#include "appfreeze_util.h"

#include <fuzzer/FuzzedDataProvider.h>
#include <iostream>
#include "securec.h"

namespace OHOS {
using namespace OHOS::AppExecFwk;

constexpr size_t STRING_MAX_LENGTH = 128;
constexpr size_t U32_AT_SIZE = 4;

bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    std::string dirPath;
    std::string fileName;
    std::string format;
    std::string filePath;
    int32_t pid;
    dirPath = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    fileName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    format = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    filePath = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    float floatValue = fdp.ConsumeFloatingPoint<float>();
    pid = fdp.ConsumeIntegralInRange<int32_t>(0, U32_AT_SIZE);
    AppfreezeUtil::CreateFile(dirPath, fileName);
    AppfreezeUtil::GetMilliseconds();
    AppfreezeUtil::RoundToTwoDecimals(floatValue);
    AppfreezeUtil::GetCpuCount();
    AppfreezeUtil::FreezePathToRealPath(filePath);
    AppfreezeUtil::GetUidByPid(pid);
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