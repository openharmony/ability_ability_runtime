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
#ifndef OHOS_ABILITY_ABILITY_APP_CAPTURE_PERF_H
#define OHOS_ABILITY_ABILITY_APP_CAPTURE_PERF_H
 
#include <memory>
#include <mutex>
#include <thread>
#include <charconv>
 
#include "fault_data.h"
 
namespace OHOS {
namespace AppExecFwk {
class AppCapturePerf {
public:
    AppCapturePerf() {}
    ~AppCapturePerf() {}
    static AppCapturePerf &GetInstance();
    int32_t CapturePerf(const FaultData &faultData);
    std::vector<std::string> SplitStr(const std::string &s, char delimiter);
private:
    std::mutex singletonMutex_;
};
}  // namespace AppExecFwk
}  // namespace OHOS
#endif // OHOS_ABILITY_ABILITY_APP_CAPTURE_PERF_H