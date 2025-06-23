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
#include "appcapture_perf.h"
 
#include <mutex>
#include <algorithm>
#include <string>
 
#include "hisysevent.h"
#include "lperf.h"
#include "hilog_tag_wrapper.h"
 
namespace OHOS {
namespace AppExecFwk {
const int32_t CAPTURE_DURATION = 1000;
const int32_t FREQ = 100;
 
std::shared_ptr<AppCapturePerf> AppCapturePerf::instance_ = nullptr;
std::mutex AppCapturePerf::singletonMutex_;
 
std::shared_ptr<AppCapturePerf> AppCapturePerf::GetInstance()
{
    if (instance_ == nullptr) {
        std::lock_guard<std::mutex> lock(singletonMutex_);
        if (instance_ == nullptr) {
            instance_ = std::make_shared<AppCapturePerf>();
        }
    }
    return instance_;
}
 
std::vector<std::string> AppCapturePerf::SplitStr(const std::string &s, char delimiter)
{
    std::vector<std::string> tokens;
    std::string token;
    std::istringstream tokenStream(s);
    while (std::getline(tokenStream, token, delimiter)) {
        tokens.push_back(token);
    }
    return tokens;
}
 
int32_t AppCapturePerf::CapturePerf(const FaultData &faultData)
{
    std::vector<int32_t> tids;
    std::vector<std::string> threads = SplitStr(faultData.errorObject.stack, ',');
    for (int32_t i = 0; i < threads.size(); i++) {
        if (threads[i] == "") {
            continue;
        }
        tids.push_back(stoi(threads[i]));
    }
    int res = -2;
    auto &instance = Developtools::HiPerf::HiPerfLocal::Lperf::GetInstance();
    res = instance.StartProcessStackSampling(tids, FREQ, CAPTURE_DURATION, false);
    if (res != 0) {
        TAG_LOGE(AAFwkTag::APPDFR, "hiperf stack capture failed");
        return 0;
    }
    std::vector<std::string> perf;
    for (int32_t i = 0; i < tids.size(); i++) {
        std::string stack;
        res = instance.CollectSampleStackByTid(tids[i], stack);
        if (res != 0) {
            perf.push_back("");
            continue;
        }
        perf.push_back(stack);
    }
    res = instance.FinishProcessStackSampling();
    if (res != 0) {
        TAG_LOGE(AAFwkTag::APPDFR, "hiperf stack clean failed");
    }
    int64_t perfId = std::strtoll(faultData.timeoutMarkers.c_str(), nullptr, 10);
    int ret = HiSysEventWrite(HiviewDFX::HiSysEvent::Domain::RELIABILITY, "CPU_LOAD_CAPTURE_STACK",
        HiviewDFX::HiSysEvent::EventType::STATISTIC, "APP_NAME", faultData.errorObject.name,
        "TIDS", tids, "PERF", perf, "PERFID", perfId);
    if (ret != 0) {
        TAG_LOGE(AAFwkTag::APPDFR, "HiSysEventWrite CPU_LOAD_CAPTURE_STACK failed");
    }
    return 0;
}
 
void AppCapturePerf::DestroyInstance()
{
    std::lock_guard<std::mutex> lock(singletonMutex_);
    if (instance_ != nullptr) {
        instance_.reset();
        instance_ = nullptr;
    }
}
 
}  // namespace AppExecFwk
}  // namespace OHOS