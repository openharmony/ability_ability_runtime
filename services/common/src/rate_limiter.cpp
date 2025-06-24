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

#include "rate_limiter.h"

#include "hilog_tag_wrapper.h"

namespace OHOS {
namespace AAFwk {
namespace {
constexpr int64_t CLEAN_INTERVAL_MS = 60000; // 60s
constexpr int64_t EXTENSION_LIMIT_INTERVAL_MS = 1000; // 1s
constexpr int32_t EXTENSION_MAX_LIMIT = 20;
constexpr int64_t REPORT_LIMIT_INTERVAL_MS = 5000; // 5s
constexpr int32_t REPORT_MAX_LIMIT = 1;
}

RateLimiter &RateLimiter::GetInstance()
{
    static RateLimiter instance;
    return instance;
}

bool RateLimiter::CheckExtensionLimit(int32_t uid)
{
    CleanCallMap();
    return CheckSingleLimit(uid, extensionCallMap_, extensionCallMapLock_, EXTENSION_LIMIT_INTERVAL_MS,
        EXTENSION_MAX_LIMIT);
}

bool RateLimiter::CheckReportLimit(int32_t uid)
{
    return CheckSingleLimit(uid, reportCallMap_, reportCallMapLock_, REPORT_LIMIT_INTERVAL_MS, REPORT_MAX_LIMIT);
}

bool RateLimiter::CheckSingleLimit(int32_t uid, std::unordered_map<int32_t, std::vector<int64_t>> &callMap,
    std::mutex &mapLock, int64_t limitInterval, int32_t maxLimit)
{
    int64_t currentTimeMillis = CurrentTimeMillis();
    int64_t timeBefore = currentTimeMillis - limitInterval;
    std::lock_guard<std::mutex> guard(mapLock);
    auto &timestamps = callMap[uid];
    
    auto it = std::lower_bound(timestamps.begin(), timestamps.end(), timeBefore);
    timestamps.erase(timestamps.begin(), it);

    if (timestamps.size() >= static_cast<size_t>(maxLimit)) {
        return true;
    }

    timestamps.emplace_back(currentTimeMillis);
    return false;
}

void RateLimiter::CleanCallMap()
{
    {
        std::lock_guard<std::mutex> guard(lastCleanTimeMillisLock_);
        auto currentTimeMillis = CurrentTimeMillis();
        if (currentTimeMillis - lastCleanTimeMillis_ < CLEAN_INTERVAL_MS) {
            return;
        }
        lastCleanTimeMillis_ = currentTimeMillis;
    }
    CleanSingleCallMap(extensionCallMap_, extensionCallMapLock_, EXTENSION_LIMIT_INTERVAL_MS);
    CleanSingleCallMap(reportCallMap_, reportCallMapLock_, REPORT_LIMIT_INTERVAL_MS);
}

void RateLimiter::CleanSingleCallMap(std::unordered_map<int32_t, std::vector<int64_t>> &callMap, std::mutex &mapLock,
    int64_t limitInterval)
{
    int64_t timeBefore = CurrentTimeMillis() - limitInterval;
    std::lock_guard<std::mutex> guard(mapLock);
    auto it = callMap.begin();
    while (it != callMap.end()) {
        bool allExpired = true;
        for (const auto &timestamp : it->second) {
            if (timestamp >= timeBefore) {
                allExpired = false;
                break;
            }
        }
        
        if (allExpired) {
            it = callMap.erase(it);
        } else {
            ++it;
        }
    }
    TAG_LOGI(AAFwkTag::SERVICE_EXT, "CleanSingleCallMap end, size:%{public}zu", callMap.size());
}

int64_t RateLimiter::CurrentTimeMillis()
{
    auto now = std::chrono::steady_clock::now().time_since_epoch();
    return std::chrono::duration_cast<std::chrono::milliseconds>(now).count();
}
}  // namespace AAFwk
}  // namespace OHOS
