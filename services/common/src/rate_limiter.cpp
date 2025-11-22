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
const std::vector<int32_t> EXTENSION_TIERS = { 50, 100, 200 };
constexpr int64_t REPORT_LIMIT_INTERVAL_MS = 5000; // 5s
constexpr int32_t REPORT_MAX_LIMIT = 1;
}

RateLimiter &RateLimiter::GetInstance()
{
    static RateLimiter instance;
    return instance;
}

RateLimiter::LimitResult RateLimiter::CheckExtensionLimit(int32_t uid)
{
    CleanCallMap();
    int64_t currentTimeMillis = CurrentTimeMillis();
    int64_t timeBefore = currentTimeMillis - EXTENSION_LIMIT_INTERVAL_MS;
    std::lock_guard<std::mutex> guard(extensionCallMapLock_);
    auto& timestamps = extensionCallMap_[uid];
    auto it = std::lower_bound(timestamps.begin(), timestamps.end(), timeBefore);
    timestamps.erase(timestamps.begin(), it);
    timestamps.emplace_back(currentTimeMillis);
    int currentCount = timestamps.size();
    LimitResult result{false, 0};
    {
        std::lock_guard<std::mutex> tierGuard(tierTriggerTimesLock_);
        auto& userTiers = tierTriggerTimes_[uid];
        CleanUserTierTriggerTimes(userTiers, timeBefore);
        for (auto tierIt = EXTENSION_TIERS.rbegin(); tierIt != EXTENSION_TIERS.rend(); ++tierIt) {
            int32_t limit = *tierIt;
            if (currentCount >= limit) {
                auto triggerIt = userTiers.find(limit);
                result = {true, limit};
                if (triggerIt == userTiers.end() || triggerIt->second < timeBefore) {
                    userTiers[limit] = currentTimeMillis;
                    break;
                }
            }
        }
    }
    return result;
}

bool RateLimiter::CheckReportLimit(int32_t uid, int32_t triggeredTier)
{
    std::lock_guard<std::mutex> guard(tierReportCallMapLock_);
    auto& userTierReports = tierReportCallMap_[uid];
    auto& timestamps = userTierReports[triggeredTier];
    int64_t currentTimeMillis = CurrentTimeMillis();
    int64_t timeBefore = currentTimeMillis - REPORT_LIMIT_INTERVAL_MS;
    auto it = std::lower_bound(timestamps.begin(), timestamps.end(), timeBefore);
    timestamps.erase(timestamps.begin(), it);
    if (timestamps.size() >= static_cast<size_t>(REPORT_MAX_LIMIT)) {
        return true;
    }
    timestamps.emplace_back(currentTimeMillis);
    return false;
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
    int64_t currentTimeMillis;
    {
        std::lock_guard<std::mutex> guard(lastCleanTimeMillisLock_);
        currentTimeMillis = CurrentTimeMillis();
        if (currentTimeMillis - lastCleanTimeMillis_ < CLEAN_INTERVAL_MS) {
            return;
        }
        lastCleanTimeMillis_ = currentTimeMillis;
    }
    
    CleanSingleCallMap(extensionCallMap_, extensionCallMapLock_, EXTENSION_LIMIT_INTERVAL_MS);
    CleanTierTriggerTimes(currentTimeMillis);
}

void RateLimiter::CleanTierTriggerTimes(int64_t currentTimeMillis)
{
    std::lock_guard<std::mutex> guard(tierTriggerTimesLock_);
    int64_t timeBefore = currentTimeMillis - EXTENSION_LIMIT_INTERVAL_MS;
    
    auto it = tierTriggerTimes_.begin();
    while (it != tierTriggerTimes_.end()) {
        auto& userTiers = it->second;
        CleanUserTierTriggerTimes(userTiers, timeBefore);
        
        if (userTiers.empty()) {
            it = tierTriggerTimes_.erase(it);
        } else {
            ++it;
        }
    }
}

void RateLimiter::CleanUserTierTriggerTimes(std::unordered_map<int32_t, int64_t>& userTiers, int64_t timeBefore)
{
    auto tierIt = userTiers.begin();
    while (tierIt != userTiers.end()) {
        if (tierIt->second < timeBefore) {
            tierIt = userTiers.erase(tierIt);
        } else {
            ++tierIt;
        }
    }
}

void RateLimiter::CleanSingleCallMap(std::unordered_map<int32_t, std::vector<int64_t>>& callMap, 
                                    std::mutex& mapLock, int64_t limitInterval) {
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
}

int64_t RateLimiter::CurrentTimeMillis()
{
    auto now = std::chrono::steady_clock::now().time_since_epoch();
    return std::chrono::duration_cast<std::chrono::milliseconds>(now).count();
}
}  // namespace AAFwk
}  // namespace OHOS
