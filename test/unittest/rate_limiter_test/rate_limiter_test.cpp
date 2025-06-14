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

#include <gtest/gtest.h>
#include <thread>
#include <chrono>

#include "hilog_tag_wrapper.h"
#define private public
#include "rate_limiter.h"
#undef private

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace AAFwk {
namespace {
constexpr int64_t EXTENSION_LIMIT_INTERVAL_MS = 1000;  // 1s
constexpr int32_t EXTENSION_MAX_LIMIT = 20;
constexpr int64_t REPORT_LIMIT_INTERVAL_MS = 5000; // 5s
constexpr int32_t REPORT_MAX_LIMIT = 1;
}
class RateLimiterTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

void RateLimiterTest::SetUpTestCase(void)
{}

void RateLimiterTest::TearDownTestCase(void)
{}

void RateLimiterTest::SetUp()
{
    RateLimiter::GetInstance().extensionCallMap_.clear();
}

void RateLimiterTest::TearDown()
{}

/**
 * @tc.number: CheckExtensionLimitTest_0100
 * @tc.desc: Test CheckExtensionLimit
 * @tc.type: FUNC
 */
HWTEST_F(RateLimiterTest, CheckExtensionLimitTest_0100, TestSize.Level2)
{
    TAG_LOGI(AAFwkTag::TEST, "CheckExtensionLimitTest_0100 start.");

    auto &rateLimiter = RateLimiter::GetInstance();
    auto uid = 20010001;
    auto isLimit = rateLimiter.CheckExtensionLimit(uid);
    EXPECT_FALSE(isLimit);

    TAG_LOGI(AAFwkTag::TEST, "CheckExtensionLimitTest_0100 end.");
}

/**
 * @tc.number: CheckExtensionLimitTest_0200
 * @tc.desc: Test CheckExtensionLimit
 * @tc.type: FUNC
 */
HWTEST_F(RateLimiterTest, CheckExtensionLimitTest_0200, TestSize.Level2)
{
    TAG_LOGI(AAFwkTag::TEST, "CheckExtensionLimitTest_0200 start.");

    auto &rateLimiter = RateLimiter::GetInstance();
    auto uid = 20010001;
    for (int i = 0; i < EXTENSION_MAX_LIMIT; i++) {
        rateLimiter.CheckExtensionLimit(uid);
    }
    auto isLimit = rateLimiter.CheckExtensionLimit(uid);
    EXPECT_TRUE(isLimit);

    TAG_LOGI(AAFwkTag::TEST, "CheckExtensionLimitTest_0200 end.");
}

/**
 * @tc.number: CheckReportLimitTest_0100
 * @tc.desc: Test CheckReportLimit
 * @tc.type: FUNC
 */
HWTEST_F(RateLimiterTest, CheckReportLimitTest_0100, TestSize.Level2)
{
    TAG_LOGI(AAFwkTag::TEST, "CheckReportLimitTest_0100 start.");

    auto &rateLimiter = RateLimiter::GetInstance();
    auto uid = 20010001;
    auto isLimit = rateLimiter.CheckReportLimit(uid);
    EXPECT_FALSE(isLimit);

    TAG_LOGI(AAFwkTag::TEST, "CheckReportLimitTest_0100 end.");
}

/**
 * @tc.number: CheckReportLimitTest_0200
 * @tc.desc: Test CheckReportLimit
 * @tc.type: FUNC
 */
HWTEST_F(RateLimiterTest, CheckReportLimitTest_0200, TestSize.Level2)
{
    TAG_LOGI(AAFwkTag::TEST, "CheckReportLimitTest_0200 start.");

    auto &rateLimiter = RateLimiter::GetInstance();
    auto uid = 20010001;
    for (int i = 0; i < REPORT_MAX_LIMIT; i++) {
        rateLimiter.CheckReportLimit(uid);
    }
    auto isLimit = rateLimiter.CheckReportLimit(uid);
    EXPECT_TRUE(isLimit);

    TAG_LOGI(AAFwkTag::TEST, "CheckReportLimitTest_0200 end.");
}

/**
 * @tc.number: CleanCallMapTest_0100
 * @tc.desc: Test CleanCallMap
 * @tc.type: FUNC
 */
HWTEST_F(RateLimiterTest, CleanCallMapTest_0100, TestSize.Level2)
{
    TAG_LOGI(AAFwkTag::TEST, "CleanCallMapTest_0100 start.");

    auto &rateLimiter = RateLimiter::GetInstance();
    auto uid1 = 20010001;
    auto uid2 = 20010002;

    rateLimiter.CheckExtensionLimit(uid1);
    rateLimiter.CheckExtensionLimit(uid1);
    rateLimiter.CheckExtensionLimit(uid1);
    std::this_thread::sleep_for(std::chrono::milliseconds(EXTENSION_LIMIT_INTERVAL_MS + 100));
    rateLimiter.CheckExtensionLimit(uid2);
    rateLimiter.CheckExtensionLimit(uid2);

    rateLimiter.lastCleanTimeMillis_ = 0;
    rateLimiter.CleanCallMap();
    auto mapSize = rateLimiter.extensionCallMap_.size();
    TAG_LOGI(AAFwkTag::TEST, "extensionCallMap_ size:%{public}zu", mapSize);
    EXPECT_EQ(mapSize, 1);

    TAG_LOGI(AAFwkTag::TEST, "CleanCallMapTest_0100 end.");
}

/**
 * @tc.number: CleanCallMapTest_0200
 * @tc.desc: Test CleanCallMap
 * @tc.type: FUNC
 */
HWTEST_F(RateLimiterTest, CleanCallMapTest_0200, TestSize.Level2)
{
    TAG_LOGI(AAFwkTag::TEST, "CleanCallMapTest_0200 start.");

    auto &rateLimiter = RateLimiter::GetInstance();
    auto uid1 = 20010001;
    auto uid2 = 20010002;

    rateLimiter.CheckReportLimit(uid1);
    std::this_thread::sleep_for(std::chrono::milliseconds(REPORT_LIMIT_INTERVAL_MS + 100));
    rateLimiter.CheckReportLimit(uid2);

    rateLimiter.lastCleanTimeMillis_ = 0;
    rateLimiter.CleanCallMap();
    auto mapSize = rateLimiter.reportCallMap_.size();
    TAG_LOGI(AAFwkTag::TEST, "reportCallMap_ size:%{public}zu", mapSize);
    EXPECT_EQ(mapSize, 1);

    TAG_LOGI(AAFwkTag::TEST, "CleanCallMapTest_0200 end.");
}
}  // namespace AAFwk
}  // namespace OHOS