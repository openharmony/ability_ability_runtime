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

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "fill_request_callback_interface.h"
#include "hilog_tag_wrapper.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace AAFwk {

AbilityRuntime::AutoFill::PopupSize popupSize { .unit = AbilityRuntime::AutoFill::PopupDimensionUnit::PX,
    .width = 3.0,
    .height = 4.0 };

AbilityRuntime::AutoFill::PopupOffset popupOffset { .unit = AbilityRuntime::AutoFill::PopupDimensionUnit::VP,
    .deltaX = 6.1,
    .deltaY = 7.1 };

AbilityRuntime::AutoFill::PopupLength popupLength { .unit = AbilityRuntime::AutoFill::PopupDimensionUnit::FP,
    .length = 10.0 };

AbilityRuntime::AutoFill::PopupLength arrowLength { .unit = AbilityRuntime::AutoFill::PopupDimensionUnit::PERCENT,
    .length = 20.0 };

std::function<void(std::string)> stringValue = [](const std::string& str) {};

class IFillRequestCallbackTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() override {}
    void TearDown() override {}
};

class MockIFillRequestCallback : public AbilityRuntime::IFillRequestCallback {
public:
    MOCK_METHOD(void, OnFillRequestSuccess, (const AbilityBase::ViewData& viewData), (override));
    MOCK_METHOD(void, OnFillRequestFailed, (int32_t errCode, const std::string& fillContent, bool isPopup), (override));
    MOCK_METHOD(void, onPopupConfigWillUpdate, (AbilityRuntime::AutoFill::AutoFillCustomConfig & config), (override));
};

/**
 * @tc.number: IFillRequestCallback_onPopupConfigWillUpdate_0100
 * @tc.name: onPopupConfigWillUpdate
 * @tc.desc: onPopupConfigWillUpdate
 */
HWTEST_F(IFillRequestCallbackTest, IFillRequestCallback_onPopupConfigWillUpdate_0100, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "IFillRequestCallback_onPopupConfigWillUpdate_0100 start");

    std::shared_ptr<MockIFillRequestCallback> mockIFillRequestCallback = std::make_shared<MockIFillRequestCallback>();
    EXPECT_NE(mockIFillRequestCallback, nullptr);
    int32_t backgroundColor = 0xffffff;
    int32_t maskColor = 0xffffff;
    std::string inspectorId = "123456";
    AbilityRuntime::AutoFill::AutoFillCustomConfig config = { true, inspectorId, 1, true, true, popupSize, popupOffset,
        popupLength, arrowLength, AbilityRuntime::AutoFill::PopupPlacement::NONE, backgroundColor, maskColor,
        std::move(stringValue) };

    EXPECT_CALL(*mockIFillRequestCallback, onPopupConfigWillUpdate(_))
        .Times(1)
        .WillOnce(Invoke(
            [inspectorId, backgroundColor, maskColor](AbilityRuntime::AutoFill::AutoFillCustomConfig& updatedConfig) {
                EXPECT_EQ(updatedConfig.inspectorId, inspectorId);
                EXPECT_EQ(updatedConfig.backgroundColor, backgroundColor);
                EXPECT_EQ(updatedConfig.maskColor, maskColor);
            }));

    mockIFillRequestCallback->onPopupConfigWillUpdate(config);

    TAG_LOGI(AAFwkTag::TEST, "IFillRequestCallback_onPopupConfigWillUpdate_0100 start");
}
} // namespace AAFwk
} // namespace OHOS