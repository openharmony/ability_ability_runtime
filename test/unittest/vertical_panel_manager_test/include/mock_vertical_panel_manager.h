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

#ifndef OHOS_ABILITY_RUNTIME_MOCK_VERTICAL_PANEL_MANAGER_H
#define OHOS_ABILITY_RUNTIME_MOCK_VERTICAL_PANEL_MANAGER_H
#include "ability_context_impl.h"
#include "gmock/gmock.h"
#include "mock_ui_content.h"
#define private public
#include "panel_start_callback.h"
#undef private
#include "ui_content.h"

const size_t OHOS::AbilityRuntime::Context::CONTEXT_TYPE_ID(std::hash<const char *>{}("MockAbilityContext"));

namespace OHOS {
namespace AbilityRuntime {

class MockAbilityContext : public OHOS::AbilityRuntime::AbilityContextImpl {
public:
    MockAbilityContext() = default;
    ~MockAbilityContext() = default;
    MOCK_METHOD(Ace::MockUIContent *, GetUIContent, (), (override));
};

class MockPanelStartCallback : public OHOS::AbilityRuntime::PanelStartCallback {
public:
    MOCK_METHOD(void, OnError, (int32_t number), (override));
    MOCK_METHOD(void, OnResult, (int32_t resultCode, const AAFwk::Want &want), (override));
};

}  // namespace AbilityRuntime
}  // namespace OHOS
#endif  // OHOS_ABILITY_RUNTIME_MOCK_VERTICAL_PANEL_MANAGER_H
