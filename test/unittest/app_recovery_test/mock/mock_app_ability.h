/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#ifndef MOCK_OHOS_APP_ABILITY_RECOVERY_TEST_H
#define MOCK_OHOS_APP_ABILITY_RECOVERY_TEST_H
#include "ability_loader.h"
#include "recovery_param.h"
#include "ui_ability.h"
#include "want.h"

namespace OHOS {
namespace AppExecFwk {
class MockAppAbility : public AbilityRuntime::UIAbility {
protected:
    int32_t OnSaveState(int32_t reason, WantParams &wantParams,
        AppExecFwk::AbilityTransactionCallbackInfo<AppExecFwk::OnSaveStateResult> *callbackInfo,
        bool &isAsync, AppExecFwk::StateReason stateReason) override
    {
        return -1;
    }

    std::string GetContentInfo() override
    {
        return "test";
    }
};
}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // MOCK_OHOS_APP_ABILITY_RECOVERY_TEST_H
