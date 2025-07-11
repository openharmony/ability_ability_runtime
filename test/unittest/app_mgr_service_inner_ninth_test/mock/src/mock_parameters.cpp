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

#include "parameters.h"
#include "mock_my_status.h"

namespace OHOS {
namespace system {
constexpr const char* PRODUCT_ASSERT_FAULT_DIALOG_ENABLED = "persisit.sys.abilityms.support_assert_fault_dialog";

bool GetBoolParameter(const std::string& key, bool def)
{
    if (key == PRODUCT_ASSERT_FAULT_DIALOG_ENABLED) {
        return OHOS::AAFwk::MyStatus::GetInstance().getDialogEnabled_;
    }
    return OHOS::AAFwk::MyStatus::GetInstance().getBoolParameter_;
}
} // namespace system
} // namespace OHOS