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

#ifndef OHOS_ABILITY_RUNTIME_MODAL_SYSTEM_DIALOG_UTIL_H
#define OHOS_ABILITY_RUNTIME_MODAL_SYSTEM_DIALOG_UTIL_H

#include "app_mgr_interface.h"

namespace OHOS {
namespace AbilityRuntime {
/**
 * @class ModalSystemDialogUtil
 * provides modal system dialog utilities.
 */
class ModalSystemDialogUtil final {
public:
    /**
     * @brief Check debug app in developer mode.
     * @param applicationInfo. The application info.
     * @return Returns ture or false.
     */
    static bool CheckDebugAppNotInDeveloperMode(const AppExecFwk::ApplicationInfo &applicationInfo);

    /**
     * @brief Prompt user that developer mode has not been turned on.
     * @param bundleName. The bundleName of the blocked hap.
     * @param abilityName. The abilityName of the blocked hap.
     */
    static void ShowDeveloperModeDialog(const std::string &bundleName, const std::string &abilityName);
};
}  // namespace AbilityRuntime
}  // namespace OHOS
#endif  // OHOS_ABILITY_RUNTIME_MODAL_SYSTEM_DIALOG_UTIL_H
