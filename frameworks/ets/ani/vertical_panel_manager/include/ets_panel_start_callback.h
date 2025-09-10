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

#ifndef OHOS_ABILITY_RUNTIME_ETS_PANEL_START_CALLBACK_H
#define OHOS_ABILITY_RUNTIME_ETS_PANEL_START_CALLBACK_H

#include "ani.h"
#include "panel_start_callback.h"

namespace OHOS {
namespace AbilityRuntime {
class EtsPanelStartCallback : public PanelStartCallback {
public:
    explicit EtsPanelStartCallback(ani_vm *vm) : vm_(vm) {}
    ~EtsPanelStartCallback() override;
#ifdef SUPPORT_SCREEN
    void OnError(int32_t number) override;
    void OnResult(int32_t resultCode, const AAFwk::Want &want) override;
#endif // SUPPORT_SCREEN
    void SetEtsCallbackObject(ani_object aniObject);

private:
    ani_env *GetAniEnv();
    void CallObjectMethod(const char *name, const char *signature, ...);

    ani_vm *vm_ = nullptr;
    ani_ref callback_ = nullptr;
};
} // namespace AbilityRuntime
} // namespace OHOS
#endif // OHOS_ABILITY_RUNTIME_ETS_PANEL_START_CALLBACK_H