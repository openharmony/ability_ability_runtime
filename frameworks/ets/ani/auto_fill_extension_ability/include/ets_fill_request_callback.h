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

#ifndef OHOS_ABILITY_RUNTIME_ETS_FILL_REQUEST_CALLBACK_H
#define OHOS_ABILITY_RUNTIME_ETS_FILL_REQUEST_CALLBACK_H

#include "ets_auto_fill_extension_util.h"
#include "session_info.h"
#include "want.h"
#include "window.h"

namespace OHOS {
namespace AbilityRuntime {
class EtsFillRequestCallback {
public:
    EtsFillRequestCallback(sptr<AAFwk::SessionInfo> sessionInfo, sptr<Rosen::Window> uiWindow);
    virtual ~EtsFillRequestCallback() = default;

    static ani_object SetEtsFillRequestCallback(ani_env *env, sptr<AAFwk::SessionInfo> sessionInfo,
        sptr<Rosen::Window> uiWindow);
    static EtsFillRequestCallback *GetEtsFillRequestCallback(ani_env *env, ani_object object);
    static void Clean(ani_env *env, ani_object object);
    static ani_object CreateEtsFillRequestCallback(ani_env *env, sptr<AAFwk::SessionInfo> sessionInfo,
        sptr<Rosen::Window> uiWindow);
    static void FillRequestSuccess(ani_env *env, ani_object object, ani_object responseObj);
    static void FillRequestFailed(ani_env *env, ani_object object);
    static void FillRequestCanceled(ani_env *env, ani_object object, ani_object fillContentObj);
    static void FillRequestAutoFillPopupConfig(ani_env *env, ani_object object, ani_object autoFillPopupConfigObj);

private:
    void OnFillRequestSuccess(ani_env *env, ani_object object, ani_object responseObj);
    void OnFillRequestFailed(ani_env *env, ani_object object);
    void OnFillRequestCanceled(ani_env *env, ani_object object, ani_object fillContentObj);
    void OnFillRequestAutoFillPopupConfig(ani_env *env, ani_object object, ani_object autoFillPopupConfigObj);
    bool SetPopupConfigToWantParams(ani_env *env, ani_object autoFillPopupConfigObj, AAFwk::WantParams& wantParams);
    void SendResultCodeAndViewData(const EtsAutoFillExtensionUtil::AutoFillResultCode &resultCode,
        const std::string &etsString);

    sptr<AAFwk::SessionInfo> sessionInfo_;
    sptr<Rosen::Window> uiWindow_;
};
} // namespace AbilityRuntime
} // namespace OHOS
#endif // OHOS_ABILITY_RUNTIME_ETS_FILL_REQUEST_CALLBACK_H