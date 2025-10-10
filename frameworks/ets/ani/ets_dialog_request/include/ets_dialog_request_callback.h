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
#ifndef OHOS_ABILITY_RUNTIME_ETS_DIALOG_REQUEST_CALLBACK_H
#define OHOS_ABILITY_RUNTIME_ETS_DIALOG_REQUEST_CALLBACK_H

#include "idialog_request_callback.h"
#include "ani.h"

namespace OHOS {
namespace AbilityRuntime {
class EtsDialogRequestCallback {
public:
    explicit EtsDialogRequestCallback(const sptr<IDialogRequestCallback> remoteObj) :callback_(remoteObj) {}
    virtual ~EtsDialogRequestCallback() = default;
    static EtsDialogRequestCallback *GetEtsDialogReqCallback(ani_env *env, ani_object aniObj);
    static void SetRequestResult(ani_env *env, ani_object param, ani_object result);
private:
    void OnSetRequestResult(ani_env *env, ani_object param, ani_object result);
    sptr<IDialogRequestCallback> GetDialogRequestCallback(ani_env *env, ani_object object);
private:
    sptr<IDialogRequestCallback> callback_;
};
ani_object CreateEtsDialogRequestCallback(ani_env *env, const sptr<IDialogRequestCallback> &remoteObj);
} // AbilityRuntime
} // OHOS
#endif  // OHOS_ABILITY_RUNTIME_DIALOG_REQUEST_CALLBACK_H
