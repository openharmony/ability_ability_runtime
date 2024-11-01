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

#ifndef OHOS_ABILITY_RUNTIME_NAPI_DATA_ABILITY_OBSERVER_H
#define OHOS_ABILITY_RUNTIME_NAPI_DATA_ABILITY_OBSERVER_H

#include "data_ability_helper_common.h"
#include "data_ability_observer_stub.h"
#include "feature_ability_common.h"

namespace OHOS {
namespace AppExecFwk {
class NAPIDataAbilityObserver : public AAFwk::DataAbilityObserverStub {
public:
    void OnChange() override;
    void SetEnv(const napi_env &env);
    void SetCallbackRef(const napi_ref &ref);
    void ReleaseJSCallback();

    void CallJsMethod();

private:
    void SafeReleaseJSCallback();

    napi_env env_ = nullptr;
    napi_ref ref_ = nullptr;
    bool isCallingback_ = false;
    bool needRelease_ = false;
    std::mutex mutex_;
};
}  // namespace AppExecFwk
}  // namespace OHOS
#endif /* OHOS_ABILITY_RUNTIME_NAPI_DATA_ABILITY_OBSERVER_H */