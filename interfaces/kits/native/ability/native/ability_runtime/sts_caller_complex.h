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

#ifndef OHOS_ABILITY_RUNTIME_SIMULATOR_STS_CALLER_COMPLEX_H
#define OHOS_ABILITY_RUNTIME_SIMULATOR_STS_CALLER_COMPLEX_H

#include <functional>
#include <memory>

#include "caller_callback.h"
#include "sts_runtime.h"

namespace OHOS {
namespace AbilityRuntime {
using ReleaseCallFunc = std::function<ErrCode(std::shared_ptr<CallerCallBack>)>;

ani_object CreateEtsCaller(ani_env *env, ReleaseCallFunc releaseCallFunc,
    sptr<IRemoteObject> callee, std::shared_ptr<CallerCallBack> callback);
ani_object CreateEtsCallee(ani_env *env);
} // namespace AbilityRuntime
} // namespace OHOS
#endif // OHOS_ABILITY_RUNTIME_SIMULATOR_STS_CALLER_COMPLEX_H
