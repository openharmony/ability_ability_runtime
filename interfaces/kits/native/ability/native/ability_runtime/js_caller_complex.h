/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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
#ifndef OHOS_ABILITY_RUNTIME_JS_CALLER_COMPLEX_H
#define OHOS_ABILITY_RUNTIME_JS_CALLER_COMPLEX_H

#include <memory>
#include <functional>
#include <native_engine/native_value.h>

#include "ability_context.h"
#include "iremote_object.h"

namespace OHOS {
namespace AbilityRuntime {
using ReleaseCallFunc = std::function<ErrCode(std::shared_ptr<CallerCallBack>&)>;

napi_value CreateJsCallerComplex(
    napi_env env, ReleaseCallFunc releaseCallFunc, sptr<IRemoteObject> callee,
    std::shared_ptr<CallerCallBack> callerCallBack);

napi_value CreateJsCalleeRemoteObject(napi_env env, sptr<IRemoteObject> callee);
} // AbilityRuntime
} // OHOS
#endif  // OHOS_ABILITY_RUNTIME_JS_CALLER_COMPLEX_H
