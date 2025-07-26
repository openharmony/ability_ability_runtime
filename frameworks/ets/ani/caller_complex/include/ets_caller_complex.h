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

#ifndef OHOS_ABILITY_RUNTIME_ETS_CALLER_COMPLEX_H
#define OHOS_ABILITY_RUNTIME_ETS_CALLER_COMPLEX_H

#include <functional>
#include <memory>

#include "ani.h"
#include "caller_callback.h"

namespace OHOS {
namespace AbilityRuntime {
class EtsCallerComplex {
public:
    EtsCallerComplex(ReleaseCallFunc releaseCallFunc, std::shared_ptr<CallerCallBack> callerCallBack,
        sptr<IRemoteObject> callee) : releaseCallFunc_(releaseCallFunc), callerCallback_(callerCallBack),
        remoteObj_(callee) {}
    ~EtsCallerComplex() = default;

    static void ReleaseCall(ani_env *env, ani_object aniObj);

    static ani_object CreateEtsCaller(ani_env *env, ReleaseCallFunc releaseCallFunc,
        sptr<IRemoteObject> callee, std::shared_ptr<CallerCallBack> callback);
    static EtsCallerComplex* GetComplexPtrFrom(ani_env *env, ani_object aniObj);
    static ani_ref GetEtsRemoteObj(ani_env *env, ani_object aniObj);
    static void SetCallerCallback(std::shared_ptr<CallerCallBack> callback, ani_env *env, ani_object callerObj);

    static ani_object NativeTransferStatic(ani_env *env, ani_object, ani_object input);
    static ani_object NativeTransferDynamic(ani_env *env, ani_object, ani_object input);
    static bool IsInstanceOf(ani_env *env, ani_object aniObj);
    static ani_object CreateDynamicCaller(ani_env *env, sptr<IRemoteObject> remoteObj);
protected:
    void ReleaseCallInner(ani_env *env);
private:
    ReleaseCallFunc releaseCallFunc_;
    std::shared_ptr<CallerCallBack> callerCallback_;
    wptr<IRemoteObject> remoteObj_;
};

struct CallbackWrap {
    CallbackWrap(ani_env *env, ani_object callerObj, const std::string &callbackName);
    CallbackWrap(CallbackWrap &) = delete;
    void operator=(CallbackWrap &) = delete;
    ~CallbackWrap();
    void Invoke(const std::string &msg) const;
private:
    ani_vm *aniVM = nullptr;
    ani_ref callbackRef = nullptr;
    std::string name;
};
} // namespace AbilityRuntime
} // namespace OHOS
#endif // OHOS_ABILITY_RUNTIME_ETS_CALLER_COMPLEX_H