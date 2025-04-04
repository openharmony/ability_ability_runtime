/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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

#include "js_ability_delegator_registry.h"

#include <memory>
#include "ability_delegator.h"
#include "ability_delegator_registry.h"
#include "hilog_tag_wrapper.h"
#include "js_ability_delegator.h"
#include "js_ability_delegator_utils.h"
#include "js_runtime_utils.h"

namespace OHOS {
namespace AbilityDelegatorJs {
using namespace OHOS::AbilityRuntime;
namespace {
thread_local std::unique_ptr<NativeReference> reference;

class JsAbilityDelegatorRegistry {
public:
    JsAbilityDelegatorRegistry() = default;
    ~JsAbilityDelegatorRegistry() = default;

    static void Finalizer(napi_env env, void *data, void *hint)
    {
        TAG_LOGI(AAFwkTag::DELEGATOR, "called");
        reference.reset();
        std::unique_ptr<JsAbilityDelegatorRegistry>(static_cast<JsAbilityDelegatorRegistry *>(data));
    }

    static napi_value GetAbilityDelegator(napi_env env, napi_callback_info info)
    {
        GET_CB_INFO_AND_CALL(env, info, JsAbilityDelegatorRegistry, OnGetAbilityDelegator);
    }

    static napi_value GetArguments(napi_env env, napi_callback_info info)
    {
        GET_CB_INFO_AND_CALL(env, info, JsAbilityDelegatorRegistry, OnGetArguments);
    }

private:
    napi_value OnGetAbilityDelegator(napi_env env, size_t argc, napi_value* argv)
    {
        TAG_LOGD(AAFwkTag::DELEGATOR, "called");
        if (!AppExecFwk::AbilityDelegatorRegistry::GetAbilityDelegator()) {
            TAG_LOGE(AAFwkTag::DELEGATOR, "null dgt");
            return CreateJsNull(env);
        }

        if (!reference) {
            auto value = CreateJsAbilityDelegator(env);
            napi_ref ref = nullptr;
            napi_create_reference(env, value, 1, &ref);
            reference.reset(reinterpret_cast<NativeReference*>(ref));
        }

        return reference->GetNapiValue();
    }

    napi_value OnGetArguments(napi_env env, size_t argc, napi_value* argv)
    {
        TAG_LOGI(AAFwkTag::DELEGATOR, "called");

        std::shared_ptr<AppExecFwk::AbilityDelegatorArgs> abilityDelegatorArgs =
            AppExecFwk::AbilityDelegatorRegistry::GetArguments();
        if (!abilityDelegatorArgs) {
            TAG_LOGE(AAFwkTag::DELEGATOR, "get delegator args object failed");
            return CreateJsNull(env);
        }
        return CreateJsAbilityDelegatorArguments(env, abilityDelegatorArgs);
    }
};
} // namespace

napi_value JsAbilityDelegatorRegistryInit(napi_env env, napi_value exportObj)
{
    TAG_LOGI(AAFwkTag::DELEGATOR, "called");
    if (env == nullptr || exportObj == nullptr) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "null env or exportObj");
        return nullptr;
    }

    std::unique_ptr<JsAbilityDelegatorRegistry> jsDelegatorManager = std::make_unique<JsAbilityDelegatorRegistry>();
    napi_wrap(env, exportObj, jsDelegatorManager.release(), JsAbilityDelegatorRegistry::Finalizer, nullptr, nullptr);

    const char *moduleName = "JsAbilityDelegatorRegistry";
    BindNativeFunction(env, exportObj, "getAbilityDelegator", moduleName,
        JsAbilityDelegatorRegistry::GetAbilityDelegator);
    BindNativeFunction(env, exportObj, "getArguments", moduleName, JsAbilityDelegatorRegistry::GetArguments);

    napi_set_named_property(env, exportObj, "AbilityLifecycleState",
        AbilityLifecycleStateInit(env));

    return CreateJsUndefined(env);
}

napi_value AbilityLifecycleStateInit(napi_env env)
{
    TAG_LOGI(AAFwkTag::DELEGATOR, "called");

    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "null env");
        return nullptr;
    }

    napi_value objValue = nullptr;
    napi_create_object(env, &objValue);
    if (objValue == nullptr) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "null objValue");
        return nullptr;
    }
    napi_set_named_property(env, objValue, "UNINITIALIZED",
        CreateJsValue(env, static_cast<int32_t>(AbilityLifecycleState::UNINITIALIZED)));
    napi_set_named_property(env, objValue, "CREATE",
        CreateJsValue(env, static_cast<int32_t>(AbilityLifecycleState::CREATE)));
    napi_set_named_property(env, objValue, "FOREGROUND",
        CreateJsValue(env, static_cast<int32_t>(AbilityLifecycleState::FOREGROUND)));
    napi_set_named_property(env, objValue, "BACKGROUND",
        CreateJsValue(env, static_cast<int32_t>(AbilityLifecycleState::BACKGROUND)));
    napi_set_named_property(env, objValue, "DESTROY",
        CreateJsValue(env, static_cast<int32_t>(AbilityLifecycleState::DESTROY)));

    return objValue;
}
}  // namespace AbilityDelegatorJs
}  // namespace OHOS
