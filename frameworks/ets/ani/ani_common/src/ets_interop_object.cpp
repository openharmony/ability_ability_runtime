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

#include "ets_interop_object.h"

#include "hilog_tag_wrapper.h"
#include "interop_js/hybridgref_ani.h"
#include "interop_js/hybridgref_napi.h"
#include "js_ability_lifecycle_callback.h"
#include "js_runtime.h"
#include "native_engine/native_engine.h"

#ifdef WINDOWS_PLATFORM
#define ETS_EXPORT __declspec(dllexport)
#else
#define ETS_EXPORT __attribute__((visibility("default")))
#endif

namespace OHOS {
namespace AbilityRuntime {
EtsInteropObject::EtsInteropObject(napi_env env, std::shared_ptr<NativeReference> ref)
{
    if (env == nullptr || ref == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null env or ref");
        return;
    }
    env_ = env;
    hybridgref_create_from_napi(env, ref->GetNapiValue(), &ref_);
}

EtsInteropObject::~EtsInteropObject()
{
    if (ref_ == nullptr) {
        return;
    }
    if (env_ != nullptr) {
        hybridgref_delete_from_napi(env_, ref_);
    }
}

ani_object EtsInteropObject::GetAniValue(ani_env *env)
{
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null env");
        return nullptr;
    }
    ani_object result = nullptr;
    hybridgref_get_esvalue(env, ref_, &result);
    return result;
}

bool EtsInteropObject::IsFromNapi()
{
    return env_ != nullptr && ref_ != nullptr;
}

extern "C" ETS_EXPORT InteropObject* OHOS_CreateEtsInteropObject(const Runtime &runtime,
    const AbilityLifecycleCallbackArgs &arg)
{
    std::shared_ptr<NativeReference> ref = static_cast<const JsAbilityLifecycleCallbackArgs&>(arg).ref_;
    if (ref == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null ref");
        return nullptr;
    }
    napi_env env = static_cast<const JsRuntime&>(runtime).GetNapiEnv();
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null env");
        return nullptr;
    }
    return new (std::nothrow) EtsInteropObject(env, ref);
}
}  // namespace AbilityRuntime
}  // namespace OHOS