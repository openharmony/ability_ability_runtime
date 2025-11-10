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

#include "interop_object.h"

#include <node_api.h>

#include "ani.h"
#include "hilog_tag_wrapper.h"
#include "interop_js/hybridgref_ani.h"
#include "interop_js/hybridgref_napi.h"

namespace OHOS {
namespace AbilityRuntime {
InteropObject::InteropObject(ani_env *env, ani_ref ref)
{
    if (env == nullptr || ref == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null env or ref");
        return;
    }
    ani_vm *aniVM = nullptr;
    if (env->GetVM(&aniVM) != ANI_OK) {
        TAG_LOGE(AAFwkTag::APPKIT, "GetVM failed");
        return;
    }
    vm_ = aniVM;
    hybridgref_create_from_ani(env, ref, &ref_);
}

InteropObject::InteropObject(napi_env env, napi_value value)
{
    if (env == nullptr || value == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null env or value");
        return;
    }
    env_ = env;
    hybridgref_create_from_napi(env, value, &ref_);
}

InteropObject::~InteropObject()
{
    if (ref_ == nullptr) {
        return;
    }
    if (vm_ != nullptr) {
        ani_env *env = GetAniEnv();
        if (env == nullptr) {
            TAG_LOGE(AAFwkTag::APPKIT, "null env");
            return;
        }
        hybridgref_delete_from_ani(env, ref_);
    }
    if (env_ != nullptr) {
        hybridgref_delete_from_napi(env_, ref_);
    }
}

ani_env *InteropObject::GetAniEnv()
{
    if (vm_ == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null vm_");
        return nullptr;
    }
    ani_env* env = nullptr;
    if (vm_->GetEnv(ANI_VERSION_1, &env) != ANI_OK) {
        TAG_LOGE(AAFwkTag::APPKIT, "GetEnv failed");
        return nullptr;
    }
    return env;
}

ani_object InteropObject::GetAniValue(ani_env *env)
{
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null env");
        return nullptr;
    }
    ani_object result = nullptr;
    hybridgref_get_esvalue(env, ref_, &result);
    return result;
}

napi_value InteropObject::GetNapiValue(napi_env env)
{
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null env");
        return nullptr;
    }
    napi_value result = nullptr;
    if (!hybridgref_get_napi_value(env, ref_, &result)) {
        TAG_LOGE(AAFwkTag::APPKIT, "failed to get napi value");
        napi_get_undefined(env, &result);
    }
    return result;
}

bool InteropObject::IsFromAni()
{
    return vm_ != nullptr;
}

bool InteropObject::IsFromNapi()
{
    return env_ != nullptr;
}
}  // namespace AbilityRuntime
}  // namespace OHOS