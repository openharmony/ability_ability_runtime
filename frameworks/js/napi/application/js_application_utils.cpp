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

#include "js_application_utils.h"
#include "js_runtime.h"
#include "js_runtime_utils.h"
#include "hilog_tag_wrapper.h"

namespace OHOS {
namespace AbilityRuntime {

napi_value AppPreloadTypeInit(napi_env env)
{
    TAG_LOGD(AAFwkTag::APPKIT, "called");

    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null env");
        return nullptr;
    }

    napi_value object = nullptr;
    napi_create_object(env, &object);
    if (object == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null obj");
        return nullptr;
    }

    napi_set_named_property(env, object, "UNSPECIFIED",
        CreateJsValue(env, static_cast<int32_t>(AppPreloadType::UNSPECIFIED)));
    napi_set_named_property(env, object, "TYPE_CREATE_PROCESS",
        CreateJsValue(env, static_cast<int32_t>(AppPreloadType::TYPE_CREATE_PROCESS)));
    napi_set_named_property(env, object, "TYPE_CREATE_ABILITY_STAGE",
        CreateJsValue(env, static_cast<int32_t>(AppPreloadType::TYPE_CREATE_ABILITY_STAGE)));
    napi_set_named_property(env, object, "TYPE_CREATE_WINDOW_STAGE",
        CreateJsValue(env, static_cast<int32_t>(AppPreloadType::TYPE_CREATE_WINDOW_STAGE)));

    return object;
}
}  // namespace AbilityRuntime
}  // namespace OHOS