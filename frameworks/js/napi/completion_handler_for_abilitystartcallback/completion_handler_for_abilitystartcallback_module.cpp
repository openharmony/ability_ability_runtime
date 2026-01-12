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

#include "ability_failure_code.h"
#include "hilog_tag_wrapper.h"
#include "js_runtime_utils.h"
#include "native_engine/native_engine.h"

namespace OHOS {
namespace AbilityRuntime {

static napi_status SetEnumItem(napi_env env, napi_value object, const char* name, int32_t value)
{
    AbilityRuntime::HandleScope handleScope(env);
    napi_status status;
    napi_value itemName;
    napi_value itemValue;

    NAPI_CALL_BASE(env, status = napi_create_string_utf8(env, name, NAPI_AUTO_LENGTH, &itemName), status);
    NAPI_CALL_BASE(env, status = napi_create_int32(env, value, &itemValue), status);

    NAPI_CALL_BASE(env, status = napi_set_property(env, object, itemName, itemValue), status);
    NAPI_CALL_BASE(env, status = napi_set_property(env, object, itemValue, itemName), status);

    return napi_ok;
}

static napi_value InitFailureCodeObject(napi_env env)
{
    AbilityRuntime::HandleEscape handleEscape(env);
    napi_value object;
    NAPI_CALL(env, napi_create_object(env, &object));
    NAPI_CALL(env, SetEnumItem(env, object, "FAILURE_CODE_SYSTEM_MALFUNCTION",
        static_cast<int32_t>(FailureCode::FAILURE_CODE_SYSTEM_MALFUNCTION)));
    NAPI_CALL(env, SetEnumItem(env, object, "FAILURE_CODE_USER_CANCEL",
        static_cast<int32_t>(FailureCode::FAILURE_CODE_USER_CANCEL)));
    return handleEscape.Escape(object);
}

static napi_value CompletionHandlerForAbilityStartCallbackInit(napi_env env, napi_value exports)
{
    AbilityRuntime::HandleEscape handleEscape(env);
    napi_value failureCode = InitFailureCodeObject(env);
    if (failureCode == nullptr) {
        TAG_LOGE(AAFwkTag::JSNAPI, "null failureCode");
        return nullptr;
    }

    napi_property_descriptor exportObjs[] = {
        DECLARE_NAPI_PROPERTY("AbilityStartFailureCode", failureCode),
    };

    napi_status status = napi_define_properties(env, exports, sizeof(exportObjs) / sizeof(exportObjs[0]), exportObjs);
    if (status != napi_ok) {
        TAG_LOGE(AAFwkTag::JSNAPI, "define properties failed");
        return nullptr;
    }

    return handleEscape.Escape(exports);
}

/*
 * The module definition.
 */
static napi_module _module = {
    .nm_version = 0,
    .nm_flags = 0,
    .nm_filename = nullptr,
    .nm_register_func = CompletionHandlerForAbilityStartCallbackInit,
    .nm_modname = "app.ability.CompletionHandlerForAbilityStartCallback",
    .nm_priv = (static_cast<void *>(0)),
    .reserved = {0}
};

/*
 * The module registration.
 */
extern "C" __attribute__((constructor)) void RegisterModule(void)
{
    napi_module_register(&_module);
}
}
}
