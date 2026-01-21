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

#include "hilog_tag_wrapper.h"
#include "js_runtime_utils.h"
#include "napi/native_api.h"
#include "napi/native_common.h"

namespace OHOS {
namespace AAFwk {
enum ErrorCode {
    NO_ERROR = 0,
    INVALID_PARAMETER = -1,
    ABILITY_NOT_FOUND = -2,
    PERMISSION_DENY = -3,
};

static napi_status SetEnumItem(napi_env env, napi_value object, const char* name, int32_t value)
{
    TAG_LOGD(AAFwkTag::JSNAPI, "SetEnumItem called");
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

static napi_value InitErrorCodeEnum(napi_env env)
{
    TAG_LOGD(AAFwkTag::JSNAPI, "InitErrorCodeEnum called");
    AbilityRuntime::HandleEscape handleEscape(env);
    napi_value object;
    NAPI_CALL(env, napi_create_object(env, &object));
    NAPI_CALL(env, SetEnumItem(env, object, "NO_ERROR", ErrorCode::NO_ERROR));
    NAPI_CALL(env, SetEnumItem(env, object, "INVALID_PARAMETER", ErrorCode::INVALID_PARAMETER));
    NAPI_CALL(env, SetEnumItem(env, object, "ABILITY_NOT_FOUND", ErrorCode::ABILITY_NOT_FOUND));
    NAPI_CALL(env, SetEnumItem(env, object, "PERMISSION_DENY", ErrorCode::PERMISSION_DENY));
    return handleEscape.Escape(object);
}

/*
 * The module initialization.
 */
static napi_value ErrorCodeEnumInit(napi_env env, napi_value exports)
{
    AbilityRuntime::HandleEscape handleEscape(env);
    napi_value errorCode = InitErrorCodeEnum(env);
    napi_property_descriptor exportObjs[] = {
        DECLARE_NAPI_PROPERTY("ErrorCode", errorCode),
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
    .nm_version = 1,
    .nm_flags = 0,
    .nm_filename = nullptr,
    .nm_register_func = ErrorCodeEnumInit,
    .nm_modname = "ability.errorCode",
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
}  // namespace AAFwk
}  // namespace OHOS