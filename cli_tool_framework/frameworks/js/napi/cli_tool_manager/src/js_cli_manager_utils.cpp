/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "js_cli_manager_utils.h"

#include <map>

#include "hilog_tag_wrapper.h"
#include "js_error_utils.h"
#include "js_runtime_utils.h"
#include "napi/native_api.h"
#include "napi_common_util.h"
#include "ability_runtime_error_util.h"

using namespace OHOS::AbilityRuntime;

namespace OHOS {
namespace CliTool {
namespace {
constexpr int32_t TIME_OUT = 30 * 1000;
}
bool UnwrapStringMap(napi_env env, napi_value obj,
    std::map<std::string, std::string> &values)
{
    if (obj == nullptr) {
        TAG_LOGE(AAFwkTag::CLI_TOOL, "Input object is null");
        return false;
    }

    napi_valuetype valueType = napi_undefined;
    napi_status status = napi_typeof(env, obj, &valueType);
    if (status != napi_ok || valueType != napi_object) {
        TAG_LOGE(AAFwkTag::CLI_TOOL, "Input is not an object");
        return false;
    }

    napi_value propertyNames = nullptr;
    if (napi_get_property_names(env, obj, &propertyNames) != napi_ok) {
        TAG_LOGE(AAFwkTag::CLI_TOOL, "Failed to get property names");
        return false;
    }
    uint32_t propertyCount = 0;
    if (napi_get_array_length(env, propertyNames, &propertyCount) != napi_ok) {
        TAG_LOGE(AAFwkTag::CLI_TOOL, "Failed to get array length");
        return false;
    }

    values.clear();
    for (uint32_t i = 0; i < propertyCount; i++) {
        napi_value key = nullptr;
        if (napi_get_element(env, propertyNames, i, &key) != napi_ok) {
            TAG_LOGE(AAFwkTag::CLI_TOOL, "Failed to get element");
            return false;
        }

        std::string keyStr;
        if (!AppExecFwk::UnwrapStringFromJS2(env, key, keyStr)) {
            TAG_LOGE(AAFwkTag::CLI_TOOL, "Failed to unwrap key");
            return false;
        }

        napi_value value = nullptr;
        if (napi_get_named_property(env, obj, keyStr.c_str(), &value) != napi_ok) {
            TAG_LOGE(AAFwkTag::CLI_TOOL, "Failed to get value");
            return false;
        }

        std::string valueStr;
        if (!AppExecFwk::UnwrapStringFromJS2(env, value, valueStr)) {
            TAG_LOGE(AAFwkTag::CLI_TOOL, "Failed to unwrap value");
            return false;
        }

        values.emplace(std::make_pair(keyStr, valueStr));
    }

    return true;
}

bool UnwrapExecOptions(napi_env env, napi_value obj, ExecOptions &options)
{
    if (obj == nullptr) {
        // Use default options
        options.background = false;
        options.yieldMs = 0;
        options.timeout = TIME_OUT;
        options.workingDir = "";
        return true;
    }

    napi_valuetype valueType = napi_undefined;
    napi_status status = napi_typeof(env, obj, &valueType);
    if (status != napi_ok || valueType != napi_object) {
        TAG_LOGE(AAFwkTag::CLI_TOOL, "Input is not an object");
        return false;
    }

    // Extract background (optional)
    napi_value backgroundProp = nullptr;
    if (napi_get_named_property(env, obj, "background", &backgroundProp) != napi_ok) {
        TAG_LOGE(AAFwkTag::CLI_TOOL, "invalid background property");
        return false;
    }
    if (!AppExecFwk::UnwrapBoolFromJS2(env, backgroundProp, options.background)) {
        TAG_LOGE(AAFwkTag::CLI_TOOL, "unwrap background failed");
        return false;
    }

    // Extract yieldMs (optional)
    napi_value yieldMsProp = nullptr;
    if (napi_get_named_property(env, obj, "yieldMs", &yieldMsProp) != napi_ok) {
        TAG_LOGE(AAFwkTag::CLI_TOOL, "invalid yieldMs property");
        return false;
    }
    if (!AppExecFwk::UnwrapInt32FromJS2(env, yieldMsProp, options.yieldMs)) {
        TAG_LOGE(AAFwkTag::CLI_TOOL, "unwrap yieldMs failed");
        return false;
    }

    // Extract timeout (optional)
    napi_value timeoutProp = nullptr;
    if (napi_get_named_property(env, obj, "timeout", &timeoutProp) != napi_ok) {
        TAG_LOGE(AAFwkTag::CLI_TOOL, "invalid timeout property");
        return false;
    }
    if (!AppExecFwk::UnwrapInt32FromJS2(env, timeoutProp, options.timeout)) {
        TAG_LOGE(AAFwkTag::CLI_TOOL, "unwrap timeout failed");
        return false;
    }

    // Extract workingDir (optional)
    napi_value workingDirProp = nullptr;
    if (napi_get_named_property(env, obj, "workingDir", &workingDirProp) != napi_ok) {
        TAG_LOGE(AAFwkTag::CLI_TOOL, "invalid workingDir property");
        return false;
    }
    if (!AppExecFwk::UnwrapStringFromJS2(env, workingDirProp, options.workingDir)) {
        TAG_LOGE(AAFwkTag::CLI_TOOL, "unwrap workingDir failed");
        return false;
    }

    // Extract env (optional)
    napi_value envProp = nullptr;
    if (napi_get_named_property(env, obj, "env", &envProp) != napi_ok) {
        TAG_LOGE(AAFwkTag::CLI_TOOL, "invalid env property");
        return false;
    }
    if (!UnwrapStringMap(env, envProp, options.env)) {
        TAG_LOGE(AAFwkTag::CLI_TOOL, "unwrap env failed");
        return false;
    }

    return true;
}

napi_value CreateJsCliSessionInfo(napi_env env, const CliSessionInfo &session)
{
    napi_value jsObj = nullptr;
    napi_status status = napi_create_object(env, &jsObj);
    if (status != napi_ok) {
        TAG_LOGE(AAFwkTag::CLI_TOOL, "Failed to create JS object");
        return nullptr;
    }

    // Set sessionId
    napi_value jsSessionId = AppExecFwk::WrapStringToJS(env, session.sessionId);
    napi_set_named_property(env, jsObj, "sessionId", jsSessionId);

    // Set toolName
    napi_value jsToolName = AppExecFwk::WrapStringToJS(env, session.toolName);
    napi_set_named_property(env, jsObj, "toolName", jsToolName);

    // Set status
    napi_value jsStatus = AppExecFwk::WrapStringToJS(env, session.status);
    napi_set_named_property(env, jsObj, "status", jsStatus);

    // Set startTime
    napi_value jsStartTime = AppExecFwk::WrapInt64ToJS(env, session.startTime);
    napi_set_named_property(env, jsObj, "startTime", jsStartTime);

    // Set endTime
    napi_value jsEndTime = AppExecFwk::WrapInt64ToJS(env, session.endTime);
    napi_set_named_property(env, jsObj, "endTime", jsEndTime);

    // Set result if present
    if (session.result != nullptr) {
        napi_value jsResult = nullptr;
        status = napi_create_object(env, &jsResult);
        if (status == napi_ok) {
            // Set exitCode
            napi_value jsExitCode = AppExecFwk::WrapInt32ToJS(env, session.result->exitCode);
            napi_set_named_property(env, jsResult, "exitCode", jsExitCode);

            // Set outputText
            napi_value jsOutputText = AppExecFwk::WrapStringToJS(env, session.result->outputText);
            napi_set_named_property(env, jsResult, "outputText", jsOutputText);

            // Set errorText
            napi_value jsErrorText = AppExecFwk::WrapStringToJS(env, session.result->errorText);
            napi_set_named_property(env, jsResult, "errorText", jsErrorText);

            // Set signalNumber
            napi_value jsSignalNumber = AppExecFwk::WrapInt32ToJS(env, session.result->signalNumber);
            napi_set_named_property(env, jsResult, "signalNumber", jsSignalNumber);

            // Set timedOut
            napi_value jsTimedOut = AppExecFwk::WrapBoolToJS(env, session.result->timedOut);
            napi_set_named_property(env, jsResult, "timedOut", jsTimedOut);

            // Set executionTime
            napi_value jsExecutionTime = AppExecFwk::WrapInt64ToJS(env, session.result->executionTime);
            napi_set_named_property(env, jsResult, "executionTime", jsExecutionTime);

            napi_set_named_property(env, jsObj, "result", jsResult);
        }
    }

    return jsObj;
}

napi_value CreateCliJsErrorByNativeErr(napi_env env, int32_t errCode)
{
    return CreateJsErrorByNativeErr(env, errCode);
}

} // namespace CliTool
} // namespace OHOS
