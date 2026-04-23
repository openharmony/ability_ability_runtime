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

#include "js_cli_manager.h"

#include <map>
#include <string>
#include <ctime>

#include "hilog_tag_wrapper.h"
#include "js_cli_manager_utils.h"
#include "js_error_utils.h"
#include "js_runtime_utils.h"
#include "napi/native_api.h"
#include "napi_common_util.h"
#include "cli_tool_mgr_client.h"

using namespace OHOS::AbilityRuntime;

namespace OHOS {
namespace CliTool {
namespace {
constexpr int32_t INDEX_ZERO = 0;
constexpr int32_t INDEX_ONE = 1;
constexpr int32_t INDEX_TWO = 2;
constexpr int32_t INDEX_THREE = 3;
} // namespace

void JSCliManager::Finalizer(napi_env env, void *data, void *hint)
{
    TAG_LOGD(AAFwkTag::CLI_TOOL, "JSCliManager::Finalizer is called");
    std::unique_ptr<JSCliManager>(static_cast<JSCliManager*>(data));
}

napi_value JSCliManager::ExecTool(napi_env env, napi_callback_info info)
{
    GET_CB_INFO_AND_CALL(env, info, JSCliManager, OnExecTool);
}

napi_value JSCliManager::OnExecTool(napi_env env, size_t argc, napi_value *argv)
{
    TAG_LOGD(AAFwkTag::CLI_TOOL, "JSCliManager::OnExecTool called");
    HandleEscape handleEscape(env);
    if (argc < INDEX_THREE) {
        ThrowTooFewParametersError(env);
        return CreateJsUndefined(env);
    }

    ExecToolParam param;
    if (!AppExecFwk::UnwrapStringFromJS2(env, argv[INDEX_ZERO], param.toolName) || param.toolName.empty()) {
        ThrowInvalidParamError(env, "Tool toolName is required");
        return CreateJsUndefined(env);
    }

    std::map<std::string, std::string> args;
    if (!UnwrapStringMap(env, argv[INDEX_ONE], args)) {
        ThrowInvalidParamError(env, "Tool args is required");
        return CreateJsUndefined(env);
    }

    if (!AppExecFwk::UnwrapStringFromJS2(env, argv[INDEX_TWO], param.challenge)) {
        ThrowInvalidParamError(env, "Tool challenge is required");
        return CreateJsUndefined(env);
    }

    if (argc > INDEX_THREE && argv[INDEX_THREE] != nullptr) {
        if (!UnwrapExecOptions(env, argv[INDEX_THREE], param.options)) {
            ThrowInvalidParamError(env, "Tool options is required");
            return CreateJsUndefined(env);
        }
    }

    auto innerErrCode = std::make_shared<int32_t>(ERR_OK);
    auto session = std::make_shared<CliSessionInfo>();

    NapiAsyncTask::ExecuteCallback execute = [innerErrCode, param, args, session]() {
        *innerErrCode = CliToolMGRClient::GetInstance().ExecTool(param, args, *session);
    };

    NapiAsyncTask::CompleteCallback complete = [innerErrCode, session](
        napi_env env, NapiAsyncTask &task, int32_t status) {
        HandleScope handleScope(env);
        if (*innerErrCode != ERR_OK) {
            task.Reject(env, CreateCliJsErrorByNativeErr(env, *innerErrCode));
            return;
        }

        napi_value jsSession = CreateJsCliSessionInfo(env, *session);
        if (jsSession == nullptr) {
            task.Reject(env, CreateJsUndefined(env));
            return;
        }

        task.ResolveWithNoError(env, jsSession);
    };

    napi_value asyncResult = nullptr;
    NapiAsyncTask::Schedule("JsCliManager::OnExecTool", env,
        CreateAsyncTaskWithLastParam(env, nullptr, std::move(execute), std::move(complete), &asyncResult));
    return handleEscape.Escape(asyncResult);
}

napi_value JSCliManagerInit(napi_env env, napi_value exportObj)
{
    TAG_LOGD(AAFwkTag::CLI_TOOL, "Init JSCliManager");

    if (env == nullptr || exportObj == nullptr) {
        TAG_LOGW(AAFwkTag::CLI_TOOL, "Null env or exportObj");
        return nullptr;
    }

    std::unique_ptr<JSCliManager> jsCliManager = std::make_unique<JSCliManager>();
    napi_wrap(env, exportObj, jsCliManager.release(), JSCliManager::Finalizer, nullptr, nullptr);

    const char *moduleName = "JsCliManager";
    BindNativeFunction(env, exportObj, "execTool", moduleName, JSCliManager::ExecTool);

    TAG_LOGD(AAFwkTag::CLI_TOOL, "JSCliManagerInit end");
    return CreateJsUndefined(env);
}

} // namespace CliTool
} // namespace OHOS
