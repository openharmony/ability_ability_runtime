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

#include "js_agent_manager.h"

#include <cstddef>
#include <cstdint>
#include <mutex>

#include "agent_manager_client.h"
#include "hilog_tag_wrapper.h"
#include "js_agent_manager_utils.h"
#include "js_error_utils.h"
#include "js_runtime.h"
#include "js_runtime_utils.h"
#include "napi/native_api.h"
#include "napi_common_util.h"

using namespace OHOS::AbilityRuntime;

namespace OHOS {
namespace AgentRuntime {
namespace {
constexpr size_t ARGC_ONE = 1;
constexpr size_t ARGC_TWO = 2;
constexpr int32_t ARG_INDEX_0 = 0;
constexpr int32_t ARG_INDEX_1 = 1;

class JsAgentManager final {
public:
    JsAgentManager() {}
    ~JsAgentManager() {}

    static void Finalizer(napi_env env, void* data, void* hint)
    {
        TAG_LOGD(AAFwkTag::SER_ROUTER, "finalizer called");
        std::unique_ptr<JsAgentManager>(static_cast<JsAgentManager*>(data));
    }

    static napi_value GetAllAgentCards(napi_env env, napi_callback_info info)
    {
        GET_CB_INFO_AND_CALL(env, info, JsAgentManager, OnGetAllAgentCards);
    }

    static napi_value GetAgentCardsByBundleName(napi_env env, napi_callback_info info)
    {
        GET_CB_INFO_AND_CALL(env, info, JsAgentManager, OnGetAgentCardsByBundleName);
    }

    static napi_value GetAgentCardByUrl(napi_env env, napi_callback_info info)
    {
        GET_CB_INFO_AND_CALL(env, info, JsAgentManager, OnGetAgentCardByUrl);
    }

private:
    napi_value OnGetAllAgentCards(napi_env env, size_t argc, napi_value* argv)
    {
        auto innerErrorCode = std::make_shared<int32_t>(ERR_OK);
        auto cards = std::make_shared<std::vector<AgentCard>>();
        NapiAsyncTask::ExecuteCallback execute = [innerErrorCode, cards]() {
            *innerErrorCode = AgentManagerClient::GetInstance().GetAllAgentCards(*cards);
        };

        NapiAsyncTask::CompleteCallback complete = [innerErrorCode, cards](
            napi_env env, NapiAsyncTask &task, int32_t status) {
            if (*innerErrorCode != ERR_OK) {
                TAG_LOGE(AAFwkTag::SER_ROUTER, "error: %{public}d", *innerErrorCode);
                task.Reject(env, CreateJsErrorByNativeErr(env, *innerErrorCode));
                return;
            }
            TAG_LOGI(AAFwkTag::SER_ROUTER, "cards.size: %{public}zu", cards->size());
            task.ResolveWithNoError(env, CreateJsAgentCardArray(env, *cards));
        };

        napi_value result = nullptr;
        NapiAsyncTask::Schedule("JsAgentManager::OnGetAllAgentCards", env,
            CreateAsyncTaskWithLastParam(env, nullptr, std::move(execute), std::move(complete), &result));
        return result;
    }

    napi_value OnGetAgentCardsByBundleName(napi_env env, size_t argc, napi_value* argv)
    {
        if (argc < ARGC_ONE) {
            ThrowTooFewParametersError(env);
            return CreateJsUndefined(env);
        }

        std::string bundleName;
        if (!ConvertFromJsValue(env, argv[ARG_INDEX_0], bundleName)) {
            TAG_LOGE(AAFwkTag::SER_ROUTER, "bundleName not string");
            ThrowInvalidParamError(env, "Parse param bundleName failed, must be a string.");
            return CreateJsUndefined(env);
        }

        auto innerErrorCode = std::make_shared<int32_t>(ERR_OK);
        auto cards = std::make_shared<std::vector<AgentCard>>();
        NapiAsyncTask::ExecuteCallback execute = [bundleName, innerErrorCode, cards]() {
            *innerErrorCode = AgentManagerClient::GetInstance().GetAgentCardsByBundleName(bundleName, *cards);
        };

        NapiAsyncTask::CompleteCallback complete = [innerErrorCode, cards](
            napi_env env, NapiAsyncTask &task, int32_t status) {
            if (*innerErrorCode != ERR_OK) {
                TAG_LOGE(AAFwkTag::SER_ROUTER, "error: %{public}d", *innerErrorCode);
                task.Reject(env, CreateJsErrorByNativeErr(env, *innerErrorCode));
                return;
            }
            TAG_LOGI(AAFwkTag::SER_ROUTER, "cards.size: %{public}zu", cards->size());
            task.ResolveWithNoError(env, CreateJsAgentCardArray(env, *cards));
        };

        napi_value result = nullptr;
        NapiAsyncTask::Schedule("JsAgentManager::OnGetAgentCardsByBundleName", env,
            CreateAsyncTaskWithLastParam(env, nullptr, std::move(execute), std::move(complete), &result));
        return result;
    }

    napi_value OnGetAgentCardByUrl(napi_env env, size_t argc, napi_value* argv)
    {
        if (argc < ARGC_TWO) {
            ThrowTooFewParametersError(env);
            return CreateJsUndefined(env);
        }

        std::string bundleName;
        if (!ConvertFromJsValue(env, argv[ARG_INDEX_0], bundleName)) {
            TAG_LOGE(AAFwkTag::SER_ROUTER, "bundleName not string");
            ThrowInvalidParamError(env, "Parse param bundleName failed, must be a string.");
            return CreateJsUndefined(env);
        }

        std::string url;
        if (!ConvertFromJsValue(env, argv[ARG_INDEX_1], url)) {
            TAG_LOGE(AAFwkTag::SER_ROUTER, "url not string");
            ThrowInvalidParamError(env, "Parse param url failed, must be a string.");
            return CreateJsUndefined(env);
        }

        auto innerErrorCode = std::make_shared<int32_t>(ERR_OK);
        auto card = std::make_shared<AgentCard>();
        NapiAsyncTask::ExecuteCallback execute = [bundleName, url, innerErrorCode, card]() {
            *innerErrorCode = AgentManagerClient::GetInstance().GetAgentCardByUrl(bundleName, url, *card);
        };

        NapiAsyncTask::CompleteCallback complete = [innerErrorCode, card](
            napi_env env, NapiAsyncTask &task, int32_t status) {
            if (*innerErrorCode != ERR_OK) {
                TAG_LOGE(AAFwkTag::SER_ROUTER, "error: %{public}d", *innerErrorCode);
                task.Reject(env, CreateJsErrorByNativeErr(env, *innerErrorCode));
                return;
            }
            task.ResolveWithNoError(env, CreateJsAgentCard(env, *card));
        };

        napi_value result = nullptr;
        NapiAsyncTask::Schedule("JsAgentManager::OnGetAgentCardByUrl", env,
            CreateAsyncTaskWithLastParam(env, nullptr, std::move(execute), std::move(complete), &result));
        return result;
    }
};
} // namespace

napi_value JsAgentManagerInit(napi_env env, napi_value exportObj)
{
    TAG_LOGD(AAFwkTag::SER_ROUTER, "init agentManager");
    if (env == nullptr || exportObj == nullptr) {
        TAG_LOGW(AAFwkTag::SER_ROUTER, "null env or exportObj");
        return nullptr;
    }

    std::unique_ptr<JsAgentManager> jsAgentManager = std::make_unique<JsAgentManager>();
    napi_wrap(env, exportObj, jsAgentManager.release(), JsAgentManager::Finalizer, nullptr, nullptr);
    const char *moduleName = "AgentManager";
    BindNativeFunction(env, exportObj, "getAllAgentCards", moduleName, JsAgentManager::GetAllAgentCards);
    BindNativeFunction(env, exportObj, "getAgentCardsByBundleName", moduleName,
        JsAgentManager::GetAgentCardsByBundleName);
    BindNativeFunction(env, exportObj, "getAgentCardByUrl", moduleName, JsAgentManager::GetAgentCardByUrl);
    TAG_LOGD(AAFwkTag::SER_ROUTER, "end");
    return CreateJsUndefined(env);
}
}  // namespace AgentRuntime
}  // namespace OHOS
