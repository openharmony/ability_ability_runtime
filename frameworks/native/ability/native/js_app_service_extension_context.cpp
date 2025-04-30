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

#include "js_app_service_extension_context.h"
#include "js_service_extension_context.h"
#include <chrono>
#include <cstdint>

#include "ability_manager_client.h"
#include "ability_runtime/js_caller_complex.h"
#include "hilog_tag_wrapper.h"
#include "js_extension_context.h"
#include "js_error_utils.h"
#include "js_data_struct_converter.h"
#include "js_runtime.h"
#include "js_runtime_utils.h"
#include "napi/native_api.h"
#include "napi_common_ability.h"
#include "napi_common_want.h"
#include "napi_common_util.h"
#include "napi_remote_object.h"
#include "napi_common_start_options.h"
#include "open_link_options.h"
#include "open_link/napi_common_open_link_options.h"
#include "start_options.h"
#include "hitrace_meter.h"
#include "uri.h"

namespace OHOS {
namespace AbilityRuntime {
namespace {
constexpr int32_t INDEX_ZERO = 0;
constexpr int32_t INDEX_ONE = 1;
constexpr int32_t ERROR_CODE_ONE = 1;
constexpr int32_t ERROR_CODE_TWO = 2;
constexpr size_t ARGC_ZERO = 0;
constexpr size_t ARGC_ONE = 1;
constexpr size_t ARGC_TWO = 2;

static std::mutex g_connectsMutex;
static std::map<ConnectionKey, sptr<JSAppServiceExtensionConnection>, key_compare> g_connects;
static int64_t g_serialNumber = 0;

void RemoveConnection(int64_t connectId)
{
    TAG_LOGD(AAFwkTag::APP_SERVICE_EXT, "enter");
    std::lock_guard guard(g_connectsMutex);
    auto item = std::find_if(g_connects.begin(), g_connects.end(),
    [&connectId](const auto &obj) {
        return connectId == obj.first.id;
    });
    if (item != g_connects.end()) {
        TAG_LOGD(AAFwkTag::APP_SERVICE_EXT, "remove conn ability exist");
        if (item->second) {
            item->second->RemoveConnectionObject();
        }
        g_connects.erase(item);
    } else {
        TAG_LOGD(AAFwkTag::APP_SERVICE_EXT, "remove conn ability not exist");
    }
}

class JsAppServiceExtensionContext final {
public:
    explicit JsAppServiceExtensionContext(
        const std::shared_ptr<AppServiceExtensionContext>& context) : context_(context) {}
    ~JsAppServiceExtensionContext() = default;

    static void Finalizer(napi_env env, void* data, void* hint)
    {
        TAG_LOGD(AAFwkTag::APP_SERVICE_EXT, "called");
        std::unique_ptr<JsAppServiceExtensionContext>(static_cast<JsAppServiceExtensionContext*>(data));
    }

    static napi_value ConnectAbility(napi_env env, napi_callback_info info)
    {
        GET_NAPI_INFO_AND_CALL(env, info, JsAppServiceExtensionContext, OnConnectAbility);
    }

    static napi_value DisconnectAbility(napi_env env, napi_callback_info info)
    {
        GET_NAPI_INFO_AND_CALL(env, info, JsAppServiceExtensionContext, OnDisconnectAbility);
    }

    static napi_value TerminateSelf(napi_env env, napi_callback_info info)
    {
        GET_NAPI_INFO_AND_CALL(env, info, JsAppServiceExtensionContext, OnTerminateSelf);
    }

private:
    std::weak_ptr<AppServiceExtensionContext> context_;

    napi_value OnTerminateSelf(napi_env env, NapiCallbackInfo& info)
    {
        HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
        TAG_LOGI(AAFwkTag::APP_SERVICE_EXT, "TerminateSelf");
        auto innerErrCode = std::make_shared<ErrCode>(ERR_OK);
        NapiAsyncTask::ExecuteCallback execute = [weak = context_, innerErrCode]() {
            auto context = weak.lock();
            if (!context) {
                TAG_LOGW(AAFwkTag::APP_SERVICE_EXT, "context released");
                *innerErrCode = static_cast<int32_t>(ERROR_CODE_ONE);
                return;
            }
            *innerErrCode = context->TerminateSelf();
        };
        NapiAsyncTask::CompleteCallback complete =
            [innerErrCode](napi_env env, NapiAsyncTask& task, int32_t status) {
                if (*innerErrCode == ERR_OK) {
                    task.Resolve(env, CreateJsUndefined(env));
                } else if (*innerErrCode == ERROR_CODE_ONE) {
                    task.Reject(env, CreateJsError(env, *innerErrCode, "context is released"));
                } else {
                    task.Reject(env, CreateJsErrorByNativeErr(env, *innerErrCode));
                }
            };

        napi_value lastParam = (info.argc == ARGC_ZERO) ? nullptr : info.argv[INDEX_ZERO];
        napi_value result = nullptr;
        NapiAsyncTask::ScheduleHighQos("JsAppServiceExtensionContext::TerminateSelf",
            env, CreateAsyncTaskWithLastParam(env, lastParam, std::move(execute), std::move(complete), &result));
        return result;
    }

    bool CheckConnectionParam(napi_env env, napi_value value,
        sptr<JSAppServiceExtensionConnection>& connection, AAFwk::Want& want, int32_t accountId = -1) const
    {
        if (!CheckTypeForNapiValue(env, value, napi_object)) {
            TAG_LOGE(AAFwkTag::APP_SERVICE_EXT, "get connection obj failed");
            return false;
        }
        connection->SetJsConnectionObject(value);
        ConnectionKey key;
        {
            std::lock_guard guard(g_connectsMutex);
            key.id = g_serialNumber;
            key.want = want;
            key.accountId = accountId;
            connection->SetConnectionId(key.id);
            g_connects.emplace(key, connection);
            if (g_serialNumber < INT32_MAX) {
                g_serialNumber++;
            } else {
                g_serialNumber = 0;
            }
        }
        TAG_LOGD(AAFwkTag::APP_SERVICE_EXT, "Unable to find connection, make new one");
        return true;
    }

    NapiAsyncTask::ExecuteCallback GetConnectAbilityExecFunc(const AAFwk::Want &want,
        sptr<JSAppServiceExtensionConnection> connection, int64_t connectId, std::shared_ptr<int> innerErrorCode)
    {
        return [weak = context_, want, connection, connectId, innerErrorCode]() {
            TAG_LOGI(AAFwkTag::APP_SERVICE_EXT, "Connect ability: %{public}d",
                static_cast<int32_t>(connectId));

            auto context = weak.lock();
            if (!context) {
                TAG_LOGE(AAFwkTag::APP_SERVICE_EXT, "context released");
                *innerErrorCode = static_cast<int>(AbilityErrorCode::ERROR_CODE_INVALID_CONTEXT);
                return;
            }

            *innerErrorCode = context->ConnectAbility(want, connection);
        };
    }

    napi_value OnConnectAbility(napi_env env, NapiCallbackInfo& info)
    {
        HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
        TAG_LOGD(AAFwkTag::APP_SERVICE_EXT, "called");
        // Check params count
        if (info.argc < ARGC_TWO) {
            TAG_LOGE(AAFwkTag::APP_SERVICE_EXT, "invalid argc");
            ThrowTooFewParametersError(env);
            return CreateJsUndefined(env);
        }
        // Unwrap want and connection
        AAFwk::Want want;
        sptr<JSAppServiceExtensionConnection> connection = new JSAppServiceExtensionConnection(env);
        if (!AppExecFwk::UnwrapWant(env, info.argv[0], want)) {
            ThrowInvalidParamError(env, "Parse param want failed, must be a Want.");
            return CreateJsUndefined(env);
        }
        if (!CheckConnectionParam(env, info.argv[1], connection, want)) {
            ThrowInvalidParamError(env, "Parse param options failed, must be a ConnectOptions.");
            return CreateJsUndefined(env);
        }
        int64_t connectId = connection->GetConnectionId();
        auto innerErrorCode = std::make_shared<int>(ERR_OK);
        auto execute = GetConnectAbilityExecFunc(want, connection, connectId, innerErrorCode);
        NapiAsyncTask::CompleteCallback complete = [connection, connectId, innerErrorCode](napi_env env,
            NapiAsyncTask& task, int32_t status) {
            if (*innerErrorCode == 0) {
                TAG_LOGI(AAFwkTag::APP_SERVICE_EXT, "Connect ability success");
                task.ResolveWithNoError(env, CreateJsUndefined(env));
                return;
            }

            TAG_LOGE(AAFwkTag::APP_SERVICE_EXT, "Connect ability failed");
            int32_t errcode = static_cast<int32_t>(AbilityRuntime::GetJsErrorCodeByNativeError(*innerErrorCode));
            if (errcode) {
                connection->CallJsFailed(errcode);
                RemoveConnection(connectId);
            }
        };
        napi_value result = nullptr;
        NapiAsyncTask::ScheduleHighQos("JSAppServiceExtensionConnection::OnConnectAbility",
            env, CreateAsyncTaskWithLastParam(env, nullptr, std::move(execute), std::move(complete), &result));
        return CreateJsValue(env, connectId);
    }

    void FindConnection(AAFwk::Want& want, sptr<JSAppServiceExtensionConnection>& connection, int64_t& connectId,
        int32_t &accountId) const
    {
        TAG_LOGI(AAFwkTag::APP_SERVICE_EXT, "Disconnect ability:%{public}d",
            static_cast<int32_t>(connectId));
        std::lock_guard guard(g_connectsMutex);
        auto item = std::find_if(g_connects.begin(),
            g_connects.end(),
            [&connectId](const auto &obj) {
                return connectId == obj.first.id;
            });
        if (item != g_connects.end()) {
            // match id
            want = item->first.want;
            connection = item->second;
            accountId = item->first.accountId;
            TAG_LOGD(AAFwkTag::APP_SERVICE_EXT, "find conn ability exist");
        }
        return;
    }

    napi_value OnDisconnectAbility(napi_env env, NapiCallbackInfo& info)
    {
        HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
        TAG_LOGD(AAFwkTag::APP_SERVICE_EXT, "called");
        if (info.argc < ARGC_ONE) {
            TAG_LOGE(AAFwkTag::APP_SERVICE_EXT, "invalid argc");
            ThrowTooFewParametersError(env);
            return CreateJsUndefined(env);
        }
        int64_t connectId = -1;
        if (!AppExecFwk::UnwrapInt64FromJS2(env, info.argv[INDEX_ZERO], connectId)) {
            ThrowInvalidParamError(env, "Parse param connection failed, must be a number.");
            return CreateJsUndefined(env);
        }
        AAFwk::Want want;
        sptr<JSAppServiceExtensionConnection> connection = nullptr;
        int32_t accountId = -1;
        FindConnection(want, connection, connectId, accountId);
        // begin disconnect
        auto innerErrCode = std::make_shared<ErrCode>(ERR_OK);
        NapiAsyncTask::ExecuteCallback execute = [weak = context_, want, connection, accountId, innerErrCode]() {
            auto context = weak.lock();
            if (!context) {
                TAG_LOGW(AAFwkTag::APP_SERVICE_EXT, "context released");
                *innerErrCode = static_cast<int32_t>(ERROR_CODE_ONE);
                return;
            }
            if (!connection) {
                TAG_LOGW(AAFwkTag::APP_SERVICE_EXT, "null connection");
                *innerErrCode = static_cast<int32_t>(ERROR_CODE_TWO);
                return;
            }
            TAG_LOGD(AAFwkTag::APP_SERVICE_EXT, "context->DisconnectAbility");
            *innerErrCode = context->DisconnectAbility(want, connection, accountId);
        };
        NapiAsyncTask::CompleteCallback complete =
            [innerErrCode](napi_env env, NapiAsyncTask& task, int32_t status) {
                if (*innerErrCode == ERR_OK) {
                    task.Resolve(env, CreateJsUndefined(env));
                } else if (*innerErrCode == ERROR_CODE_ONE) {
                    task.Reject(env, CreateJsError(env, *innerErrCode, "Context is released"));
                } else if (*innerErrCode == ERROR_CODE_TWO) {
                    task.Reject(env, CreateJsError(env, *innerErrCode, "not found connection"));
                } else {
                    task.Reject(env, CreateJsErrorByNativeErr(env, *innerErrCode));
                }
            };
        napi_value lastParam = (info.argc == ARGC_ONE) ? nullptr : info.argv[INDEX_ONE];
        napi_value result = nullptr;
        NapiAsyncTask::Schedule("JSAppServiceExtensionConnection::OnDisconnectAbility",
            env, CreateAsyncTaskWithLastParam(env, lastParam, std::move(execute), std::move(complete), &result));
        return result;
    }
};
} // namespace

napi_value CreateJsAppServiceExtensionContext(napi_env env, std::shared_ptr<AppServiceExtensionContext> context)
{
    TAG_LOGD(AAFwkTag::APP_SERVICE_EXT, "called");
    std::shared_ptr<OHOS::AppExecFwk::AbilityInfo> abilityInfo = nullptr;
    if (context) {
        abilityInfo = context->GetAbilityInfo();
    }
    napi_value object = CreateJsExtensionContext(env, context, abilityInfo);

    std::unique_ptr<JsAppServiceExtensionContext> jsContext = std::make_unique<JsAppServiceExtensionContext>(context);
    napi_wrap(env, object, jsContext.release(), JsAppServiceExtensionContext::Finalizer, nullptr, nullptr);

    const char *moduleName = "JsAppServiceExtensionContext";
    BindNativeFunction(
        env, object, "connectServiceExtensionAbility", moduleName, JsAppServiceExtensionContext::ConnectAbility);
    BindNativeFunction(
        env, object, "disconnectServiceExtensionAbility", moduleName, JsAppServiceExtensionContext::DisconnectAbility);
    BindNativeFunction(
        env, object, "terminateSelf", moduleName, JsAppServiceExtensionContext::TerminateSelf);
    return object;
}

}  // namespace AbilityRuntime
}  // namespace OHOS
