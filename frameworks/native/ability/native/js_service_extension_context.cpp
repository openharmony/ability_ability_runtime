/*
 * Copyright (c) 2022-2025 Huawei Device Co., Ltd.
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

#include "js_service_extension_context.h"

#include <chrono>
#include <cstdint>

#include "ability_manager_client.h"
#include "ability_runtime/js_caller_complex.h"
#include "hilog_tag_wrapper.h"
#include "js_extension_context.h"
#include "js_error_utils.h"
#include "js_data_struct_converter.h"
#include "js_deferred_callback.h"
#include "js_runtime.h"
#include "js_runtime_utils.h"
#include "js_start_abilities_observer.h"
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
constexpr int32_t INDEX_TWO = 2;
constexpr int32_t INDEX_THREE = 3;
constexpr int32_t INDEX_FOUR = 4;
constexpr int32_t ERROR_CODE_ONE = 1;
constexpr int32_t ERROR_CODE_TWO = 2;
constexpr size_t ARGC_ZERO = 0;
constexpr size_t ARGC_ONE = 1;
constexpr size_t ARGC_TWO = 2;
constexpr size_t ARGC_THREE = 3;
constexpr size_t ARGC_FOUR = 4;
constexpr const char* ATOMIC_SERVICE_PREFIX = "com.atomicservice.";
const std::string JSON_KEY_ERR_MSG = "errMsg";

class StartAbilityByCallParameters {
public:
    int err = 0;
    sptr<IRemoteObject> remoteCallee = nullptr;
    std::shared_ptr<CallerCallBack> callerCallBack = nullptr;
    std::mutex mutexlock;
    std::condition_variable condition;
};

static std::mutex g_connectsMutex;
static std::map<ConnectionKey, sptr<JSServiceExtensionConnection>, key_compare> g_connects;
static int64_t g_serialNumber = 0;

void RemoveConnection(int64_t connectId)
{
    TAG_LOGD(AAFwkTag::SERVICE_EXT, "enter");
    std::lock_guard guard(g_connectsMutex);
    auto item = std::find_if(g_connects.begin(), g_connects.end(),
    [&connectId](const auto &obj) {
        return connectId == obj.first.id;
    });
    if (item != g_connects.end()) {
        TAG_LOGD(AAFwkTag::SERVICE_EXT, "remove conn ability exist");
        if (item->second) {
            item->second->RemoveConnectionObject();
        }
        g_connects.erase(item);
    } else {
        TAG_LOGD(AAFwkTag::SERVICE_EXT, "remove conn ability not exist");
    }
}

class JsServiceExtensionContext final {
public:
    explicit JsServiceExtensionContext(const std::shared_ptr<ServiceExtensionContext>& context) : context_(context) {}
    ~JsServiceExtensionContext() = default;

    static void Finalizer(napi_env env, void* data, void* hint)
    {
        TAG_LOGD(AAFwkTag::SERVICE_EXT, "called");
        std::unique_ptr<JsServiceExtensionContext>(static_cast<JsServiceExtensionContext*>(data));
    }

    static napi_value StartAbility(napi_env env, napi_callback_info info)
    {
        GET_NAPI_INFO_AND_CALL(env, info, JsServiceExtensionContext, OnStartAbility);
    }

    static napi_value OpenLink(napi_env env, napi_callback_info info)
    {
        GET_NAPI_INFO_AND_CALL(env, info, JsServiceExtensionContext, OnOpenLink);
    }

    static napi_value StartAbilityAsCaller(napi_env env, napi_callback_info info)
    {
        GET_NAPI_INFO_AND_CALL(env, info, JsServiceExtensionContext, OnStartAbilityAsCaller);
    }

    static napi_value StartRecentAbility(napi_env env, napi_callback_info info)
    {
        GET_NAPI_INFO_AND_CALL(env, info, JsServiceExtensionContext, OnStartRecentAbility);
    }

    static napi_value StartAbilityByCall(napi_env env, napi_callback_info info)
    {
        GET_NAPI_INFO_AND_CALL(env, info, JsServiceExtensionContext, OnStartAbilityByCall);
    }

    static napi_value StartAbilityWithAccount(napi_env env, napi_callback_info info)
    {
        GET_NAPI_INFO_AND_CALL(env, info, JsServiceExtensionContext, OnStartAbilityWithAccount);
    }

    static napi_value StartUIAbilities(napi_env env, napi_callback_info info)
    {
        GET_NAPI_INFO_AND_CALL(env, info, JsServiceExtensionContext, OnStartUIAbilities);
    }

    static napi_value ConnectAbilityWithAccount(napi_env env, napi_callback_info info)
    {
        GET_NAPI_INFO_AND_CALL(env, info, JsServiceExtensionContext, OnConnectAbilityWithAccount);
    }

    static napi_value TerminateAbility(napi_env env, napi_callback_info info)
    {
        GET_NAPI_INFO_AND_CALL(env, info, JsServiceExtensionContext, OnTerminateAbility);
    }

    static napi_value ConnectAbility(napi_env env, napi_callback_info info)
    {
        GET_NAPI_INFO_AND_CALL(env, info, JsServiceExtensionContext, OnConnectAbility);
    }

    static napi_value DisconnectAbility(napi_env env, napi_callback_info info)
    {
        GET_NAPI_INFO_AND_CALL(env, info, JsServiceExtensionContext, OnDisconnectAbility);
    }

    static napi_value StartServiceExtensionAbility(napi_env env, napi_callback_info info)
    {
        GET_NAPI_INFO_AND_CALL(env, info, JsServiceExtensionContext, OnStartExtensionAbility);
    }

    static napi_value StartUIServiceExtensionAbility(napi_env env, napi_callback_info info)
    {
        GET_NAPI_INFO_AND_CALL(env, info, JsServiceExtensionContext, OnStartUIServiceExtension);
    }

    static napi_value StartServiceExtensionAbilityWithAccount(napi_env env, napi_callback_info info)
    {
        GET_NAPI_INFO_AND_CALL(env, info, JsServiceExtensionContext, OnStartExtensionAbilityWithAccount);
    }

    static napi_value StopServiceExtensionAbility(napi_env env, napi_callback_info info)
    {
        GET_NAPI_INFO_AND_CALL(env, info, JsServiceExtensionContext, OnStopExtensionAbility);
    }

    static napi_value StopServiceExtensionAbilityWithAccount(napi_env env, napi_callback_info info)
    {
        GET_NAPI_INFO_AND_CALL(env, info, JsServiceExtensionContext, OnStopExtensionAbilityWithAccount);
    }

    static napi_value RequestModalUIExtension(napi_env env, napi_callback_info info)
    {
        GET_NAPI_INFO_AND_CALL(env, info, JsServiceExtensionContext, OnRequestModalUIExtension);
    }

    static napi_value PreStartMission(napi_env env, napi_callback_info info)
    {
        GET_NAPI_INFO_AND_CALL(env, info, JsServiceExtensionContext, OnPreStartMission);
    }

    static napi_value OpenAtomicService(napi_env env, napi_callback_info info)
    {
        GET_NAPI_INFO_AND_CALL(env, info, JsServiceExtensionContext, OnOpenAtomicService);
    }

private:
    std::weak_ptr<ServiceExtensionContext> context_;
    sptr<JsFreeInstallObserver> freeInstallObserver_ = nullptr;
    static void ClearFailedCallConnection(
        const std::weak_ptr<ServiceExtensionContext>& serviceContext, const std::shared_ptr<CallerCallBack> &callback)
    {
        TAG_LOGD(AAFwkTag::SERVICE_EXT, "called");
        auto context = serviceContext.lock();
        if (context == nullptr || callback == nullptr) {
            TAG_LOGE(AAFwkTag::SERVICE_EXT, "null context or callback");
            return;
        }

        context->ClearFailedCallConnection(callback);
    }

    void AddFreeInstallObserver(napi_env env, const AAFwk::Want &want, napi_value callback,
        napi_value* result, bool isOpenLink = false)
    {
        // adapter free install async return install and start result
        int ret = 0;
        if (freeInstallObserver_ == nullptr) {
            freeInstallObserver_ = new JsFreeInstallObserver(env);
            auto context = context_.lock();
            if (!context) {
                TAG_LOGW(AAFwkTag::SERVICE_EXT, "context released");
                return;
            }
            ret = context->AddFreeInstallObserver(freeInstallObserver_);
        }

        if (ret != ERR_OK) {
            TAG_LOGE(AAFwkTag::SERVICE_EXT, "AddFreeInstallObserver failed");
            return;
        }
        std::string startTime = want.GetStringParam(Want::PARAM_RESV_START_TIME);
        // build a callback observer with last param
        if (!isOpenLink) {
            TAG_LOGI(AAFwkTag::SERVICE_EXT, "AddJsObserverObject");
            std::string bundleName = want.GetElement().GetBundleName();
            std::string abilityName = want.GetElement().GetAbilityName();
            freeInstallObserver_->AddJsObserverObject(
                bundleName, abilityName, startTime, callback, result);
            return;
        }
        std::string url = want.GetUriString();
        freeInstallObserver_->AddJsObserverObject(startTime, url, callback, result);
    }

    napi_value OnStartAbility(napi_env env, NapiCallbackInfo& info, bool isStartRecent = false)
    {
        HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
        TAG_LOGD(AAFwkTag::SERVICE_EXT, "StartAbility");

        size_t unwrapArgc = 0;
        AAFwk::Want want;
        AAFwk::StartOptions startOptions;
        if (!CheckStartAbilityInputParam(env, info, want, startOptions, unwrapArgc)) {
            return CreateJsUndefined(env);
        }

        if (isStartRecent) {
            TAG_LOGD(AAFwkTag::SERVICE_EXT, "OnStartRecentAbility is called");
            want.SetParam(Want::PARAM_RESV_START_RECENT, true);
        }

        if ((want.GetFlags() & Want::FLAG_INSTALL_ON_DEMAND) == Want::FLAG_INSTALL_ON_DEMAND) {
            std::string startTime = std::to_string(std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::
                system_clock::now().time_since_epoch()).count());
            want.SetParam(Want::PARAM_RESV_START_TIME, startTime);
        }

        auto innerErrorCode = std::make_shared<int>(ERR_OK);
        auto execute = GetStartAbilityExecFunc(want, startOptions, DEFAULT_INVAL_VALUE,
            unwrapArgc != 1, innerErrorCode);
        auto complete = GetSimpleCompleteFunc(innerErrorCode);

        napi_value lastParam = (info.argc == unwrapArgc) ? nullptr : info.argv[unwrapArgc];
        napi_value result = nullptr;
        if ((want.GetFlags() & Want::FLAG_INSTALL_ON_DEMAND) == Want::FLAG_INSTALL_ON_DEMAND) {
            AddFreeInstallObserver(env, want, lastParam, &result);
            NapiAsyncTask::ScheduleHighQos("JSServiceExtensionContext::OnStartAbility", env,
                CreateAsyncTaskWithLastParam(env, nullptr, std::move(execute), nullptr, nullptr));
        } else {
            NapiAsyncTask::ScheduleHighQos("JSServiceExtensionContext::OnStartAbility", env,
                CreateAsyncTaskWithLastParam(env, lastParam, std::move(execute), std::move(complete), &result));
        }
        return result;
    }

    bool CheckUrl(std::string &urlValue)
    {
        if (urlValue.empty()) {
            return false;
        }
        Uri uri = Uri(urlValue);
        if (uri.GetScheme().empty() || uri.GetHost().empty()) {
            return false;
        }

        return true;
    }

    bool ParseOpenLinkParams(const napi_env &env, const NapiCallbackInfo &info, std::string &linkValue,
        AAFwk::OpenLinkOptions &openLinkOptions, AAFwk::Want &want)
    {
        if (info.argc != ARGC_TWO) {
            TAG_LOGE(AAFwkTag::SERVICE_EXT, "wrong argc");
            ThrowTooFewParametersError(env);
            return false;
        }

        if (!CheckTypeForNapiValue(env, info.argv[ARGC_ZERO], napi_string)) {
            TAG_LOGE(AAFwkTag::SERVICE_EXT, "link must be string");
            ThrowInvalidParamError(env, "Parse param link failed, must be a string.");
            return false;
        }
        if (!ConvertFromJsValue(env, info.argv[ARGC_ZERO], linkValue) || !CheckUrl(linkValue)) {
            TAG_LOGE(AAFwkTag::SERVICE_EXT, "param link invalid");
            ThrowInvalidParamError(env, "link parameter invalid.");
            return false;
        }

        if (CheckTypeForNapiValue(env, info.argv[INDEX_ONE], napi_object)) {
            TAG_LOGD(AAFwkTag::SERVICE_EXT, "OpenLinkOptions used");
            if (!AppExecFwk::UnwrapOpenLinkOptions(env, info.argv[INDEX_ONE], openLinkOptions, want)) {
                TAG_LOGE(AAFwkTag::SERVICE_EXT, "OpenLinkOptions parse failed");
                ThrowInvalidParamError(env, "Parse param options failed, must be a OpenLinkOptions.");
                return false;
            }
        }

        return true;
    }

    napi_value OnOpenLink(napi_env env, NapiCallbackInfo& info)
    {
        HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
        TAG_LOGD(AAFwkTag::SERVICE_EXT, "OnOpenLink");

        std::string linkValue("");
        AAFwk::OpenLinkOptions openLinkOptions;
        AAFwk::Want want;
        want.SetParam(AppExecFwk::APP_LINKING_ONLY, false);

        if (!ParseOpenLinkParams(env, info, linkValue, openLinkOptions, want)) {
            TAG_LOGE(AAFwkTag::SERVICE_EXT, "parse OpenLinkParams failed");
            ThrowInvalidParamError(env,
                "Parse param link or openLinkOptions failed, link must be string, openLinkOptions must be options.");
            return CreateJsUndefined(env);
        }

        want.SetUri(linkValue);
        std::string startTime = std::to_string(std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::
            system_clock::now().time_since_epoch()).count());
        want.SetParam(Want::PARAM_RESV_START_TIME, startTime);

        return OnOpenLinkInner(env, want, startTime, linkValue);
    }

    napi_value OnOpenLinkInner(napi_env env, const AAFwk::Want& want,
        const std::string& startTime, const std::string& url)
    {
        auto innerErrorCode = std::make_shared<int>(ERR_OK);
        NapiAsyncTask::ExecuteCallback execute = [weak = context_, want, innerErrorCode]() {
            auto context = weak.lock();
            if (!context) {
                TAG_LOGW(AAFwkTag::SERVICE_EXT, "context released");
                *innerErrorCode = static_cast<int>(AbilityErrorCode::ERROR_CODE_INVALID_CONTEXT);
                return;
            }
            *innerErrorCode = context->OpenLink(want, -1);
        };

        NapiAsyncTask::CompleteCallback complete = [innerErrorCode, startTime, url,
            freeInstallObserver = freeInstallObserver_](
            napi_env env, NapiAsyncTask& task, int32_t status) {
            if (*innerErrorCode == 0) {
                TAG_LOGI(AAFwkTag::SERVICE_EXT, "OpenLink success");
                return;
            }
            if (freeInstallObserver == nullptr) {
                TAG_LOGE(AAFwkTag::SERVICE_EXT, "null freeInstallObserver_");
                return;
            }
            if (*innerErrorCode == AAFwk::ERR_OPEN_LINK_START_ABILITY_DEFAULT_OK) {
                TAG_LOGI(AAFwkTag::SERVICE_EXT, "start ability by default succeeded");
                freeInstallObserver->OnInstallFinishedByUrl(startTime, url, ERR_OK);
                return;
            }
            TAG_LOGI(AAFwkTag::SERVICE_EXT, "OpenLink failed");
            freeInstallObserver->OnInstallFinishedByUrl(startTime, url, *innerErrorCode);
        };

        napi_value result = nullptr;
        AddFreeInstallObserver(env, want, nullptr, &result, true);
        NapiAsyncTask::ScheduleHighQos("JSServiceExtensionContext::OnOpenLink", env,
            CreateAsyncTaskWithLastParam(env, nullptr, std::move(execute), std::move(complete), nullptr));
        
        return result;
    }

    void UnwrapCompletionHandlerInStartOptions(napi_env env, napi_value param,
        AAFwk::StartOptions &options)
    {
        napi_value completionHandler = AppExecFwk::GetPropertyValueByPropertyName(env, param,
            "completionHandler", napi_object);
        if (completionHandler == nullptr) {
            TAG_LOGD(AAFwkTag::SERVICE_EXT, "null completionHandler");
            return;
        }
        TAG_LOGI(AAFwkTag::SERVICE_EXT, "completionHandler exists");
        napi_value onRequestSuccObj = AppExecFwk::GetPropertyValueByPropertyName(env, completionHandler,
            "onRequestSuccess", napi_function);
        napi_value onRequestFailObj = AppExecFwk::GetPropertyValueByPropertyName(env, completionHandler,
            "onRequestFailure", napi_function);
        if (onRequestSuccObj == nullptr || onRequestFailObj == nullptr) {
            TAG_LOGE(AAFwkTag::SERVICE_EXT, "null onRequestSuccObj or onRequestFailObj");
            return;
        }
        OnRequestResult onRequestSucc = [env, completionHandler, onRequestSuccObj](
            const AppExecFwk::ElementName &element, const std::string &message) {
            size_t argc = ARGC_TWO;
            napi_value argv[ARGC_TWO] = { AppExecFwk::WrapElementName(env, element), CreateJsValue(env, message) };
            napi_status status = napi_call_function(env, completionHandler, onRequestSuccObj, argc, argv, nullptr);
            if (status != napi_ok) {
                TAG_LOGE(AAFwkTag::SERVICE_EXT, "call onRequestSuccess, failed: %{public}d", status);
            }
        };
        OnRequestResult onRequestFail = [env, completionHandler, onRequestFailObj](
            const AppExecFwk::ElementName &element, const std::string &message) {
            size_t argc = ARGC_TWO;
            napi_value argv[ARGC_TWO] = { AppExecFwk::WrapElementName(env, element), CreateJsValue(env, message) };
            napi_status status = napi_call_function(env, completionHandler, onRequestFailObj, argc, argv, nullptr);
            if (status != napi_ok) {
                TAG_LOGE(AAFwkTag::SERVICE_EXT, "call onRequestFailure, failed: %{public}d", status);
            }
        };
        auto context = context_.lock();
        if (!context) {
            TAG_LOGE(AAFwkTag::SERVICE_EXT, "null context");
            return;
        }
        auto time = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(
            std::chrono::high_resolution_clock::now().time_since_epoch()).count());
        std::string requestId = std::to_string(time);
        if (context->AddCompletionHandler(requestId, onRequestSucc, onRequestFail) != ERR_OK) {
            TAG_LOGE(AAFwkTag::SERVICE_EXT, "add completionHandler failed");
            return;
        }
        options.requestId_ = requestId;
    }

    napi_value OnOpenAtomicService(napi_env env, NapiCallbackInfo &info)
    {
        TAG_LOGD(AAFwkTag::SERVICE_EXT, "OpenAtomicService");
        if (info.argc == ARGC_ZERO) {
            ThrowTooFewParametersError(env);
            return CreateJsUndefined(env);
        }

        std::string appId;
        if (!ConvertFromJsValue(env, info.argv[INDEX_ZERO], appId)) {
            TAG_LOGE(AAFwkTag::SERVICE_EXT, "parse appId failed");
            ThrowInvalidParamError(env, "Parse param appId failed, appId must be string.");
            return CreateJsUndefined(env);
        }

        AAFwk::Want want;
        AAFwk::StartOptions startOptions;
        if (info.argc > ARGC_ONE && CheckTypeForNapiValue(env, info.argv[INDEX_ONE], napi_object)) {
            TAG_LOGD(AAFwkTag::SERVICE_EXT, "atomic service options is used");
            if (!AppExecFwk::UnwrapStartOptionsAndWant(env, info.argv[INDEX_ONE], startOptions, want)) {
                TAG_LOGE(AAFwkTag::SERVICE_EXT, "invalid atomic service options");
                ThrowInvalidParamError(env, "Parse param startOptions failed, startOptions must be StartOption.");
                return CreateJsUndefined(env);
            }
            UnwrapCompletionHandlerInStartOptions(env, info.argv[INDEX_ONE], startOptions);
        }

        std::string bundleName = ATOMIC_SERVICE_PREFIX + appId;
        TAG_LOGD(AAFwkTag::SERVICE_EXT, "bundleName: %{public}s", bundleName.c_str());
        want.SetBundle(bundleName);
        want.AddFlags(Want::FLAG_INSTALL_ON_DEMAND);
        std::string startTime = std::to_string(std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count());
        want.SetParam(Want::PARAM_RESV_START_TIME, startTime);
        return OpenAtomicServiceInner(env, want, startOptions, startTime);
    }

    napi_value OpenAtomicServiceInner(napi_env env, const AAFwk::Want &want, const AAFwk::StartOptions &options,
        std::string startTime)
    {
        auto innerErrorCode = std::make_shared<int>(ERR_OK);
        NapiAsyncTask::ExecuteCallback execute = [weak = context_, want, options, innerErrorCode]() {
            auto context = weak.lock();
            if (!context) {
                TAG_LOGW(AAFwkTag::SERVICE_EXT, "context released");
                *innerErrorCode = static_cast<int>(AbilityErrorCode::ERROR_CODE_INVALID_CONTEXT);
                return;
            }
            *innerErrorCode = context->OpenAtomicService(want, options);
        };
        NapiAsyncTask::CompleteCallback complete = [innerErrorCode, startTime, want, observer = freeInstallObserver_,
            weak = context_, options](
            napi_env env, NapiAsyncTask &task, int32_t status) {
            if (*innerErrorCode == 0) {
                TAG_LOGI(AAFwkTag::SERVICE_EXT, "OpenAtomicService success");
                return;
            }
            TAG_LOGI(AAFwkTag::SERVICE_EXT, "OpenAtomicService failed");
            if (observer != nullptr) {
                std::string bundleName = want.GetElement().GetBundleName();
                std::string abilityName = want.GetElement().GetAbilityName();
                observer->OnInstallFinished(bundleName, abilityName, startTime, *innerErrorCode);
            }
            auto context = weak.lock();
            if (context == nullptr) {
                TAG_LOGW(AAFwkTag::SERVICE_EXT, "null context");
                return;
            }
            if (!options.requestId_.empty()) {
                nlohmann::json jsonObject = nlohmann::json {
                    { JSON_KEY_ERR_MSG, "failed to call openAtomicService" }
                };
                context->OnRequestFailure(options.requestId_, want.GetElement(), jsonObject.dump());
            }
        };
        napi_value result = nullptr;
        AddFreeInstallObserver(env, want, nullptr, &result);
        NapiAsyncTask::ScheduleHighQos("JSServiceExtensionContext::OnOpenAtomicService", env,
            CreateAsyncTaskWithLastParam(env, nullptr, std::move(execute), std::move(complete), nullptr));
        return result;
    }

    napi_value OnStartRecentAbility(napi_env env, NapiCallbackInfo& info, bool isStartRecent = false)
    {
        return OnStartAbility(env, info, true);
    }

    napi_value OnStartAbilityAsCaller(napi_env env, NapiCallbackInfo& info)
    {
        HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
        TAG_LOGI(AAFwkTag::SERVICE_EXT, "StartAbilityAsCaller");

        size_t unwrapArgc = 0;
        AAFwk::Want want;
        AAFwk::StartOptions startOptions;
        if (!CheckStartAbilityInputParam(env, info, want, startOptions, unwrapArgc)) {
            return CreateJsUndefined(env);
        }
        auto innerErrCode = std::make_shared<ErrCode>(ERR_OK);
        NapiAsyncTask::ExecuteCallback execute = [weak = context_, want, startOptions, unwrapArgc, innerErrCode]() {
            TAG_LOGD(AAFwkTag::SERVICE_EXT, "startAbility begin");
            auto context = weak.lock();
            if (!context) {
                TAG_LOGW(AAFwkTag::SERVICE_EXT, "context released");
                *innerErrCode = static_cast<int32_t>(AbilityErrorCode::ERROR_CODE_INVALID_CONTEXT);
                return;
            }
            *innerErrCode =(unwrapArgc == 1) ? context->StartAbilityAsCaller(want) :
                context->StartAbilityAsCaller(want, startOptions);
        };
        NapiAsyncTask::CompleteCallback complete =
            [innerErrCode](napi_env env, NapiAsyncTask& task, int32_t status) {
                if (*innerErrCode == ERR_OK) {
                    task.Resolve(env, CreateJsUndefined(env));
                } else if (*innerErrCode == static_cast<int32_t>(AbilityErrorCode::ERROR_CODE_INVALID_CONTEXT)) {
                    task.Reject(env, CreateJsError(env, AbilityErrorCode::ERROR_CODE_INVALID_CONTEXT));
                } else {
                    task.Reject(env, CreateJsErrorByNativeErr(env, *innerErrCode));
                }
            };

        napi_value lastParam = (info.argc == unwrapArgc) ? nullptr : info.argv[unwrapArgc];
        napi_value result = nullptr;
        NapiAsyncTask::ScheduleHighQos("JSServiceExtensionContext::OnStartAbilityAsCaller",
            env, CreateAsyncTaskWithLastParam(env, lastParam, std::move(execute), std::move(complete), &result));
        return result;
    }

    bool CheckStartAbilityInputParam(napi_env env, NapiCallbackInfo& info,
        AAFwk::Want& want, AAFwk::StartOptions& startOptions, size_t& unwrapArgc) const
    {
        if (info.argc < ARGC_ONE) {
            TAG_LOGE(AAFwkTag::SERVICE_EXT, "invalid argc");
            ThrowTooFewParametersError(env);
            return false;
        }
        unwrapArgc = ARGC_ZERO;
        // Check input want
        if (!AppExecFwk::UnwrapWant(env, info.argv[INDEX_ZERO], want)) {
            ThrowInvalidParamError(env, "Parse param want failed, must be a Want.");
            return false;
        }
        ++unwrapArgc;
        if (info.argc > ARGC_ONE && CheckTypeForNapiValue(env, info.argv[1], napi_object)) {
            TAG_LOGD(AAFwkTag::SERVICE_EXT, "OnStartAbility start options used");
            AppExecFwk::UnwrapStartOptions(env, info.argv[1], startOptions);
            unwrapArgc++;
        }
        return true;
    }

    napi_value OnStartAbilityByCall(napi_env env, NapiCallbackInfo& info)
    {
        TAG_LOGI(AAFwkTag::SERVICE_EXT, "StartAbilityByCall");
        AAFwk::Want want;
        int32_t accountId = DEFAULT_INVAL_VALUE;
        if (!CheckStartAbilityByCallInputParam(env, info, want, accountId)) {
            return CreateJsUndefined(env);
        }

        std::shared_ptr<StartAbilityByCallParameters> calls = std::make_shared<StartAbilityByCallParameters>();
        napi_value retsult = nullptr;
        calls->callerCallBack = std::make_shared<CallerCallBack>();
        calls->callerCallBack->SetCallBack(GetCallBackDone(calls));
        calls->callerCallBack->SetOnRelease(GetReleaseListen());

        auto context = context_.lock();
        if (context == nullptr) {
            TAG_LOGE(AAFwkTag::SERVICE_EXT, "null context");
            ThrowError(env, AbilityErrorCode::ERROR_CODE_INNER);
            return CreateJsUndefined(env);
        }

        auto ret = context->StartAbilityByCall(want, calls->callerCallBack, accountId);
        if (ret) {
            TAG_LOGE(AAFwkTag::SERVICE_EXT, "OnStartAbilityByCall failed");
            ThrowErrorByNativeErr(env, ret);
            return CreateJsUndefined(env);
        }

        if (calls->remoteCallee == nullptr) {
            TAG_LOGD(AAFwkTag::SERVICE_EXT, "async wait execute");
            NapiAsyncTask::ScheduleHighQos("JsAbilityContext::OnStartAbilityByCall", env,
                CreateAsyncTaskWithLastParam(
                    env, nullptr, GetCallExecute(calls), GetCallComplete(calls), &retsult));
        } else {
            NapiAsyncTask::ScheduleHighQos("JSServiceExtensionContext::OnStartAbilityByCall", env,
                CreateAsyncTaskWithLastParam(env, nullptr, nullptr, GetCallComplete(calls), &retsult));
        }
        return retsult;
    }

    bool CheckStartAbilityByCallInputParam(
        napi_env env, NapiCallbackInfo& info, AAFwk::Want& want, int32_t& accountId)
    {
        if (info.argc < ARGC_ONE) {
            TAG_LOGE(AAFwkTag::SERVICE_EXT, "invalid argc");
            ThrowTooFewParametersError(env);
            return false;
        }

        if (!AppExecFwk::UnwrapWant(env, info.argv[INDEX_ZERO], want)) {
            ThrowInvalidParamError(env, "Parse param want failed, must be a Want.");
            return false;
        }

        if (info.argc > ARGC_ONE) {
            if (CheckTypeForNapiValue(env, info.argv[INDEX_ONE], napi_number)) {
                if (!ConvertFromJsValue(env, info.argv[1], accountId)) {
                    TAG_LOGE(AAFwkTag::SERVICE_EXT, "check param accountId failed");
                    ThrowInvalidParamError(env, "Parse param accountId failed, must be a number.");
                    return false;
                }
            } else {
                TAG_LOGE(AAFwkTag::SERVICE_EXT, "param type invalid");
                ThrowInvalidParamError(env, "Parse param accountId failed, must be a number.");
                return false;
            }
        }

        TAG_LOGI(AAFwkTag::SERVICE_EXT, "callee:%{public}s.%{public}s.",
            want.GetBundle().c_str(),
            want.GetElement().GetAbilityName().c_str());
        return true;
    }

    NapiAsyncTask::CompleteCallback GetCallComplete(std::shared_ptr<StartAbilityByCallParameters> calls)
    {
        auto callComplete = [weak = context_, calldata = calls] (
            napi_env env, NapiAsyncTask& task, int32_t) {
            if (calldata->err != 0) {
                TAG_LOGE(AAFwkTag::SERVICE_EXT, "callComplete err: %{public}d", calldata->err);
                ClearFailedCallConnection(weak, calldata->callerCallBack);
                task.Reject(env, CreateJsError(env, calldata->err, "callComplete err."));
                return;
            }

            auto context = weak.lock();
            if (context != nullptr && calldata->callerCallBack != nullptr && calldata->remoteCallee != nullptr) {
                auto releaseCallFunc = [weak] (
                    const std::shared_ptr<CallerCallBack> &callback) -> ErrCode {
                    auto contextForRelease = weak.lock();
                    if (contextForRelease == nullptr) {
                        TAG_LOGE(AAFwkTag::SERVICE_EXT, "null contextForRelease");
                        return -1;
                    }
                    return contextForRelease->ReleaseCall(callback);
                };
                task.Resolve(env,
                    CreateJsCallerComplex(
                        env, releaseCallFunc, calldata->remoteCallee, calldata->callerCallBack));
            } else {
                TAG_LOGE(AAFwkTag::SERVICE_EXT, "null %{public}s",
                    context == nullptr ? "context" :
                        (calldata->remoteCallee == nullptr ? "remoteCallee" : "callerCallBack"));
                task.Reject(env, CreateJsError(env, -1, "Create Call Failed."));
            }

            TAG_LOGD(AAFwkTag::SERVICE_EXT, "end");
        };
        return callComplete;
    }

    NapiAsyncTask::ExecuteCallback GetCallExecute(std::shared_ptr<StartAbilityByCallParameters> calls)
    {
        auto callExecute = [calldata = calls] () {
            constexpr int callerTimeOut = 10; // 10s
            std::unique_lock<std::mutex> lock(calldata->mutexlock);
            if (calldata->remoteCallee != nullptr) {
                TAG_LOGI(AAFwkTag::SERVICE_EXT, "callee not null");
                return;
            }

            if (calldata->condition.wait_for(lock, std::chrono::seconds(callerTimeOut)) == std::cv_status::timeout) {
                TAG_LOGE(AAFwkTag::SERVICE_EXT, "waiting callee timeout");
                calldata->err = -1;
            }
            TAG_LOGD(AAFwkTag::SERVICE_EXT, "exit");
        };
        return callExecute;
    }

    CallerCallBack::CallBackClosure GetCallBackDone(std::shared_ptr<StartAbilityByCallParameters> calls)
    {
        auto callBackDone = [calldata = calls] (const sptr<IRemoteObject> &obj) {
            TAG_LOGD(AAFwkTag::SERVICE_EXT, "mutexlock");
            std::unique_lock<std::mutex> lock(calldata->mutexlock);
            TAG_LOGD(AAFwkTag::SERVICE_EXT, "remoteCallee assignment");
            calldata->remoteCallee = obj;
            calldata->condition.notify_all();
            TAG_LOGI(AAFwkTag::SERVICE_EXT, "end");
        };
        return callBackDone;
    }

    CallerCallBack::OnReleaseClosure GetReleaseListen()
    {
        auto releaseListen = [](const std::string &str) {
            TAG_LOGD(AAFwkTag::SERVICE_EXT, "called, %{public}s", str.c_str());
        };
        return releaseListen;
    }

    napi_value OnStartAbilityWithAccount(napi_env env, NapiCallbackInfo& info)
    {
        HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
        TAG_LOGI(AAFwkTag::SERVICE_EXT, "StartAbilityWithAccount");

        size_t unwrapArgc = 0;
        AAFwk::Want want;
        int32_t accountId = 0;
        if (!CheckStartAbilityWithAccountInputParam(env, info, want, accountId, unwrapArgc)) {
            return CreateJsUndefined(env);
        }

        AAFwk::StartOptions startOptions;
        if (info.argc > ARGC_TWO && CheckTypeForNapiValue(env, info.argv[INDEX_TWO], napi_object)) {
            TAG_LOGD(AAFwkTag::SERVICE_EXT, "start options used");
            AppExecFwk::UnwrapStartOptions(env, info.argv[INDEX_TWO], startOptions);
            unwrapArgc++;
        }

        if ((want.GetFlags() & Want::FLAG_INSTALL_ON_DEMAND) == Want::FLAG_INSTALL_ON_DEMAND) {
            std::string startTime = std::to_string(std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::
                system_clock::now().time_since_epoch()).count());
            want.SetParam(Want::PARAM_RESV_START_TIME, startTime);
        }
        auto innerErrorCode = std::make_shared<int>(ERR_OK);
        auto execute = GetStartAbilityExecFunc(want, startOptions, accountId, unwrapArgc != ARGC_TWO, innerErrorCode);
        auto complete = GetSimpleCompleteFunc(innerErrorCode);

        napi_value lastParam = (info.argc == unwrapArgc) ? nullptr : info.argv[unwrapArgc];
        napi_value result = nullptr;
        if ((want.GetFlags() & Want::FLAG_INSTALL_ON_DEMAND) == Want::FLAG_INSTALL_ON_DEMAND) {
            AddFreeInstallObserver(env, want, lastParam, &result);
            NapiAsyncTask::ScheduleHighQos("JSServiceExtensionContext::OnStartAbilityWithAccount", env,
                CreateAsyncTaskWithLastParam(env, nullptr, std::move(execute), nullptr, nullptr));
        } else {
            NapiAsyncTask::ScheduleHighQos("JSServiceExtensionContext::OnStartAbilityWithAccount", env,
                CreateAsyncTaskWithLastParam(env, lastParam, std::move(execute), std::move(complete), &result));
        }
        return result;
    }

    bool CheckStartAbilityWithAccountInputParam(
        napi_env env, NapiCallbackInfo& info,
        AAFwk::Want& want, int32_t& accountId, size_t& unwrapArgc) const
    {
        if (info.argc < ARGC_TWO) {
            TAG_LOGE(AAFwkTag::SERVICE_EXT, "invalid argc");
            ThrowTooFewParametersError(env);
            return false;
        }
        unwrapArgc = ARGC_ZERO;
        // Check input want
        if (!AppExecFwk::UnwrapWant(env, info.argv[INDEX_ZERO], want)) {
            ThrowInvalidParamError(env, "Parse param want failed, must be a Want.");
            return false;
        }
        ++unwrapArgc;
        if (!AppExecFwk::UnwrapInt32FromJS2(env, info.argv[INDEX_ONE], accountId)) {
            ThrowInvalidParamError(env, "Parse param accountId failed, must be a number.");
            return false;
        }
        ++unwrapArgc;
        return true;
    }

    napi_value OnStartUIAbilities(napi_env env, NapiCallbackInfo& info)
    {
        TAG_LOGI(AAFwkTag::SERVICE_EXT, "call OnStartUIAbilities");
        if (info.argc < ARGC_ONE) {
            TAG_LOGE(AAFwkTag::SERVICE_EXT, "Too few parameters.");
            ThrowTooFewParametersError(env);
            return CreateJsUndefined(env);
        }
    
        std::vector<AAFwk::Want> wantList;
        std::string requestKey = std::to_string(std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::
            system_clock::now().time_since_epoch()).count());
    
        if (!UnwrapWantList(env, info, wantList)) {
            TAG_LOGE(AAFwkTag::SERVICE_EXT, "Unwrap wantList param failed.");
            return CreateJsUndefined(env);
        }
        
        TAG_LOGD(AAFwkTag::SERVICE_EXT, "startUIAbilities wantListLength: %{public}zu", wantList.size());
    
        JsDeferredCallback callback(env);
        JsStartAbilitiesObserver::GetInstance().AddObserver(requestKey, callback);
        auto innerErrCode = std::make_shared<ErrCode>(ERR_OK);
        NapiAsyncTask::ExecuteCallback execute = [weak = context_, wantList, requestKey, innerErrCode]() {
            auto context = weak.lock();
            if (!context) {
                TAG_LOGW(AAFwkTag::SERVICE_EXT, "null context");
                *innerErrCode = static_cast<int>(AbilityErrorCode::ERROR_CODE_INVALID_CONTEXT);
                return;
            }
            *innerErrCode = context->StartUIAbilities(wantList, requestKey);
        };
    
        NapiAsyncTask::CompleteCallback complete = [innerErrCode, weak = context_, requestKey]
            (napi_env, NapiAsyncTask&, int32_t) {
                TAG_LOGI(AAFwkTag::SERVICE_EXT, "startUIAbilities complete innerErrCode: %{public}d", *innerErrCode);
                if (*innerErrCode == AAFwk::START_UI_ABILITIES_WAITING_SPECIFIED_CODE)  {
                    TAG_LOGI(AAFwkTag::SERVICE_EXT, "startUIAbilities waiting specified.");
                    return;
                }
                JsStartAbilitiesObserver::GetInstance().HandleFinished(requestKey, *innerErrCode);
        };
    
        NapiAsyncTask::ScheduleHighQos("JSServiceExtensionContext::OnStartUIAbilities", env,
            CreateAsyncTaskWithLastParam(env, nullptr, std::move(execute), std::move(complete), nullptr));
        return callback.result;
    }
    
    bool UnwrapWantList(napi_env env, NapiCallbackInfo &info, std::vector<AAFwk::Want> &wantList)
    {
        AppExecFwk::ComplexArrayData jsWantList;
        if (!AppExecFwk::UnwrapArrayComplexFromJS(env, info.argv[INDEX_ZERO], jsWantList)) {
            TAG_LOGE(AAFwkTag::SERVICE_EXT, "wantList not array.");
            ThrowInvalidParamError(env, "WantList is not an array.");
            return false;
        }
    
        size_t jsWantSize = jsWantList.objectList.size();
        if (jsWantSize < INDEX_ONE || jsWantSize > INDEX_FOUR) {
            TAG_LOGE(AAFwkTag::SERVICE_EXT, "wantList size not support");
            ThrowErrorByNativeErr(env, AAFwk::START_UI_ABILITIES_WANT_LIST_SIZE_ERROR);
            return false;
        }
    
        for (uint32_t index = 0; index < jsWantSize; index++) {
            AAFwk::Want curWant;
            if (!OHOS::AppExecFwk::UnwrapWant(env, jsWantList.objectList[index], curWant)) {
                TAG_LOGE(AAFwkTag::SERVICE_EXT, "startUIAbilities parse want failed");
                ThrowInvalidParamError(env, "Parse param want failed, want must be Want.");
                return false;
            }
            TAG_LOGD(AAFwkTag::SERVICE_EXT, "startUIAbilities ability:%{public}s",
                curWant.GetElement().GetAbilityName().c_str());
            wantList.emplace_back(curWant);
        }
        return true;
    }

    bool CheckConnectAbilityWithAccountInputParam(
        napi_env env, NapiCallbackInfo& info,
        AAFwk::Want& want, int32_t& accountId, sptr<JSServiceExtensionConnection>& connection) const
    {
        if (info.argc < ARGC_THREE) {
            TAG_LOGE(AAFwkTag::SERVICE_EXT, "invalid argc");
            ThrowTooFewParametersError(env);
            return false;
        }
        // Check input want
        if (!AppExecFwk::UnwrapWant(env, info.argv[INDEX_ZERO], want)) {
            ThrowInvalidParamError(env, "Parse param want failed, must be a Want.");
            return false;
        }
        if (!AppExecFwk::UnwrapInt32FromJS2(env, info.argv[INDEX_ONE], accountId)) {
            ThrowInvalidParamError(env, "Parse param accountId failed, must be a number.");
            return false;
        }
        if (!CheckConnectionParam(env, info.argv[INDEX_TWO], connection, want, accountId)) {
            ThrowInvalidParamError(env, "Parse param options failed, must be a ConnectOptions.");
            return false;
        }
        return true;
    }

    napi_value OnTerminateAbility(napi_env env, NapiCallbackInfo& info)
    {
        HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
        TAG_LOGI(AAFwkTag::SERVICE_EXT, "TerminateAbility");
        auto innerErrCode = std::make_shared<ErrCode>(ERR_OK);
        NapiAsyncTask::ExecuteCallback execute = [weak = context_, innerErrCode]() {
            auto context = weak.lock();
            if (!context) {
                TAG_LOGW(AAFwkTag::SERVICE_EXT, "context released");
                *innerErrCode = static_cast<int32_t>(ERROR_CODE_ONE);
                return;
            }
            *innerErrCode = context->TerminateAbility();
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
        NapiAsyncTask::ScheduleHighQos("JSServiceExtensionContext::OnTerminateAbility",
            env, CreateAsyncTaskWithLastParam(env, lastParam, std::move(execute), std::move(complete), &result));
        return result;
    }

    napi_value OnConnectAbility(napi_env env, NapiCallbackInfo& info)
    {
        HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
        TAG_LOGD(AAFwkTag::SERVICE_EXT, "called");
        // Check params count
        if (info.argc < ARGC_TWO) {
            TAG_LOGE(AAFwkTag::SERVICE_EXT, "invalid argc");
            ThrowTooFewParametersError(env);
            return CreateJsUndefined(env);
        }
        // Unwrap want and connection
        AAFwk::Want want;
        sptr<JSServiceExtensionConnection> connection = new JSServiceExtensionConnection(env);
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
                TAG_LOGI(AAFwkTag::SERVICE_EXT, "Connect ability success");
                task.ResolveWithNoError(env, CreateJsUndefined(env));
                return;
            }

            TAG_LOGE(AAFwkTag::SERVICE_EXT, "Connect ability failed");
            int32_t errcode = static_cast<int32_t>(AbilityRuntime::GetJsErrorCodeByNativeError(*innerErrorCode));
            if (errcode) {
                connection->CallJsFailed(errcode);
                RemoveConnection(connectId);
            }
        };
        napi_value result = nullptr;
        NapiAsyncTask::ScheduleHighQos("JSServiceExtensionConnection::OnConnectAbility",
            env, CreateAsyncTaskWithLastParam(env, nullptr, std::move(execute), std::move(complete), &result));
        return CreateJsValue(env, connectId);
    }

    napi_value OnConnectAbilityWithAccount(napi_env env, NapiCallbackInfo& info)
    {
        HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
        TAG_LOGI(AAFwkTag::SERVICE_EXT, "ConnectAbilityWithAccount");
        // Unwrap want, accountId and connection
        AAFwk::Want want;
        int32_t accountId = 0;
        sptr<JSServiceExtensionConnection> connection = new JSServiceExtensionConnection(env);
        if (!CheckConnectAbilityWithAccountInputParam(env, info, want, accountId, connection)) {
            return CreateJsUndefined(env);
        }
        int64_t connectId = connection->GetConnectionId();
        auto innerErrCode = std::make_shared<ErrCode>(ERR_OK);
        NapiAsyncTask::ExecuteCallback execute = [weak = context_,
            want, accountId, connection, connectId, innerErrCode]() {
            auto context = weak.lock();
            if (!context) {
                TAG_LOGE(AAFwkTag::SERVICE_EXT, "context released");
                *innerErrCode = static_cast<int>(ERROR_CODE_ONE);
                return;
            }
            TAG_LOGD(AAFwkTag::SERVICE_EXT, "connection:%{public}d", static_cast<int32_t>(connectId));
            *innerErrCode = context->ConnectAbilityWithAccount(want, accountId, connection);
        };
        NapiAsyncTask::CompleteCallback complete =
            [connection, connectId, innerErrCode](napi_env env, NapiAsyncTask& task, int32_t status) {
                if (*innerErrCode == ERROR_CODE_ONE) {
                    task.Reject(env, CreateJsErrorByNativeErr(env, *innerErrCode, "Context is released"));
                    RemoveConnection(connectId);
                } else {
                    int32_t errcode = static_cast<int32_t>(AbilityRuntime::GetJsErrorCodeByNativeError(*innerErrCode));
                    if (errcode) {
                        connection->CallJsFailed(errcode);
                        RemoveConnection(connectId);
                    }
                    task.Resolve(env, CreateJsUndefined(env));
                }
            };
        napi_value result = nullptr;
        NapiAsyncTask::ScheduleHighQos("JSServiceExtensionConnection::OnConnectAbilityWithAccount",
            env, CreateAsyncTaskWithLastParam(env, nullptr, nullptr, std::move(complete), &result));
        return CreateJsValue(env, connectId);
    }

    bool CheckConnectionParam(napi_env env, napi_value value,
        sptr<JSServiceExtensionConnection>& connection, AAFwk::Want& want, int32_t accountId = -1) const
    {
        if (!CheckTypeForNapiValue(env, value, napi_object)) {
            TAG_LOGE(AAFwkTag::SERVICE_EXT, "get connection obj failed");
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
        TAG_LOGD(AAFwkTag::SERVICE_EXT, "Unable to find connection, make new one");
        return true;
    }

    napi_value OnDisconnectAbility(napi_env env, NapiCallbackInfo& info)
    {
        HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
        TAG_LOGD(AAFwkTag::SERVICE_EXT, "called");
        if (info.argc < ARGC_ONE) {
            TAG_LOGE(AAFwkTag::SERVICE_EXT, "invalid argc");
            ThrowTooFewParametersError(env);
            return CreateJsUndefined(env);
        }
        int64_t connectId = -1;
        if (!AppExecFwk::UnwrapInt64FromJS2(env, info.argv[INDEX_ZERO], connectId)) {
            ThrowInvalidParamError(env, "Parse param connection failed, must be a number.");
            return CreateJsUndefined(env);
        }
        AAFwk::Want want;
        sptr<JSServiceExtensionConnection> connection = nullptr;
        int32_t accountId = -1;
        FindConnection(want, connection, connectId, accountId);
        // begin disconnect
        auto innerErrCode = std::make_shared<ErrCode>(ERR_OK);
        NapiAsyncTask::ExecuteCallback execute = [weak = context_, want, connection, accountId, innerErrCode]() {
            auto context = weak.lock();
            if (!context) {
                TAG_LOGW(AAFwkTag::SERVICE_EXT, "context released");
                *innerErrCode = static_cast<int32_t>(ERROR_CODE_ONE);
                return;
            }
            if (!connection) {
                TAG_LOGW(AAFwkTag::SERVICE_EXT, "null connection");
                *innerErrCode = static_cast<int32_t>(ERROR_CODE_TWO);
                return;
            }
            TAG_LOGD(AAFwkTag::SERVICE_EXT, "context->DisconnectAbility");
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
        NapiAsyncTask::Schedule("JSServiceExtensionConnection::OnDisconnectAbility",
            env, CreateAsyncTaskWithLastParam(env, lastParam, std::move(execute), std::move(complete), &result));
        return result;
    }

    void FindConnection(AAFwk::Want& want, sptr<JSServiceExtensionConnection>& connection, int64_t& connectId,
        int32_t &accountId) const
    {
        TAG_LOGI(AAFwkTag::SERVICE_EXT, "Disconnect ability:%{public}d",
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
            TAG_LOGD(AAFwkTag::SERVICE_EXT, "find conn ability exist");
        }
        return;
    }

    napi_value OnStartExtensionAbility(napi_env env, NapiCallbackInfo& info)
    {
        HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
        TAG_LOGI(AAFwkTag::SERVICE_EXT, "called");
        if (info.argc < ARGC_ONE) {
            TAG_LOGE(AAFwkTag::SERVICE_EXT, "invalid argc");
            ThrowTooFewParametersError(env);
            return CreateJsUndefined(env);
        }
        AAFwk::Want want;
        if (!AppExecFwk::UnwrapWant(env, info.argv[INDEX_ZERO], want)) {
            ThrowInvalidParamError(env, "Parse param want failed, must be a Want.");
            return CreateJsUndefined(env);
        }
        auto innerErrCode = std::make_shared<ErrCode>(ERR_OK);
        NapiAsyncTask::ExecuteCallback execute = [weak = context_, want, innerErrCode]() {
            auto context = weak.lock();
            if (!context) {
                TAG_LOGW(AAFwkTag::SERVICE_EXT, "context released");
                *innerErrCode = static_cast<int32_t>(AbilityErrorCode::ERROR_CODE_INVALID_CONTEXT);
                return;
            }
            *innerErrCode = context->StartServiceExtensionAbility(want);
        };
        NapiAsyncTask::CompleteCallback complete =
            [innerErrCode](napi_env env, NapiAsyncTask& task, int32_t status) {
                if (*innerErrCode == ERR_OK) {
                    task.Resolve(env, CreateJsUndefined(env));
                } else if (*innerErrCode == static_cast<int32_t>(AbilityErrorCode::ERROR_CODE_INVALID_CONTEXT)) {
                    task.Reject(env, CreateJsError(env, AbilityErrorCode::ERROR_CODE_INVALID_CONTEXT));
                } else {
                    task.Reject(env, CreateJsErrorByNativeErr(env, *innerErrCode));
                }
            };

        napi_value lastParam = (info.argc <= ARGC_ONE) ? nullptr : info.argv[ARGC_ONE];
        napi_value result = nullptr;
        NapiAsyncTask::ScheduleHighQos("JSServiceExtensionContext::OnStartExtensionAbility",
            env, CreateAsyncTaskWithLastParam(env, lastParam, std::move(execute), std::move(complete), &result));
        return result;
    }

    napi_value OnStartUIServiceExtension(napi_env env, NapiCallbackInfo& info)
    {
        TAG_LOGI(AAFwkTag::SERVICE_EXT, "called");
        if (info.argc <ARGC_TWO) {
            TAG_LOGE(AAFwkTag::SERVICE_EXT, "invalid argc");
            ThrowTooFewParametersError(env);
            return CreateJsUndefined(env);
        }

        AAFwk::Want want;
        if (!AppExecFwk::UnwrapWant(env, info.argv[INDEX_ZERO], want)) {
            TAG_LOGE(AAFwkTag::SERVICE_EXT, "parse want failed");
            ThrowInvalidParamError(env, "Parse param want failed, want must be Want.");
            return CreateJsUndefined(env);
        }
        auto innerErrCode = std::make_shared<ErrCode>(ERR_OK);
        NapiAsyncTask::ExecuteCallback execute = [weak = context_, want, innerErrCode]() {
            auto context = weak.lock();
            if (!context) {
                TAG_LOGW(AAFwkTag::SERVICE_EXT, "context released");
                *innerErrCode = static_cast<int32_t>(AbilityErrorCode::ERROR_CODE_INVALID_CONTEXT);
                return;
            }
            *innerErrCode = context->StartUIServiceExtensionAbility(want);
        };
        NapiAsyncTask::CompleteCallback complete =
            [innerErrCode](napi_env env, NapiAsyncTask& task, int32_t status) {
                if (*innerErrCode == ERR_OK) {
                    task.ResolveWithNoError(env, CreateJsUndefined(env));
                } else if (*innerErrCode == static_cast<int32_t>(AbilityErrorCode::ERROR_CODE_INVALID_CONTEXT)) {
                    task.Reject(env, CreateJsError(env, AbilityErrorCode::ERROR_CODE_INVALID_CONTEXT));
                } else {
                    task.Reject(env, CreateJsErrorByNativeErr(env, *innerErrCode));
                }
            };

        napi_value lastParam = (info.argc > ARGC_ONE) ? info.argv[INDEX_ONE] : nullptr;
        napi_value result = nullptr;
        NapiAsyncTask::ScheduleHighQos("JsAbilityContext::OnStartUIServiceExtension",
            env, CreateAsyncTaskWithLastParam(env, lastParam, std::move(execute), std::move(complete), &result));
        return result;
    }

    napi_value OnStartExtensionAbilityWithAccount(napi_env env, NapiCallbackInfo& info)
    {
        HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
        TAG_LOGI(AAFwkTag::SERVICE_EXT, "called");
        AAFwk::Want want;
        int32_t accountId = -1;
        size_t unwrapArgc = 0;
        if (!CheckStartAbilityWithAccountInputParam(env, info, want, accountId, unwrapArgc)) {
            return CreateJsUndefined(env);
        }
        auto innerErrCode = std::make_shared<ErrCode>(ERR_OK);
        NapiAsyncTask::ExecuteCallback execute = [weak = context_, want, accountId, innerErrCode]() {
            auto context = weak.lock();
            if (!context) {
                TAG_LOGW(AAFwkTag::SERVICE_EXT, "context released");
                *innerErrCode = static_cast<int32_t>(AbilityErrorCode::ERROR_CODE_INVALID_CONTEXT);
                return;
            }
            *innerErrCode = context->StartServiceExtensionAbility(want, accountId);
        };
        NapiAsyncTask::CompleteCallback complete =
            [innerErrCode](napi_env env, NapiAsyncTask& task, int32_t status) {
                if (*innerErrCode == ERR_OK) {
                    task.Resolve(env, CreateJsUndefined(env));
                } else if (*innerErrCode == static_cast<int32_t>(AbilityErrorCode::ERROR_CODE_INVALID_CONTEXT)) {
                    task.Reject(env, CreateJsError(env, AbilityErrorCode::ERROR_CODE_INVALID_CONTEXT));
                } else {
                    task.Reject(env, CreateJsErrorByNativeErr(env, *innerErrCode));
                }
            };

        napi_value lastParam = (info.argc <= ARGC_TWO) ? nullptr : info.argv[ARGC_TWO];
        napi_value result = nullptr;
        NapiAsyncTask::ScheduleHighQos("JSServiceExtensionContext::OnStartExtensionAbilityWithAccount",
            env, CreateAsyncTaskWithLastParam(env, lastParam, std::move(execute), std::move(complete), &result));
        return result;
    }

    napi_value OnStopExtensionAbility(napi_env env, NapiCallbackInfo& info)
    {
        HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
        TAG_LOGI(AAFwkTag::SERVICE_EXT, "called");
        if (info.argc < ARGC_ONE) {
            TAG_LOGE(AAFwkTag::SERVICE_EXT, "invalid argc");
            ThrowTooFewParametersError(env);
            return CreateJsUndefined(env);
        }
        AAFwk::Want want;
        if (!AppExecFwk::UnwrapWant(env, info.argv[INDEX_ZERO], want)) {
            ThrowInvalidParamError(env, "Parse param want failed, must be a Want.");
            return CreateJsUndefined(env);
        }
        auto innerErrCode = std::make_shared<ErrCode>(ERR_OK);
        NapiAsyncTask::ExecuteCallback execute = [weak = context_, want, innerErrCode]() {
            auto context = weak.lock();
            if (!context) {
                TAG_LOGW(AAFwkTag::SERVICE_EXT, "context released");
                *innerErrCode = static_cast<int32_t>(AbilityErrorCode::ERROR_CODE_INVALID_CONTEXT);
                return;
            }
            *innerErrCode = context->StopServiceExtensionAbility(want);
        };
        NapiAsyncTask::CompleteCallback complete =
            [innerErrCode](napi_env env, NapiAsyncTask& task, int32_t status) {
                if (*innerErrCode == ERR_OK) {
                    task.Resolve(env, CreateJsUndefined(env));
                } else if (*innerErrCode == static_cast<int32_t>(AbilityErrorCode::ERROR_CODE_INVALID_CONTEXT)) {
                    task.Reject(env, CreateJsError(env, AbilityErrorCode::ERROR_CODE_INVALID_CONTEXT));
                } else {
                    task.Reject(env, CreateJsErrorByNativeErr(env, *innerErrCode));
                }
            };

        napi_value lastParam = (info.argc <= ARGC_ONE) ? nullptr : info.argv[ARGC_ONE];
        napi_value result = nullptr;
        NapiAsyncTask::Schedule("JSServiceExtensionContext::OnStopExtensionAbility",
            env, CreateAsyncTaskWithLastParam(env, lastParam, std::move(execute), std::move(complete), &result));
        return result;
    }

    napi_value OnStopExtensionAbilityWithAccount(napi_env env, NapiCallbackInfo& info)
    {
        HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
        TAG_LOGI(AAFwkTag::SERVICE_EXT, "called");
        AAFwk::Want want;
        int32_t accountId = -1;
        size_t unwrapArgc = 0;
        if (!CheckStartAbilityWithAccountInputParam(env, info, want, accountId, unwrapArgc)) {
            return CreateJsUndefined(env);
        }
        auto innerErrCode = std::make_shared<ErrCode>(ERR_OK);
        NapiAsyncTask::ExecuteCallback execute = [weak = context_, want, accountId, innerErrCode]() {
            auto context = weak.lock();
            if (!context) {
                TAG_LOGW(AAFwkTag::SERVICE_EXT, "context released");
                *innerErrCode = static_cast<int32_t>(AbilityErrorCode::ERROR_CODE_INVALID_CONTEXT);
                return;
            }
            *innerErrCode = context->StopServiceExtensionAbility(want, accountId);
        };

        NapiAsyncTask::CompleteCallback complete =
            [innerErrCode](napi_env env, NapiAsyncTask& task, int32_t status) {
                if (*innerErrCode == ERR_OK) {
                    task.Resolve(env, CreateJsUndefined(env));
                } else if (*innerErrCode == static_cast<int32_t>(AbilityErrorCode::ERROR_CODE_INVALID_CONTEXT)) {
                    task.Reject(env, CreateJsError(env, AbilityErrorCode::ERROR_CODE_INVALID_CONTEXT));
                } else {
                    task.Reject(env, CreateJsErrorByNativeErr(env, *innerErrCode));
                }
            };

        napi_value lastParam = (info.argc <= ARGC_TWO) ? nullptr : info.argv[ARGC_TWO];
        napi_value result = nullptr;
        NapiAsyncTask::Schedule("JSServiceExtensionContext::OnStopExtensionAbilityWithAccount",
            env, CreateAsyncTaskWithLastParam(env, lastParam, std::move(execute), std::move(complete), &result));
        return result;
    }

    napi_value OnRequestModalUIExtension(napi_env env, NapiCallbackInfo& info)
    {
        TAG_LOGD(AAFwkTag::SERVICE_EXT, "called");

        if (info.argc < ARGC_ONE) {
            ThrowTooFewParametersError(env);
            return CreateJsUndefined(env);
        }

        AAFwk::Want want;
        if (!AppExecFwk::UnwrapWant(env, info.argv[0], want)) {
            TAG_LOGE(AAFwkTag::SERVICE_EXT, "parse want failed");
            ThrowInvalidParamError(env, "Parse param want failed, must be a Want.");
            return CreateJsUndefined(env);
        }

        auto innerErrCode = std::make_shared<ErrCode>(ERR_OK);
        NapiAsyncTask::ExecuteCallback execute = [serviceContext = context_, want, innerErrCode]() {
            auto context = serviceContext.lock();
            if (!context) {
                TAG_LOGE(AAFwkTag::APPKIT, "context released");
                *innerErrCode = static_cast<int>(AbilityErrorCode::ERROR_CODE_INNER);
                return;
            }
            *innerErrCode = AAFwk::AbilityManagerClient::GetInstance()->RequestModalUIExtension(want);
        };
        NapiAsyncTask::CompleteCallback complete = [innerErrCode](napi_env env, NapiAsyncTask& task, int32_t status) {
            if (*innerErrCode == ERR_OK) {
                task.Resolve(env, CreateJsUndefined(env));
            } else {
                TAG_LOGE(AAFwkTag::APPKIT, "OnRequestModalUIExtension failed %{public}d", *innerErrCode);
                task.Reject(env, CreateJsErrorByNativeErr(env, *innerErrCode));
            }
        };

        napi_value lastParam = (info.argc > ARGC_ONE) ? info.argv[ARGC_ONE] : nullptr;
        napi_value result = nullptr;
        NapiAsyncTask::ScheduleHighQos("JSServiceExtensionContext::OnRequestModalUIExtension",
            env, CreateAsyncTaskWithLastParam(env, lastParam, std::move(execute), std::move(complete), &result));
        return result;
    }

    bool ParsePreStartMissionArgs(const napi_env &env, const NapiCallbackInfo &info, std::string& bundleName,
        std::string& moduleName, std::string& abilityName, std::string& startTime)
    {
        if (info.argc < ARGC_FOUR) {
            TAG_LOGE(AAFwkTag::SERVICE_EXT, "invalid argc");
            ThrowTooFewParametersError(env);
            return false;
        }

        std::string args[ARGC_FOUR];
        for (size_t i = 0; i < ARGC_FOUR; i++) {
            if (!CheckTypeForNapiValue(env, info.argv[i], napi_string)) {
                TAG_LOGE(AAFwkTag::SERVICE_EXT, "param must be string");
                return false;
            }
            if (!ConvertFromJsValue(env, info.argv[i], args[i])) {
                TAG_LOGE(AAFwkTag::SERVICE_EXT, "param invalid");
                return false;
            }
        }

        bundleName = args[INDEX_ZERO];
        moduleName = args[INDEX_ONE];
        abilityName = args[INDEX_TWO];
        startTime = args[INDEX_THREE];

        return true;
    }

    napi_value OnPreStartMission(napi_env env, NapiCallbackInfo& info)
    {
        TAG_LOGD(AAFwkTag::SERVICE_EXT, "called");
        if (info.argc < ARGC_FOUR) {
            ThrowTooFewParametersError(env);
            return CreateJsUndefined(env);
        }

        std::string bundleName;
        std::string moduleName;
        std::string abilityName;
        std::string startTime;
        if (!ParsePreStartMissionArgs(env, info, bundleName, moduleName, abilityName, startTime)) {
            TAG_LOGE(AAFwkTag::SERVICE_EXT, "parse preStartMission failed");
            ThrowInvalidParamError(env, "Parse params failed, params must be strings.");
            return CreateJsUndefined(env);
        }

        auto innerErrCode = std::make_shared<ErrCode>(ERR_OK);
        NapiAsyncTask::ExecuteCallback execute = [weak = context_,
            bundleName, moduleName, abilityName, startTime, innerErrCode]() {
                auto context = weak.lock();
                if (!context) {
                    TAG_LOGW(AAFwkTag::SERVICE_EXT, "context released");
                    *innerErrCode = static_cast<int32_t>(AbilityErrorCode::ERROR_CODE_INVALID_CONTEXT);
                    return;
                }
                *innerErrCode = context->PreStartMission(bundleName, moduleName, abilityName, startTime);
            };

        NapiAsyncTask::CompleteCallback complete =
            [innerErrCode](napi_env env, NapiAsyncTask& task, int32_t status) {
                if (*innerErrCode == ERR_OK) {
                    task.ResolveWithNoError(env, CreateJsUndefined(env));
                } else if (*innerErrCode == static_cast<int32_t>(AbilityErrorCode::ERROR_CODE_INVALID_CONTEXT)) {
                    task.Reject(env, CreateJsError(env, AbilityErrorCode::ERROR_CODE_INVALID_CONTEXT));
                } else {
                    task.Reject(env, CreateJsErrorByNativeErr(env, *innerErrCode));
                }
            };

        napi_value result = nullptr;
        NapiAsyncTask::ScheduleHighQos("JSServiceExtensionContext::OnPreStartMission",
            env, CreateAsyncTaskWithLastParam(env, nullptr, std::move(execute), std::move(complete), &result));
        return result;
    }

    NapiAsyncTask::ExecuteCallback GetStartAbilityExecFunc(const AAFwk::Want &want,
        const AAFwk::StartOptions &startOptions, int32_t userId, bool useOption, std::shared_ptr<int> retCode)
    {
        return [weak = context_, want, startOptions, useOption, userId, retCode,
            &observer = freeInstallObserver_]() {
            TAG_LOGD(AAFwkTag::SERVICE_EXT, "startAbility exec begin");
            if (!retCode) {
                TAG_LOGE(AAFwkTag::SERVICE_EXT, "retCode null");
                return;
            }
            auto context = weak.lock();
            if (!context) {
                TAG_LOGW(AAFwkTag::SERVICE_EXT, "context released");
                *retCode = static_cast<int>(AbilityErrorCode::ERROR_CODE_INVALID_CONTEXT);
                return;
            }

            useOption ? *retCode = context->StartAbilityWithAccount(want, userId, startOptions) :
                *retCode = context->StartAbilityWithAccount(want, userId);
            if ((want.GetFlags() & Want::FLAG_INSTALL_ON_DEMAND) == Want::FLAG_INSTALL_ON_DEMAND &&
                *retCode != 0 && observer != nullptr) {
                std::string bundleName = want.GetElement().GetBundleName();
                std::string abilityName = want.GetElement().GetAbilityName();
                std::string startTime = want.GetStringParam(Want::PARAM_RESV_START_TIME);
                observer->OnInstallFinished(bundleName, abilityName, startTime, *retCode);
            }
        };
    }

    NapiAsyncTask::CompleteCallback GetSimpleCompleteFunc(std::shared_ptr<int> retCode)
    {
        return [retCode](napi_env env, NapiAsyncTask& task, int32_t) {
            if (!retCode) {
                TAG_LOGE(AAFwkTag::SERVICE_EXT, "StartAbility failed");
                task.Reject(env, CreateJsError(env, AbilityErrorCode::ERROR_CODE_INNER));
                return;
            }
            if (*retCode == 0) {
                TAG_LOGD(AAFwkTag::SERVICE_EXT, "StartAbility success");
                task.Resolve(env, CreateJsUndefined(env));
            } else {
                task.Reject(env, CreateJsErrorByNativeErr(env, *retCode));
            }
        };
    }

    NapiAsyncTask::ExecuteCallback GetConnectAbilityExecFunc(const AAFwk::Want &want,
        sptr<JSServiceExtensionConnection> connection, int64_t connectId, std::shared_ptr<int> innerErrorCode)
    {
        return [weak = context_, want, connection, connectId, innerErrorCode]() {
            TAG_LOGI(AAFwkTag::SERVICE_EXT, "Connect ability: %{public}d",
                static_cast<int32_t>(connectId));

            auto context = weak.lock();
            if (!context) {
                TAG_LOGE(AAFwkTag::SERVICE_EXT, "context released");
                *innerErrorCode = static_cast<int>(AbilityErrorCode::ERROR_CODE_INVALID_CONTEXT);
                return;
            }

            *innerErrorCode = context->ConnectAbility(want, connection);
        };
    }
};
} // namespace

napi_value CreateJsServiceExtensionContext(napi_env env, std::shared_ptr<ServiceExtensionContext> context)
{
    TAG_LOGD(AAFwkTag::SERVICE_EXT, "called");
    std::shared_ptr<OHOS::AppExecFwk::AbilityInfo> abilityInfo = nullptr;
    if (context) {
        abilityInfo = context->GetAbilityInfo();
    }
    napi_value object = CreateJsExtensionContext(env, context, abilityInfo);

    std::unique_ptr<JsServiceExtensionContext> jsContext = std::make_unique<JsServiceExtensionContext>(context);
    napi_wrap(env, object, jsContext.release(), JsServiceExtensionContext::Finalizer, nullptr, nullptr);

    const char *moduleName = "JsServiceExtensionContext";
    BindNativeFunction(env, object, "startAbility", moduleName, JsServiceExtensionContext::StartAbility);
    BindNativeFunction(env, object, "openLink", moduleName, JsServiceExtensionContext::OpenLink);
    BindNativeFunction(env, object, "startAbilityAsCaller",
        moduleName, JsServiceExtensionContext::StartAbilityAsCaller);
    BindNativeFunction(env, object, "terminateSelf", moduleName, JsServiceExtensionContext::TerminateAbility);
    BindNativeFunction(
        env, object, "connectServiceExtensionAbility", moduleName, JsServiceExtensionContext::ConnectAbility);
    BindNativeFunction(env, object, "disconnectAbility",
        moduleName, JsServiceExtensionContext::DisconnectAbility);
    BindNativeFunction(env, object, "disconnectServiceExtensionAbility",
        moduleName, JsServiceExtensionContext::DisconnectAbility);
    BindNativeFunction(env, object, "startAbilityWithAccount",
        moduleName, JsServiceExtensionContext::StartAbilityWithAccount);
    BindNativeFunction(env, object, "startUIAbilities", moduleName, JsServiceExtensionContext::StartUIAbilities);
    BindNativeFunction(env, object, "startAbilityByCall",
        moduleName, JsServiceExtensionContext::StartAbilityByCall);
    BindNativeFunction(
        env, object, "connectAbilityWithAccount", moduleName, JsServiceExtensionContext::ConnectAbilityWithAccount);
    BindNativeFunction(env, object,
        "connectServiceExtensionAbilityWithAccount", moduleName, JsServiceExtensionContext::ConnectAbilityWithAccount);
    BindNativeFunction(env, object, "startServiceExtensionAbility", moduleName,
        JsServiceExtensionContext::StartServiceExtensionAbility);
    BindNativeFunction(env, object, "startUIServiceExtensionAbility", moduleName,
        JsServiceExtensionContext::StartUIServiceExtensionAbility);
    BindNativeFunction(env, object, "startServiceExtensionAbilityWithAccount", moduleName,
        JsServiceExtensionContext::StartServiceExtensionAbilityWithAccount);
    BindNativeFunction(env, object, "stopServiceExtensionAbility", moduleName,
        JsServiceExtensionContext::StopServiceExtensionAbility);
    BindNativeFunction(env, object, "stopServiceExtensionAbilityWithAccount", moduleName,
        JsServiceExtensionContext::StopServiceExtensionAbilityWithAccount);
    BindNativeFunction(env, object, "startRecentAbility", moduleName,
        JsServiceExtensionContext::StartRecentAbility);
    BindNativeFunction(env, object, "requestModalUIExtension", moduleName,
        JsServiceExtensionContext::RequestModalUIExtension);
    BindNativeFunction(env, object, "preStartMission", moduleName,
        JsServiceExtensionContext::PreStartMission);
    BindNativeFunction(env, object, "openAtomicService", moduleName,
        JsServiceExtensionContext::OpenAtomicService);
    return object;
}

JSServiceExtensionConnection::JSServiceExtensionConnection(napi_env env) : env_(env) {}

JSServiceExtensionConnection::~JSServiceExtensionConnection()
{
    if (jsConnectionObject_ == nullptr) {
        return;
    }

    uv_loop_t *loop = nullptr;
    napi_get_uv_event_loop(env_, &loop);
    if (loop == nullptr) {
        return;
    }

    uv_work_t *work = new (std::nothrow) uv_work_t;
    if (work == nullptr) {
        return;
    }
    work->data = reinterpret_cast<void *>(jsConnectionObject_.release());
    int ret = uv_queue_work(loop, work, [](uv_work_t *work) {},
    [](uv_work_t *work, int status) {
        if (work == nullptr) {
            return;
        }
        if (work->data == nullptr) {
            delete work;
            work = nullptr;
            return;
        }
        delete reinterpret_cast<NativeReference *>(work->data);
        work->data = nullptr;
        delete work;
        work = nullptr;
    });
    if (ret != 0) {
        delete reinterpret_cast<NativeReference *>(work->data);
        work->data = nullptr;
        delete work;
        work = nullptr;
    }
}

void JSServiceExtensionConnection::SetConnectionId(int64_t id)
{
    connectionId_ = id;
}

int64_t JSServiceExtensionConnection::GetConnectionId()
{
    return connectionId_;
}

void JSServiceExtensionConnection::OnAbilityConnectDone(const AppExecFwk::ElementName &element,
    const sptr<IRemoteObject> &remoteObject, int resultCode)
{
    TAG_LOGD(AAFwkTag::SERVICE_EXT, "called, resultCode:%{public}d", resultCode);
    wptr<JSServiceExtensionConnection> connection = this;
    std::unique_ptr<NapiAsyncTask::CompleteCallback> complete = std::make_unique<NapiAsyncTask::CompleteCallback>
        ([connection, element, remoteObject, resultCode](napi_env env, NapiAsyncTask &task, int32_t status) {
            sptr<JSServiceExtensionConnection> connectionSptr = connection.promote();
            if (!connectionSptr) {
                TAG_LOGE(AAFwkTag::SERVICE_EXT, "null connectionSptr");
                return;
            }
            connectionSptr->HandleOnAbilityConnectDone(element, remoteObject, resultCode);
        });

    napi_ref callback = nullptr;
    std::unique_ptr<NapiAsyncTask::ExecuteCallback> execute = nullptr;
    NapiAsyncTask::Schedule("JSServiceExtensionConnection::OnAbilityConnectDone",
        env_, std::make_unique<NapiAsyncTask>(callback, std::move(execute), std::move(complete)));
}

void JSServiceExtensionConnection::HandleOnAbilityConnectDone(const AppExecFwk::ElementName &element,
    const sptr<IRemoteObject> &remoteObject, int resultCode)
{
    TAG_LOGD(AAFwkTag::SERVICE_EXT, "resultCode:%{public}d", resultCode);
    // wrap ElementName
    napi_value napiElementName = OHOS::AppExecFwk::WrapElementName(env_, element);

    // wrap RemoteObject
    napi_value napiRemoteObject = NAPI_ohos_rpc_CreateJsRemoteObject(env_, remoteObject);
    napi_value argv[] = {napiElementName, napiRemoteObject};
    if (jsConnectionObject_ == nullptr) {
        TAG_LOGE(AAFwkTag::SERVICE_EXT, "null jsConnectionObject_");
        return;
    }
    napi_value obj = jsConnectionObject_->GetNapiValue();
    if (!CheckTypeForNapiValue(env_, obj, napi_object)) {
        TAG_LOGE(AAFwkTag::SERVICE_EXT, "get object error");
        return;
    }
    napi_value methodOnConnect = nullptr;
    napi_get_named_property(env_, obj, "onConnect", &methodOnConnect);
    if (methodOnConnect == nullptr) {
        TAG_LOGE(AAFwkTag::SERVICE_EXT, "null methodOnConnect");
        return;
    }
    TAG_LOGI(AAFwkTag::SERVICE_EXT, "Call onConnect");
    napi_status status = napi_call_function(env_, obj, methodOnConnect, ARGC_TWO, argv, nullptr);
    if (status != napi_ok) {
        TAG_LOGE(AAFwkTag::SERVICE_EXT, "call js func failed %{public}d", status);
    }
}

void JSServiceExtensionConnection::OnAbilityDisconnectDone(const AppExecFwk::ElementName &element, int resultCode)
{
    TAG_LOGD(AAFwkTag::SERVICE_EXT, "called, resultCode:%{public}d", resultCode);
    wptr<JSServiceExtensionConnection> connection = this;
    std::unique_ptr<NapiAsyncTask::CompleteCallback> complete = std::make_unique<NapiAsyncTask::CompleteCallback>
        ([connection, element, resultCode](napi_env env, NapiAsyncTask &task, int32_t status) {
            sptr<JSServiceExtensionConnection> connectionSptr = connection.promote();
            if (!connectionSptr) {
                TAG_LOGI(AAFwkTag::SERVICE_EXT, "null connectionSptr");
                return;
            }
            connectionSptr->HandleOnAbilityDisconnectDone(element, resultCode);
        });
    napi_ref callback = nullptr;
    std::unique_ptr<NapiAsyncTask::ExecuteCallback> execute = nullptr;
    NapiAsyncTask::Schedule("JSServiceExtensionConnection::OnAbilityDisconnectDone",
        env_, std::make_unique<NapiAsyncTask>(callback, std::move(execute), std::move(complete)));
}

void JSServiceExtensionConnection::HandleOnAbilityDisconnectDone(const AppExecFwk::ElementName &element,
    int resultCode)
{
    TAG_LOGD(AAFwkTag::SERVICE_EXT, "called, resultCode:%{public}d", resultCode);
    napi_value napiElementName = OHOS::AppExecFwk::WrapElementName(env_, element);
    napi_value argv[] = {napiElementName};
    if (jsConnectionObject_ == nullptr) {
        TAG_LOGE(AAFwkTag::SERVICE_EXT, "null jsConnectionObject_");
        return;
    }
    napi_value obj = jsConnectionObject_->GetNapiValue();
    if (!CheckTypeForNapiValue(env_, obj, napi_object)) {
        TAG_LOGE(AAFwkTag::SERVICE_EXT, "get object error");
        return;
    }

    napi_value method = nullptr;
    napi_get_named_property(env_, obj, "onDisconnect", &method);
    if (method == nullptr) {
        TAG_LOGE(AAFwkTag::SERVICE_EXT, "null method");
        return;
    }

    // release connect
    {
        std::lock_guard guard(g_connectsMutex);
        TAG_LOGD(AAFwkTag::SERVICE_EXT, "OnAbilityDisconnectDone g_connects.size:%{public}zu", g_connects.size());
        std::string bundleName = element.GetBundleName();
        std::string abilityName = element.GetAbilityName();
        auto item = std::find_if(g_connects.begin(),
            g_connects.end(),
            [bundleName, abilityName, connectionId = connectionId_](
                const auto &obj) {
                return (bundleName == obj.first.want.GetBundle()) &&
                    (abilityName == obj.first.want.GetElement().GetAbilityName()) &&
                    connectionId == obj.first.id;
            });
        if (item != g_connects.end()) {
            // match bundlename && abilityname
            g_connects.erase(item);
            TAG_LOGD(
                AAFwkTag::SERVICE_EXT, "OnAbilityDisconnectDone erase g_connects.size:%{public}zu", g_connects.size());
        }
    }
    TAG_LOGI(AAFwkTag::SERVICE_EXT, "Call onDisconnect");
    napi_status status = napi_call_function(env_, obj, method, ARGC_ONE, argv, nullptr);
    if (status != napi_ok) {
        TAG_LOGE(AAFwkTag::SERVICE_EXT, "call js func failed %{public}d", status);
    }
}

void JSServiceExtensionConnection::SetJsConnectionObject(napi_value jsConnectionObject)
{
    napi_ref ref = nullptr;
    napi_create_reference(env_, jsConnectionObject, 1, &ref);
    jsConnectionObject_ = std::unique_ptr<NativeReference>(reinterpret_cast<NativeReference*>(ref));
}

void JSServiceExtensionConnection::RemoveConnectionObject()
{
    jsConnectionObject_.reset();
}

void JSServiceExtensionConnection::CallJsFailed(int32_t errorCode)
{
    TAG_LOGD(AAFwkTag::SERVICE_EXT, "called");
    if (jsConnectionObject_ == nullptr) {
        TAG_LOGE(AAFwkTag::SERVICE_EXT, "null jsConnectionObject_");
        return;
    }
    napi_value obj = jsConnectionObject_->GetNapiValue();
    if (!CheckTypeForNapiValue(env_, obj, napi_object)) {
        TAG_LOGE(AAFwkTag::SERVICE_EXT, "get obj failed");
        return;
    }

    napi_value method = nullptr;
    napi_get_named_property(env_, obj, "onFailed", &method);
    if (method == nullptr) {
        TAG_LOGE(AAFwkTag::SERVICE_EXT, "get onFailed failed");
        return;
    }
    napi_value argv[] = {CreateJsValue(env_, errorCode)};
    napi_call_function(env_, obj, method, ARGC_ONE, argv, nullptr);
    TAG_LOGD(AAFwkTag::SERVICE_EXT, "end");
}
}  // namespace AbilityRuntime
}  // namespace OHOS
