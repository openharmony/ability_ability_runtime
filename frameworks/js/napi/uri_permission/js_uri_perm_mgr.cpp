/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "js_uri_perm_mgr.h"

#include "hilog_wrapper.h"
#include "js_error_utils.h"
#include "js_runtime_utils.h"
#include "uri.h"
#include "uri_permission_manager_client.h"

namespace OHOS {
namespace AbilityRuntime {
class JsUriPermMgr {
public:
    JsUriPermMgr() = default;
    ~JsUriPermMgr() = default;

    static void Finalizer(NativeEngine* engine, void* data, void* hint)
    {
        HILOG_INFO("JsUriPermMgr::Finalizer is called");
        std::unique_ptr<JsUriPermMgr>(static_cast<JsUriPermMgr*>(data));
    }

    static NativeValue* GrantUriPermission(NativeEngine* engine, NativeCallbackInfo* info)
    {
        JsUriPermMgr* me = CheckParamsAndGetThis<JsUriPermMgr>(engine, info);
        return (me != nullptr) ? me->OnGrantUriPermission(*engine, *info) : nullptr;
    }

    static NativeValue* GrantUriPermissionFromSelf(NativeEngine* engine, NativeCallbackInfo* info)
    {
        JsUriPermMgr* me = CheckParamsAndGetThis<JsUriPermMgr>(engine, info);
        return (me != nullptr) ? me->OnGrantUriPermissionFromSelf(*engine, *info) : nullptr;
    }

    static NativeValue* RevokeUriPermission(NativeEngine* engine, NativeCallbackInfo* info)
    {
        JsUriPermMgr* me = CheckParamsAndGetThis<JsUriPermMgr>(engine, info);
        return (me != nullptr) ? me->OnRevokeUriPermission(*engine, *info) : nullptr;
    }

private:
    NativeValue* OnGrantUriPermission(NativeEngine& engine, NativeCallbackInfo& info)
    {
        constexpr int32_t argCountFour = 4;
        constexpr int32_t argCountThree = 3;
        // only support 3 or 4 params (3 parameter and 1 optional callback)
        if (info.argc != argCountThree && info.argc != argCountFour) {
            HILOG_ERROR("Invalid arguments");
            ThrowTooFewParametersError(engine);
            return engine.CreateUndefined();
        }
        std::vector<std::shared_ptr<NativeReference>> args;
        for (size_t i = 0; i < info.argc; ++i) {
            args.emplace_back(engine.CreateReference(info.argv[i], 1));
        }
        HILOG_DEBUG("Grant Uri Permission start");

        AsyncTask::CompleteCallback complete =
        [args, argCountFour, argCountThree](NativeEngine& engine, AsyncTask& task, int32_t status) {
            if (args.size() != argCountThree && args.size() != argCountFour) {
                HILOG_ERROR("Wrong number of parameters.");
                task.Reject(engine, CreateJsError(engine, -1, "Wrong number of parameters."));
                return;
            }

            std::string uriStr;
            if (!ConvertFromJsValue(engine, args[0]->Get(), uriStr)) {
                HILOG_ERROR("%{public}s called, the first parameter is invalid.", __func__);
                task.Reject(engine, CreateJsError(engine, -1, "uri conversion failed."));
                return;
            }

            int flag = 0;
            if (!ConvertFromJsValue(engine, args[1]->Get(), flag)) {
                HILOG_ERROR("%{public}s called, the second parameter is invalid.", __func__);
                task.Reject(engine, CreateJsError(engine, -1, "flag conversion failed."));
                return;
            }

            std::string targetBundleName;
            if (!ConvertFromJsValue(engine, args[3]->Get(), targetBundleName)) {
                HILOG_ERROR("%{public}s called, the fourth parameter is invalid.", __func__);
                task.Reject(engine, CreateJsError(engine, -1, "targetBundleName conversion failed."));
                return;
            }

            Uri uri(uriStr);
            int autoremove = 0;
            AAFwk::UriPermissionManagerClient::GetInstance()->GrantUriPermission(uri, flag,
                targetBundleName, autoremove);
            task.Resolve(engine, CreateJsValue(engine, 0));
        };

        NativeValue* lastParam = (info.argc == argCountFour) ? info.argv[argCountThree] : nullptr;
        NativeValue* result = nullptr;
        AsyncTask::Schedule("JsUriPermMgr::OnGrantUriPermission",
            engine, CreateAsyncTaskWithLastParam(engine, lastParam, nullptr, std::move(complete), &result));
        return result;
    }

    NativeValue* OnGrantUriPermissionFromSelf(NativeEngine& engine, NativeCallbackInfo& info)
    {
        constexpr int32_t argCountThree = 3;
        constexpr int32_t argCountFour = 4;
        // only support 3 or 4 params (4 parameter and 1 optional callback)
        if (info.argc != argCountThree && info.argc != argCountFour) {
            HILOG_ERROR("Invalid arguments");
            ThrowTooFewParametersError(engine);
            return engine.CreateUndefined();
        }
        std::vector<std::shared_ptr<NativeReference>> args;
        for (size_t i = 0; i < info.argc; ++i) {
            args.emplace_back(engine.CreateReference(info.argv[i], 1));
        }
        HILOG_DEBUG("Grant Uri Permission start");

        AsyncTask::CompleteCallback complete =
        [args, argCountFour, argCountThree](NativeEngine& engine, AsyncTask& task, int32_t status) {
            if (args.size() != argCountThree && args.size() != argCountFour) {
                HILOG_ERROR("Wrong number of parameters.");
                task.Reject(engine, CreateJsError(engine, -1, "Wrong number of parameters."));
                return;
            }

            std::string uriStr;
            if (!ConvertFromJsValue(engine, args[0]->Get(), uriStr)) {
                HILOG_ERROR("%{public}s called, the first parameter is invalid.", __func__);
                task.Reject(engine, CreateJsError(engine, -1, "uri conversion failed."));
                return;
            }

            int flag = 0;
            if (!ConvertFromJsValue(engine, args[1]->Get(), flag)) {
                HILOG_ERROR("%{public}s called, the second parameter is invalid.", __func__);
                task.Reject(engine, CreateJsError(engine, -1, "flag conversion failed."));
                return;
            }

            std::string targetBundleName;
            if (!ConvertFromJsValue(engine, args[2]->Get(), targetBundleName)) {
                HILOG_ERROR("%{public}s called, the fourth parameter is invalid.", __func__);
                task.Reject(engine, CreateJsError(engine, -1, "targetBundleName conversion failed."));
                return;
            }
            
            Uri uri(uriStr);
            AAFwk::UriPermissionManagerClient::GetInstance()->GrantUriPermissionFromSelf(uri,
                flag, targetBundleName);
            task.Resolve(engine, CreateJsValue(engine, 0));
        };
        NativeValue* lastParam = (info.argc == argCountFour) ? info.argv[argCountThree] : nullptr;
        NativeValue* result = nullptr;
        AsyncTask::Schedule("JsUriPermMgr::OnGrantUriPermission",
            engine, CreateAsyncTaskWithLastParam(engine, lastParam, nullptr, std::move(complete), &result));
        return result;
    }

    NativeValue* OnRevokeUriPermission(NativeEngine& engine, NativeCallbackInfo& info)
    {
        constexpr int32_t argCountThree = 3;
        constexpr int32_t argCountTwo = 2;
        // only support 2 or 3 params (2 parameter and 1 optional callback)
        if (info.argc != argCountThree && info.argc != argCountTwo) {
            HILOG_ERROR("Invalid arguments");
            ThrowTooFewParametersError(engine);
            return engine.CreateUndefined();
        }
        std::vector<std::shared_ptr<NativeReference>> args;
        for (size_t i = 0; i < info.argc; ++i) {
            args.emplace_back(engine.CreateReference(info.argv[i], 1));
        }
        HILOG_DEBUG("Remove Uri Permission start");

        AsyncTask::CompleteCallback complete =
        [args, argCountThree, argCountTwo](NativeEngine& engine, AsyncTask& task, int32_t status) {
            if (args.size() != argCountThree && args.size() != argCountTwo) {
                HILOG_ERROR("Wrong number of parameters.");
                task.Reject(engine, CreateJsError(engine, -1, "Wrong number of parameters."));
                return;
            }

            std::string uriStr;
            if (!ConvertFromJsValue(engine, args[0]->Get(), uriStr)) {
                HILOG_ERROR("%{public}s called, the first parameter is invalid.", __func__);
                task.Reject(engine, CreateJsError(engine, -1, "uri conversion failed."));
                return;
            }
            std::string bundleName;
            if (!ConvertFromJsValue(engine, args[0]->Get(), bundleName)) {
                HILOG_ERROR("%{public}s called, the first parameter is invalid.", __func__);
                task.Reject(engine, CreateJsError(engine, -1, "BundleName conversion failed."));
                return;
            }

            Uri uri(uriStr);
            AAFwk::UriPermissionManagerClient::GetInstance()->RevokeUriPermissionManually(uri, bundleName);
            task.Resolve(engine, CreateJsValue(engine, 0));
        };

        NativeValue* lastParam = (info.argc == argCountThree) ? info.argv[argCountTwo] : nullptr;
        NativeValue* result = nullptr;
        AsyncTask::Schedule("JsUriPermMgr::OnRevokeUriPermission",
            engine, CreateAsyncTaskWithLastParam(engine, lastParam, nullptr, std::move(complete), &result));
        return result;
    }
};

NativeValue* CreateJsUriPermMgr(NativeEngine* engine, NativeValue* exportObj)
{
    HILOG_INFO("CreateJsUriPermMgr is called");
    if (engine == nullptr || exportObj == nullptr) {
        HILOG_INFO("Invalid input parameters");
        return nullptr;
    }

    NativeObject* object = ConvertNativeValueTo<NativeObject>(exportObj);
    if (object == nullptr) {
        HILOG_INFO("object is nullptr");
        return nullptr;
    }

    std::unique_ptr<JsUriPermMgr> jsUriPermMgr = std::make_unique<JsUriPermMgr>();
    object->SetNativePointer(jsUriPermMgr.release(), JsUriPermMgr::Finalizer, nullptr);

    const char *moduleName = "JsUriPermMgr";
    BindNativeFunction(*engine, *object, "grantUriPermission", moduleName, JsUriPermMgr::GrantUriPermission);
    BindNativeFunction(*engine, *object, "grantUriPermissionFromSelf",
        moduleName, JsUriPermMgr::GrantUriPermissionFromSelf);
    BindNativeFunction(*engine, *object, "RevokeUriPermission", moduleName, JsUriPermMgr::RevokeUriPermission);
    return engine->CreateUndefined();
}
}  // namespace AbilityRuntime
}  // namespace OHOS
