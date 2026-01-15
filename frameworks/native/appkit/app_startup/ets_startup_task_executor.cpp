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

#include "ets_startup_task_executor.h"

#include <mutex>

#include "ani_common_util.h"
#include "event_handler.h"
#include "ets_startup_task_result.h"
#include "hilog_tag_wrapper.h"
#include "hitrace_meter.h"

namespace OHOS {
namespace AbilityRuntime {
namespace {
static std::shared_ptr<AppExecFwk::EventHandler> g_mainHandler = nullptr;
std::mutex g_mainHandlerMutex;
}
int32_t ETSStartupTaskExecutor::RunOnTaskPool(ani_env *env, ani_ref startupTask,
    ani_ref context, std::shared_ptr<StartupTaskResultCallback> callback)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    TAG_LOGD(AAFwkTag::STARTUP, "RunOnTaskPool called for task");
    if (env == nullptr || startupTask == nullptr || context == nullptr) {
        TAG_LOGE(AAFwkTag::STARTUP, "null args in RunOnTaskPool");
        return ERR_STARTUP_INTERNAL_ERROR;
    }

    ani_status status = ANI_ERROR;
    ani_class cls = nullptr;
    ani_method ctor = nullptr;
    ani_object object = nullptr;

    if ((status = env->FindClass("appstartup.StartupTaskExecutor.StartupTaskExecutor", &cls)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::STARTUP, "FindClass failed, status: %{public}d", status);
        return ERR_STARTUP_INTERNAL_ERROR;
    }
    if (cls == nullptr) {
        TAG_LOGE(AAFwkTag::STARTUP, "null cls");
        return ERR_STARTUP_INTERNAL_ERROR;
    }

    if ((status = env->Class_FindMethod(cls, "<ctor>", ":", &ctor)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::STARTUP, "findMethod failed, status: %{public}d", status);
        return ERR_STARTUP_INTERNAL_ERROR;
    }

    if ((status = env->Object_New(cls, ctor, &object)) != ANI_OK || object == nullptr) {
        TAG_LOGE(AAFwkTag::STARTUP, "Object_New failed, status: %{public}d", status);
        return ERR_STARTUP_INTERNAL_ERROR;
    }

    ani_object startupTaskObj = reinterpret_cast<ani_object>(startupTask);
    ani_object contextObj = reinterpret_cast<ani_object>(context);

    auto weakCallback = new (std::nothrow) std::weak_ptr<StartupTaskResultCallback>(callback);
    if (weakCallback == nullptr) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "null weakCallback");
        return ERR_STARTUP_INTERNAL_ERROR;
    }
    ani_long nativeCallbackLong = reinterpret_cast<ani_long>(weakCallback);
    if ((status = env->Object_CallMethodByName_Void(object, "asyncPushTask",
        "C{@ohos.app.appstartup.StartupTask.StartupTask}C{application.AbilityStageContext.AbilityStageContext}"
        "l:", startupTaskObj, contextObj, nativeCallbackLong)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::STARTUP, "failed to call asyncPushTask, status: %{public}d", status);
        delete weakCallback;
        return ERR_STARTUP_FAILED_TO_EXECUTE_STARTUP;
    }

    TAG_LOGD(AAFwkTag::STARTUP, "RunOnTaskPool completed successfully for task");
    return ERR_OK;
}

int32_t ETSStartupTaskExecutor::RunOnMainThread(ani_env *env, ani_ref startupTask,
    ani_ref context, std::shared_ptr<StartupTaskResultCallback> callback)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    TAG_LOGD(AAFwkTag::STARTUP, "RunOnMainThread called");
    if (env == nullptr || startupTask == nullptr || context == nullptr) {
        TAG_LOGE(AAFwkTag::STARTUP, "null env, args or context in RunOnMainThread");
        return ERR_STARTUP_INTERNAL_ERROR;
    }

    ani_status status = ANI_ERROR;
    ani_class cls = nullptr;
    ani_method ctor = nullptr;
    ani_object object = nullptr;
    if ((status = env->FindClass("appstartup.StartupTaskExecutor.StartupTaskExecutor", &cls)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::STARTUP, "status : %{public}d", status);
        return ERR_STARTUP_INTERNAL_ERROR;
    }
    if (cls == nullptr) {
        TAG_LOGE(AAFwkTag::STARTUP, "null cls");
        return ERR_STARTUP_INTERNAL_ERROR;
    }

    if ((status = env->Class_FindMethod(cls, "<ctor>", ":", &ctor)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::STARTUP, "findMethod failed, status : %{public}d", status);
        return ERR_STARTUP_INTERNAL_ERROR;
    }

    if ((status = env->Object_New(cls, ctor, &object)) != ANI_OK || object == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "Object_New status : %{public}d or null object", status);
        return ERR_STARTUP_INTERNAL_ERROR;
    }

    auto weakCallback = new (std::nothrow) std::weak_ptr<StartupTaskResultCallback>(callback);
    if (weakCallback == nullptr) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "null weakCallback");
        return ERR_STARTUP_INTERNAL_ERROR;
    }
    ani_object startupTaskObj = reinterpret_cast<ani_object>(startupTask);
    ani_object contextObj = reinterpret_cast<ani_object>(context);
    ani_long nativeCallbackLong = reinterpret_cast<ani_long>(weakCallback);
    if ((status = env->Object_CallMethodByName_Void(object, "executeStartupTaskOnMainThread",
        "C{@ohos.app.appstartup.StartupTask.StartupTask}C{application.AbilityStageContext.AbilityStageContext}"
        "l:", startupTaskObj, contextObj, nativeCallbackLong)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::STARTUP, "failed to call executeStartupTaskOnMainThread, status:%{public}d", status);
        delete weakCallback;
        return ERR_STARTUP_FAILED_TO_EXECUTE_STARTUP;
    }

    return ERR_OK;
}

void ETSStartupTaskExecutor::NativeOnTaskSuccess(ani_env *env, ani_object obj,
    ani_long callbackLong, ani_object result)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    TAG_LOGD(AAFwkTag::STARTUP, "NativeOnTaskSuccess called");
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::STARTUP, "env null");
        return;
    }

    auto weakCallback = reinterpret_cast<std::weak_ptr<StartupTaskResultCallback>*>(callbackLong);
    if (weakCallback == nullptr) {
        TAG_LOGE(AAFwkTag::STARTUP, "null weakCallback");
        return;
    }
    auto callback = weakCallback->lock();
    delete weakCallback;
    if (callback == nullptr) {
        TAG_LOGE(AAFwkTag::STARTUP, "null callback");
        return;
    }

    ani_vm *aniVm = nullptr;
    if (env->GetVM(&aniVm) != ANI_OK) {
        TAG_LOGE(AAFwkTag::STARTUP, "GetVM failed");
        return;
    }
    std::shared_ptr<StartupTaskResult> taskResult = std::make_shared<EtsStartupTaskResult>(aniVm, result);
    PostMainThreadTask([callback, taskResult]() {
        if (callback == nullptr) {
            TAG_LOGE(AAFwkTag::STARTUP, "null callback");
            return;
        }
        TAG_LOGD(AAFwkTag::STARTUP, "PostMainThreadTask enter");
        callback->Call(taskResult);
    });
}

void ETSStartupTaskExecutor::NativeOnTaskFailure(ani_env *env, ani_object thisObj,
    ani_long callbackLong, ani_string errorMessage)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    TAG_LOGD(AAFwkTag::STARTUP, "NativeOnTaskFailure called");
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::STARTUP, "env null");
        return;
    }

    auto weakCallback = reinterpret_cast<std::weak_ptr<StartupTaskResultCallback>*>(callbackLong);
    if (weakCallback == nullptr) {
        TAG_LOGE(AAFwkTag::STARTUP, "null weakCallback");
        return;
    }
    auto callback = weakCallback->lock();
    delete weakCallback;
    if (callback == nullptr) {
        TAG_LOGE(AAFwkTag::STARTUP, "null callback");
        return;
    }

    std::string strErrorMessage;
    if (!AppExecFwk::GetStdString(env, errorMessage, strErrorMessage)) {
        TAG_LOGE(AAFwkTag::STARTUP, "GetStdString failed.");
        strErrorMessage = "Unknown error";
    }
    std::shared_ptr<StartupTaskResult> taskResult = std::make_shared<EtsStartupTaskResult>(
        ERR_STARTUP_FAILED_TO_EXECUTE_STARTUP, strErrorMessage);
    PostMainThreadTask([callback, taskResult]() {
        if (callback == nullptr) {
            TAG_LOGE(AAFwkTag::STARTUP, "null callback");
            return;
        }
        TAG_LOGD(AAFwkTag::STARTUP, "PostMainThreadTask enter");
        callback->Call(taskResult);
    });
}

void ETSStartupTaskExecutor::PostMainThreadTask(std::function<void()> task)
{
    if (task == nullptr) {
        TAG_LOGE(AAFwkTag::STARTUP, "null task");
        return;
    }
    std::lock_guard<std::mutex> lock(g_mainHandlerMutex);
    if (g_mainHandler == nullptr) {
        g_mainHandler = std::make_shared<AppExecFwk::EventHandler>(AppExecFwk::EventRunner::GetMainEventRunner());
    }
    g_mainHandler->PostTask(task);
}

void ETSStartupTaskExecutorInit(ani_env *env)
{
    TAG_LOGI(AAFwkTag::STARTUP, "Init startup task executor");

    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::STARTUP, "env is null");
        return;
    }
    ani_class startupTaskExecutorCls = nullptr;
    auto status = env->FindClass("appstartup.StartupTaskExecutor.StartupTaskExecutor", &startupTaskExecutorCls);
    if (status != ANI_OK || startupTaskExecutorCls == nullptr) {
        TAG_LOGE(AAFwkTag::STARTUP, "find StartupTaskExecutor class failed");
        return;
    }

    std::array startupTaskExecutorNativeFuncs = {
        ani_native_function { "nativeOnTaskSuccess", "lY:",
            reinterpret_cast<void*>(ETSStartupTaskExecutor::NativeOnTaskSuccess) },
        ani_native_function { "nativeOnTaskFailure", "lC{std.core.String}:",
            reinterpret_cast<void*>(ETSStartupTaskExecutor::NativeOnTaskFailure) },
    };

    status = env->Class_BindNativeMethods(startupTaskExecutorCls,
        startupTaskExecutorNativeFuncs.data(),
        static_cast<int32_t>(startupTaskExecutorNativeFuncs.size()));
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::STARTUP, "bind StartupTaskExecutor native methods failed");
        return;
    }

    TAG_LOGI(AAFwkTag::STARTUP, "StartupTaskExecutor native methods bound successfully");
}

extern "C" {
ANI_EXPORT ani_status ANI_Constructor(ani_vm *vm, uint32_t *result)
{
    TAG_LOGD(AAFwkTag::STARTUP, "ANI_Constructor");
    ani_env *env = nullptr;
    ani_status status = ANI_ERROR;
    if (vm == nullptr) {
        TAG_LOGE(AAFwkTag::STARTUP, "null vm");
        return ANI_ERROR;
    }
    status = vm->GetEnv(ANI_VERSION_1, &env);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::STARTUP, "GetEnv failed status: %{public}d", status);
        return ANI_NOT_FOUND;
    }

    ETSStartupTaskExecutorInit(env);
    *result = ANI_VERSION_1;
    TAG_LOGD(AAFwkTag::STARTUP, "ANI_Constructor finish");
    return ANI_OK;
}
}
} // namespace AbilityRuntime
} // namespace OHOS