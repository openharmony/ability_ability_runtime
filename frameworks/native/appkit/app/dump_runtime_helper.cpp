/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "dump_runtime_helper.h"

#include "app_mgr_client.h"
#include "faultloggerd_client.h"
#include "hilog_tag_wrapper.h"
#include "js_runtime.h"
#include "js_runtime_utils.h"
#include "singleton.h"
#include "dfx_jsnapi.h"

namespace OHOS {
namespace AppExecFwk {
const char *MODULE_NAME = "hiviewdfx.jsLeakWatcher";
const char *CHECK = "check";
const char *REQUIRE_NAPI = "requireNapi";

DumpRuntimeHelper::DumpRuntimeHelper(const std::shared_ptr<OHOSApplication> &application)
    : application_(application)
{}

void DumpRuntimeHelper::SetAppFreezeFilterCallback()
{
    if (application_ == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null application");
        return;
    }
    auto& runtime = application_->GetRuntime();
    if (runtime == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null runtime");
        return;
    }
    auto appfreezeFilterCallback = [] (const int32_t pid) -> bool {
        auto client = DelayedSingleton<AppExecFwk::AppMgrClient>::GetInstance();
        if (client == nullptr) {
            TAG_LOGE(AAFwkTag::APPKIT, "null client");
            return false;
        }
        return client->SetAppFreezeFilter(pid);
    };
    auto vm = (static_cast<AbilityRuntime::JsRuntime&>(*runtime)).GetEcmaVm();
    panda::DFXJSNApi::SetAppFreezeFilterCallback(vm, appfreezeFilterCallback);
}

void DumpRuntimeHelper::DumpJsHeap(const OHOS::AppExecFwk::JsHeapDumpInfo &info)
{
    if (application_ == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null application");
        return;
    }
    auto& runtime = application_->GetRuntime();
    if (runtime == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null runtime");
        return;
    }
    if (info.needLeakobj) {
        std::string checkList = "";
        GetCheckList(runtime, checkList);
        WriteCheckList(checkList);
    }

    if (info.needSnapshot == true) {
        runtime->DumpHeapSnapshot(info.tid, info.needGc);
    } else {
        if (info.needGc == true) {
            runtime->ForceFullGC(info.tid);
        }
    }
}

void DumpRuntimeHelper::GetCheckList(const std::unique_ptr<AbilityRuntime::Runtime> &runtime, std::string &checkList)
{
    if (runtime->GetLanguage() != AbilityRuntime::Runtime::Language::JS) {
        TAG_LOGE(AAFwkTag::APPKIT, "current language not js");
        return;
    }
    AbilityRuntime::JsRuntime &jsruntime = static_cast<AbilityRuntime::JsRuntime&>(*runtime);
    AbilityRuntime::HandleScope handleScope(jsruntime);
    auto env = jsruntime.GetNapiEnv();

    napi_value global = nullptr;
    napi_get_global(env, &global);
    napi_value requireValue = GetJsLeakModule(env, global);
    if (requireValue == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null requireValue");
        return;
    }
    napi_value result = GetMethodCheck(env, requireValue, global);
    if (result == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null result");
        return;
    }

    size_t checkListSize = 0;
    napi_get_value_string_utf8(env, result, nullptr, 0, &checkListSize);
    checkList.resize(checkListSize + 1);
    napi_get_value_string_utf8(env, result, &checkList[0], checkListSize + 1, &checkListSize);
}

napi_value DumpRuntimeHelper::GetJsLeakModule(napi_env env, napi_value global)
{
    napi_value napiFunc = nullptr;
    napi_status status = napi_get_named_property(env, global, REQUIRE_NAPI, &napiFunc);
    if (status != napi_ok) {
        TAG_LOGE(AAFwkTag::APPKIT, "fail, %{public}d", status);
        return nullptr;
    }
    napi_value moduleName = nullptr;
    napi_create_string_utf8(env, MODULE_NAME, strlen(MODULE_NAME), &moduleName);
    napi_value param[1] = {moduleName};
    napi_value requireValue = nullptr;
    status = napi_call_function(env, global, napiFunc, 1, &param[0], &requireValue);
    if (status != napi_ok) {
        TAG_LOGE(AAFwkTag::APPKIT, "fail, %{public}d", status);
        return nullptr;
    }
    return requireValue;
}

napi_value DumpRuntimeHelper::GetMethodCheck(napi_env env, napi_value requireValue, napi_value global)
{
    napi_value methodCheck = nullptr;
    napi_status status = napi_get_named_property(env, requireValue, CHECK, &methodCheck);
    if (status != napi_ok) {
        TAG_LOGE(AAFwkTag::APPKIT, "fail, %{public}d", status);
        return nullptr;
    }
    napi_valuetype valuetype = napi_undefined;
    status = napi_typeof(env, methodCheck, &valuetype);
    if (status != napi_ok) {
        TAG_LOGE(AAFwkTag::APPKIT, "failed, %{public}d", status);
        return nullptr;
    }
    napi_value result = nullptr;
    status = napi_call_function(env, global, methodCheck, 0, nullptr, &result);
    if (status != napi_ok) {
        TAG_LOGE(AAFwkTag::APPKIT, "fail, %{public}d", status);
        return nullptr;
    }
    return result;
}

void DumpRuntimeHelper::WriteCheckList(const std::string &checkList)
{
    TAG_LOGD(AAFwkTag::APPKIT, "called");
    int32_t fd = RequestFileDescriptor(static_cast<int32_t>(FaultLoggerType::JS_HEAP_LEAK_LIST));
    if (fd < 0) {
        TAG_LOGE(AAFwkTag::APPKIT, "fd:%{public}d.\n", fd);
        return;
    }
    if (write(fd, checkList.c_str(), strlen(checkList.c_str())) == -1) {
        TAG_LOGE(AAFwkTag::APPKIT, "fd:%{public}d, errno:%{public}d.\n", fd, errno);
        close(fd);
        return;
    }
    close(fd);
}

} // namespace AppExecFwk
} // namespace OHOS
