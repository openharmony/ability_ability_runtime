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

#include "native_child_process.h"
#include <map>
#include <mutex>
#include "hilog_tag_wrapper.h"
#include "native_child_callback.h"
#include "child_process_args_manager.h"
#include "child_process_manager.h"
#include "child_callback_manager.h"
#include "child_process_manager_error_utils.h"
#include "app_mgr_client.h"

using namespace OHOS;
using namespace OHOS::AbilityRuntime;

namespace {

std::mutex g_mutexCallBackObj;
constexpr size_t MAX_KEY_SIZE = 20;
constexpr size_t MAX_FD_SIZE = 16;

} // Anonymous namespace

int OH_Ability_CreateNativeChildProcess(const char* libName, OH_Ability_OnNativeChildProcessStarted onProcessStarted)
{
    if (libName == nullptr || *libName == '\0' || onProcessStarted == nullptr) {
        TAG_LOGE(AAFwkTag::PROCESSMGR, "null libname or callback");
        return NCP_ERR_INVALID_PARAM;
    }

    std::string strLibName(libName);
    if (strLibName.find("../") != std::string::npos) {
        TAG_LOGE(AAFwkTag::PROCESSMGR, "relative path not allow");
        return NCP_ERR_INVALID_PARAM;
    }

    sptr<IRemoteObject> callbackStub(new (std::nothrow) NativeChildCallback(onProcessStarted));
    if (!callbackStub) {
        TAG_LOGE(AAFwkTag::PROCESSMGR, "null callbackStub");
        return NCP_ERR_INTERNAL;
    }

    ChildProcessManager &mgr = ChildProcessManager::GetInstance();
    auto cpmErr = mgr.StartNativeChildProcessByAppSpawnFork(strLibName, callbackStub);
    if (cpmErr != ChildProcessManagerErrorCode::ERR_OK) {
        return ChildProcessManagerErrorUtil::CvtChildProcessManagerErrCode(cpmErr);
    }

    ChildCallbackManager::GetInstance().AddRemoteObject(callbackStub);
    return NCP_NO_ERROR;
}

Ability_NativeChildProcess_ErrCode OH_Ability_StartNativeChildProcess(const char* entry,
    NativeChildProcess_Args args, NativeChildProcess_Options options, int32_t *pid)
{
    if (entry == nullptr || *entry == '\0') {
        TAG_LOGE(AAFwkTag::PROCESSMGR, "Invalid entry");
        return NCP_ERR_INVALID_PARAM;
    }
    std::string entryName(entry);
    if (entryName.find(":") == std::string::npos) {
        TAG_LOGE(AAFwkTag::PROCESSMGR, "entry point misses a colon");
        return NCP_ERR_INVALID_PARAM;
    }
    if (pid == nullptr) {
        TAG_LOGE(AAFwkTag::PROCESSMGR, "pid null");
        return NCP_ERR_INVALID_PARAM;
    }

    std::map<std::string, int32_t> fds;
    NativeChildProcess_Fd* cur = args.fdList.head;
    while (cur != nullptr) {
        if (!cur->fdName) {
            TAG_LOGE(AAFwkTag::PROCESSMGR, "fdName null");
            return NCP_ERR_INVALID_PARAM;
        }
        std::string key(cur->fdName);
        if (key.size() > MAX_KEY_SIZE) {
            TAG_LOGE(AAFwkTag::PROCESSMGR, "fd name too long");
            return NCP_ERR_INVALID_PARAM;
        }
        fds.emplace(key, cur->fd);
        cur = cur->next;
    }
    if (fds.size() > MAX_FD_SIZE) {
        TAG_LOGE(AAFwkTag::PROCESSMGR, "too many fds");
        return NCP_ERR_INVALID_PARAM;
    }
    AppExecFwk::ChildProcessArgs childArgs;
    childArgs.fds = fds;
    if (args.entryParams != nullptr && *(args.entryParams) != '\0') {
        std::string entryParams(args.entryParams);
        childArgs.entryParams = entryParams;
    }
    AppExecFwk::ChildProcessOptions childProcessOptions;
    childProcessOptions.isolationMode = options.isolationMode == NCP_ISOLATION_MODE_ISOLATED;
    int32_t childProcessType = AppExecFwk::CHILD_PROCESS_TYPE_NATIVE_ARGS;

    ChildProcessManager &mgr = ChildProcessManager::GetInstance();
    auto cpmErr = mgr.StartChildProcessWithArgs(entryName, *pid, childProcessType, childArgs, childProcessOptions);
    if (cpmErr != ChildProcessManagerErrorCode::ERR_OK) {
        return ChildProcessManagerErrorUtil::CvtChildProcessManagerErrCode(cpmErr);
    }
    return NCP_NO_ERROR;
}

NativeChildProcess_Args* OH_Ability_GetCurrentChildProcessArgs()
{
    NativeChildProcess_Args* result = ChildProcessArgsManager::GetInstance().GetChildProcessArgs();
    if (result == nullptr) {
        TAG_LOGE(AAFwkTag::PROCESSMGR, "GetChildProcessArgs null");
    }
    return result;
}

Ability_NativeChildProcess_ErrCode OH_Ability_RegisterNativeChildProcessExitCallback(
    OH_Ability_OnNativeChildProcessExit onProcessExit)
{
    if (onProcessExit == nullptr) {
        TAG_LOGE(AAFwkTag::PROCESSMGR, "null callback func pointer");
        return NCP_ERR_INVALID_PARAM;
    }

    sptr<OHOS::AppExecFwk::INativeChildNotify> callbackStub(new (std::nothrow)) NativeChildCallback(nullptr, onProcessExit);
    if (!callbackStub) {
        TAG_LOGE(AAFwkTag::PROCESSMGR, "null callbackStub");
        return NCP_ERR_INTERNAL;
    }

    auto appMgrClient = std::make_shared<OHOS::AppExecFwk::AppMgrClient>();
    if (!appMgrClient) {
        TAG_LOGE(AAFwkTag::PROCESSMGR, "null appMgrClient");
        return NCP_ERR_INTERNAL;
    }

    auto ret = appMgrClient->RegisterNativeChildExitNotify(callbackStub);
    if (ret != NCP_NO_ERROR) {
        TAG_LOGE(AAFwkTag::PROCESSMGR, "register native child exit notify failed, %{public}d", ret);
        return NCP_ERR_INTERNAL;
    }

    return NCP_NO_ERROR;
}

Ability_NativeChildProcess_ErrCode OH_Ability_UnregisterNativeChildProcessExitCallback(
    OH_Ability_OnNativeChildProcessExit onProcessExit)
{
    if (onProcessExit == nullptr) {
        TAG_LOGE(AAFwkTag::PROCESSMGR, "null callback func pointer");
        return NCP_ERR_INVALID_PARAM;
    }

    sptr<OHOS::AppExecFwk::INativeChildNotify> callbackStub(new (std::nothrow)) NativeChildCallback(nullptr, onProcessExit);
    if (!callbackStub) {
        TAG_LOGE(AAFwkTag::PROCESSMGR, "null callbackStub");
        return NCP_ERR_INTERNAL;
    }

    auto appMgrClient = std::make_shared<OHOS::AppExecFwk::AppMgrClient>();
    if (!appMgrClient) {
        TAG_LOGE(AAFwkTag::PROCESSMGR, "null appMgrClient");
        return NCP_ERR_INTERNAL;
    }

    auto ret = appMgrClient->UnregisterNativeChildExitNotify(callbackStub);
    if (ret == AAFwk::ERR_NATIVE_CHILD_EXIT_CALLBACK_NOT_EXIST) {
        TAG_LOGE(AAFwkTag::PROCESSMGR, "native chlid exit callback not exist, %{public}d", ret);
        return NCP_ERR_CALLBACK_NOT_EXIST;
    } else if (ret != NCP_NO_ERROR) {
        TAG_LOGE(AAFwkTag::PROCESSMGR, "unregister native child exit notify failed, %{public}d", ret);
        return NCP_ERR_INTERNAL;
    }

    return NCP_NO_ERROR;
}
