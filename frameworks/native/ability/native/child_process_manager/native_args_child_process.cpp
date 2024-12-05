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

#include "native_args_child_process.h"

#include <dlfcn.h>
#include "hilog_tag_wrapper.h"
#include "securec.h"

namespace OHOS {
namespace AbilityRuntime {

std::shared_ptr<ChildProcess> NativeArgsChildProcess::Create()
{
    return std::make_shared<NativeArgsChildProcess>();
}

NativeArgsChildProcess::~NativeArgsChildProcess()
{
    UnloadNativeLib();
}

bool NativeArgsChildProcess::Init(const std::shared_ptr<ChildProcessStartInfo> &info)
{
    TAG_LOGD(AAFwkTag::PROCESSMGR, "NativeArgsChildProcess init called.");
    if (info == nullptr) {
        TAG_LOGE(AAFwkTag::PROCESSMGR, "null info");
        return false;
    }

    if (!ChildProcess::Init(info)) {
        TAG_LOGE(AAFwkTag::PROCESSMGR, "base class init failed");
        return false;
    }

    return LoadNativeLib(info);
}

void NativeArgsChildProcess::OnStart(std::shared_ptr<AppExecFwk::ChildProcessArgs> args)
{
    if (args == nullptr) {
        TAG_LOGE(AAFwkTag::PROCESSMGR, "null args");
        return;
    }
    ChildProcess::OnStart(args);

    TAG_LOGI(AAFwkTag::PROCESSMGR, "Enter native lib entry function");
    auto nativeArgs = ParseToNativeArgs(args->entryParams, args->fds);

    if (!entryFunc_) {
        TAG_LOGE(AAFwkTag::PROCESSMGR, "null entryFunc");
        return;
    }
    entryFunc_(nativeArgs);
    TAG_LOGI(AAFwkTag::PROCESSMGR, "Native lib entry function returned");
}

NativeChildProcess_Args NativeArgsChildProcess::ParseToNativeArgs(const std::string &entryParams,
    const std::map<std::string, int32_t> &fds)
{
    NativeChildProcess_Args args;
    args.fdList.head = nullptr;
    args.entryParams = new(std::nothrow) char[entryParams.size() + 1];
    if (!args.entryParams) {
        TAG_LOGE(AAFwkTag::PROCESSMGR, "null entryParams");
        return args;
    }
    if (strcpy_s(args.entryParams, entryParams.size() + 1, entryParams.c_str()) != ERR_OK) {
        delete[] args.entryParams;
        args.entryParams = nullptr;
        TAG_LOGE(AAFwkTag::APPKIT, "strcpy_s failed");
        return args;
    }
    NativeChildProcess_Fd *tail = nullptr;
    for (const auto &fd : fds) {
        auto &fdName = fd.first;
        auto fdValue = fd.second;

        NativeChildProcess_Fd *node = new(std::nothrow) NativeChildProcess_Fd;
        if (!node) {
            TAG_LOGE(AAFwkTag::PROCESSMGR, "null node");
            return args;
        }
        node->next = nullptr;
        node->fdName = new char[fdName.size() + 1];
        if (strcpy_s(node->fdName, fdName.size() + 1, fdName.c_str()) != ERR_OK) {
            delete[] node->fdName;
            node->fdName = nullptr;
            delete node;
            node = nullptr;
            TAG_LOGE(AAFwkTag::APPKIT, "strcpy_s failed");
            return args;
        }
        node->fd = fdValue;

        if (!args.fdList.head) {
            args.fdList.head = node;
        } else {
            tail->next = node;
        }
        tail = node;
    }
    return args;
}

bool NativeArgsChildProcess::LoadNativeLib(const std::shared_ptr<ChildProcessStartInfo> &info)
{
    if (info == nullptr) {
        TAG_LOGE(AAFwkTag::PROCESSMGR, "null info");
        return false;
    }
    TAG_LOGI(AAFwkTag::PROCESSMGR, "LoadNativeLib, moduleName:%{public}s, srcEntry:%{public}s, entryFunc:%{public}s",
        info->moduleName.c_str(), info->srcEntry.c_str(), info->entryFunc.c_str());
    if (nativeLibHandle_ != nullptr) {
        TAG_LOGE(AAFwkTag::PROCESSMGR, "null nativeLibHandle_");
        return false;
    }

    if (info->moduleName.empty()) {
        TAG_LOGE(AAFwkTag::PROCESSMGR, "moduleName empty");
        return false;
    }

    Dl_namespace dlnsApp;
    std::string appDlNameSpace = "moduleNs_" + info->moduleName;
    int ret = dlns_get(appDlNameSpace.c_str(), &dlnsApp);
    if (ret != 0) {
        TAG_LOGE(AAFwkTag::PROCESSMGR, "Get app dlNamespace(%{private}s) failed, err:%{public}d",
            appDlNameSpace.c_str(), ret);
        return false;
    }

    void *libHandle = dlopen_ns(&dlnsApp, info->srcEntry.c_str(), RTLD_LAZY);
    if (libHandle == nullptr) {
        TAG_LOGE(AAFwkTag::PROCESSMGR, "Load lib file %{private}s failed, err %{public}s",
            info->srcEntry.c_str(), dlerror());
        return false;
    }

    auto entryFunc = reinterpret_cast<NativeArgsChildProcess_EntryFunc>(dlsym(libHandle, info->entryFunc.c_str()));
    if (entryFunc == nullptr) {
        TAG_LOGE(AAFwkTag::PROCESSMGR, "null entryFunc, err %{public}s", dlerror());
        dlclose(libHandle);
        return false;
    }

    entryFunc_ = entryFunc;
    nativeLibHandle_ = libHandle;
    return true;
}

void NativeArgsChildProcess::UnloadNativeLib()
{
    if (nativeLibHandle_ != nullptr) {
        dlclose(nativeLibHandle_);
        nativeLibHandle_ = nullptr;
        entryFunc_ = nullptr;
    }
}

} // namespace AbilityRuntime
} // namespace OHOS