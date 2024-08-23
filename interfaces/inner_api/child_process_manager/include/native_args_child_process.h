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

#ifndef OHOS_ABILITY_RUNTIME_NATIVE_ARGS_CHILD_PROCESS_H
#define OHOS_ABILITY_RUNTIME_NATIVE_ARGS_CHILD_PROCESS_H

#include <memory>
#include <string>

#include "child_process.h"
#include "native_child_process.h"

namespace OHOS {
namespace AbilityRuntime {

class NativeArgsChildProcess : public ChildProcess {
public:
    NativeArgsChildProcess() = default;
    ~NativeArgsChildProcess();

    static std::shared_ptr<ChildProcess> Create();
    
    bool Init(const std::shared_ptr<ChildProcessStartInfo> &info) override;
    void OnStart(std::shared_ptr<AppExecFwk::ChildProcessArgs> args) override;

private:
    bool LoadNativeLib(const std::shared_ptr<ChildProcessStartInfo> &info);
    void UnloadNativeLib();
    NativeChildProcess_Args ParseToNativeArgs(const std::string &entryParams,
        const std::map<std::string, int32_t> &fds);
    typedef void (*NativeArgsChildProcess_EntryFunc)(NativeChildProcess_Args args);

    void *nativeLibHandle_ = nullptr;
    NativeArgsChildProcess_EntryFunc entryFunc_ = nullptr;
};
} // namespace AbilityRuntime
} // namespace OHOS
#endif // OHOS_ABILITY_RUNTIME_NATIVE_ARGS_CHILD_PROCESS_H