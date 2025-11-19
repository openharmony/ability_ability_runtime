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

#ifndef OHOS_ABILITY_RUNTIME_STAGE_CONTEXT_TRANSFER_H
#define OHOS_ABILITY_RUNTIME_STAGE_CONTEXT_TRANSFER_H

#include <memory>
#include <map>
#include <string>

#include "ani.h"
#include "app_startup_task.h"
#include "context.h"
#include "ets_runtime.h"
#include "native_engine/native_engine.h"

namespace OHOS {
namespace AbilityRuntime {
class StageContextTransfer {
public:
    StageContextTransfer() = default;
    ~StageContextTransfer() = default;

    StageContextTransfer(const StageContextTransfer&) = delete;
    StageContextTransfer(StageContextTransfer&&) = delete;
    StageContextTransfer &operator=(const StageContextTransfer&) = delete;
    StageContextTransfer &operator=(StageContextTransfer&&) = delete;

    static StageContextTransfer &GetInstance();

    static ani_ref GetStaticRef(ETSRuntime &etsRuntime, std::shared_ptr<NativeReference> contextRef);
    static ani_ref GetStaticRef(ani_env *aniEnv, std::shared_ptr<Context> stageContext);

    static NativeReference *GetDynamicRef(ETSRuntime &etsRuntime, ani_ref contextRef);
    static NativeReference *GetDynamicRef(napi_env napiEnv, std::shared_ptr<Context> stageContext);

    static std::shared_ptr<Context> UnwrapContext(ani_env *aniEnv, ani_ref contextRef);
    static std::shared_ptr<Context> UnwrapContext(napi_env napiEnv, std::shared_ptr<NativeReference> contextRef);

    void SaveContextRef(const std::string &moduleName, std::shared_ptr<NativeReference> ref);
    std::shared_ptr<NativeReference> GetContextRef(const std::string &moduleName);

private:
    static std::unique_ptr<NativeReference> CreateNativeReference(napi_env napiEnv,
        std::shared_ptr<Context> stageContext);

    std::map<std::string, std::shared_ptr<NativeReference>> contextRefMap_;
    std::mutex contextRefMapMutex_;
};
} // namespace AbilityRuntime
} // namespace OHOS
#endif // OHOS_ABILITY_RUNTIME_STAGE_CONTEXT_TRANSFER_H