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

#ifndef ABILITY_ABILITY_RUNTIME_JS_RUNTIME_LITE_H
#define ABILITY_ABILITY_RUNTIME_JS_RUNTIME_LITE_H

#include <mutex>
#include <thread>
#include <unordered_map>
#include <unordered_set>

#include "js_environment.h"
#include "native_engine/native_engine.h"
#include "runtime.h"
#include <nlohmann/json.hpp>

using Options = OHOS::AbilityRuntime::Runtime::Options;
namespace OHOS {
namespace AbilityRuntime {
class JsRuntimeLite {
public:
    JsRuntimeLite(const JsRuntimeLite&) = delete;
    JsRuntimeLite& operator=(const JsRuntimeLite&) = delete;
    void GetPkgContextInfoListMap(const std::map<std::string, std::string> &contextInfoMap,
        std::map<std::string, std::vector<std::vector<std::string>>> &pkgContextInfoMap,
        std::map<std::string, std::string> &pkgAliasMap);
    static JsRuntimeLite& GetInstance();
    static void InitJsRuntimeLite(const Options& options);
    std::shared_ptr<Options> GetChildOptions();
    napi_status CreateJsEnv(const Options& options, std::shared_ptr<JsEnv::JsEnvironment>& jsEnv);
    napi_status RemoveJsEnv(napi_env env);
    napi_status Init(const Options& options, napi_env env);
    
private:
    JsRuntimeLite();
    ~JsRuntimeLite();
    napi_status AddEnv(napi_env env, std::shared_ptr<JsEnv::JsEnvironment> jsEnv);
    panda::ecmascript::EcmaVM* GetEcmaVm(const std::shared_ptr<JsEnv::JsEnvironment>& jsEnv) const;
    std::shared_ptr<JsEnv::JsEnvironment> GetJsEnv(napi_env env);
    void LoadAotFile(const Options& options, const std::shared_ptr<JsEnv::JsEnvironment>& jsEnv);
    void InitConsoleModule(const std::shared_ptr<JsEnv::JsEnvironment>& jsEnv);
    void InitTimerModule(const std::shared_ptr<JsEnv::JsEnvironment>& jsEnv);
    void SetModuleLoadChecker(const std::shared_ptr<ModuleCheckerDelegate>& moduleCheckerDelegate,
        const std::shared_ptr<JsEnv::JsEnvironment>& jsEnv);
    void SetRequestAotCallback(const std::shared_ptr<JsEnv::JsEnvironment>& jsEnv);
    bool InitLoop(const std::shared_ptr<JsEnv::JsEnvironment>& jsEnv);
    void InitWorkerModule(const Options& options, const std::shared_ptr<JsEnv::JsEnvironment>& jsEnv);
    void ParsePkgContextInfoJson(
        nlohmann::json &pkgJson, std::vector<std::vector<std::string>> &pkgContextInfoList,
        std::map<std::string, std::string> &pkgAliasMap);
    void ParsePkgContextInfoJsonString(
        const nlohmann::json &itemObject, const std::string &key, std::vector<std::string> &items);
    void SetChildOptions(const Options& options);
    std::unordered_map<napi_env, std::shared_ptr<JsEnv::JsEnvironment>> envMap_;
    std::unordered_set<pid_t> threadIds_;
    bool preloaded_ = false;
    std::mutex envMutex_;
    std::mutex childOptionsMutex_;
    std::shared_ptr<Options> childOptions_;
};
} // namespace AbilityRuntime
} // namespace OHOS
#endif // ABILITY_ABILITY_RUNTIME_JS_RUNTIME_LITE_H