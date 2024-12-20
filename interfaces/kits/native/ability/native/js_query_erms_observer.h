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

#ifndef OHOS_ABILITY_RUNTIME_JS_QUERY_ERMS_OBSERVER_H
#define OHOS_ABILITY_RUNTIME_JS_QUERY_ERMS_OBSERVER_H

#include <memory>
#include <string>
#include <vector>

#include "native_engine/native_engine.h"
#include "query_erms_observer_stub.h"
#include "js_runtime_utils.h"

namespace OHOS {
namespace AbilityRuntime {
struct JsQueryERMSObserverObject {
    std::string appId;
    std::string startTime;
    napi_deferred deferred;
};

class JsQueryERMSObserver : public QueryERMSObserverStub {
public:
    /**
     * JsQueryERMSObserver, constructor.
     *
     */
    explicit JsQueryERMSObserver(napi_env env);

    /**
     * JsQueryERMSObserver, destructor.
     *
     */
    ~JsQueryERMSObserver();

    /**
     * OnQueryFinished, return free install result.
     *
     * @param appId Query ERMS app id.
     * @param startTime Free install start request time.
     * @param rule The ERMS query result.
     * @param resultCode The result code.
     */
    void OnQueryFinished(const std::string &appId, const std::string &startTime,
        const AtomicServiceStartupRule &rule, int32_t resultCode) override;

    /**
     * @brief Use for context to add an callback into the observer.
     *
     * @param appId Query ERMS app id.
     * @param startTime The start time.
     * @param result the promise to return.
     */
    void AddJsObserverObject(const std::string &appId, const std::string &startTime, napi_value* result);

private:
    /**
     * CallPromise, resolve promise.
     *
     * @param deferred The promise that is to be resolved.
     * @param rule The ERMS query result.
     * @param resultCode The result code.
     */
    void CallPromise(napi_deferred deferred, const AtomicServiceStartupRule &rule, int32_t resultCode);

    /**
     * HandleOnQueryFinished, handle the event of free install upon finished.
     *
     * @param appId Query ERMS app id.
     * @param startTime The start time.
     * @param rule The ERMS query result.
     * @param resultCode The result code.
     */
    void HandleOnQueryFinished(const std::string &appId, const std::string &startTime,
        const AtomicServiceStartupRule &rule, int32_t resultCode);

    /**
     * CreateJsAtomicServiceStartupRule, create js atomic service startup rule.
     *
     * @param env The env.
     * @param rule The ERMS query result.
     */
    napi_value CreateJsAtomicServiceStartupRule(napi_env env, const AbilityRuntime::AtomicServiceStartupRule &rule);

    napi_env env_;
    std::mutex jsObserverObjectListLock_;
    std::vector<JsQueryERMSObserverObject> jsObserverObjectList_;
};
} // namespace AbilityRuntime
} // namespace OHOS

#endif // OHOS_ABILITY_RUNTIME_JS_QUERY_ERMS_OBSERVER_H