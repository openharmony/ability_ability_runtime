/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#include "napi_common_execute_result.h"

#include "hilog_tag_wrapper.h"
#include "insight_intent_execute_result.h"
#include "napi_common_util.h"
#include "napi_common_want.h"
#include "want_params.h"
#include <memory>

namespace OHOS {
namespace AbilityRuntime {
using namespace OHOS::AppExecFwk;
bool UnwrapResultOfExecuteResult(napi_env env, napi_value param, InsightIntentExecuteResult &executeResult)
{
    napi_value result = nullptr;
    napi_get_named_property(env, param, "result", &result);
    if (result != nullptr) {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, result, &valueType);
        if (valueType != napi_object) {
            TAG_LOGE(AAFwkTag::BRIDGE, "type not function");
            return false;
        }
        auto wp = std::make_shared<AAFwk::WantParams>();
        if (!AppExecFwk::UnwrapWantParams(env, result, *wp)) {
            TAG_LOGE(AAFwkTag::BRIDGE, "unwrap want failed");
            return false;
        }
        if (!executeResult.CheckResult(wp)) {
            TAG_LOGE(AAFwkTag::BRIDGE, "Check wp fail");
            return false;
        }
        executeResult.result = wp;
    }
    return true;
}

bool UnwrapResultOfDecoratorExecuteResult(napi_env env, napi_value param, InsightIntentExecuteResult &executeResult)
{
    if (param == nullptr) {
        TAG_LOGE(AAFwkTag::BRIDGE, "decorator param null");
        return false;
    }
    napi_valuetype valueType = napi_undefined;
    napi_typeof(env, param, &valueType);
    if (valueType != napi_object) {
        TAG_LOGE(AAFwkTag::BRIDGE, "type not object");
        return false;
    }
    auto wp = std::make_shared<AAFwk::WantParams>();
    if (!AppExecFwk::UnwrapWantParams(env, param, *wp)) {
        TAG_LOGE(AAFwkTag::BRIDGE, "unwrap want failed");
        return false;
    }
    if (!executeResult.CheckResult(wp)) {
        TAG_LOGE(AAFwkTag::BRIDGE, "Check wp fail");
        return false;
    }
    executeResult.result = wp;
    return true;
}

bool UnwrapExecuteResult(
    napi_env env, napi_value param, InsightIntentExecuteResult &executeResult, bool isDecorator)
{
    TAG_LOGD(AAFwkTag::BRIDGE, "called");

    if (!IsTypeForNapiValue(env, param, napi_valuetype::napi_object)) {
        TAG_LOGE(AAFwkTag::BRIDGE, "UnwrapExecuteResult not object");
        return false;
    }
    if (isDecorator) {
        executeResult.isDecorator = true;
        if (!UnwrapResultOfDecoratorExecuteResult(env, param, executeResult)) {
            TAG_LOGE(AAFwkTag::BRIDGE, "unwrap decorator fail");
            return false;
        }
        return true;
    }

    int32_t code = 0;
    if (!UnwrapInt32ByPropertyName(env, param, "code", code)) {
        TAG_LOGE(AAFwkTag::BRIDGE, "parse code fail");
        return false;
    }
    executeResult.code = code;

    if (IsExistsByPropertyName(env, param, "result")) {
        if (!UnwrapResultOfExecuteResult(env, param, executeResult)) {
            TAG_LOGE(AAFwkTag::BRIDGE, "unwrap result fail");
            return false;
        }
    }

    if (IsExistsByPropertyName(env, param, "uris")) {
        std::vector<std::string> uris;
        if (!UnwrapStringArrayByPropertyName(env, param, "uris", uris)) {
            TAG_LOGE(AAFwkTag::BRIDGE, "unwrap uris is null");
            return false;
        }
        executeResult.uris = uris;
    }

    if (IsExistsByPropertyName(env, param, "flags")) {
        int32_t flags = 0;
        if (!UnwrapInt32ByPropertyName(env, param, "flags", flags)) {
            TAG_LOGE(AAFwkTag::BRIDGE, "unwrap flags is null");
            return false;
        }
        executeResult.flags = flags;
    }

    return true;
}
}  // namespace AbilityRuntime
}  // namespace OHOS
