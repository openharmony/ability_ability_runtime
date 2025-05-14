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

#ifndef OHOS_ABILITY_RUNTIME_EXECUTE_OHMURL_OPERATOR_H
#define OHOS_ABILITY_RUNTIME_EXECUTE_OHMURL_OPERATOR_H

#include "hilog_tag_wrapper.h"
#include "js_runtime.h"

namespace OHOS {
namespace AbilityRuntime {
using ExecuteOhmUrlCallback = std::function<void()>;
class ExecuteOhmUrlOperator final {
public:
    ExecuteOhmUrlOperator(JsRuntime& runtime, const std::string &moduleName, const std::string &hapPath,
        const std::string &srcEntrance) : runtime_(runtime), moduleName_(moduleName), hapPath_(hapPath),
        srcEntrance_(srcEntrance)
    {}

    ~ExecuteOhmUrlOperator() = default;

    void operator()()
    {
        TAG_LOGD(AAFwkTag::INTENT, "Execute ohmurl, moduleName %{public}s, srcEntrance %{private}s",
            moduleName_.c_str(), srcEntrance_.c_str());
        auto ret = runtime_.ExecuteSecureWithOhmUrl(moduleName_, hapPath_, srcEntrance_);
        if (!ret) {
            TAG_LOGE(AAFwkTag::INTENT, "Execute ohmurl failed, moduleName %{public}s, srcEntrance %{private}s",
                moduleName_.c_str(), srcEntrance_.c_str());
        }
    }

private:
    JsRuntime& runtime_;
    std::string moduleName_;
    std::string hapPath_;
    std::string srcEntrance_;
};
} // namespace AbilityRuntime
} // namespace OHOS
#endif // OHOS_ABILITY_RUNTIME_EXECUTE_OHMURL_OPERATOR_H
