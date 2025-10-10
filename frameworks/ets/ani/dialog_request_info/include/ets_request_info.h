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

#ifndef OHOS_ABILITY_RUNTIME_ETS_REQUEST_INFO_H
#define OHOS_ABILITY_RUNTIME_ETS_REQUEST_INFO_H

#include "iremote_object.h"
#include "ani.h"

namespace OHOS {
namespace AbilityRuntime {
class RequestInfo {
public:
    RequestInfo(const sptr<IRemoteObject> &token, int32_t left, int32_t top, int32_t width, int32_t height);
    ~RequestInfo();
    static ani_object WrapRequestInfo(ani_env *env, RequestInfo *request);
    static std::shared_ptr<RequestInfo> UnwrapRequestInfo(ani_env *env, ani_object param);
    sptr<IRemoteObject> GetToken();
    static ani_object CreateEtsWindowRect(
        ani_env *env, int32_t left, int32_t top, int32_t width, int32_t height);
private:
    sptr<IRemoteObject> callerToken_;
    int32_t left_ = 0;
    int32_t top_ = 0;
    int32_t width_ = 0;
    int32_t height_ = 0;
};
}  // namespace AbilityRuntime
}  // namespace OHOS
#endif // OHOS_ABILITY_RUNTIME_REQUEST_INFO_H
