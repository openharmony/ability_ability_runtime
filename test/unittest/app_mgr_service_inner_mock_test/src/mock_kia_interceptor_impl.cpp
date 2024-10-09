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

#include "mock_kia_interceptor_impl.h"

#include "constants.h"

namespace OHOS {
namespace AppExecFwk {
int MockKiaInterceptorImpl::onInterceptRetCode = 0;
std::string MockKiaInterceptorImpl::kiaWatermarkBusinessName;
bool MockKiaInterceptorImpl::isWatermarkEnabled = false;

int MockKiaInterceptorImpl::OnIntercept(AAFwk::Want &want)
{
    if (onInterceptRetCode != 0) {
        return onInterceptRetCode;
    }

    want.SetParam(KEY_WATERMARK_BUSINESS_NAME, kiaWatermarkBusinessName);
    want.SetParam(KEY_IS_WATERMARK_ENABLED, isWatermarkEnabled);
    return onInterceptRetCode;
}
}  // namespace AppExecFwk
}  // namespace OHOS
