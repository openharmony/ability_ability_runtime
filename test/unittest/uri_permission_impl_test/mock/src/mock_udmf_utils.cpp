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

#include "upms_udmf_utils.h"
#include "mock_my_flag.h"

namespace OHOS {
namespace AAFwk {
using MyFlag = OHOS::AAFwk::MyFlag;

int32_t UDMFUtils::GetBatchData(const std::string &key, std::vector<std::string> &uris)
{
    return 0;
}

int32_t UDMFUtils::AddPrivilege(const std::string &key, uint32_t tokenId, const std::string &readPermission)
{
    return 0;
}

int32_t UDMFUtils::ProcessUdmfKey(const std::string &key, uint32_t callerTokenId, uint32_t targetTokenId,
    std::vector<std::string> &uris)
{
    uris = MyFlag::udmfUtilsUris_;
    return MyFlag::processUdmfKeyRet_;
}
} // OHOS
} // AAFwk