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

#include "ability_manager_errors.h"
#include "hilog_tag_wrapper.h"
#include "hitrace_meter.h"
#include "in_process_call_wrapper.h"
#include "udmf_client.h"
#include "uri.h"

namespace OHOS {
namespace AAFwk {
namespace {
constexpr const char *UDMF_FILE_URI_ENTRY = "general.file-uri";
constexpr const char *UDMF_ORI_URI = "oriUri";
constexpr const char *FILE_SCHEME = "file";
}

int32_t UDMFUtils::GetBatchData(const std::string &key, std::vector<std::string> &uris)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    TAG_LOGI(AAFwkTag::URIPERMMGR, "GetBatchData call");
    uris.clear();
    UDMF::QueryOption query = { .key = key };
    std::vector<UDMF::UnifiedData> unifiedDataset;
    auto ret = IN_PROCESS_CALL(UDMF::UdmfClient::GetInstance().GetBatchData(query, unifiedDataset));
    if (ret != ERR_OK) {
        TAG_LOGE(AAFwkTag::URIPERMMGR, "GetBatchData failed:%{public}d", ret);
        return ret;
    }
    for (size_t i = 0; i < unifiedDataset.size(); i++) {
        std::vector<std::shared_ptr<UDMF::UnifiedRecord>> records = unifiedDataset[i].GetRecords();
        for (const auto &record : records) {
            auto fileEntry = record->GetEntry(UDMF_FILE_URI_ENTRY);
            std::shared_ptr<UDMF::Object> fileEntryObj = std::get<std::shared_ptr<UDMF::Object>>(fileEntry);
            if (fileEntryObj == nullptr) {
                TAG_LOGE(AAFwkTag::URIPERMMGR, "file entry obj null");
                return ERR_UPMS_GET_ORI_URI_FAILED;
            }
            std::string oriUri;
            fileEntryObj->GetValue(UDMF_ORI_URI, oriUri);
            if (oriUri.empty()) {
                TAG_LOGE(AAFwkTag::URIPERMMGR, "get oriUri failed");
                return ERR_UPMS_GET_ORI_URI_FAILED;
            }
            Uri uri(oriUri);
            if (uri.GetScheme() != FILE_SCHEME) {
                TAG_LOGE(AAFwkTag::URIPERMMGR, "not file uri:%{public}s", uri.GetScheme().c_str());
                return ERR_UPMS_NOT_FILE_URI;
            }
            uris.emplace_back(oriUri);
        }
    }
    if (uris.empty()) {
        TAG_LOGE(AAFwkTag::URIPERMMGR, "uris empty");
        return ERR_UPMS_GET_FILE_URIS_BY_KEY_FAILED;
    }
    return ERR_OK;
}

int32_t UDMFUtils::AddPrivilege(const std::string &key, uint32_t tokenId, const std::string &readPermission)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    TAG_LOGI(AAFwkTag::URIPERMMGR, "AddPrivilege call");
    UDMF::QueryOption query = { .key = key };
    UDMF::Privilege privilege = { .tokenId = tokenId, .readPermission = readPermission };
    auto ret = IN_PROCESS_CALL(UDMF::UdmfClient::GetInstance().AddPrivilege(query, privilege));
    if (ret != ERR_OK) {
        TAG_LOGE(AAFwkTag::URIPERMMGR, "AddPrivilege failed:%{public}d", ret);
    }
    return ret;
}

int32_t UDMFUtils::ProcessUdmfKey(const std::string &key, uint32_t callerTokenId, uint32_t targetTokenId,
    std::vector<std::string> &uris)
{
    // To check if the key belong to callerTokenId
    auto ret = AddPrivilege(key, targetTokenId, "");
    if (ret != ERR_OK) {
        TAG_LOGE(AAFwkTag::URIPERMMGR, "AddPrivilege failed:%{public}d", ret);
        return ERR_UPMS_ADD_PRIVILEGED_FAILED;
    }
    uint32_t selfToken = IPCSkeleton::GetSelfTokenID();
    ret = AddPrivilege(key, selfToken, "readAndKeep");
    if (ret != ERR_OK) {
        TAG_LOGE(AAFwkTag::URIPERMMGR, "AddPrivilege self failed:%{public}d", ret);
        return ERR_UPMS_ADD_PRIVILEGED_FAILED;
    }
    ret = GetBatchData(key, uris);
    if (ret != ERR_OK) {
        TAG_LOGE(AAFwkTag::URIPERMMGR, "GetBatchData failed:%{public}d", ret);
        return ERR_UPMS_GET_FILE_URIS_BY_KEY_FAILED;
    }
    return ERR_OK;
}
} // OHOS
} // AAFwk