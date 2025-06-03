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

#ifndef UDMF_CLIENT_H
#define UDMF_CLIENT_H

#include <sys/types.h>
#include <string>
#include <vector>

namespace OHOS {
namespace UDMF {
namespace {
constexpr const char* EMPTY_ENTRY_URI = "null";
}

struct QueryOption {
    std::string key;
};

struct Object {
    Object() {}

    Object(const std::string &uri)
    {
        value_ = uri;
    }

    bool GetValue(const std::string &key, std::string &value)
    {
        value = value_;
        return true;
    }
    std::string value_;
};

using ValueType = std::variant<std::shared_ptr<Object>>;

struct UnifiedRecord {
    UnifiedRecord(const std::string &uri)
    {
        if (uri != EMPTY_ENTRY_URI) {
            entry = std::make_shared<Object>(uri);
            return;
        }
        entry = nullptr;
    }

    ValueType GetEntry(const std::string &utdId)
    {
        return entry;
    }

    std::shared_ptr<Object> entry = nullptr;
};

struct UnifiedData {
    UnifiedData(std::vector<std::shared_ptr<UnifiedRecord>> records)
    {
        unifiedRecords_ = records;
    }

    std::vector<std::shared_ptr<UnifiedRecord>> GetRecords()
    {
        return unifiedRecords_;
    }
    std::vector<std::shared_ptr<UnifiedRecord>> unifiedRecords_;
};

struct Privilege {
    uint32_t tokenId = 0;
    std::string readPermission = "";
};

class UdmfClient {
    public:
        static UdmfClient &GetInstance();

        ~UdmfClient() {};

        int32_t GetBatchData(const QueryOption &query, std::vector<UnifiedData> &unifiedDataset);
        int32_t AddPrivilege(const QueryOption &query, const Privilege &privilege);
        static void Init();
        static std::vector<UnifiedData> unifiedData_;
        static int32_t getBatchDataRet_;
        static int32_t addPrivilegeRet_;
        static int32_t privilegeTokenId_;
    
    private:
        UdmfClient() {};
};
} // OHOS
} // UDMF
#endif // UDMF_CLIENT_H