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

#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include "insight_intent_rdb_storage_mgr.h"

namespace OHOS {
namespace AbilityRuntime {
bool g_mockDeleteStorageInsightIntentDataRet = true;
bool g_mockDeleteStorageInsightIntentByUserIdRet = true;
bool g_mockSaveStorageInsightIntentDataRet = true;
bool g_mockLoadInsightIntentInfoRet = true;
bool g_mockLoadInsightIntentInfoByNameRet = true;
bool g_mockLoadInsightIntentInfosRet = true;

void MockDeleteData(bool mockRet)
{
    g_mockDeleteStorageInsightIntentDataRet = mockRet;
}


void MockDeleteDataByUserId(bool mockRet)
{
    g_mockDeleteStorageInsightIntentByUserIdRet = mockRet;
}

void MockSaveData(bool mockRet)
{
    g_mockSaveStorageInsightIntentDataRet = mockRet;
}

void MockLoadInsightIntentInfo(bool mockRet)
{
    g_mockLoadInsightIntentInfoRet = mockRet;
}

void MockLoadInsightIntentInfoByName(bool mockRet)
{
    g_mockLoadInsightIntentInfoByNameRet = mockRet;
}

void MockLoadInsightIntentInfos(bool mockRet)
{
    g_mockLoadInsightIntentInfosRet = mockRet;
}

}
}

namespace OHOS {
namespace AbilityRuntime {
InsightRdbStorageMgr::InsightRdbStorageMgr()
{
}

InsightRdbStorageMgr::~InsightRdbStorageMgr()
{
}

int32_t  InsightRdbStorageMgr::LoadInsightIntentInfos(const int32_t userId,
    std::vector<ExtractInsightIntentInfo> &totalInfos)
{
    ExtractInsightIntentInfo totalInfo;
    totalInfos.push_back(totalInfo);
    if (g_mockLoadInsightIntentInfosRet) {
        return ERR_OK;
    }
    return ERR_INVALID_VALUE;
}

int32_t  InsightRdbStorageMgr::LoadInsightIntentInfoByName(const std::string &bundleName, const int32_t userId,
    std::vector<ExtractInsightIntentInfo> &totalInfos)
{
    ExtractInsightIntentInfo totalInfo;
    totalInfos.push_back(totalInfo);
    if (g_mockLoadInsightIntentInfoByNameRet) {
        return ERR_OK;
    }
    return ERR_INVALID_VALUE;
}

int32_t  InsightRdbStorageMgr::LoadInsightIntentInfo(const std::string &bundleName, const std::string &moduleName,
    const std::string &intentName, const int32_t userId, ExtractInsightIntentInfo &totalInfo)
{
    if (g_mockLoadInsightIntentInfoRet) {
        return ERR_OK;
    }
    return ERR_INVALID_VALUE;
}

int32_t  InsightRdbStorageMgr::SaveStorageInsightIntentData(const std::string &bundleName,
    const std::string &moduleName, const int32_t userId, ExtractInsightIntentProfileInfoVec &profileInfos)
{
    if (g_mockSaveStorageInsightIntentDataRet) {
        return ERR_OK;
    }
    return ERR_INVALID_VALUE;
}

int32_t  InsightRdbStorageMgr::DeleteStorageInsightIntentData(const std::string &bundleName,
    const std::string &moduleName, const int32_t userId)
{
    if (g_mockDeleteStorageInsightIntentDataRet) {
        return ERR_OK;
    }
    return ERR_INVALID_VALUE;
}

int32_t  InsightRdbStorageMgr::DeleteStorageInsightIntentByUserId(const int32_t userId)
{
    if (g_mockDeleteStorageInsightIntentByUserIdRet) {
        return ERR_OK;
    }
    return ERR_INVALID_VALUE;
}
}
}