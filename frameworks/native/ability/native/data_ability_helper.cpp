/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#include "data_ability_helper.h"
#include "abs_shared_result_set.h"
#include "datashare_helper.h"
#include "hilog_tag_wrapper.h"
#include "hitrace_meter.h"
#include "rdb_data_ability_utils.h"

namespace OHOS {
namespace AppExecFwk {
using namespace OHOS::RdbDataAbilityAdapter;
DataAbilityHelper::DataAbilityHelper(const std::shared_ptr<DataAbilityHelperImpl> &helperImpl)
{
    dataAbilityHelperImpl_ = helperImpl;
}

DataAbilityHelper::DataAbilityHelper(const std::shared_ptr<DataShare::DataShareHelper> &dataShareHelper)
{
    dataShareHelper_ = dataShareHelper;
}

/**
 * @brief Creates a DataAbilityHelper instance without specifying the Uri based on the given Context.
 *
 * @param context Indicates the Context object on OHOS.
 *
 * @return Returns the created DataAbilityHelper instance where Uri is not specified.
 */
std::shared_ptr<DataAbilityHelper> DataAbilityHelper::Creator(const std::shared_ptr<Context> context)
{
    TAG_LOGI(AAFwkTag::DATA_ABILITY, "Creator with context");
    DataAbilityHelper *ptrDataAbilityHelper = nullptr;
    std::shared_ptr<DataAbilityHelperImpl> dataAbilityHelperImpl = DataAbilityHelperImpl::Creator(context);
    if (dataAbilityHelperImpl) {
        ptrDataAbilityHelper = new DataAbilityHelper(dataAbilityHelperImpl);
    }
    return std::shared_ptr<DataAbilityHelper>(ptrDataAbilityHelper);
}

/**
 * @brief Creates a DataAbilityHelper instance with the Uri specified based on the given Context.
 *
 * @param context Indicates the Context object on OHOS.
 * @param uri Indicates the database table or disk file to operate.
 *
 * @return Returns the created DataAbilityHelper instance with a specified Uri.
 */
std::shared_ptr<DataAbilityHelper> DataAbilityHelper::Creator(
    const std::shared_ptr<Context> context, const std::shared_ptr<Uri> &uri)
{
    TAG_LOGI(AAFwkTag::DATA_ABILITY, "Creator with context & uri");
    if (!context || !uri) {
        TAG_LOGE(AAFwkTag::DATA_ABILITY, "invalid param");
        return nullptr;
    }
    auto sharedPtrDataAbilityHelper = DataAbilityHelper::Creator(context, uri, false);
    if (sharedPtrDataAbilityHelper) {
        return sharedPtrDataAbilityHelper;
    }

    TAG_LOGI(AAFwkTag::DATA_ABILITY, "Creator failed");
    Uri dataShareUri("");
    if (!DataAbilityHelper::TransferScheme(*uri, dataShareUri)) {
        return nullptr;
    }
    DataAbilityHelper *ptrDataAbilityHelper = nullptr;
    auto dataShareHelper = DataShare::DataShareHelper::Creator(context->GetToken(), dataShareUri.ToString());
    if (dataShareHelper) {
        ptrDataAbilityHelper = new DataAbilityHelper(dataShareHelper);
    }
    TAG_LOGD(AAFwkTag::DATA_ABILITY, "end");
    return std::shared_ptr<DataAbilityHelper>(ptrDataAbilityHelper);
}

/**
 * @brief Creates a DataAbilityHelper instance with the Uri specified based on the given Context.
 *
 * @param context Indicates the Context object on OHOS.
 * @param uri Indicates the database table or disk file to operate.
 *
 * @return Returns the created DataAbilityHelper instance with a specified Uri.
 */
std::shared_ptr<DataAbilityHelper> DataAbilityHelper::Creator(
    const std::shared_ptr<OHOS::AbilityRuntime::Context> context, const std::shared_ptr<Uri> &uri)
{
    TAG_LOGI(AAFwkTag::DATA_ABILITY, "Creator with ability runtime context & uri");
    if (!context || !uri) {
        TAG_LOGE(AAFwkTag::DATA_ABILITY, "invalid param");
        return nullptr;
    }
    auto sharedPtrDataAbilityHelper = DataAbilityHelper::Creator(context, uri, false);
    if (sharedPtrDataAbilityHelper) {
        return sharedPtrDataAbilityHelper;
    }

    TAG_LOGI(AAFwkTag::DATA_ABILITY, "Creator failed");
    Uri dataShareUri("");
    if (!DataAbilityHelper::TransferScheme(*uri, dataShareUri)) {
        return nullptr;
    }
    DataAbilityHelper *ptrDataAbilityHelper = nullptr;
    auto dataShareHelper = DataShare::DataShareHelper::Creator(context->GetToken(), dataShareUri.ToString());
    if (dataShareHelper) {
        ptrDataAbilityHelper = new DataAbilityHelper(dataShareHelper);
    }
    return std::shared_ptr<DataAbilityHelper>(ptrDataAbilityHelper);
}

/**
 * @brief You can use this method to specify the Uri of the data to operate and set the binding relationship
 * between the ability using the Data template (Data ability for short) and the associated client process in
 * a DataAbilityHelper instance.
 *
 * @param context Indicates the Context object on OHOS.
 * @param uri Indicates the database table or disk file to operate.
 * @param tryBind Specifies whether the exit of the corresponding Data ability process causes the exit of the
 * client process.
 *
 * @return Returns the created DataAbilityHelper instance.
 */
std::shared_ptr<DataAbilityHelper> DataAbilityHelper::Creator(
    const std::shared_ptr<Context> context, const std::shared_ptr<Uri> &uri, const bool tryBind)
{
    TAG_LOGI(AAFwkTag::DATA_ABILITY, "Creator with context & uri & tryBind");
    DataAbilityHelper *ptrDataAbilityHelper = nullptr;
    auto dataAbilityHelperImpl = DataAbilityHelperImpl::Creator(context, uri, tryBind);
    if (dataAbilityHelperImpl) {
        ptrDataAbilityHelper = new DataAbilityHelper(dataAbilityHelperImpl);
    }
    return std::shared_ptr<DataAbilityHelper>(ptrDataAbilityHelper);
}

/**
 * @brief You can use this method to specify the Uri of the data to operate and set the binding relationship
 * between the ability using the Data template (Data ability for short) and the associated client process in
 * a DataAbilityHelper instance.
 *
 * @param context Indicates the Context object on OHOS.
 * @param uri Indicates the database table or disk file to operate.
 * @param tryBind Specifies whether the exit of the corresponding Data ability process causes the exit of the
 * client process.
 *
 * @return Returns the created DataAbilityHelper instance.
 */
std::shared_ptr<DataAbilityHelper> DataAbilityHelper::Creator(
    const std::shared_ptr<OHOS::AbilityRuntime::Context> context, const std::shared_ptr<Uri> &uri, const bool tryBind)
{
    TAG_LOGI(
        AAFwkTag::DATA_ABILITY, "Creator with ability runtime context & uri & tryBind");
    DataAbilityHelper *ptrDataAbilityHelper = nullptr;
    auto dataAbilityHelperImpl = DataAbilityHelperImpl::Creator(context, uri, tryBind);
    if (dataAbilityHelperImpl) {
        ptrDataAbilityHelper = new DataAbilityHelper(dataAbilityHelperImpl);
    }
    return std::shared_ptr<DataAbilityHelper>(ptrDataAbilityHelper);
}

/**
 * @brief Creates a DataAbilityHelper instance without specifying the Uri based.
 *
 * @param token Indicates the System token.
 *
 * @return Returns the created DataAbilityHelper instance where Uri is not specified.
 */
std::shared_ptr<DataAbilityHelper> DataAbilityHelper::Creator(const sptr<IRemoteObject> token)
{
    TAG_LOGI(AAFwkTag::DATA_ABILITY, "Creator with token");
    DataAbilityHelper *ptrDataAbilityHelper = nullptr;
    auto dataAbilityHelperImpl = DataAbilityHelperImpl::Creator(token);
    if (dataAbilityHelperImpl) {
        ptrDataAbilityHelper = new DataAbilityHelper(dataAbilityHelperImpl);
    }
    return std::shared_ptr<DataAbilityHelper>(ptrDataAbilityHelper);
}

/**
 * @brief You can use this method to specify the Uri of the data to operate and set the binding relationship
 * between the ability using the Data template (Data ability for short) and the associated client process in
 * a DataAbilityHelper instance.
 *
 * @param token Indicates the System token.
 * @param uri Indicates the database table or disk file to operate.
 *
 * @return Returns the created DataAbilityHelper instance.
 */
std::shared_ptr<DataAbilityHelper> DataAbilityHelper::Creator(
    const sptr<IRemoteObject> token, const std::shared_ptr<Uri> &uri)
{
    TAG_LOGI(AAFwkTag::DATA_ABILITY, "Creator with token & uri");
    if (!token || !uri) {
        TAG_LOGE(AAFwkTag::DATA_ABILITY, "invalid param");
        return nullptr;
    }
    DataAbilityHelper *ptrDataAbilityHelper = nullptr;
    auto dataAbilityHelperImpl = DataAbilityHelperImpl::Creator(token, uri);
    if (dataAbilityHelperImpl) {
        ptrDataAbilityHelper = new DataAbilityHelper(dataAbilityHelperImpl);
    } else {
        TAG_LOGI(AAFwkTag::DATA_ABILITY, "Creator failed");
        Uri dataShareUri("");
        if (!DataAbilityHelper::TransferScheme(*uri, dataShareUri)) {
            return nullptr;
        }
        auto dataShareHelper = DataShare::DataShareHelper::Creator(token, dataShareUri.ToString());
        if (dataShareHelper) {
            ptrDataAbilityHelper = new DataAbilityHelper(dataShareHelper);
        }
    }
    return std::shared_ptr<DataAbilityHelper>(ptrDataAbilityHelper);
}

/**
 * @brief Releases the client resource of the Data ability.
 * You should call this method to releases client resource after the data operations are complete.
 *
 * @return Returns true if the resource is successfully released; returns false otherwise.
 */
bool DataAbilityHelper::Release()
{
    TAG_LOGI(AAFwkTag::DATA_ABILITY, "called");
    bool ret = false;
    if (dataAbilityHelperImpl_) {
        TAG_LOGI(AAFwkTag::DATA_ABILITY, "DataAbilityHelperImpl Release");
        ret = dataAbilityHelperImpl_->Release();
    }
    if (dataShareHelper_) {
        TAG_LOGI(AAFwkTag::DATA_ABILITY, "DataShareHelper Release");
        ret = dataShareHelper_->Release();
        dataShareHelper_.reset();
    }
    return ret;
}

/**
 * @brief Obtains the MIME types of files supported.
 *
 * @param uri Indicates the path of the files to obtain.
 * @param mimeTypeFilter Indicates the MIME types of the files to obtain. This parameter cannot be null.
 *
 * @return Returns the matched MIME types. If there is no match, null is returned.
 */
std::vector<std::string> DataAbilityHelper::GetFileTypes(Uri &uri, const std::string &mimeTypeFilter)
{
    HITRACE_METER_NAME(HITRACE_TAG_DISTRIBUTEDDATA, __PRETTY_FUNCTION__);
    TAG_LOGI(AAFwkTag::DATA_ABILITY, "called");
    std::vector<std::string> matchedMIMEs;
    auto dataAbilityHelperImpl = GetDataAbilityHelperImpl();
    if (dataAbilityHelperImpl) {
        TAG_LOGI(AAFwkTag::DATA_ABILITY, "Ability GetFileTypes");
        matchedMIMEs = dataAbilityHelperImpl->GetFileTypes(uri, mimeTypeFilter);
    }
    auto dataShareHelper = GetDataShareHelper();
    if (dataShareHelper) {
        TAG_LOGI(AAFwkTag::DATA_ABILITY, "Share GetFileTypes");
        Uri dataShareUri("");
        if (TransferScheme(uri, dataShareUri)) {
            matchedMIMEs = dataShareHelper->GetFileTypes(dataShareUri, mimeTypeFilter);
        }
    }
    return matchedMIMEs;
}

/**
 * @brief Opens a file in a specified remote path.
 *
 * @param uri Indicates the path of the file to open.
 * @param mode Indicates the file open mode, which can be "r" for read-only access, "w" for write-only access
 * (erasing whatever data is currently in the file), "wt" for write access that truncates any existing file,
 * "wa" for write-only access to append to any existing data, "rw" for read and write access on any existing data,
 *  or "rwt" for read and write access that truncates any existing file.
 *
 * @return Returns the file descriptor.
 */
int DataAbilityHelper::OpenFile(Uri &uri, const std::string &mode)
{
    TAG_LOGI(AAFwkTag::DATA_ABILITY, "called");
    int fd = -1;
    auto dataAbilityHelperImpl = GetDataAbilityHelperImpl();
    if (dataAbilityHelperImpl) {
        TAG_LOGI(AAFwkTag::DATA_ABILITY, "Ability OpenFile");
        fd = dataAbilityHelperImpl->OpenFile(uri, mode);
    }
    auto dataShareHelper = GetDataShareHelper();
    if (dataShareHelper) {
        if (callFromJs_) {
            TAG_LOGE(AAFwkTag::DATA_ABILITY, "Share no this interface");
        } else {
            TAG_LOGI(AAFwkTag::DATA_ABILITY, "Share OpenFile");
            Uri dataShareUri("");
            if (TransferScheme(uri, dataShareUri)) {
                fd = dataShareHelper->OpenFile(dataShareUri, mode);
            }
        }
    }
    return fd;
}

/**
 * @brief This is like openFile, open a file that need to be able to return sub-sections of files，often assets
 * inside of their .hap.
 *
 * @param uri Indicates the path of the file to open.
 * @param mode Indicates the file open mode, which can be "r" for read-only access, "w" for write-only access
 * (erasing whatever data is currently in the file), "wt" for write access that truncates any existing file,
 * "wa" for write-only access to append to any existing data, "rw" for read and write access on any existing
 * data, or "rwt" for read and write access that truncates any existing file.
 *
 * @return Returns the RawFileDescriptor object containing file descriptor.
 */
int DataAbilityHelper::OpenRawFile(Uri &uri, const std::string &mode)
{
    TAG_LOGI(AAFwkTag::DATA_ABILITY, "called");
    int fd = -1;
    auto dataAbilityHelperImpl = GetDataAbilityHelperImpl();
    if (dataAbilityHelperImpl) {
        TAG_LOGI(AAFwkTag::DATA_ABILITY, "Ability OpenRawFile");
        fd = dataAbilityHelperImpl->OpenRawFile(uri, mode);
    }
    auto dataShareHelper = GetDataShareHelper();
    if (dataShareHelper) {
        TAG_LOGI(AAFwkTag::DATA_ABILITY, "Share OpenFile");
        Uri dataShareUri("");
        if (TransferScheme(uri, dataShareUri)) {
            fd = dataShareHelper->OpenRawFile(dataShareUri, mode);
        }
    }
    return fd;
}

/**
 * @brief Inserts a single data record into the database.
 *
 * @param uri Indicates the path of the data to operate.
 * @param value Indicates the data record to insert. If this parameter is null, a blank row will be inserted.
 *
 * @return Returns the index of the inserted data record.
 */
int DataAbilityHelper::Insert(Uri &uri, const NativeRdb::ValuesBucket &value)
{
    HITRACE_METER_NAME(HITRACE_TAG_DISTRIBUTEDDATA, __PRETTY_FUNCTION__);
    TAG_LOGI(AAFwkTag::DATA_ABILITY, "called");
    int index = -1;
    auto dataAbilityHelperImpl = GetDataAbilityHelperImpl();
    if (dataAbilityHelperImpl) {
        TAG_LOGI(AAFwkTag::DATA_ABILITY, "Ability Insert");
        index = dataAbilityHelperImpl->Insert(uri, value);
    }
    auto dataShareHelper = GetDataShareHelper();
    if (dataShareHelper) {
        TAG_LOGI(AAFwkTag::DATA_ABILITY, "Share Insert");
        DataShare::DataShareValuesBucket dataShareValue = RdbDataAbilityUtils::ToDataShareValuesBucket(value);
        Uri dataShareUri("");
        if (TransferScheme(uri, dataShareUri)) {
            index = dataShareHelper->Insert(dataShareUri, dataShareValue);
        }
    }
    return index;
}

std::shared_ptr<AppExecFwk::PacMap> DataAbilityHelper::Call(
    const Uri &uri, const std::string &method, const std::string &arg, const AppExecFwk::PacMap &pacMap)
{
    std::shared_ptr<AppExecFwk::PacMap> result = nullptr;
    TAG_LOGI(AAFwkTag::DATA_ABILITY, "called");
    auto dataAbilityHelperImpl = GetDataAbilityHelperImpl();
    if (dataAbilityHelperImpl) {
        TAG_LOGI(AAFwkTag::DATA_ABILITY, "Ability Call");
        result = dataAbilityHelperImpl->Call(uri, method, arg, pacMap);
    }
    if (dataShareHelper_) {
        TAG_LOGE(AAFwkTag::DATA_ABILITY, "Share no Call");
    }
    return result;
}

/**
 * @brief Updates data records in the database.
 *
 * @param uri Indicates the path of data to update.
 * @param value Indicates the data to update. This parameter can be null.
 * @param predicates Indicates filter criteria. You should define the processing logic when this parameter is null.
 *
 * @return Returns the number of data records updated.
 */
int DataAbilityHelper::Update(
    Uri &uri, const NativeRdb::ValuesBucket &value, const NativeRdb::DataAbilityPredicates &predicates)
{
    HITRACE_METER_NAME(HITRACE_TAG_DISTRIBUTEDDATA, __PRETTY_FUNCTION__);
    TAG_LOGI(AAFwkTag::DATA_ABILITY, "called");
    int index = -1;
    auto dataAbilityHelperImpl = GetDataAbilityHelperImpl();
    if (dataAbilityHelperImpl) {
        TAG_LOGI(AAFwkTag::DATA_ABILITY, "Ability Update");
        index = dataAbilityHelperImpl->Update(uri, value, predicates);
    }
    auto dataShareHelper = GetDataShareHelper();
    if (dataShareHelper) {
        TAG_LOGI(AAFwkTag::DATA_ABILITY, "Share Update");
        DataShare::DataShareValuesBucket dataShareValue = RdbDataAbilityUtils::ToDataShareValuesBucket(value);
        DataShare::DataSharePredicates dataSharePredicates = RdbDataAbilityUtils::ToDataSharePredicates(predicates);
        Uri dataShareUri("");
        if (TransferScheme(uri, dataShareUri)) {
            index = dataShareHelper->Update(dataShareUri, dataSharePredicates, dataShareValue);
        }
    }
    return index;
}

/**
 * @brief Deletes one or more data records from the database.
 *
 * @param uri Indicates the path of the data to operate.
 * @param predicates Indicates filter criteria. You should define the processing logic when this parameter is null.
 *
 * @return Returns the number of data records deleted.
 */
int DataAbilityHelper::Delete(Uri &uri, const NativeRdb::DataAbilityPredicates &predicates)
{
    HITRACE_METER_NAME(HITRACE_TAG_DISTRIBUTEDDATA, __PRETTY_FUNCTION__);
    TAG_LOGI(AAFwkTag::DATA_ABILITY, "called");
    int index = -1;
    auto dataAbilityHelperImpl = GetDataAbilityHelperImpl();
    if (dataAbilityHelperImpl) {
        TAG_LOGI(AAFwkTag::DATA_ABILITY, "Ability Delete");
        return dataAbilityHelperImpl->Delete(uri, predicates);
    }
    auto dataShareHelper = GetDataShareHelper();
    if (dataShareHelper) {
        TAG_LOGI(AAFwkTag::DATA_ABILITY, "Share Delete");
        DataShare::DataSharePredicates dataSharePredicates = RdbDataAbilityUtils::ToDataSharePredicates(predicates);
        Uri dataShareUri("");
        if (TransferScheme(uri, dataShareUri)) {
            index = dataShareHelper->Delete(dataShareUri, dataSharePredicates);
        }
    }
    return index;
}

/**
 * @brief Deletes one or more data records from the database.
 *
 * @param uri Indicates the path of data to query.
 * @param columns Indicates the columns to query. If this parameter is null, all columns are queried.
 * @param predicates Indicates filter criteria. You should define the processing logic when this parameter is null.
 *
 * @return Returns the query result.
 */
std::shared_ptr<NativeRdb::AbsSharedResultSet> DataAbilityHelper::Query(
    Uri &uri, std::vector<std::string> &columns, const NativeRdb::DataAbilityPredicates &predicates)
{
    HITRACE_METER_NAME(HITRACE_TAG_DISTRIBUTEDDATA, __PRETTY_FUNCTION__);
    TAG_LOGD(AAFwkTag::DATA_ABILITY, "called");
    std::shared_ptr<NativeRdb::AbsSharedResultSet> resultSet = nullptr;
    auto dataAbilityHelperImpl = GetDataAbilityHelperImpl();
    if (dataAbilityHelperImpl) {
        TAG_LOGD(AAFwkTag::DATA_ABILITY, "Ability Query");
        return dataAbilityHelperImpl->Query(uri, columns, predicates);
    }
    auto dataShareHelper = GetDataShareHelper();
    if (dataShareHelper) {
        TAG_LOGD(AAFwkTag::DATA_ABILITY, "Share Query");
        DataShare::DataSharePredicates dataSharePredicates = RdbDataAbilityUtils::ToDataSharePredicates(predicates);
        Uri dataShareUri("");
        if (TransferScheme(uri, dataShareUri)) {
            std::shared_ptr<DataShare::DataShareResultSet> dataShareResultSet
                = dataShareHelper->Query(dataShareUri, dataSharePredicates, columns);
            if (!dataShareResultSet) {
                TAG_LOGE(AAFwkTag::DATA_ABILITY, "null dataShareResultSet");
                return nullptr;
            }
            resultSet = RdbDataAbilityUtils::ToAbsSharedResultSet(dataShareResultSet);
            if (!resultSet) {
                TAG_LOGE(AAFwkTag::DATA_ABILITY, "Transfer to AbsSharedResultSet failed");
            }
        }
    }
    return resultSet;
}

/**
 * @brief Obtains the MIME type matching the data specified by the URI of the Data ability. This method should be
 * implemented by a Data ability. Data abilities supports general data types, including text, HTML, and JPEG.
 *
 * @param uri Indicates the URI of the data.
 *
 * @return Returns the MIME type that matches the data specified by uri.
 */
std::string DataAbilityHelper::GetType(Uri &uri)
{
    HITRACE_METER_NAME(HITRACE_TAG_DISTRIBUTEDDATA, __PRETTY_FUNCTION__);
    TAG_LOGI(AAFwkTag::DATA_ABILITY, "called");
    std::string type;
    auto dataAbilityHelperImpl = GetDataAbilityHelperImpl();
    if (dataAbilityHelperImpl) {
        TAG_LOGI(AAFwkTag::DATA_ABILITY, "Ability GetType");
        type = dataAbilityHelperImpl->GetType(uri);
    }
    auto dataShareHelper = GetDataShareHelper();
    if (dataShareHelper) {
        TAG_LOGI(AAFwkTag::DATA_ABILITY, "Share GetType");
        Uri dataShareUri("");
        if (TransferScheme(uri, dataShareUri)) {
            type = dataShareHelper->GetType(dataShareUri);
        }
    }
    return type;
}

/**
 * @brief Reloads data in the database.
 *
 * @param uri Indicates the position where the data is to reload. This parameter is mandatory.
 * @param extras Indicates the PacMap object containing the additional parameters to be passed in this call. This
 * parameter can be null. If a custom Sequenceable object is put in the PacMap object and will be transferred across
 * processes, you must call BasePacMap.setClassLoader(ClassLoader) to set a class loader for the custom object.
 *
 * @return Returns true if the data is successfully reloaded; returns false otherwise.
 */
bool DataAbilityHelper::Reload(Uri &uri, const PacMap &extras)
{
    TAG_LOGI(AAFwkTag::DATA_ABILITY, "called");
    bool ret = false;
    auto dataAbilityHelperImpl = GetDataAbilityHelperImpl();
    if (dataAbilityHelperImpl) {
        TAG_LOGI(AAFwkTag::DATA_ABILITY, "Ability Reload");
        ret = dataAbilityHelperImpl->Reload(uri, extras);
    }
    if (dataShareHelper_) {
        TAG_LOGE(AAFwkTag::DATA_ABILITY, "Share no Reload");
    }
    return ret;
}

/**
 * @brief Inserts multiple data records into the database.
 *
 * @param uri Indicates the path of the data to operate.
 * @param values Indicates the data records to insert.
 *
 * @return Returns the number of data records inserted.
 */
int DataAbilityHelper::BatchInsert(Uri &uri, const std::vector<NativeRdb::ValuesBucket> &values)
{
    HITRACE_METER_NAME(HITRACE_TAG_DISTRIBUTEDDATA, __PRETTY_FUNCTION__);
    TAG_LOGI(AAFwkTag::DATA_ABILITY, "called");
    int ret = -1;
    auto dataAbilityHelperImpl = GetDataAbilityHelperImpl();
    if (dataAbilityHelperImpl) {
        TAG_LOGI(AAFwkTag::DATA_ABILITY, "Ability BatchInsert");
        ret = dataAbilityHelperImpl->BatchInsert(uri, values);
    }
    auto dataShareHelper = GetDataShareHelper();
    if (dataShareHelper) {
        TAG_LOGI(AAFwkTag::DATA_ABILITY, "Share BatchInsert");
        std::vector<DataShare::DataShareValuesBucket> dataShareValues;
        for (auto value : values) {
            DataShare::DataShareValuesBucket dataShareValue = RdbDataAbilityUtils::ToDataShareValuesBucket(value);
            dataShareValues.push_back(dataShareValue);
        }
        Uri dataShareUri("");
        if (TransferScheme(uri, dataShareUri)) {
            ret = dataShareHelper->BatchInsert(dataShareUri, dataShareValues);
        }
    }
    return ret;
}

/**
 * @brief Registers an observer to DataObsMgr specified by the given Uri.
 *
 * @param uri, Indicates the path of the data to operate.
 * @param dataObserver, Indicates the IDataAbilityObserver object.
 */
void DataAbilityHelper::RegisterObserver(const Uri &uri, const sptr<AAFwk::IDataAbilityObserver> &dataObserver)
{
    TAG_LOGI(AAFwkTag::DATA_ABILITY, "called");
    auto dataAbilityHelperImpl = GetDataAbilityHelperImpl();
    if (dataAbilityHelperImpl) {
        TAG_LOGI(AAFwkTag::DATA_ABILITY, "Ability RegisterObserver");
        dataAbilityHelperImpl->RegisterObserver(uri, dataObserver);
    }
    auto dataShareHelper = GetDataShareHelper();
    if (dataShareHelper) {
        TAG_LOGI(AAFwkTag::DATA_ABILITY, "Share RegisterObserver");
        Uri dataShareUri("");
        if (TransferScheme(uri, dataShareUri)) {
            dataShareHelper->RegisterObserver(dataShareUri, dataObserver);
        }
    }
}

/**
 * @brief Deregisters an observer used for DataObsMgr specified by the given Uri.
 *
 * @param uri, Indicates the path of the data to operate.
 * @param dataObserver, Indicates the IDataAbilityObserver object.
 */
void DataAbilityHelper::UnregisterObserver(const Uri &uri, const sptr<AAFwk::IDataAbilityObserver> &dataObserver)
{
    TAG_LOGI(AAFwkTag::DATA_ABILITY, "called");
    auto dataAbilityHelperImpl = GetDataAbilityHelperImpl();
    if (dataAbilityHelperImpl) {
        TAG_LOGI(AAFwkTag::DATA_ABILITY, "Ability UnregisterObserver");
        dataAbilityHelperImpl->UnregisterObserver(uri, dataObserver);
    }
    auto dataShareHelper = GetDataShareHelper();
    if (dataShareHelper) {
        TAG_LOGI(AAFwkTag::DATA_ABILITY, "Share UnregisterObserver");
        Uri dataShareUri("");
        if (TransferScheme(uri, dataShareUri)) {
            dataShareHelper->UnregisterObserver(dataShareUri, dataObserver);
        }
    }
}

/**
 * @brief Notifies the registered observers of a change to the data resource specified by Uri.
 *
 * @param uri, Indicates the path of the data to operate.
 */
void DataAbilityHelper::NotifyChange(const Uri &uri)
{
    HITRACE_METER_NAME(HITRACE_TAG_DISTRIBUTEDDATA, __PRETTY_FUNCTION__);
    TAG_LOGI(AAFwkTag::DATA_ABILITY, "called");
    auto dataAbilityHelperImpl = GetDataAbilityHelperImpl();
    if (dataAbilityHelperImpl) {
        TAG_LOGI(AAFwkTag::DATA_ABILITY, "Ability NotifyChange");
        dataAbilityHelperImpl->NotifyChange(uri);
    }
    auto dataShareHelper = GetDataShareHelper();
    if (dataShareHelper) {
        TAG_LOGI(AAFwkTag::DATA_ABILITY, "Share NotifyChange");
        Uri dataShareUri("");
        if (TransferScheme(uri, dataShareUri)) {
            dataShareHelper->NotifyChange(dataShareUri);
        }
    }
}

/**
 * @brief Converts the given uri that refer to the Data ability into a normalized URI. A normalized URI can be used
 * across devices, persisted, backed up, and restored. It can refer to the same item in the Data ability even if the
 * context has changed. If you implement URI normalization for a Data ability, you must also implement
 * denormalizeUri(ohos.utils.net.Uri) to enable URI denormalization. After this feature is enabled, URIs passed to any
 * method that is called on the Data ability must require normalization verification and denormalization. The default
 * implementation of this method returns null, indicating that this Data ability does not support URI normalization.
 *
 * @param uri Indicates the Uri object to normalize.
 *
 * @return Returns the normalized Uri object if the Data ability supports URI normalization; returns null otherwise.
 */
Uri DataAbilityHelper::NormalizeUri(Uri &uri)
{
    HITRACE_METER_NAME(HITRACE_TAG_DISTRIBUTEDDATA, __PRETTY_FUNCTION__);
    TAG_LOGI(AAFwkTag::DATA_ABILITY, "called");
    Uri urivalue("");
    auto dataAbilityHelperImpl = GetDataAbilityHelperImpl();
    if (dataAbilityHelperImpl) {
        TAG_LOGI(AAFwkTag::DATA_ABILITY, "Ability NormalizeUri");
        urivalue = dataAbilityHelperImpl->NormalizeUri(uri);
    }
    auto dataShareHelper = GetDataShareHelper();
    if (dataShareHelper) {
        TAG_LOGI(AAFwkTag::DATA_ABILITY, "Share NormalizeUri");
        Uri dataShareUri("");
        if (TransferScheme(uri, dataShareUri)) {
            urivalue = dataShareHelper->NormalizeUri(dataShareUri);
        }
    }
    return urivalue;
}

/**
 * @brief Converts the given normalized uri generated by normalizeUri(ohos.utils.net.Uri) into a denormalized one.
 * The default implementation of this method returns the original URI passed to it.
 *
 * @param uri uri Indicates the Uri object to denormalize.
 *
 * @return Returns the denormalized Uri object if the denormalization is successful; returns the original Uri passed to
 * this method if there is nothing to do; returns null if the data identified by the original Uri cannot be found in the
 * current environment.
 */
Uri DataAbilityHelper::DenormalizeUri(Uri &uri)
{
    HITRACE_METER_NAME(HITRACE_TAG_DISTRIBUTEDDATA, __PRETTY_FUNCTION__);
    TAG_LOGI(AAFwkTag::DATA_ABILITY, "called");
    Uri urivalue("");
    auto dataAbilityHelperImpl = GetDataAbilityHelperImpl();
    if (dataAbilityHelperImpl) {
        TAG_LOGI(AAFwkTag::DATA_ABILITY, "Ability DenormalizeUri");
        urivalue = dataAbilityHelperImpl->DenormalizeUri(uri);
    }
    auto dataShareHelper = GetDataShareHelper();
    if (dataShareHelper) {
        TAG_LOGI(AAFwkTag::DATA_ABILITY, "Share DenormalizeUri");
        Uri dataShareUri("");
        if (TransferScheme(uri, dataShareUri)) {
            urivalue = dataShareHelper->DenormalizeUri(dataShareUri);
        }
    }
    return urivalue;
}

std::vector<std::shared_ptr<DataAbilityResult>> DataAbilityHelper::ExecuteBatch(
    const Uri &uri, const std::vector<std::shared_ptr<DataAbilityOperation>> &operations)
{
    TAG_LOGI(AAFwkTag::DATA_ABILITY, "called");
    std::vector<std::shared_ptr<DataAbilityResult>> results;
    auto dataAbilityHelperImpl = GetDataAbilityHelperImpl();
    if (dataAbilityHelperImpl) {
        TAG_LOGI(AAFwkTag::DATA_ABILITY, "Ability ExecuteBatch");
        results = dataAbilityHelperImpl->ExecuteBatch(uri, operations);
    }
    if (dataShareHelper_) {
        TAG_LOGE(AAFwkTag::DATA_ABILITY, "Share no ExecuteBatch");
    }
    return results;
}

bool DataAbilityHelper::TransferScheme(const Uri &uri, Uri &dataShareUri)
{
    const std::string dataAbilityScheme = "dataability";
    const std::string dataShareScheme = "datashare";
    const std::string fileScheme = "file";
    const std::string dataSharePrefix = "datashare:///";
    const std::string filePrefix = "file://";

    Uri inputUri = uri;
    if (inputUri.GetScheme() == dataShareScheme) {
        dataShareUri = Uri(inputUri.ToString());
        TAG_LOGI(AAFwkTag::DATA_ABILITY, "data share uri: %{public}s no need transfer",
            inputUri.ToString().c_str());
        return true;
    }

    if (inputUri.GetScheme() == dataAbilityScheme) {
        string uriStr = inputUri.ToString();
        uriStr.replace(0, dataAbilityScheme.length(), dataShareScheme);
        dataShareUri = Uri(uriStr);
        TAG_LOGI(AAFwkTag::DATA_ABILITY, "ability uri: %{public}s transfer to share uri: %{public}s",
            inputUri.ToString().c_str(), dataShareUri.ToString().c_str());
        return true;
    }

    if (inputUri.GetScheme() == fileScheme) {
        string uriStr = inputUri.ToString();
        uriStr.replace(0, filePrefix.length(), dataSharePrefix);
        dataShareUri = Uri(uriStr);
        TAG_LOGD(AAFwkTag::DATA_ABILITY, "file uri: %{public}s transfer to share uri: %{public}s",
            inputUri.ToString().c_str(), dataShareUri.ToString().c_str());
        return true;
    }

    TAG_LOGE(AAFwkTag::DATA_ABILITY, "invalid param, uri: %{private}s", inputUri.ToString().c_str());
    return false;
}

void DataAbilityHelper::SetCallFromJs()
{
    callFromJs_ = true;
}
}  // namespace AppExecFwk
}  // namespace OHOS

