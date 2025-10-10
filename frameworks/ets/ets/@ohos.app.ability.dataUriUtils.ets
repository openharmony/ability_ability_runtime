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

import hilog from '@ohos.hilog';

let domainID = 0xD001320;
let TAG = 'ETSENV';

const URI_SPLIT = '/';

const ERROR_CODE_INVALID_PARAM = 401;
const ERROR_CODE_INNER_ERROR = 16000050;

const ERROR_MSG_INVALID_PARAM = 'Invalid input parameter.';
const ERROR_MSG_INNER_ERROR = 'Internal error.';

let errMap = new Map<number, string>();
errMap.set(ERROR_CODE_INVALID_PARAM, ERROR_MSG_INVALID_PARAM);
errMap.set(ERROR_CODE_INNER_ERROR, ERROR_MSG_INNER_ERROR);

class DataUriError extends Error {
  constructor(code: int) {
    super(errMap.has(code) ? errMap.get(code) : ERROR_MSG_INNER_ERROR);
    this.code = code;
  }
}

namespace dataUriUtils {
  export function getId(uri: string): number {
    hilog.debug(domainID, TAG, 'DataUriUtils getId called.');
    if (typeof uri !== 'string') {
      throw new DataUriError(ERROR_CODE_INVALID_PARAM);
    }
    let index = uri.lastIndexOf(URI_SPLIT);
    if (index === -1) {
      throw new DataUriError(ERROR_CODE_INVALID_PARAM);
    }
    let ret = uri.substring(index + 1);
    if (ret === '' || isNaN(Number(ret))) {
      throw new DataUriError(ERROR_CODE_INVALID_PARAM);
    }
    return Number(ret);
  }

  export function attachId(uri: string, id: number): string {
    hilog.debug(domainID, TAG, 'DataUriUtils attachId called.');
    if (typeof uri !== 'string' || typeof id !== 'number') {
      throw new DataUriError(ERROR_CODE_INVALID_PARAM);
    }
    return uri + URI_SPLIT + id;
  }

  export function deleteId(uri: string): string {
    hilog.debug(domainID, TAG, 'DataUriUtils deleteId called.');
    if (typeof uri !== 'string') {
      throw new DataUriError(ERROR_CODE_INVALID_PARAM);
    }
    let index = uri.lastIndexOf(URI_SPLIT);
    if (index === -1) {
      throw new DataUriError(ERROR_CODE_INVALID_PARAM);
    }
    let id = uri.substring(index + 1);
    if (id === '' || isNaN(Number(id))) {
      throw new DataUriError(ERROR_CODE_INVALID_PARAM);
    }
    return uri.substring(0, index);
  }

  export function updateId(uri: string, id: number): string {
    hilog.debug(domainID, TAG, 'DataUriUtils updateId called.');
    if (typeof uri !== 'string' || typeof id !== 'number') {
      throw new DataUriError(ERROR_CODE_INVALID_PARAM);
    }
    let ret = dataUriUtils.deleteId(uri);
    if (ret === uri) {
      throw new DataUriError(ERROR_CODE_INVALID_PARAM);
    }
    return ret + URI_SPLIT + id;
  }
}

export default dataUriUtils;