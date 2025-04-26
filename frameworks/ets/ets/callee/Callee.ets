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
import rpc from '@ohos.rpc';
import { BusinessError } from '@ohos.base';
import { Callee, CalleeCallback } from '@ohos.app.ability.UIAbility';

const domainID = 0x0000;
const TAG = 'UIAbility';

const EVENT_CALL_NOTIFY = 1;
const REQUEST_SUCCESS = 0;
const REQUEST_FAILED = 1;
const PERMISSION_ABILITY_BACKGROUND_COMMUNICATION = 'ohos.permission.ABILITY_BACKGROUND_COMMUNICATION';

const ERROR_CODE_INVALID_PARAM = 401;
const ERROR_CODE_FUNC_REGISTERED = 16200004;
const ERROR_CODE_FUNC_NOT_EXIST = 16200005;
const ERROR_CODE_INNER_ERROR = 16000050;

const ERROR_MSG_INVALID_PARAM = 'Invalid input parameter.';
const ERROR_MSG_FUNC_REGISTERED = 'Method registered. The method has registered.';
const ERROR_MSG_FUNC_NOT_EXIST = 'The method has not been registered.';
const ERROR_MSG_INNER_ERROR = 'Inner Error.';

let errMap = new Map<number, string>();
errMap.set(ERROR_CODE_INVALID_PARAM, ERROR_MSG_INVALID_PARAM);
errMap.set(ERROR_CODE_FUNC_REGISTERED, ERROR_MSG_FUNC_REGISTERED);
errMap.set(ERROR_CODE_FUNC_NOT_EXIST, ERROR_MSG_FUNC_NOT_EXIST);
errMap.set(ERROR_CODE_INNER_ERROR, ERROR_MSG_INNER_ERROR);

function buildError(code: number): BusinessError {
  return new BusinessError(code, new Error(errMap.get(code) as string));
}

export class CalleeImpl extends rpc.RemoteObject implements Callee {
  private callList = new Map<string, CalleeCallback>();
  private startUpNewRule = false;
  constructor() {
    super('rpc.application.callee');
    hilog.info(domainID, TAG, 'Callee constructor is OK');
  }

  setNewRuleFlag(flag: boolean): void {
    this.startUpNewRule = flag;
  }

  onRemoteMessageRequest(code: number, data: rpc.MessageSequence, reply: rpc.MessageSequence,
    option: rpc.MessageOption): Boolean|Promise<Boolean> {
    hilog.info(domainID, TAG, 'Callee onRemoteMessageRequest code [' + code + ']');
    return true;
  }

  on(method: string, callback: CalleeCallback): void {
    if (this.callList.has(method)) {
      hilog.info(domainID, TAG, 'Callee on error, [' + method + '] has registered');
      throw buildError(ERROR_CODE_FUNC_REGISTERED);
    }

    this.callList.set(method, callback);
    hilog.info(domainID, TAG, 'Callee on method [' + method + ']');
  }

  off(method: string): void {
    if (!this.callList.has(method)) {
      hilog.info(domainID, TAG, 'Callee off error, this.callList not found ' + method);
      throw buildError(ERROR_CODE_FUNC_NOT_EXIST);
    }

    this.callList.delete(method);
    hilog.info(domainID, TAG, 'Callee off method [' + method + ']');
  }
}