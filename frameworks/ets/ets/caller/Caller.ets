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
import { Caller, OnReleaseCallback, OnRemoteStateChangeCallback } from '@ohos.app.ability.UIAbility';

const domainID = 0x0000;
const TAG = 'UIAbility';

const EVENT_CALL_NOTIFY = 1;
const REQUEST_SUCCESS = 0;

const ERROR_CODE_INVALID_PARAM = 401;
const ERROR_CODE_CALLER_RELEASED = 16200001;
const ERROR_CODE_CLAAEE_INVALID = 16200002;
const ERROR_CODE_INNER_ERROR = 16000050;

const ERROR_MSG_INVALID_PARAM = 'Invalid input parameter.';
const ERROR_MSG_CALLER_RELEASED = 'Caller released. The caller has been released.';
const ERROR_MSG_CLAAEE_INVALID = 'The callee does not exist.';
const ERROR_MSG_INNER_ERROR = 'Inner Error.';

let errMap = new Map<number, string>();
errMap.set(ERROR_CODE_INVALID_PARAM, ERROR_MSG_INVALID_PARAM);
errMap.set(ERROR_CODE_CALLER_RELEASED, ERROR_MSG_CALLER_RELEASED);
errMap.set(ERROR_CODE_CLAAEE_INVALID, ERROR_MSG_CLAAEE_INVALID);
errMap.set(ERROR_CODE_INNER_ERROR, ERROR_MSG_INNER_ERROR);

function buildError(code: number): BusinessError {
  return new BusinessError(code, new Error(errMap.get(code) as string));
}

export class ReleaseCallback {
  private myFun_: OnReleaseCallback = (msg: string) => {}
  constructor(myFun: OnReleaseCallback) {
    this.myFun_ = myFun;
  }
  invoke(msg: string): void {
    this.myFun_(msg);
  }
}

export class CallerImpl implements Caller {
  nativeCaller: long;
  private callee: rpc.IRemoteObject | null = null;
  native nativeReleaseSync(): void;
  native nativeOnReleaseSync(callback: ReleaseCallback): void;
  native nativeOnRemoteStateChangeSync(callback: OnRemoteStateChangeCallback): void;
  private releaseState = false;

  constructor() {
    hilog.info(domainID, TAG, 'Caller::constructor');
  }

  call(method: string, data: rpc.Parcelable): Promise<void> {
    return new Promise<void>((resolve: (data: undefined)=>void, reject: (error: Error) => void): void => {
      hilog.info(domainID, TAG, 'Caller call');
      resolve(undefined);
      return;
    });
  }

  release(): void {
    hilog.info(domainID, TAG, 'Caller release called.');
    if (this.releaseState === true) {
      hilog.info(domainID, TAG, 'Caller release remoteObj releaseState is true');
      throw buildError(ERROR_CODE_CALLER_RELEASED);
    }

    if (this.callee == null) {
      hilog.info(domainID, TAG, 'Caller release call remoteObj is released');
      throw buildError(ERROR_CODE_CLAAEE_INVALID);
    }

    this.releaseState = true;
    this.callee = null;
    this.nativeReleaseSync();
  }

  onRelease(callback: OnReleaseCallback): void {
    hilog.info(domainID, TAG, 'onRelease called');
    this.nativeOnReleaseSync(new ReleaseCallback(callback));
  }
}
